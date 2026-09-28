"""Citadel monitor backend for Linux: ss, /proc, cgroups, the package
databases (pacman, dpkg, rpm), NetworkManager/iwd, and the kernel log that
citadel-helper >= 1.2 writes for new connections.
"""
import concurrent.futures
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import sqlite3
import shutil
import subprocess
import sys
import threading
import time
import urllib.request


from .common import *                                     # noqa: F401,F403
from .common import _run                                  # noqa: F401




# ------------------------------------------------------------------ ss parsing

USERS = re.compile(r'users:\(\("([^"]*)",pid=(\d+),fd=\d+')
UIDF = re.compile(r"\buid:(\d+)")
CGF = re.compile(r"\bcgroup:(\S+)")


def parse_ss(args, proto):
    try:
        text = subprocess.run(["ss", "-H", "-n", "-p", "-e", "--cgroup"] + args,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows, cur = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":                          # -i info line
            if cur is not None:
                m = re.search(r"bytes_sent:(\d+)", line)
                if m:
                    cur["up"] = int(m.group(1))
                m = re.search(r"bytes_received:(\d+)", line)
                if m:
                    cur["down"] = int(m.group(1))
            continue
        toks = line.split()
        # tcp with state filter: Recv-Q Send-Q Local Peer ...
        # (when several states are requested, ss prints the state first)
        if not toks[0].isdigit():
            state, toks = toks[0], toks[1:]
        else:
            state = "ESTAB"
        if len(toks) < 4:
            continue
        laddr, lport = split_addr(toks[2])
        raddr, rport = split_addr(toks[3])
        if not raddr or rport == 0 or raddr in ("*", "0.0.0.0", "::"):
            continue
        m = USERS.search(line)
        comm, pid = (m.group(1), int(m.group(2))) if m else ("", 0)
        m = UIDF.search(line)
        uid = int(m.group(1)) if m else 0
        m = CGF.search(line)
        cg = m.group(1) if m else ""
        cur = {"proto": proto, "state": state, "laddr": laddr, "lport": lport,
               "raddr": raddr, "rport": rport, "comm": comm, "pid": pid,
               "uid": uid, "cgroup": cg, "up": 0, "down": 0}
        rows.append(cur)
    return rows


def proc_table():
    """pid -> (exe, cgroup) for this user's processes."""
    table = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            if os.stat("/proc/" + d).st_uid != MY_UID:
                continue
            exe = os.readlink("/proc/%s/exe" % d)
        except OSError:
            continue
        cg = read("/proc/%s/cgroup" % d).strip()
        cg = cg.split("::", 1)[1] if "::" in cg else ""
        table[int(d)] = (exe, cg)
    return table


# ------------------------------------------------------------------ trust

trust_cache = {}
owner_cache = {}


# Package databases. The integrity check compares a program against the
# checksum its package recorded: pacman (sha256 in the mtree), dpkg (md5 in
# info/*.md5sums) or rpm (the package's file digests). Detected once.
PKG_ROOT = os.environ.get("CITADEL_PKGDB_ROOT", "")      # tests: a fake / for the databases


def pkg_backend():
    if os.path.isdir(PKG_ROOT + "/var/lib/pacman/local") and shutil.which("pacman"):
        return "pacman"
    if os.path.isdir(PKG_ROOT + "/var/lib/dpkg/info") and shutil.which("dpkg-query"):
        return "dpkg"
    if shutil.which("rpm") and (os.path.isdir("/var/lib/rpm") or os.path.isdir("/usr/lib/sysimage/rpm")):
        return "rpm"
    return ""


PKG_BACKEND = pkg_backend()


def _alt_paths(path):
    """Merged /usr: dpkg and rpm may list /bin/x for /usr/bin/x (and back)."""
    out = [path]
    for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib/", "/lib/"), ("/usr/lib64/", "/lib64/")):
        if path.startswith(a):
            out.append(b + path[len(a):])
        elif path.startswith(b):
            out.append(a + path[len(b):])
    return out


def pkg_owner(path):
    if path in owner_cache:
        return owner_cache[path]
    name = ""
    for cand in _alt_paths(path):
        try:
            if PKG_BACKEND == "pacman":
                p = subprocess.run(["pacman", "-Qqo", cand], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
                name = p.stdout.strip().splitlines()[0] if p.returncode == 0 and p.stdout.strip() else ""
            elif PKG_BACKEND == "dpkg":
                p = subprocess.run(["dpkg-query", "-S", cand], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
                line = p.stdout.strip().splitlines()[0] if p.returncode == 0 and p.stdout.strip() else ""
                # "pkg: /path" or "pkg:arch: /path"; "diversion by ..." lines are skipped
                name = line.rsplit(": ", 1)[0].split(",")[0].strip() if line and not line.startswith("diversion") else ""
            elif PKG_BACKEND == "rpm":
                p = subprocess.run(["rpm", "-qf", "--qf", "%{NAME}\n", cand], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, timeout=10)
                name = p.stdout.strip().splitlines()[0] if p.returncode == 0 and p.stdout.strip() else ""
        except (OSError, subprocess.TimeoutExpired, IndexError):
            name = ""
        if name:
            break
    owner_cache[path] = name
    return name


def mtree_digest(pkg, path, base=None):
    """("sha256", hex) recorded by pacman for this file, from the local db mtree."""
    base = base or PKG_ROOT + "/var/lib/pacman/local"
    try:
        dirs = [d for d in os.listdir(base) if d.startswith(pkg + "-")]
    except OSError:
        return None
    want = "./" + path.lstrip("/")
    for d in dirs:
        desc = read(os.path.join(base, d, "desc"))
        if ("%%NAME%%\n%s\n" % pkg) not in desc:
            continue
        try:
            with gzip.open(os.path.join(base, d, "mtree"), "rt", errors="replace") as f:
                for line in f:
                    if line.startswith(want + " "):
                        m = re.search(r"sha256digest=([0-9a-f]{64})", line)
                        return ("sha256", m.group(1)) if m else None
        except OSError:
            return None
    return None


def dpkg_digest(pkg, path, base=None):
    """("md5", hex) from dpkg's md5sums for this file (any listed path alias)."""
    base = base or PKG_ROOT + "/var/lib/dpkg/info"
    wants = {p.lstrip("/") for p in _alt_paths(path)}
    names = [pkg] if ":" in pkg else [pkg]
    try:
        names += [f[:-len(".md5sums")] for f in os.listdir(base) if f.startswith(pkg + ":") and f.endswith(".md5sums")]
    except OSError:
        return None
    for n in names:
        try:
            with open(os.path.join(base, n + ".md5sums"), errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split(None, 1)
                    if len(parts) == 2 and parts[1] in wants and re.fullmatch(r"[0-9a-f]{32}", parts[0]):
                        return ("md5", parts[0])
        except OSError:
            continue
    return None


RPM_ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}


def rpm_digest(pkg, path):
    """(algo, hex) from the rpm database's file digests for this file."""
    try:
        p = subprocess.run(["rpm", "-q", "--qf", "%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\n]", pkg],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_rpm_digests(p.stdout if p.returncode == 0 else "", path)


def parse_rpm_digests(text, path):
    lines = text.splitlines()
    if not lines:
        return None
    try:
        algo = RPM_ALGOS.get(int(lines[0].strip() or "1"), "")
    except ValueError:
        algo = "md5"                       # (none) on old rpms: md5
    wants = set(_alt_paths(path))
    for line in lines[1:]:
        name, _, digest = line.partition("\t")
        if name in wants and digest:
            return (algo, digest.strip()) if algo else None
    return None


def package_digest(pkg, path):
    if PKG_BACKEND == "pacman":
        return mtree_digest(pkg, path)
    if PKG_BACKEND == "dpkg":
        return dpkg_digest(pkg, path)
    if PKG_BACKEND == "rpm":
        return rpm_digest(pkg, path)
    return None


def trust(exe, deleted=False):
    """level: verified | modified | unpackaged | suspicious | unknown"""
    if not exe:
        return {"level": "unknown"}
    try:
        st = os.stat(exe)
        key = (exe, st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return {"level": "suspicious" if deleted else "unknown", "reason": "missing"}
    if key in trust_cache and not deleted:
        return trust_cache[key]
    if deleted:
        return {"level": "suspicious", "reason": "binary deleted since start"}
    if re.match(r"^/(tmp|var/tmp|dev/shm|run/user/\d+)/", exe):
        t = {"level": "suspicious", "reason": "runs from a temporary folder"}
    else:
        try:
            digest = sha256(exe)
        except OSError:
            digest = ""
        real = os.path.realpath(exe)
        pkg = pkg_owner(real) or (pkg_owner(exe) if real != exe else "")
        if pkg:
            want = package_digest(pkg, real)
            try:
                got = digest if want and want[0] == "sha256" else (file_digest(real, want[0]) if want else "")
            except (OSError, ValueError):
                got = ""
            if want and got == want[1]:
                t = {"level": "verified", "pkg": pkg}
            elif want:
                t = {"level": "modified", "pkg": pkg, "reason": "differs from package"}
            else:
                t = {"level": "verified", "pkg": pkg, "reason": "no checksum in package"}
        elif PKG_BACKEND:
            t = {"level": "unpackaged", "reason": "not from a system package"}
        else:
            t = {"level": "unknown", "reason": "no package database this Citadel knows"}
        t["hash"] = digest
    trust_cache[key] = t
    return t


# ------------------------------------------------------------------ network id

net_state = {"ts": 0, "names": [], "ssid": "", "source": "none"}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def nm_networks():
    """Active NetworkManager connection names -> (names, ssid) or None."""
    out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "con", "show", "--active"])
    if out is None:
        return None
    names, ssid = [], ""
    for line in out.splitlines():
        name, _, typ = line.rpartition(":")
        name = name.replace("\\:", ":")
        if not name or typ in ("loopback", "tun", "wireguard", "bridge"):
            continue
        names.append(name)
        if typ == "802-11-wireless" and not ssid:
            ssid = name
    return names, ssid


def parse_iwctl_devices(text):
    """Device names from `iwctl station list`."""
    devs = []
    for line in ANSI.sub("", text).splitlines():
        parts = line.split()
        # rows look like "  wlan0   connected   " under a dashed header
        if len(parts) >= 2 and parts[1] in ("connected", "disconnected", "connecting",
                                             "disconnecting", "roaming"):
            devs.append(parts[0])
    return devs


def parse_iwctl_connected(text):
    """SSID from `iwctl station <dev> show`, or ""."""
    for line in ANSI.sub("", text).splitlines():
        m = re.match(r"^\s*Connected network\s+(.+?)\s*$", line)
        if m:
            return m.group(1)
    return ""


def iwd_networks():
    """Connected iwd SSIDs -> (names, ssid) or None when iwd is unavailable."""
    out = _run(["iwctl", "station", "list"])
    if out is None:
        return None
    names = []
    for dev in parse_iwctl_devices(out):
        show = _run(["iwctl", "station", dev, "show"])
        ssid = parse_iwctl_connected(show or "")
        if ssid:
            names.append(ssid)
    return names, (names[0] if names else "")


def wired_networks():
    """Physical, non-wireless interfaces that are up: "Wired (enp3s0)"."""
    names = []
    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return names
    for n in ifaces:
        base = "/sys/class/net/" + n
        if not os.path.exists(base + "/device") or os.path.exists(base + "/wireless"):
            continue
        if read(base + "/operstate").strip() == "up":
            names.append("Wired (%s)" % n)
    return names


def network_ids():
    """Names that zones can be linked to. NetworkManager connection names when
    NM runs; otherwise iwd SSIDs plus wired interfaces; otherwise nothing."""
    if time.time() - net_state["ts"] < 10:
        return net_state
    source, names, ssid = "none", [], ""
    nm = nm_networks()
    if nm is not None:
        source, (names, ssid) = "networkmanager", nm
    else:
        iw = iwd_networks()
        wired = wired_networks()
        if iw is not None:
            source, names, ssid = "iwd", iw[0] + wired, iw[1]
        elif wired:
            source, names = "interfaces", wired
    net_state.update({"ts": time.time(), "names": names, "ssid": ssid, "source": source})
    return net_state


def iface_totals():
    rx = tx = 0
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not os.path.exists("/sys/class/net/%s/device" % name):
            continue                      # only physical NICs (skip tun, lo)
        f = rest.split()
        try:
            rx += int(f[0])
            tx += int(f[8])
        except (IndexError, ValueError):
            pass
    return rx, tx


def proc_stat(pid):
    """(comm, ppid, starttime) from /proc/<pid>/stat, or None."""
    raw = read("/proc/%d/stat" % pid)
    if not raw:
        return None
    lp, rp = raw.find("("), raw.rfind(")")
    if lp < 0 or rp < 0:
        return None
    comm = raw[lp + 1:rp]
    rest = raw[rp + 2:].split()
    try:
        return comm, int(rest[1]), int(rest[19])
    except (IndexError, ValueError):
        return None


def proc_cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            raw = f.read(8192)
    except OSError:
        return []
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
KV = re.compile(r"\b([A-Z]+)=(\S*)")


def kernel_log_reader():
    """Follow the kernel log for Citadel's connection lines (needs journal
    read access, which wheel members have on Arch)."""
    while True:
        try:
            p = subprocess.Popen(["journalctl", "-k", "-f", "-n", "0", "-o", "short-unix", "--no-hostname"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except OSError as e:
            kernel_state.update(running=False, error="journalctl unavailable: %s" % e)
            return
        kernel_state.update(running=True, error="")
        for line in p.stdout:
            i = line.find("citadel: ")
            if i < 0:
                continue
            f = dict(KV.findall(line[i:]))
            try:
                ev = {"ts": float(line.split(None, 1)[0]), "proto": f.get("PROTO", "").lower(),
                      "src": f.get("SRC", ""), "dst": f.get("DST", ""),
                      "spt": int(f.get("SPT") or 0), "dpt": int(f.get("DPT") or 0),
                      "uid": int(f.get("UID") or -1)}
            except ValueError:
                continue
            if ev["uid"] != MY_UID or not ev["dst"] or ev["proto"] not in ("tcp", "udp"):
                continue
            with kev_lock:
                kernel_events.append(ev)
                if len(kernel_events) > 2000:
                    del kernel_events[:500]
            kernel_state["seen"] += 1
        kernel_state.update(running=False, error="kernel log reader stopped")
        time.sleep(5)
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def boot_time():
    for line in read("/proc/stat").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return time.time() - time.monotonic()


BOOT = boot_time()


def process_watcher():
    """Every 50 ms, remember new processes of this user with their origin,
    so a connection can still be attributed after the process exits."""
    known = set()
    while True:
        try:
            pids = {int(d) for d in os.listdir("/proc") if d.isdigit()}
        except OSError:
            time.sleep(1)
            continue
        now = time.time()
        for pid in pids - known:
            try:
                if os.stat("/proc/%d" % pid).st_uid != MY_UID:
                    continue
            except OSError:
                continue
            d = describe(pid)
            if not d:
                continue
            cg = read("/proc/%d/cgroup" % pid).strip()
            cg = cg.split("::", 1)[1].lstrip("/") if "::" in cg else ""
            o = origin(pid, cg) or {}
            # exact start from /proc/<pid>/stat, not the moment this scan saw it
            started = BOOT + d["start"] / float(CLK_TCK)
            rec = {"pid": pid, "ppid": d["ppid"], "start": min(now, started), "end": None, "exe": d["exe"],
                   "comm": d["comm"], "name": d["name"], "kind": d["kind"], "cgroup": cg, "args": d["args"],
                   "origin": o, "hosts": hosts_in_args(d["args"]),
                   "scriptHosts": script_hosts(d["id"]) if d["kind"] == "script" else []}
            with proc_lock:
                proc_seen[pid] = rec
        with proc_lock:
            for pid in known - pids:
                r = proc_seen.get(pid)
                if r and r["end"] is None:
                    r["end"] = now
            for pid in [p for p, r in proc_seen.items() if r["end"] and now - r["end"] > 180]:
                del proc_seen[pid]
        known = pids
        time.sleep(0.05)          # a scan costs ~0.1 ms, so 20/s is ~0.2% of a core


def proc_exe(pid):
    try:
        return os.readlink("/proc/%d/exe" % pid).replace(" (deleted)", "")
    except OSError:
        return ""


def start_threads():
    threading.Thread(target=process_watcher, daemon=True).start()
    threading.Thread(target=kernel_log_reader, daemon=True).start()
