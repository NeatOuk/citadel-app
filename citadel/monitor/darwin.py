"""Citadel monitor backend for macOS.

Same functions as linux.py, from macOS tools that need no root:
  connections   lsof -nP -i -T s -F   (this user's sockets, with TCP state)
  bytes         a long-running `nettop` stream (per-connection counters)
  processes     one `ps` snapshot per tick (path, parent, start time)
  command line  sysctl KERN_PROCARGS2, else ps
  integrity     codesign + spctl (Apple, App Store, notarized, signed, ad-hoc, unsigned)
  networks      Wi-Fi name (ipconfig getsummary), active Ethernet ports
  totals        netstat -ibn
The parsers are plain functions over command output, so they are tested on
any OS with recorded output (tests/macos/).
"""
import ctypes
import ctypes.util
import os
import re
import subprocess
import sys
import threading
import time

from .common import *                                     # noqa: F401,F403
from .common import MANAGERS, SHARED_BIN_DIRS, TERMINALS, sha256, log

# launchd starts everything; Homebrew puts shared tools in its own bin
MANAGERS.update({"launchd"})
TERMINALS.update({"Terminal", "iTerm2", "Ghostty", "WezTerm", "Alacritty", "Warp", "stable"})
SHARED_BIN_DIRS.update({"/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/libexec"})


def _text(cmd, timeout=10):
    """stdout (and for codesign, stderr) of a command, "" when it fails."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT if cmd[0] == "codesign" else subprocess.DEVNULL,
                           text=True, errors="replace", timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ------------------------------------------------------------------ connections

def _split_endpoint(s):
    """'10.0.0.2:51234' / '[2001:db8::1]:443' / nettop's '2001:db8::1.443' -> (ip, port)."""
    s = s.strip()
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
    else:
        host, sep, port = s.rpartition(":")
        if not sep or ":" in host and not port.isdigit():
            host, _, port = s.rpartition(".")
        elif ":" in host:                                   # bare IPv6 with a trailing .port
            h2, _, p2 = s.rpartition(".")
            if p2.isdigit() and ":" in h2:
                host, port = h2, p2
    host = host.split("%", 1)[0]
    if host.startswith("::ffff:") and "." in host:
        host = host[7:]
    return host, int(port) if port.isdigit() else 0


def parse_lsof(text):
    """lsof -F pcuPnT output -> [{pid, comm, uid, proto, state, laddr, lport, raddr, rport}]."""
    rows = []
    pid, comm, uid = 0, "", -1
    cur = None

    def flush():
        if cur and cur.get("name") and "->" in cur["name"]:
            left, _, right = cur["name"].partition("->")
            laddr, lport = _split_endpoint(left)
            raddr, rport = _split_endpoint(right)
            if raddr and rport:
                rows.append({"pid": pid, "comm": comm, "uid": uid, "proto": cur.get("proto", "tcp"),
                             "state": cur.get("state", "ESTABLISHED" if cur.get("proto") == "tcp" else "UNCONN"),
                             "laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport})
    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            flush()
            cur = None
            pid, comm, uid = int(val) if val.isdigit() else 0, "", -1
        elif tag == "c":
            comm = val
        elif tag == "u":
            uid = int(val) if val.isdigit() else -1
        elif tag == "f":
            flush()
            cur = {}
        elif cur is not None and tag == "P":
            cur["proto"] = val.lower()
        elif cur is not None and tag == "n":
            cur["name"] = val
        elif cur is not None and tag == "T" and val.startswith("ST="):
            cur["state"] = val[3:]
    flush()
    return rows


_lsof_cache = {"ts": 0, "rows": []}


def parse_ss(args, proto):
    """Same shape as linux.parse_ss: established/connecting TCP, connected UDP."""
    if time.time() - _lsof_cache["ts"] > 0.5:
        _lsof_cache["rows"] = parse_lsof(_text(["lsof", "-nP", "-w", "-i", "-T", "s", "-F", "pcuPnT"]))
        _lsof_cache["ts"] = time.time()
    out = []
    counters = _nettop["flows"]
    for r in _lsof_cache["rows"]:
        if r["proto"] != proto:
            continue
        st = r["state"].upper()
        if proto == "tcp":
            if st not in ("ESTABLISHED", "SYN_SENT"):
                continue
            state = "ESTAB" if st == "ESTABLISHED" else "SYN-SENT"
        else:
            state = "ESTAB"
        down, up = counters.get((r["lport"], r["raddr"], r["rport"]), (0, 0))
        out.append({"proto": proto, "state": state, "laddr": r["laddr"], "lport": r["lport"], "raddr": r["raddr"],
                    "rport": r["rport"], "comm": r["comm"], "pid": r["pid"], "uid": r["uid"], "cgroup": "",
                    "up": up, "down": down})
    return out


# ------------------------------------------------------------------ bytes (nettop)

_nettop = {"flows": {}, "running": False}


def parse_nettop_line(line):
    """'tcp4 10.0.0.2:51234<->1.2.3.4:443,120,340,' -> ((lport, raddr, rport), bytes_in, bytes_out)."""
    parts = line.strip().split(",")
    if len(parts) < 3 or "<->" not in parts[0]:
        return None
    flow = parts[0].split(None, 1)
    if len(flow) != 2:
        return None
    left, _, right = flow[1].partition("<->")
    _, lport = _split_endpoint(left)
    raddr, rport = _split_endpoint(right)
    try:
        return (lport, raddr, rport), int(parts[1] or 0), int(parts[2] or 0)
    except ValueError:
        return None


def _nettop_reader():
    """Keep the latest per-connection byte counters from a nettop stream."""
    while True:
        try:
            p = subprocess.Popen(["nettop", "-L", "0", "-s", "2", "-n", "-x", "-J", "bytes_in,bytes_out"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        except OSError as e:
            log("nettop unavailable: %s" % e)
            return
        _nettop["running"] = True
        fresh = {}
        for line in p.stdout:
            if line.startswith(","):                        # a new sample starts with the header
                if fresh:
                    _nettop["flows"] = fresh
                fresh = {}
                continue
            got = parse_nettop_line(line)
            if got:
                fresh[got[0]] = (got[1], got[2])
        _nettop["running"] = False
        time.sleep(5)


# ------------------------------------------------------------------ processes

_ps = {"ts": 0, "rows": {}}
_LSTART = "%a %b %d %H:%M:%S %Y"


def parse_ps(text):
    """ps -axww -o pid=,ppid=,uid=,lstart=,comm= -> {pid: (ppid, uid, start, comm)}."""
    rows = {}
    for line in text.splitlines():
        parts = line.split(None, 8)
        if len(parts) < 9 or not parts[0].isdigit():
            continue
        try:
            start = int(time.mktime(time.strptime(" ".join(parts[3:8]), _LSTART)))
        except ValueError:
            start = 0
        rows[int(parts[0])] = (int(parts[1]), int(parts[2]), start, parts[8].strip())
    return rows


def _snapshot():
    if time.time() - _ps["ts"] > 0.5:
        _ps["rows"] = parse_ps(_text(["ps", "-axww", "-o", "pid=,ppid=,uid=,lstart=,comm="]))
        _ps["ts"] = time.time()
    return _ps["rows"]


def proc_table():
    """pid -> (exe, "") for this user's processes (macOS has no cgroups)."""
    return {pid: (comm, "") for pid, (_, uid, _, comm) in _snapshot().items() if uid == MY_UID and comm.startswith("/")}


def proc_stat(pid):
    row = _snapshot().get(pid)
    if not row:
        return None
    ppid, _, start, comm = row
    return os.path.basename(comm), ppid, start


def proc_exe(pid):
    row = _snapshot().get(pid)
    return row[3] if row and row[3].startswith("/") else ""


_libc = None


def _procargs(pid):
    """argv from sysctl KERN_PROCARGS2: argc, exec path, padding, argv."""
    global _libc
    if sys.platform != "darwin":
        return None
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, int(pid))                # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t(0)
    if _libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or not size.value:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if _libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None
    return parse_procargs(buf.raw[:size.value])


def parse_procargs(raw):
    if len(raw) < 4:
        return None
    argc = int.from_bytes(raw[:4], sys.byteorder)
    rest = raw[4:]
    _, _, rest = rest.partition(b"\0")                       # exec path
    rest = rest.lstrip(b"\0")
    args = rest.split(b"\0")[:argc]
    return [a.decode("utf-8", "replace") for a in args]


def proc_cmdline(pid):
    args = _procargs(pid)
    if args:
        return args
    return _text(["ps", "-o", "args=", "-p", str(int(pid))]).split()


# ------------------------------------------------------------------ integrity (code signing)

trust_cache = {}
TMP_DIRS = re.compile(r"^/(private/)?(tmp|var/tmp|var/folders/[^/]+/[^/]+/T)/")


def bundle_of(exe):
    """/Applications/Foo.app/Contents/MacOS/Foo -> /Applications/Foo.app"""
    m = re.match(r"^(.*?\.app)/Contents/MacOS/", exe)
    return m.group(1) if m else exe


def classify_signature(codesign_out, verify_ok, spctl_out):
    """Integrity level from `codesign -dv`, `codesign -v` and `spctl -a -vv` output."""
    if "not signed at all" in codesign_out:
        return {"level": "unpackaged", "reason": "unsigned"}
    if not verify_ok:
        return {"level": "modified", "reason": "signature does not match the program"}
    authorities = re.findall(r"^Authority=(.+)$", codesign_out, re.M)
    team = (re.search(r"^TeamIdentifier=(.+)$", codesign_out, re.M) or [None, ""])[1].strip()
    source = (re.search(r"source=(.+)$", spctl_out, re.M) or [None, ""])[1].strip()
    if "Signature=adhoc" in codesign_out:
        return {"level": "unpackaged", "reason": "ad-hoc signed (no developer)"}
    if source == "Apple System" or (authorities and authorities[0].startswith("Software Signing")):
        return {"level": "verified", "pkg": "Apple"}
    if source == "Mac App Store":
        return {"level": "verified", "pkg": "App Store" + (" · " + team if team and team != "not set" else "")}
    signer = authorities[0] if authorities else ("team " + team if team else "a developer")
    signer = signer.replace("Developer ID Application: ", "")
    if "Notarized" in source:
        return {"level": "verified", "pkg": signer}
    return {"level": "unpackaged", "reason": "signed by %s, not notarized" % signer}


_trust_pending = set()
_trust_pool = None


def trust(exe, deleted=False):
    """level: verified | modified | unpackaged | suspicious | unknown (as on Linux).

    codesign + spctl can take a second or more per program, so the first
    call for a program returns "checking" and the check runs in the
    background; later ticks carry the result."""
    global _trust_pool
    if not exe:
        return {"level": "unknown"}
    try:
        st = os.stat(exe)
        key = (exe, st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return {"level": "suspicious" if deleted else "unknown", "reason": "missing"}
    if key in trust_cache:
        return trust_cache[key]
    if key not in _trust_pending:
        _trust_pending.add(key)
        if _trust_pool is None:
            import concurrent.futures
            _trust_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        _trust_pool.submit(_check_trust, exe, key)
    return {"level": "unknown", "reason": "checking the signature"}


def trust_now(exe):
    """The same check, synchronously (tests, selftest)."""
    st = os.stat(exe)
    key = (exe, st.st_ino, st.st_mtime_ns, st.st_size)
    return trust_cache.get(key) or _check_trust(exe, key)


def _check_trust(exe, key):
    try:
        t = _signature_level(exe)
    except Exception as e:                                  # never let one program stop the checks
        t = {"level": "unknown", "reason": str(e)[:80]}
    trust_cache[key] = t
    _trust_pending.discard(key)
    return t


def _signature_level(exe):
    if TMP_DIRS.match(exe):
        t = {"level": "suspicious", "reason": "runs from a temporary folder"}
    else:
        target = bundle_of(exe)
        info = _text(["codesign", "-dv", "--verbose=2", target])
        try:
            ok = subprocess.run(["codesign", "-v", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        try:
            spctl = subprocess.run(["spctl", "-a", "-t", "exec", "-vv", target], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            spctl = ""
        t = classify_signature(info, ok, spctl)
    try:
        t["hash"] = sha256(exe)
    except OSError:
        t["hash"] = ""
    return t


# ------------------------------------------------------------------ networks

net_state = {"ts": 0, "names": [], "ssid": "", "source": "none"}


def parse_hardware_ports(text):
    """networksetup -listallhardwareports -> [(port name, device)]."""
    out, port = [], None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            out.append((port, line.split(":", 1)[1].strip()))
            port = None
    return out


def parse_ssid(summary):
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", summary, re.M)
    if not m or m.group(1) in ("<redacted>", "<SSID Redacted>"):
        return ""
    return m.group(1)


def network_ids():
    """Wi-Fi name (macOS 15 may hide it without Location access) and active
    wired ports, as zone names."""
    if time.time() - net_state["ts"] < 10:
        return net_state
    names, ssid = [], ""
    for port, dev in parse_hardware_ports(_text(["networksetup", "-listallhardwareports"])):
        if port == "Wi-Fi":
            ssid = parse_ssid(_text(["ipconfig", "getsummary", dev]))
            if ssid:
                names.append(ssid)
        elif "status: active" in _text(["ifconfig", dev]) and ("Ethernet" in port or "LAN" in port or "Thunderbolt" in port):
            names.append(port)
    net_state.update({"ts": time.time(), "names": names, "ssid": ssid, "source": "macos" if names else "none"})
    return net_state


def parse_netstat(text):
    """netstat -ibn -> (rx, tx) summed over physical en* interfaces (one row each)."""
    rx = tx = 0
    seen = set()
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10 or not f[0].startswith("en") or not f[2].startswith("<Link#") or f[0] in seen:
            continue
        seen.add(f[0])
        try:
            rx += int(f[-5])
            tx += int(f[-2])
        except ValueError:
            pass
    return rx, tx


def iface_totals():
    return parse_netstat(_text(["netstat", "-ibn"]))


def start_threads():
    threading.Thread(target=_nettop_reader, daemon=True).start()
