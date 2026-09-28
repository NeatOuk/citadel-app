"""Citadel monitor, the part every OS shares.

A long-running user process: every tick it prints one JSON line that the
daemon (or the Omarchy plugin's Service) reads:
  {"type":"tick", ...}      live connections, apps, totals, network
  {"type":"stats", ...}     traffic series + top apps/hosts/countries (sqlite)
  {"type":"resolved", ...}  forward DNS for hosts named in rules
  {"type":"lists", ...}     blocklist subscription status (+ IP CIDRs)
  {"type":"geoip", ...}     GeoIP database status
  {"type":"log", ...}       non-fatal errors

It reads JSON commands on stdin, one per line:
  {"cmd":"config","interval":2,"retentionDays":30,"resolveHosts":[...],
   "lists":[{"id","url","kind":"ip"|"domain","enabled"}]}
  {"cmd":"refreshLists"}   {"cmd":"geoipDownload"}   {"cmd":"stats"}

What differs per OS (sockets, processes, integrity, networks, byte
counters) comes from a backend, `B`: citadel.monitor.linux or .darwin.
Only stdlib is required. GeoIP needs python-maxminddb (optional).
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


B = None      # the OS backend, set by use()


def use(backend):
    global B
    B = backend



HOME = os.path.expanduser("~")
STATE = os.environ.get("CITADEL_STATE_DIR") or os.path.join(HOME, ".local/share/citadel")
LISTS_DIR = os.path.join(STATE, "lists")
GEO_DIR = os.path.join(STATE, "geo")
GEO_DB = os.path.join(GEO_DIR, "dbip-country-lite.mmdb")
ASN_DB = os.path.join(GEO_DIR, "dbip-asn-lite.mmdb")
HISTORY_DB = os.path.join(STATE, "history.db")
MY_UID = os.getuid()
UA = "citadel/1.0"

cfg = {"interval": 2.0, "retentionDays": 30, "resolveHosts": [], "lists": []}
out_lock = threading.Lock()


def emit(obj):
    line = json.dumps(obj, separators=(",", ":"))
    with out_lock:
        try:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        except BrokenPipeError:
            os._exit(0)


def log(msg):
    emit({"type": "log", "msg": str(msg)[:500]})


def split_addr(field):
    field = field.strip()
    if field.startswith("["):
        host, _, port = field[1:].partition("]:")
    else:
        host, _, port = field.rpartition(":")
    host = host.split("%", 1)[0]          # 192.168.5.6%wlp0s20f3
    if host.startswith("::ffff:") and "." in host:
        host = host[7:]
    return host, (int(port) if port.isdigit() else 0)


def classify(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "lan"
    if a.is_multicast:
        return "multicast"
    return "internet"


# ------------------------------------------------------------------ processes

def read(path, default=""):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


SHARED_BIN_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
                   os.path.join(HOME, ".local/bin"), os.path.join(HOME, "bin"), os.path.join(HOME, ".cargo/bin")}


def apps_from(table):
    """exe -> {pids, cgroups, owned}: a cgroup is 'owned' by an exe when every
    process in it is that exe or lives in the same directory (helpers such as
    chrome_crashpad_handler). Only owned cgroups are safe to block whole."""
    by_cg = {}
    for pid, (exe, cg) in table.items():
        clean = exe.replace(" (deleted)", "")
        # helpers that never use the network (e.g. the `cat` pipes Edge's
        # launcher leaves behind) don't make an app's scope shared; shells do
        if os.path.basename(clean) in HELPERS:
            continue
        by_cg.setdefault(cg, set()).add(clean)
    apps = {}
    for pid, (exe, cg) in table.items():
        clean = exe.replace(" (deleted)", "")
        a = apps.setdefault(clean, {"pids": [], "cgroups": set(), "owned": set(),
                                    "deleted": False})
        a["pids"].append(pid)
        a["cgroups"].add(cg)
        if exe.endswith(" (deleted)"):
            a["deleted"] = True
    for exe, a in apps.items():
        base = os.path.dirname(exe)
        # an app's own folder (/opt/microsoft/msedge) groups its helpers; a
        # shared one (/usr/bin) says nothing: curl and bash are not one app
        own_dir = base not in SHARED_BIN_DIRS
        for cg in a["cgroups"]:
            if cg and all(e == exe or (own_dir and os.path.dirname(e) == base) for e in by_cg.get(cg, ())):
                a["owned"].add(cg)
    return apps


def file_digest(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ DNS

rdns_cache = {}         # ip -> (name|"", ts)
rdns_pending = set()
pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
fwd_cache = {}          # host -> {"ips": [...], "ts": t}


def _rdns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        name = ""
    rdns_cache[ip] = (name, time.time())
    rdns_pending.discard(ip)


def rdns(ip):
    hit = rdns_cache.get(ip)
    if hit and time.time() - hit[1] < 3600:
        return hit[0] or None
    if ip not in rdns_pending and classify(ip) in ("internet", "lan"):
        rdns_pending.add(ip)
        pool.submit(_rdns, ip)
    return hit[0] if hit and hit[0] else None


def resolve_hosts(force=False):
    out = {}
    now = time.time()
    for h in cfg.get("resolveHosts") or []:
        h = str(h).strip().lower()
        if not h:
            continue
        c = fwd_cache.get(h)
        if c and not force and now - c["ts"] < 300:
            out[h] = c["ips"]
            continue
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(h, None)})
        except (OSError, UnicodeError):
            ips = []
        fwd_cache[h] = {"ips": ips, "ts": now}
        out[h] = ips
    emit({"type": "resolved", "hosts": out})


# ------------------------------------------------------------------ GeoIP

# Two DB-IP Lite databases (CC BY 4.0): country, and the network owner (ASN)
# of each IP, e.g. "Google LLC". Both are downloaded together.
GEO_DBS = {"country": GEO_DB, "asn": ASN_DB}
geo = {k: {"reader": None, "mtime": 0} for k in GEO_DBS}
geo_error = {"msg": ""}


def geo_reader(kind="country"):
    g = geo[kind]
    try:
        mt = os.path.getmtime(GEO_DBS[kind])
    except OSError:
        g["reader"] = None
        return None
    if g["reader"] is None or mt != g["mtime"]:
        try:
            import maxminddb
            g["reader"] = maxminddb.open_database(GEO_DBS[kind])
            g["mtime"] = mt
            geo_error["msg"] = ""
        except ImportError:
            geo_error["msg"] = "python-maxminddb is not installed"
            g["reader"] = None
        except Exception as e:                           # corrupt file
            geo_error["msg"] = str(e)[:200]
            g["reader"] = None
    return g["reader"]


geo_cache = {}
org_cache = {}


def country(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    r = geo_reader()
    cc = ""
    if r and classify(ip) == "internet":
        try:
            rec = r.get(ip) or {}
            cc = ((rec.get("country") or {}).get("iso_code")) or ""
        except Exception:
            cc = ""
    if r:
        geo_cache[ip] = cc
    return cc


def owner(ip):
    """Network owner of an IP from the ASN database, e.g. "Google LLC"."""
    if ip in org_cache:
        return org_cache[ip]
    r = geo_reader("asn")
    org = ""
    if r and classify(ip) == "internet":
        try:
            org = (r.get(ip) or {}).get("autonomous_system_organization") or ""
        except Exception:
            org = ""
    if r:
        if len(org_cache) > 20000:
            org_cache.clear()
        org_cache[ip] = org
    return org


def geo_status():
    r = geo_reader()
    st = {"type": "geoip", "installed": r is not None, "owner": geo_reader("asn") is not None,
          "error": geo_error["msg"]}
    if r is not None:
        st["updated"] = int(geo["country"]["mtime"])
    emit(st)


def geo_fetch(name, path):
    """Download this month's (else last month's) DB-IP Lite `name` database."""
    last = None
    for months_back in (0, 1):
        d = datetime.date.today().replace(day=1) - datetime.timedelta(days=31 * months_back)
        url = "https://download.db-ip.com/free/dbip-%s-lite-%04d-%02d.mmdb.gz" % (name, d.year, d.month)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = gzip.decompress(resp.read())
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
            return None
        except Exception as e:
            last = e
    return last


def geo_download(only_missing=False):
    def run():
        try:
            os.makedirs(GEO_DIR, exist_ok=True)
            errors = []
            for name, kind in (("country", "country"), ("asn", "asn")):
                if only_missing and os.path.exists(GEO_DBS[kind]):
                    continue
                err = geo_fetch(name, GEO_DBS[kind])
                if err:
                    errors.append("%s: %s" % (name, err))
                geo[kind]["reader"] = None
            geo_cache.clear()
            org_cache.clear()
            if errors:
                emit({"type": "geoip", "installed": geo_reader() is not None, "owner": geo_reader("asn") is not None,
                      "error": "download failed: " + "; ".join(errors)})
            else:
                geo_status()
        except Exception as e:
            emit({"type": "geoip", "installed": False, "error": str(e)[:200]})
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------------ blocklists

lists_state = {"domains": {}, "ips": {}, "nets": {}, "meta": {}}   # id -> set / list / nets / meta
ip_match_cache = {}
lists_lock = threading.Lock()
DOMAIN_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")


# Address space an IP blocklist must never cover: LAN, loopback, link-local,
# CGNAT/Tailscale, multicast and reserved. Lists such as FireHOL level 1
# include these "bogons", which would cut the user off from their own network.
NEVER_BLOCK = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
    "::/127", "::ffff:0:0/96", "64:ff9b::/96", "fc00::/7", "fe80::/10", "ff00::/8")]


def safe_to_block(net):
    return not any(net.version == n.version and net.overlaps(n) for n in NEVER_BLOCK)


def parse_list(kind, text):
    if kind == "ip":
        nets = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            tok = line.split()[0]
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                continue
            if safe_to_block(net):
                nets.append(str(net))
        return nets
    doms = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        # hosts format "0.0.0.0 domain", adblock "||domain^", or bare domain
        tok = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1") else parts[0]
        tok = tok.strip("|^").lstrip("*.")
        if DOMAIN_RE.match(tok) and tok not in ("localhost", "localhost.localdomain"):
            doms.add(tok)
    return doms


def list_path(lid):
    return os.path.join(LISTS_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", lid) + ".txt")


def load_lists(download=False):
    def run():
        os.makedirs(LISTS_DIR, exist_ok=True)
        domains, ips, meta = {}, {}, {}
        for L in cfg.get("lists") or []:
            lid, url, kind = str(L.get("id")), str(L.get("url", "")), L.get("kind", "domain")
            if not L.get("enabled", True) or not lid:
                continue
            path = list_path(lid)
            err = ""
            stale = not os.path.exists(path) or time.time() - os.path.getmtime(path) > 86400
            if url.startswith(("https://", "http://")) and (download or stale):
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": UA})
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        data = resp.read(64 * 1024 * 1024)
                    with open(path + ".tmp", "wb") as f:
                        f.write(data)
                    os.replace(path + ".tmp", path)
                except Exception as e:
                    err = "download failed: %s" % e
            text = read(path)
            parsed = parse_list(kind, text) if text else ([] if kind == "ip" else set())
            if kind == "ip":
                ips[lid] = parsed
            else:
                domains[lid] = parsed
            meta[lid] = {"id": lid, "kind": kind, "count": len(parsed), "error": err,
                         "updated": int(os.path.getmtime(path)) if os.path.exists(path) else 0}
        nets = {}
        for lid, cidrs in ips.items():
            by_len = {}
            for c in cidrs:
                n = ipaddress.ip_network(c)
                by_len.setdefault((n.version, n.prefixlen), set()).add(int(n.network_address))
            nets[lid] = by_len
        with lists_lock:
            lists_state["domains"], lists_state["ips"], lists_state["meta"] = domains, ips, meta
            lists_state["nets"] = nets
            ip_match_cache.clear()
        all_ips = sorted({n for v in ips.values() for n in v})
        emit({"type": "lists", "lists": list(meta.values()), "ipCidrs": all_ips})
    threading.Thread(target=run, daemon=True).start()


def ip_list_match(ip):
    """IP -> id of the first IP blocklist containing it (prefix-length buckets)."""
    if ip in ip_match_cache:
        return ip_match_cache[ip]
    hit = ""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        a = None
    if a is not None:
        bits = 32 if a.version == 4 else 128
        val = int(a)
        with lists_lock:
            for lid, by_len in lists_state["nets"].items():
                for (ver, plen), starts in by_len.items():
                    if ver == a.version and ((val >> (bits - plen)) << (bits - plen)) in starts:
                        hit = lid
                        break
                if hit:
                    break
    ip_match_cache[ip] = hit
    return hit


def list_match(host, ip=""):
    hit = ip_list_match(ip) if ip else ""
    if hit or not host:
        return hit
    h = host.lower().rstrip(".")
    with lists_lock:
        doms = lists_state["domains"]
        if not doms:
            return ""
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            for lid, s in doms.items():
                if cand in s:
                    return lid
    return ""


def _run(cmd, timeout=5):
    """stdout of a command, or None if it is missing or fails."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


# ------------------------------------------------------------------ history

class History:
    def __init__(self):
        os.makedirs(STATE, exist_ok=True)
        self.db = sqlite3.connect(HISTORY_DB, check_same_thread=False)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS flows (
              id INTEGER PRIMARY KEY, start REAL, last REAL, exe TEXT, comm TEXT,
              proto TEXT, raddr TEXT, rport INTEGER, host TEXT, cc TEXT,
              up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, system INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS flows_start ON flows(start);
            CREATE TABLE IF NOT EXISTS samples (t INTEGER PRIMARY KEY, rx INTEGER, tx INTEGER);
        """)
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(flows)")}
        if "via" not in cols:                       # added in 1.2
            self.db.execute("ALTER TABLE flows ADD COLUMN via TEXT DEFAULT ''")
        self.ids = {}           # socket key -> row id
        self.last_prune = 0

    def update(self, conns, now):
        cur = self.db.cursor()
        seen = set()
        for c in conns:
            k = c["key"]
            seen.add(k)
            rid = self.ids.get(k)
            if rid is None:
                cur.execute("INSERT INTO flows(start,last,exe,comm,proto,raddr,rport,host,cc,up,down,system,via)"
                            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (now, now, c.get("exe") or "", c.get("app") or "", c["proto"], c["raddr"],
                             c["rport"], c.get("host") or "", c.get("cc") or "", c["up"], c["down"],
                             1 if c.get("system") else 0, c.get("via") or ""))
                self.ids[k] = cur.lastrowid
            else:
                cur.execute("UPDATE flows SET last=?, up=?, down=?, host=COALESCE(NULLIF(?,''),host),"
                            " cc=COALESCE(NULLIF(?,''),cc) WHERE id=?",
                            (now, c["up"], c["down"], c.get("host") or "", c.get("cc") or "", rid))
        for k in list(self.ids):
            if k not in seen:
                del self.ids[k]
        if now - self.last_prune > 3600:
            cutoff = now - 86400 * max(1, int(cfg.get("retentionDays") or 30))
            cur.execute("DELETE FROM flows WHERE last < ?", (cutoff,))
            cur.execute("DELETE FROM samples WHERE t < ?", (int(now) - 86400 * 2,))
            self.last_prune = now
        self.db.commit()

    def record_short(self, items):
        self.db.executemany(
            "INSERT INTO flows(start,last,exe,comm,proto,raddr,rport,host,cc,up,down,system,via)"
            " VALUES(?,?,?,?,?,?,?,?,?,0,0,0,?)",
            [(c["ts"], c["ts"], c["exe"], c["app"], c["proto"], c["raddr"], c["rport"], c["host"],
              c["cc"], c["via"]) for c in items])
        self.db.commit()

    def sample(self, t, rx, tx):
        self.db.execute("INSERT OR REPLACE INTO samples(t,rx,tx) VALUES(?,?,?)", (t, rx, tx))

    def stats(self):
        now = time.time()
        day0 = datetime.datetime.combine(datetime.date.today(), datetime.time()).timestamp()
        q = self.db.execute

        def top(col, since, n=8):
            rows = q("SELECT %s, SUM(up), SUM(down), COUNT(*) FROM flows WHERE last >= ? AND system=0"
                     " AND (%s) != '' GROUP BY %s ORDER BY SUM(up)+SUM(down) DESC LIMIT ?" % (col, col, col),
                     (since, n)).fetchall()
            return [{"name": r[0], "up": r[1] or 0, "down": r[2] or 0, "flows": r[3]} for r in rows]

        # per-minute series for the last hour from 1 s-resolution samples
        rows = q("SELECT t, rx, tx FROM samples WHERE t >= ? ORDER BY t", (int(now) - 3660,)).fetchall()
        buckets = {}
        prev = None
        for t, rx, tx in rows:
            if prev is not None and rx >= prev[1] and tx >= prev[2]:
                b = (t // 60) * 60
                acc = buckets.setdefault(b, [0, 0])
                acc[0] += rx - prev[1]
                acc[1] += tx - prev[2]
            prev = (t, rx, tx)
        start = (int(now) // 60) * 60 - 59 * 60
        series = [{"t": start + i * 60, "down": buckets.get(start + i * 60, [0, 0])[0],
                   "up": buckets.get(start + i * 60, [0, 0])[1]} for i in range(60)]
        app_col = "CASE WHEN COALESCE(via,'') != '' THEN comm || ' via ' || via ELSE comm END"
        emit({"type": "stats", "series": series,
              "topAppsToday": top(app_col, day0), "topHostsToday": top("COALESCE(NULLIF(host,''),raddr)", day0),
              "countriesToday": top("cc", day0, 30), "topApps7d": top(app_col, now - 7 * 86400)})


# ------------------------------------------------------------------ main loop

# ------------------------------------------------------------------ origin
# Who started a process and why: the parent chain, the first "meaningful"
# ancestor (skipping shells and wrappers), the unit, and a masked command
# line. Cached per (pid, start time) so pid reuse can't mix processes up.

SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "env", "xargs", "timeout",
          "nohup", "setsid", "flock", "nice", "ionice", "stdbuf", "uwsm", "uwsm-app",
          "systemd-run", "sudo", "doas", "pkexec", "script", "time", "exec", "chrt"}
INTERPRETERS = {"bash", "sh", "dash", "zsh", "fish", "python", "python3", "node", "perl",
                "ruby", "lua", "luajit", "deno", "bun", "php", "tclsh", "osascript"}
TERMINALS = {"ghostty", "alacritty", "kitty", "foot", "wezterm", "wezterm-gui", "konsole",
             "gnome-terminal-server", "xterm", "st", "tmux: server", "tmux", "zellij"}
MANAGERS = {"systemd", "init"}
SECRET_WORDS = r"(?:token|secret|passw(?:or)?d|pwd|auth|authorization|api[_-]?key|apikey|key|sig|signature|session|cookie|bearer|credential)"
origin_cache = {}        # (pid, starttime) -> origin dict


def interp_name(base):
    """python3.14 -> python3, node22 -> node"""
    m = re.match(r"^([a-z]+?)(?:[0-9.]+)?$", base)
    return m.group(1) if m else base


def redact_args(args):
    """Mask credentials in an argument vector (curl/wget/git style and URLs)."""
    out = []
    mask_next = None
    for a in args:
        if mask_next == "all":
            out.append("***"); mask_next = None; continue
        if mask_next == "header":
            name, sep, _ = a.partition(":")
            out.append(name + ": ***" if sep and re.search(SECRET_WORDS, name, re.I) else _redact_url(a))
            mask_next = None; continue
        if mask_next == "data":
            out.append("<%d bytes>" % len(a)); mask_next = None; continue
        if a in ("-u", "--user", "--proxy-user", "-E", "--cert", "--key", "--pass", "--oauth2-bearer",
                 "--password", "--http-password", "--ftp-password", "--proxy-password"):
            out.append(a); mask_next = "all"; continue
        if a in ("-H", "--header", "--proxy-header"):
            out.append(a); mask_next = "header"; continue
        if a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json",
                 "-F", "--form", "--post-data", "--body-data"):
            out.append(a); mask_next = "data"; continue
        m = re.match(r"^(--(?:user|password|http-password|header|data[a-z-]*|json|post-data|oauth2-bearer)=)(.*)$", a)
        if m:
            out.append(m.group(1) + ("<%d bytes>" % len(m.group(2)) if "data" in m.group(1) or "json" in m.group(1) else "***"))
            continue
        out.append(_redact_url(a))
    return out


def _redact_url(a):
    # any user info in a URL (user:pass@ or a bare token@) is a credential
    a = re.sub(r"(\b[a-z][a-z0-9+.-]*://)[^/\s@]+@", r"\1***@", a, flags=re.I)
    # ?token=...&key=...
    a = re.sub(r"([?&;][^=&\s]*" + SECRET_WORDS + r"[^=&\s]*=)[^&\s#]*", r"\1***", a, flags=re.I)
    # KEY=secret env-style assignments
    a = re.sub(r"^([A-Za-z_]*" + SECRET_WORDS + r"[A-Za-z_]*=).+$", r"\1***", a, flags=re.I)
    return a


def unit_name(cg):
    """cgroup path -> readable unit: 'app-Hyprland-xdg\\x2dterminal\\x2dexec-79be.scope'."""
    last = (cg or "").rstrip("/").rsplit("/", 1)[-1]
    return last.replace("\\x2d", "-").replace("\\x40", "@")


def describe(pid):
    """-> {name, kind, exe, pid} for one process; interpreters running a
    script are named after the script."""
    st = B.proc_stat(pid)
    if not st:
        return None
    comm, ppid, start = st
    try:
        exe = B.proc_exe(pid)
    except OSError:
        exe = ""
    base = os.path.basename(exe) or comm
    args = B.proc_cmdline(pid)
    kind, name, ident = "app", base, exe or comm
    if interp_name(base) in INTERPRETERS and len(args) > 1:
        # first non-option argument is the script (skip "-u", "-c <code>" etc.)
        script = ""
        i = 1
        while i < len(args):
            a = args[i]
            if a == "-c" or a == "-e":
                break                    # inline code: no script file
            if a in ("-m",) and i + 1 < len(args):
                script = args[i + 1]; break
            if not a.startswith("-"):
                script = a; break
            i += 1
        if script:
            kind, name, ident = "script", os.path.basename(script), script if script.startswith("/") else name
    if comm in TERMINALS or base in TERMINALS:
        kind = "terminal"
    return {"pid": pid, "ppid": ppid, "start": start, "comm": comm, "exe": exe,
            "name": name, "kind": kind, "id": ident, "args": args}


def origin(pid, cg=""):
    """Launch chain and responsible ancestor for a process of this user."""
    st = B.proc_stat(pid)
    if not st:
        return None
    key = (pid, st[2])
    hit = origin_cache.get(key)
    if hit is not None:
        return hit
    me = describe(pid)
    if not me:
        return None
    chain, via = [], None
    cur = me["ppid"]
    for _ in range(12):
        if cur <= 1:
            break
        d = describe(cur)
        if not d:
            break
        if d["comm"] in MANAGERS or d["exe"].endswith("/systemd"):
            break
        chain.append(d["name"])
        if via is None and not (d["comm"] in SHELLS and d["kind"] != "script") \
                and not (interp_name(d["comm"]) in INTERPRETERS and d["kind"] != "script"):
            via = d
        if d["kind"] == "terminal":
            break                        # started by you in a terminal
        cur = d["ppid"]
    cmd = " ".join(redact_args(me["args"]))[:400]
    out = {"cmd": cmd, "chain": chain[:8], "unit": unit_name(cg),
           "via": None if not via else {"name": via["name"], "kind": via["kind"], "id": via["id"]}}
    # the same program started by itself (chromium helpers) has no "via"
    if via and (via["id"] == me["id"] or via["name"] == me["name"]):
        out["via"] = None
    origin_cache[key] = out
    if len(origin_cache) > 4000:
        for k in list(origin_cache)[:1000]:
            del origin_cache[k]
    return out


# ------------------------------------------------------------------ short-lived connections
# With citadel-helper >= 1.2 and enforcement on, the kernel logs every new
# outbound connection from this user ("citadel: ... SRC= DST= SPT= DPT=").
# A connection whose socket is already gone at the next poll is matched to
# a process seen by the fast process watcher below.

kev_lock = threading.Lock()
kernel_events = []           # parsed log lines waiting for correlation
kernel_state = {"running": False, "error": "", "seen": 0}


proc_seen = {}               # pid -> record (kept ~3 min after exit)
proc_lock = threading.Lock()


HOST_ARG = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^/@\s]+@)?(\[[0-9a-f:]+\]|[a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/?#].*)?$", re.I)


def hosts_in_args(args):
    """Host names / IPs mentioned in a command line (URLs, host:port, user@host)."""
    out = []
    for a in args[1:]:
        if a.startswith("-") or len(a) > 2048:
            continue
        m = HOST_ARG.match(a.strip())
        if m:
            h = m.group(1).strip("[]").lower()
            if h not in out:
                out.append(h)
    return out[:8]


URL_IN_TEXT = re.compile(r"\b(?:https?|wss?|ftp)://(?:[^/@\s\"']+@)?([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})", re.I)
script_host_cache = {}


def script_hosts(path):
    """Hosts named in a launcher script's own text (first 64 KB, cached by mtime)."""
    if not path or not path.startswith("/"):
        return []
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns)
        if key in script_host_cache:
            return script_host_cache[key]
        with open(path, "r", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        return []
    hosts = []
    for h in URL_IN_TEXT.findall(text):
        h = h.lower()
        if h not in hosts:
            hosts.append(h)
    script_host_cache[key] = hosts[:32]
    return script_host_cache[key]


def host_ips(host):
    """Forward-resolve (cached) for matching a command line to a destination."""
    c = fwd_cache.get(host)
    if c and time.time() - c["ts"] < 300:
        return c["ips"]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
        ips = [host]
    else:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except (OSError, UnicodeError):
            ips = []
    fwd_cache[host] = {"ips": ips, "ts": time.time()}
    return ips


NON_NETWORK = SHELLS | {"sleep", "cat", "grep", "sed", "awk", "head", "tail", "tr", "cut", "sort",
                        "uniq", "wc", "jq", "date", "printf", "echo", "test", "[", "true", "false",
                        "basename", "dirname", "readlink", "mkdir", "rm", "mv", "cp", "ls", "stat",
                        "notify-send", "hyprctl", "pgrep", "ps", "id", "env", "tee", "xargs"}
# utilities that can't open a connection; shells excluded (they run tools)
HELPERS = NON_NETWORK - SHELLS


def attribute(ev):
    """-> (record, confidence) for a kernel connection event."""
    ts = ev["ts"]
    me = os.getpid()
    with proc_lock:
        # never blame Citadel's own helpers (pacman -Qqo, nmcli, ss, journalctl)
        cands = [r for r in proc_seen.values()
                 if r["start"] <= ts + 0.3 and (r["end"] is None or r["end"] >= ts - 0.6)
                 and r.get("ppid") != me and r["pid"] != me
                 and r["comm"] not in NON_NETWORK and os.path.basename(r["exe"]) not in NON_NETWORK]
    # 1. the command line names a host that resolves to this destination
    for r in sorted(cands, key=lambda r: -r["start"]):
        for h in r["hosts"]:
            if ev["dst"] in host_ips(h):
                return r, "matched"
    # 2. a running launcher script whose text names a host that resolves to
    #    this destination (its child was too quick for the watcher to see)
    with proc_lock:
        scripts = [r for r in proc_seen.values() if r["scriptHosts"]
                   and r["start"] <= ts + 0.3 and (r["end"] is None or r["end"] >= ts - 0.6)]
    for r in sorted(scripts, key=lambda r: -r["start"]):
        for h in r["scriptHosts"]:
            if ev["dst"] in host_ips(h):
                child = {"pid": 0, "exe": "", "cgroup": r["cgroup"],
                         "origin": {"via": {"name": r["name"], "kind": "script", "id": r["args"][1] if len(r["args"]) > 1 and r["args"][1].startswith("/") else r["name"]},
                                    "cmd": "", "chain": [r["name"]], "unit": unit_name(r["cgroup"])}}
                return child, "matched"
    # 3. exactly one short-lived candidate started just before the connection
    fresh = [r for r in cands if ts - 3.0 <= r["start"] <= ts + 0.3]
    if len(fresh) == 1:
        return fresh[0], "likely"
    if fresh:
        return max(fresh, key=lambda r: r["start"]), "unclear"
    return None, "unknown"


def short_connections(conns, prev_keys):
    """Kernel events whose sockets the poll never saw -> connection records."""
    now = time.time()
    with kev_lock:
        ready = [e for e in kernel_events if now - e["ts"] >= 0.4]
        kernel_events[:] = [e for e in kernel_events if now - e["ts"] < 0.4]
    seen = {(c["lport"], c["raddr"], c["rport"]) for c in conns} | prev_keys
    out = []
    for ev in ready:
        if (ev["spt"], ev["dst"], ev["dpt"]) in seen or classify(ev["dst"]) in ("loopback", "multicast"):
            continue
        rec, conf = attribute(ev)
        guess = ""
        if conf == "unclear" and rec:
            # a timing guess is not good enough to name the app (or to base a
            # policy on it): keep it only as a hint
            go = (rec.get("origin") or {}).get("via") or {}
            guess = os.path.basename(rec.get("exe", "")) + (" via " + go["name"] if go.get("name") else "")
            rec = None
        o = (rec or {}).get("origin") or {}
        v = o.get("via") or {}
        exe = (rec or {}).get("exe", "")
        host = rdns(ev["dst"])
        out.append({
            "key": "short|%s|%d|%s|%d|%.3f" % (ev["proto"], ev["spt"], ev["dst"], ev["dpt"], ev["ts"]),
            "short": True, "ts": ev["ts"], "confidence": conf,
            "proto": ev["proto"], "state": "finished", "raddr": ev["dst"], "rport": ev["dpt"], "lport": ev["spt"],
            "pid": (rec or {}).get("pid", 0), "exe": exe,
            "app": os.path.basename(exe) if exe else ("short-lived process" if rec else "unknown"),
            "cgroup": (rec or {}).get("cgroup", ""), "system": False, "scope": classify(ev["dst"]),
            "host": host or "", "cc": country(ev["dst"]), "org": owner(ev["dst"]), "up": 0, "down": 0, "upRate": 0, "downRate": 0,
            "new": True, "list": list_match(host, ev["dst"]), "guess": guess,
            "via": v.get("name", ""), "viaId": v.get("id", ""), "viaKind": v.get("kind", ""),
            "cmd": o.get("cmd", ""), "chain": o.get("chain", []), "unit": o.get("unit", "")})
    return out


EMPTY_ORIGIN = {"via": "", "viaId": "", "viaKind": "", "cmd": "", "chain": [], "unit": ""}


def origin_fields(pid, cg):
    o = origin(pid, cg)
    if not o:
        return dict(EMPTY_ORIGIN, unit=unit_name(cg))
    v = o["via"] or {}
    return {"via": v.get("name", ""), "viaId": v.get("id", ""), "viaKind": v.get("kind", ""),
            "cmd": o["cmd"], "chain": o["chain"], "unit": o["unit"]}


def app_name(exe, comm, cg):
    if exe:
        return os.path.basename(exe)
    if comm:
        return comm
    unit = cg.rstrip("/").rsplit("/", 1)[-1] if cg else ""
    return unit or "unknown"


def tick(hist, prev, table_cache):
    now = time.time()
    rows = B.parse_ss(["-t", "-i", "state", "established", "state", "syn-sent"], "tcp")
    rows += B.parse_ss(["-u", "state", "established"], "udp")
    table = B.proc_table()
    apps = apps_from(table)
    conns = []
    for r in rows:
        kind = classify(r["raddr"])
        if kind in ("loopback", "multicast"):
            continue
        exe = table.get(r["pid"], ("", ""))[0].replace(" (deleted)", "") if r["pid"] else ""
        system = r["uid"] != MY_UID
        key = "%s|%s:%d|%s:%d" % (r["proto"], r["laddr"], r["lport"], r["raddr"], r["rport"])
        p = prev.get(key)
        dt = max(0.5, now - p["ts"]) if p else 0
        up_rate = max(0, (r["up"] - p["up"]) / dt) if p else 0
        down_rate = max(0, (r["down"] - p["down"]) / dt) if p else 0
        host = rdns(r["raddr"])
        c = {"key": key, "proto": r["proto"], "state": r["state"].lower(),
             "raddr": r["raddr"], "rport": r["rport"], "lport": r["lport"],
             "pid": r["pid"], "exe": exe, "app": app_name(exe, r["comm"], r["cgroup"]),
             "cgroup": r["cgroup"].lstrip("/"), "system": system, "scope": kind,
             "host": host or "", "cc": country(r["raddr"]), "org": owner(r["raddr"]),
             "up": r["up"], "down": r["down"], "upRate": up_rate, "downRate": down_rate,
             "new": p is None, "list": list_match(host, r["raddr"]) if not system else ""}
        c.update(origin_fields(r["pid"], r["cgroup"]) if (r["pid"] and not system) else EMPTY_ORIGIN)
        if re.search(r"/citadel-proxy(\s|$)", c["cmd"]):
            # Citadel's own proxy tunnels: the app's side is shown separately
            c.update(app="Citadel proxy", via="", viaId="", viaKind="")
        conns.append(c)
    nextprev = {c["key"]: {"ts": now, "up": c["up"], "down": c["down"],
                           "sock": (c["lport"], c["raddr"], c["rport"])} for c in conns}
    short = short_connections(conns, {p["sock"] for p in prev.values() if "sock" in p})

    app_out = {}
    for exe, a in apps.items():
        if not exe or exe.startswith(("/usr/lib/systemd/", "/usr/bin/systemd")):
            continue
        t = B.trust(exe, a["deleted"])
        app_out[exe] = {"name": os.path.basename(exe), "pids": sorted(a["pids"])[:50],
                        "cgroups": sorted(c.lstrip("/") for c in a["cgroups"] if c),
                        "owned": sorted(c.lstrip("/") for c in a["owned"] if c),
                        "trust": t}
    rx, tx = B.iface_totals()
    hist.sample(int(now), rx, tx)
    hist.update(conns, now)
    if short:
        hist.record_short(short)
    net = B.network_ids()
    emit({"type": "tick", "ts": now, "uid": MY_UID, "selfPid": os.getpid(), "shellPid": os.getppid(), "conns": conns, "apps": app_out,
          "totals": {"rx": rx, "tx": tx}, "network": {"names": net["names"], "ssid": net["ssid"], "source": net["source"]},
          "short": short,
          "kernelLog": {"running": kernel_state["running"], "error": kernel_state["error"], "seen": kernel_state["seen"]},
          "rdnsPending": len(rdns_pending)})
    return nextprev


def handle(cmd, hist):
    c = cmd.get("cmd")
    if c == "config":
        for k in ("interval", "retentionDays", "resolveHosts", "lists"):
            if k in cmd:
                cfg[k] = cmd[k]
        try:
            cfg["interval"] = min(60.0, max(1.0, float(cfg["interval"])))
        except (TypeError, ValueError):
            cfg["interval"] = 2.0
        threading.Thread(target=resolve_hosts, daemon=True).start()
        load_lists(download=False)
    elif c == "refreshLists":
        load_lists(download=True)
    elif c == "geoipDownload":
        geo_download()
    elif c == "stats":
        hist.stats()
    elif c == "resolve":
        threading.Thread(target=resolve_hosts, args=(True,), daemon=True).start()


def main():
    B.start_threads()
    hist = History()
    prev = {}
    geo_status()
    if geo_reader() is not None and geo_reader("asn") is None:
        geo_download(only_missing=True)        # installs from before the owner database
    last_stats = last_resolve = last_lists = 0
    buf = b""
    next_tick = time.time()
    while True:
        timeout = max(0.0, next_tick - time.time())
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            chunk = os.read(sys.stdin.fileno(), 65536)
            if not chunk:                      # parent closed stdin: shell gone
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    handle(json.loads(line.decode("utf-8", "replace")), hist)
                except ValueError:
                    log("bad command")
                except Exception as e:
                    log("command failed: %s" % e)
            continue
        try:
            prev = tick(hist, prev, None)
        except Exception as e:
            log("tick failed: %s" % e)
        now = time.time()
        if now - last_stats > 15:
            try:
                hist.stats()
            except Exception as e:
                log("stats failed: %s" % e)
            last_stats = now
        if now - last_resolve > 300:
            threading.Thread(target=resolve_hosts, daemon=True).start()
            last_resolve = now
        if now - last_lists > 3600:            # daily refresh check (stale > 24 h)
            load_lists(download=False)
            last_lists = now
        next_tick = now + float(cfg["interval"])
