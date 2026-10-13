"""Launchers that start routed browsers through Citadel's front door.

Resolve hostnames through proxy needs the app to hand over the host name
itself: on systemd-resolved systems apps resolve through glibc, which no
firewall rule can redirect, so a name only the proxy's DNS knows never even
becomes a connection. Chromium-family browsers can be told to use a SOCKS5
proxy (--proxy-server), and then send every host name to it. Citadel puts a
copy of such an app's menu launcher in ~/.local/share/applications with that
option added, marked as Citadel's, and removes it when the app is no longer
routed. A launcher the user made themselves is never touched.

shortcut: native packages only; Flatpak browsers run from /app inside their
sandbox, so their launchers can't be matched to the app's path. Upgrade when
someone routes a Flatpak browser.
"""
import os
import re
import shutil

from .platform import write_atomic

BROWSER_RE = re.compile(r"(^|/)(msedge|chrome|chromium|chromium-browser|brave|vivaldi-bin|opera)$")
MARK = "X-Citadel-Managed=true"
FLAG = "--proxy-server=socks5://127.0.0.1:%d"


def data_dirs():
    home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    rest = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    return home, [d for d in rest.split(":") if d]


def user_dir():
    return os.path.join(data_dirs()[0], "applications")


def is_browser(exe):
    return bool(exe and BROWSER_RE.search(exe))


def exec_binary(line):
    """The program of an Exec= line (unquoted), or ""."""
    value = line.split("=", 1)[1].strip()
    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end > 0 else ""
    return value.split(None, 1)[0] if value else ""


def with_flag(line, flag):
    """An Exec= line with flag right after its program."""
    key, value = line.split("=", 1)
    value = value.strip()
    prog = exec_binary(line)
    quoted = value.startswith('"')
    rest = value[len(prog) + (2 if quoted else 0):]
    if flag in rest:
        return line
    return "%s=%s %s%s" % (key, ('"%s"' % prog) if quoted else prog, flag, rest)


def _program_dir(prog):
    path = prog if os.path.isabs(prog) else shutil.which(prog)
    return os.path.dirname(os.path.realpath(path)) if path else ""


def launchers_for(exe):
    """System launchers whose program is this browser (or a wrapper beside it)."""
    want = os.path.dirname(os.path.realpath(exe))
    found = []
    for d in data_dirs()[1]:
        apps = os.path.join(d, "applications")
        try:
            names = sorted(os.listdir(apps))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".desktop"):
                continue
            try:
                with open(os.path.join(apps, name), encoding="utf-8") as f:
                    text = f.read()
            except (OSError, UnicodeDecodeError):
                continue
            prog = next((exec_binary(l) for l in text.splitlines() if l.startswith("Exec=")), "")
            if prog and _program_dir(prog) == want:
                found.append((name, text))
    return found


def managed_text(text, port):
    """The launcher with every Exec= line starting through the front door, marked as Citadel's."""
    out, marked = [], False
    for line in text.splitlines():
        if line.startswith("Exec="):
            line = with_flag(line, FLAG % port)
        out.append(line)
        if line.strip() == "[Desktop Entry]" and not marked:
            out.append(MARK)
            marked = True
    return "\n".join(out) + "\n"


def _is_managed(path):
    try:
        with open(path, encoding="utf-8") as f:
            return MARK in f.read()
    except (OSError, UnicodeDecodeError):
        return False


def sync(exes, port):
    """Make the launchers of these browsers start through 127.0.0.1:port (0 or no
    exes: none do). -> [{"exe", "name", "file", "state": "managed"|"own"|"none"}]."""
    udir = user_dir()
    wanted, status = {}, []
    for exe in sorted(e for e in exes if is_browser(e)) if port else []:
        found = launchers_for(exe)
        if not found:
            status.append({"exe": exe, "name": os.path.basename(exe), "file": "", "state": "none"})
        for name, text in found:
            dst = os.path.join(udir, name)
            own = os.path.exists(dst) and not _is_managed(dst)
            if not own:
                wanted[dst] = managed_text(text, port)
            status.append({"exe": exe, "name": os.path.basename(exe), "file": dst, "state": "own" if own else "managed"})
    for dst, text in wanted.items():
        try:
            with open(dst, encoding="utf-8") as f:
                if f.read() == text:
                    continue
        except (OSError, UnicodeDecodeError):
            pass
        write_atomic(dst, text, 0o644)
    try:
        names = os.listdir(udir)
    except OSError:
        names = []
    for name in names:
        path = os.path.join(udir, name)
        if name.endswith(".desktop") and path not in wanted and _is_managed(path):
            os.unlink(path)
    return status


def started_through(pid, port):
    """Was this browser process started with the front-door option? None if it is gone
    or is one of the browser's helper processes (renderers etc. carry --type=)."""
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            args = f.read().decode(errors="replace").replace("\0", " ").split()   # Chromium rewrites it space-separated
    except OSError:
        return None
    if any(a.startswith("--type=") for a in args):
        return None
    return (FLAG % port) in args
