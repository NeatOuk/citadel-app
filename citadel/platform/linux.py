"""Desktop-neutral pieces the daemon needs: files, notifications, keyring,
groups, launching the app. Anything tied to one desktop or distro lives here.
"""
import asyncio
import grp
import os
import pwd
import shutil
import subprocess
import tempfile


def write_atomic(path, text, mode=0o600):
    """Write via a temp file + rename, so readers never see half a file."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def privileged_group():
    """(group that may run the helper without a password, is the user in it).

    Arch/Fedora use wheel; Debian/Ubuntu use sudo. The helper's polkit rule
    accepts either.
    """
    user = pwd.getpwuid(os.getuid()).pw_name
    mine = {g.gr_name for g in grp.getgrall() if user in g.gr_mem}
    try:
        mine.add(grp.getgrgid(os.getgid()).gr_name)
    except KeyError:
        pass
    for g in os.getgroups():
        try:
            mine.add(grp.getgrgid(g).gr_name)
        except KeyError:
            pass
    for name in ("wheel", "sudo", "admin"):
        if name in mine:
            return name, True
    try:
        grp.getgrnam("wheel")
        return "wheel", False
    except KeyError:
        return "sudo", False


async def notify(title, body, actions):
    """A desktop notification with action buttons; the process prints the
    chosen action name (or nothing) when it ends. None if notify-send is
    missing. Works with any freedesktop notification server (GNOME, KDE,
    mako, dunst, swaync, Omarchy)."""
    exe = shutil.which("notify-send")
    if not exe:
        return None
    cmd = [exe, "-a", "Citadel", "-i", "security-high", "-w"]
    for name, label in actions:
        cmd += ["-A", "%s=%s" % (name, label)]
    cmd += [title, body]
    try:
        return await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        return None


def launch_app(args):
    """Start the Citadel window (e.g. from a notification)."""
    exe = shutil.which("citadel-app")
    if exe:
        subprocess.Popen([exe] + list(args), start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def store_secret(pid, name, user, password):
    """user:password in the desktop keyring (libsecret)."""
    exe = shutil.which("secret-tool")
    if not exe:
        return False
    p = subprocess.run([exe, "store", "--label=Citadel proxy " + name, "citadel-proxy", pid],
                       input=user + ":" + password, text=True, capture_output=True)
    return p.returncode == 0


def clear_secret(pid):
    exe = shutil.which("secret-tool")
    if exe:
        subprocess.run([exe, "clear", "citadel-proxy", pid], capture_output=True)


def process_uid(pid):
    """Owner of a process, or None when it's gone."""
    try:
        return os.stat("/proc/%d" % pid).st_uid
    except OSError:
        return None


def other_core_running(marker, own_paths):
    """Is another Citadel core (the Omarchy plugin's monitor) running for this
    user? Its monitor script's file name is `marker`; `own_paths` are ours."""
    uid = os.getuid()
    own = {os.path.realpath(p) for p in own_paths}
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == os.getpid():
            continue
        try:
            if os.stat("/proc/" + d).st_uid != uid:
                continue
            with open("/proc/%s/cmdline" % d, "rb") as f:
                args = f.read().decode(errors="replace").split("\0")
        except OSError:
            continue
        for a in args[:3]:
            if os.path.basename(a) == marker and os.path.realpath(a) not in own:
                return True
    return False


def lookup_secret(pid):
    """(user, password) stored for a proxy, or None."""
    exe = shutil.which("secret-tool")
    if not exe:
        return None
    p = subprocess.run([exe, "lookup", "citadel-proxy", pid], capture_output=True, text=True)
    user, sep, password = p.stdout.rstrip("\n").partition(":")
    return (user, password) if p.returncode == 0 and sep else None
