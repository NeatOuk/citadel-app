"""macOS pieces for the daemon: notifications (osascript until the Swift host
takes over), Keychain, the admin group, launching the app, process owners.
"""
import asyncio
import grp
import os
import pwd
import shutil
import subprocess
import tempfile

from .linux import write_atomic   # plain file I/O, same on macOS  # noqa: F401


def privileged_group():
    """macOS admins are the `admin` group."""
    user = pwd.getpwuid(os.getuid()).pw_name
    try:
        g = grp.getgrnam("admin")
        return "admin", user in g.gr_mem or os.getgid() == g.gr_gid or g.gr_gid in os.getgroups()
    except KeyError:
        return "admin", False


async def notify(title, body, actions):
    """A banner via osascript. It has no buttons, so the gate is answered in
    the window; the Swift host (phase 2) adds actionable notifications. The
    process exits at once and prints nothing, i.e. "no action"."""
    exe = shutil.which("osascript")
    if not exe:
        return None

    def q(s):
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'
    script = "display notification %s with title %s" % (q(body), q("Citadel · " + title))
    try:
        return await asyncio.create_subprocess_exec(exe, "-e", script, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        return None


def launch_app(args):
    exe = shutil.which("citadel-app")
    cmd = [exe] + list(args) if exe else ["open", "-a", "Citadel", "--args"] + list(args)
    subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _security(commands):
    """Run `security -i` with commands on stdin, so secrets never appear in ps."""
    try:
        p = subprocess.run(["security", "-i"], input=commands + "\nquit\n", text=True, capture_output=True, timeout=15)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _quote(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def store_secret(pid, name, user, password):
    return _security("add-generic-password -U -s citadel-proxy -a %s -l %s -w %s"
                     % (_quote(pid), _quote("Citadel proxy " + name), _quote(user + ":" + password)))


def clear_secret(pid):
    _security("delete-generic-password -s citadel-proxy -a %s" % _quote(pid))


def process_uid(pid):
    try:
        out = subprocess.run(["ps", "-o", "uid=", "-p", str(int(pid))], capture_output=True, text=True, timeout=5).stdout
        return int(out.strip()) if out.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def other_core_running(marker, own_paths):
    """The Omarchy plugin only exists on Linux."""
    return False


def lookup_secret(pid):
    """(user, password) stored for a proxy in the Keychain, or None."""
    try:
        p = subprocess.run(["security", "find-generic-password", "-s", "citadel-proxy", "-a", str(pid), "-w"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    user, sep, password = p.stdout.rstrip("\n").partition(":")
    return (user, password) if p.returncode == 0 and sep else None
