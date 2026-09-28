"""Desktop- and OS-specific pieces the daemon needs, chosen at start-up:
linux.py (systemd, notify-send, libsecret, /proc) or darwin.py (launchd,
osascript, Keychain, ps). Both expose the same functions.
"""
import os
import sys
import tempfile

if sys.platform == "darwin":
    from .darwin import *      # noqa: F401,F403
else:
    from .linux import *       # noqa: F401,F403


def runtime_base():
    """Where per-user sockets live: $XDG_RUNTIME_DIR on Linux, $TMPDIR on macOS."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return xdg
    run = "/run/user/%d" % os.getuid()
    return run if os.path.isdir(run) else tempfile.gettempdir()
