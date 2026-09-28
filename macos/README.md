# Citadel on macOS

Same Citadel as on Linux (the daemon, the window, the policies, Explain),
with a macOS connection monitor. Built in phases:

| Phase | What works | Needs |
|---|---|---|
| **1. Watch-only** (now) | every app's connections, "started by", integrity (code signing and notarization), the gate asks in the window, history, zones | Python 3.11+, PySide6 |
| 2. Blocking and proxy routing (built, not yet signed) | a Network Extension decides every new connection (even the first packet waits for your answer), per-app proxies | an Apple Developer account, Xcode 16+, a signed system extension |
| 3. Citadel.app | one notarized download (DMG) | phase 2 |

The shared code lives in the repository root (`citadel/`, `app/`); the macOS
parts are `citadel/monitor/darwin.py`, `citadel/platform/darwin.py` and,
from phase 2, the Xcode project in this folder.

## Phase 1: try it from a checkout

```bash
# Python 3.11+ (Homebrew or python.org) and PySide6 in a virtual environment
brew install python@3.12
git clone https://github.com/NeatOuk/citadel-app.git && cd citadel-app
python3.12 -m venv ~/.venvs/citadel
~/.venvs/citadel/bin/pip install PySide6

# check
~/.venvs/citadel/bin/python -m unittest discover -s tests -t .
~/.venvs/citadel/bin/python bin/citadel-daemon --selftest

# run: the service in one terminal, the window in another
~/.venvs/citadel/bin/python bin/citadel-daemon -v
~/.venvs/citadel/bin/python bin/citadel-app

# optional: start the service at login (launchd), and stop doing so
~/.venvs/citadel/bin/python bin/citadel-daemon --install-agent
~/.venvs/citadel/bin/python bin/citadel-daemon --remove-agent
```

Good to know in phase 1:

- **Nothing is blocked yet.** Settings shows enforcement as unavailable
  until the Network Extension exists.
- **Your apps only.** Without root, `lsof` lists your own processes'
  connections; system services are not shown.
- **Short connections** that open and close between two checks can be
  missed. The Network Extension (phase 2) sees every connection.
- **Wi-Fi name for zones:** macOS 15 hides it unless the app has Location
  access; without it, zones fall back to wired ports or a manual choice.
- **Notifications** are plain banners (no buttons) until the phase 2 host
  app; answer the gate in the window.
- **Proxy logins** are kept in your Keychain (`citadel-proxy` items).

## Phase 2: what is built

Everything below compiles and is tested in CI (GitHub's macOS 15 machines);
running it needs the extension signed with an Apple Developer account.

| Piece | Where | Tested |
|---|---|---|
| Decisions (`decide`, routes, host/IP matching) | `Packages/CitadelCore` | parity with `citadel/model.py` (and so the Omarchy plugin's `Model.js`) on generated cases |
| Threat feeds (IP ranges, domain lists) | `CitadelCore/Blocklist.swift` | against the Linux monitor's own `list_match` |
| "Started by" launchers | `CitadelCore/Launcher.swift` | against the monitor's `origin()` on generated process trees |
| Proxy handshakes (SOCKS5, HTTP CONNECT) | `CitadelCore/ProxyHandshake.swift` | byte-for-byte with `citadel-proxy` |
| Network filter: decide, pause at the gate, resume | `CitadelFilter/FilterDataProvider.swift` | builds |
| Per-app proxy routing, failing closed | `CitadelFilter/TransparentProxyProvider.swift` | builds |
| Host app: installs the extension, bridges it to `citadel-daemon`, notifications with Allow / Block buttons, start at login | `CitadelHost/` | builds; the daemon side is tested against a fake host (`tests/test_hostbridge.py`) |

How a new connection flows:

```
app ─► CitadelFilter (system extension)
        ├─ policy or feed decides ─────────────► allow / drop
        └─ no policy: pause ─► Citadel host app ─► citadel-daemon ─► gate (window, notification)
                                                           answer ─► resume: allow / drop
```

Known limit: a Block applies to **new** connections. A content filter can
only cut an established connection whose data it has been watching from
the start, which would slow every connection on the Mac, so connections
that were already open end when they close.

To try it once the account exists: `cd macos && xcodegen generate`, open
`Citadel.xcodeproj`, set your team on both targets, run **Citadel**, press
*Install and enable*, and allow the extension in System Settings →
General → Login Items & Extensions → Network Extensions.
