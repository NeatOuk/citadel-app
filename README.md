# Citadel for Linux

An outbound firewall for any Linux desktop (GNOME, KDE, Hyprland, Sway, …).
Every app that tries to reach somewhere new waits **at the gate**, in the
Citadel window or as a desktop notification with **Allow once / Always allow
/ Block**. Your verdicts become per-app **policies**; with
[citadel-helper](https://github.com/NeatOuk/citadel-helper) they are enforced
with nftables, and chosen apps can be routed through HTTP, HTTPS or SOCKS5
proxies.

This is the standalone edition of the [Citadel Omarchy plugin](https://github.com/NeatOuk/citadel):
the same core, as a background service with its own window and tray icon.

## How it fits together

| Piece | What it does |
|---|---|
| `citadel-daemon` (systemd user service `citadel`) | Citadel's core: watches connections, decides against your policies, queues gate requests, sends notifications, drives the helper. Keeps working with the window closed. |
| `citadel-app` | The window (Gate, Traffic, Policies, History, Settings) and a tray icon, talking to the daemon over `$XDG_RUNTIME_DIR/citadel/daemon.sock`. |
| `citadel` | A small CLI: `citadel status`, `citadel alerts`, `citadel lockdown`, `citadel guard`, `citadel enforce on`. |
| `citadel-helper` (separate package) | The only part that runs as root: applies the nftables table, restores it at boot. Without it Citadel watches and asks, but blocks nothing. |

## Install

Arch Linux:

```bash
cd packaging/arch && makepkg -si          # citadel (needs pyside6 from the repos)
systemctl --user enable --now citadel
```

Debian 13 / Ubuntu, Fedora: build the package in a container,
`packaging/build-in-docker.sh deb` or `packaging/build-in-docker.sh rpm`,
then install the file from `packaging/out/`.

Flatpak (window only): `packaging/flatpak/io.github.neatouk.Citadel.yml`.
The daemon and helper must still be installed natively; a sandbox can't
see other apps' connections or change the firewall.

Then install citadel-helper (1.3 or newer) and switch **Settings →
Enforcement** on to actually block.

**Using the Omarchy plugin too?** Don't run both cores at once yet: they
share `~/.local/share/citadel` and would both drive the firewall. Remove
the plugin from the bar first. (Making the plugin a client of this daemon
is the next step.)

## Requirements

| Need | Package |
|---|---|
| Python 3.11+ and PySide6 (Qt 6 Quick) | `pyside6` / `python3-pyside6.*` |
| Connection list | `iproute2` |
| Notifications with buttons | `libnotify` (`notify-send`) and any notification server |
| Enforcement, proxy routing | `citadel-helper` → `nftables`, `polkit`; cgroup v2 |
| Countries, network owners (optional) | `python-maxminddb`; databases download from Settings |
| Proxy logins (optional) | `libsecret` (`secret-tool`) and a keyring |
| Zones (optional) | NetworkManager or iwd; wired links work either way |
| Explain (optional) | any supported AI CLI (claude, codex, gemini, pi, opencode, crush, copilot, cursor-agent) or a custom command |

Integrity checks use the package database: pacman, dpkg or rpm.

## Development

```bash
make test                                  # model parity, daemon, integrity, QML (PySide6)
bin/citadel-daemon -v                      # run the daemon from the checkout
python3 app/citadel_app.py                 # run the window (needs PySide6)
CITADEL_STATE_DIR=~/.local/share/citadel-dev CITADEL_RUNTIME_DIR=$XDG_RUNTIME_DIR/citadel-dev bin/citadel-daemon
```

- `citadel/model.py` is a port of the plugin's `Model.js`; `tests/test_parity.py`
  runs thousands of generated cases through both and requires identical results.
- `tests/test_daemon.py` drives the real socket API with a fake monitor and a
  fake helper; nothing privileged runs.
- `tests/test_qml.py` loads every tab offscreen and fails on any QML warning.

## License

MIT, see [LICENSE](LICENSE).
