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

### 1. Dependencies

| Distro | Command |
|---|---|
| Arch Linux / Omarchy | `sudo pacman -S --needed python pyside6 qt6-declarative iproute2 libnotify` |
| Debian 13 / Ubuntu | `sudo apt install python3 python3-pyside6.qtcore python3-pyside6.qtgui python3-pyside6.qtwidgets python3-pyside6.qtnetwork python3-pyside6.qtqml python3-pyside6.qtquick python3-pyside6.qtquickcontrols2 qml6-module-qtquick qml6-module-qtquick-controls qml6-module-qtquick-layouts qml6-module-qtquick-window iproute2 libnotify-bin` |
| Fedora | `sudo dnf install python3 python3-pyside6 qt6-qtdeclarative iproute libnotify` |

Optional:

| Package (Arch name) | Adds |
|---|---|
| `citadel-helper` 1.3+ ([repo](https://github.com/NeatOuk/citadel-helper)) | blocking and proxy routing; without it Citadel watches and asks but blocks nothing |
| `python-maxminddb` | countries and network owners |
| `libsecret` | proxy usernames and passwords in the keyring |
| `networkmanager` or `iwd` | zones by Wi-Fi name (wired links work either way) |
| an AI CLI: claude, codex, gemini, pi, opencode, crush, copilot or cursor-agent (or any command you set) | Explain at the gate |

Also needed, and present on every mainstream distro: systemd, cgroup v2, and
a notification server (GNOME, KDE, mako, dunst, swaync… any freedesktop one).
Integrity checks use the system's package database: pacman, dpkg or rpm.

The packages below pull in the required dependencies themselves.

### 2. Citadel

Arch Linux:

```bash
cd packaging/arch && makepkg -si
systemctl --user enable --now citadel
```

Or run it from the checkout without installing:

```bash
bin/citadel-daemon &
bin/citadel-app
```

Debian 13 / Ubuntu, Fedora: build the package in a container,
`packaging/build-in-docker.sh deb` or `packaging/build-in-docker.sh rpm`,
then install the file from `packaging/out/`.

Flatpak (window only): `packaging/flatpak/io.github.neatouk.Citadel.yml`.
The daemon and helper must still be installed natively; a sandbox can't
see other apps' connections or change the firewall.

Then install citadel-helper (1.3 or newer) and switch **Settings →
Enforcement** on to actually block.

**Using the Omarchy plugin too?** They are separate products that share
the same policies (`~/.local/share/citadel`). Only one runs Citadel at a
time: while the plugin is active, the service pauses by itself (no
monitor, no firewall changes, no writes to your policies) and the window
says so. To switch to the app, `omarchy plugin disable neat.citadel`; the
service takes over within seconds, with the same policies. To switch back,
enable the plugin again and the service steps aside.

## Development

```bash
make test                                  # model parity, daemon, integrity, QML (PySide6)
bin/citadel-daemon -v                      # run the daemon from the checkout
python3 app/citadel_app.py                 # run the window (needs PySide6)
# beside the Omarchy plugin: own folders, enforcement off
CITADEL_ALLOW_BESIDE_PLUGIN=1 CITADEL_STATE_DIR=~/.local/share/citadel-dev \
  CITADEL_RUNTIME_DIR=$XDG_RUNTIME_DIR/citadel-dev bin/citadel-daemon
```

- `citadel/model.py` is a port of the plugin's `Model.js`; `tests/test_parity.py`
  runs thousands of generated cases through both and requires identical results.
- `tests/test_daemon.py` drives the real socket API with a fake monitor and a
  fake helper; nothing privileged runs.
- `tests/test_qml.py` loads every tab offscreen and fails on any QML warning.

## License

MIT, see [LICENSE](LICENSE).
