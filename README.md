# Citadel for Linux

An outbound firewall for any Linux desktop (GNOME, KDE, Hyprland, Sway, …),
and in progress for macOS ([macos/](macos/README.md): watch-only today).
Every app that tries to reach somewhere new waits **at the gate**, in the
Citadel window or as a desktop notification with **Allow once / Always allow
/ Block**. Your verdicts become per-app **policies**; with
[citadel-helper](https://github.com/NeatOuk/citadel-helper) they are enforced
with nftables, and chosen apps can be routed through HTTP, HTTPS or SOCKS5
proxies.

This is the standalone edition of the [Citadel Omarchy plugin](https://github.com/NeatOuk/citadel):
the same core, as a background service with its own window and tray icon.

## Key features

- **Ask at the gate.** When an app connects somewhere new, Citadel asks. Answer in
  the window or straight from the notification: **Allow once**, **Always allow** or
  **Block**. Unanswered requests fall back to your default after a timeout.
- **Per-app policies.** A policy can cover:
  - an app
  - a host (subdomains included), an IP or CIDR, a port
  - an app **only when a given script or program starts it**
  - a zone

  The most specific policy wins. Search and filter them, and export or import them.
- **Real blocking, per app.** With citadel-helper, policies are enforced with
  nftables per app (its cgroup), not just per address. Blocking something also
  closes its open connections.
- **Guarded, Open and Lockdown modes**, with optional timers.
- **Knows who started it.** `curl via backup.sh` or `git in ghostty`, with the
  command line shown and its secrets (tokens, passwords, auth headers) masked.
  Short-lived connections are caught too.
- **Integrity checks.** Programs are checked against their package's checksums
  (pacman, dpkg or rpm). An allowed app that changes without an update comes back
  to the gate.
- **Per-app proxy routing**, like Proxifier.
  - Send chosen apps through HTTP, HTTPS or SOCKS5 proxies; logins are kept in
    your keyring.
  - It fails closed: if the proxy is down, the app is blocked, never sent direct.
- **Threat feeds and imports.**
  - One-click feeds: FireHOL, Spamhaus DROP, StevenBlack, HaGeZi.
  - Import AdGuard rules, Pi-hole lists, hosts files or any list URL.
- **Explain.** See who owns a destination (e.g. *Google LLC*). On request, your own
  AI agent (claude, codex, gemini, pi, …) explains what it's for and suggests allow
  or block.
- **Traffic and history.**
  - Live connections per app, with rates, countries and why each one is allowed
    or blocked.
  - 30 days of history: top apps, hosts and countries, and the decision log.
- **Zones.** Link Wi-Fi or wired networks to zones, and Citadel switches policies
  as you move.
- **Runs quietly in the background.** A user service that keeps working with the
  window closed, plus a tray icon and a `citadel` CLI. It works on GNOME, KDE,
  Hyprland, Sway and others.
- **Shares policies with the Omarchy plugin**, and steps aside while the plugin runs.
- **Local and private.**
  - No account, no telemetry.
  - Feeds and databases download only when you turn them on.
  - Explain sends nothing until you press it.
  - The only part that runs as root is a small helper that validates everything
    it receives.

On macOS, watching and the gate work from a checkout today. Blocking and proxy
routing are built and wait for signing; see [macos/](macos/README.md).

**Every feature in detail, and its limits: [FEATURES.md](FEATURES.md).**

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
cd linux/packaging/arch && makepkg -si
systemctl --user enable --now citadel
```

Or run it from the checkout without installing:

```bash
bin/citadel-daemon &
bin/citadel-app
```

Debian 13 / Ubuntu, Fedora: build the package in a container,
`linux/packaging/build-in-docker.sh deb` or `linux/packaging/build-in-docker.sh rpm`,
then install the file from `linux/packaging/out/`.

Flatpak (window only): `linux/packaging/flatpak/io.github.neatouk.Citadel.yml`.
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

## Import from AdGuard, Pi-hole and hosts files

**Policies → Import ▸** takes:
- AdGuard / AdGuard Home rules
- Pi-hole allow and deny lists
- hosts files
- plain domain lists
- Citadel's own export

Paste them, or fetch them from a URL (GitHub page links work).

| Rule | Becomes |
|---|---|
| `\|\|ads.example.com^` (also with `$important`) | a Block policy |
| `@@\|\|good.example.com^` | an Allow policy (wins over a block of the same domain, as in AdGuard) |
| `0.0.0.0 ads.example.com` | a Block policy |
| a plain domain | Block or Allow, as you choose (Pi-hole allowlists are plain lists) |

Up to 200 blocked domains become policies you can see and edit. Bigger lists,
like HaGeZi or OISD, become a **feed**. Fetched from a URL, the feed refreshes daily.

Regex rules and AdGuard options such as `$client=` or `$dnsrewrite` have no
Citadel equivalent. They're skipped, and the import tells you how many.

**Not a DNS ad blocker.** Citadel blocks connections per app, so a listed
domain is caught when Citadel knows the connection's host name, from its own
name lookups or the app's request. Pi-hole and AdGuard Home block the DNS
lookup itself. They work well together.

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

## Layout

| Folder | What |
|---|---|
| `citadel/` | the core, shared by every OS: decisions (`model.py`), the daemon and its socket API, the CLI |
| `citadel/monitor/` | the connection monitor: `common.py` (shared), `linux.py`, `darwin.py` |
| `citadel/platform/` | OS pieces for the daemon: `linux.py`, `darwin.py` |
| `app/` | the Qt window and tray / menu-bar icon, shared by every OS |
| `libexec/` | scripts the daemon starts: monitor, proxy, Explain |
| `linux/` | Linux packaging (Arch, Debian, Fedora, Flatpak), systemd unit, desktop entries |
| `macos/` | macOS instructions; the Xcode project (Network Extension) from phase 2 |
| `tests/` | shared tests, plus `tests/macos/` (runs anywhere, with recorded macOS output) |

## License

MIT, see [LICENSE](LICENSE).
