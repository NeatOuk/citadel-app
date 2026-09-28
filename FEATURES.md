# Citadel features

Everything Citadel does, in detail. For installing, see the [README](README.md).

## Contents

1. [The gate](#1-the-gate)
2. [Policies](#2-policies)
3. [Modes](#3-modes)
4. [Enforcement](#4-enforcement)
5. [Who started it](#5-who-started-it)
6. [Integrity checks](#6-integrity-checks)
7. [Traffic](#7-traffic)
8. [History](#8-history)
9. [Threat feeds](#9-threat-feeds)
10. [Importing from AdGuard, Pi-hole and hosts files](#10-importing-from-adguard-pi-hole-and-hosts-files)
11. [Per-app proxy routing](#11-per-app-proxy-routing)
12. [Explain](#12-explain)
13. [Zones](#13-zones)
14. [Service, window, tray and CLI](#14-service-window-tray-and-cli)
15. [Living next to the Omarchy plugin](#15-living-next-to-the-omarchy-plugin)
16. [Privacy](#16-privacy)
17. [Platforms](#17-platforms)
18. [Limits](#18-limits)

---

## 1. The gate

When an app connects somewhere no policy covers, the connection waits **at the gate** for your verdict.

- **Where you answer:**
  - in the window's **Gate** tab
  - from the desktop notification, which has **Allow once / Always allow / Block / Open Citadel** buttons
- **What a request shows:**
  - the app and its integrity
  - who started it
  - the command line, with secrets masked
  - the destination (host, IP, country, port) and its network owner
- **What your answer covers:**
  - **Allow once** lets this app–host–port through for this session.
  - **Always allow** and **Block** create a policy. Under **Adjust** you choose what it covers:
    - this port, this host, or every host
    - only when started by the same launcher, or however it starts
    - how long: from now on, or until the app quits
- **Grouping:** connections from the same app to the same destination share one request.
- **No answer:** after a timeout (30 s, 90 s, 5 min, or never) the request gets your default, Allow once or Block once. The timer restarts while you read an Explain answer.
- **Changed programs:** if an app you allowed changes without a package update, its next connection comes back to the gate, marked as changed.

## 2. Policies

A policy says **Allow** or **Block** for a match.

| Field | Options |
|---|---|
| App | any app, or one program (by path) |
| Started by | however it starts, or only when a given script or program launches it |
| Destination | any, a host name (subdomains included), an IP address or a CIDR range |
| Port | any, or one port |
| Zone | all zones, or one |
| Duration | from now on, or until the app quits |
| Route (Allow only) | the default route, or via a proxy ([section 11](#11-per-app-proxy-routing)) |

- **Precedence:**
  - The most specific policy wins: app+host beats host, which beats app.
  - A port or a launcher makes a policy more specific.
  - At equal specificity, **Block** wins.
- **Managing them:**
  - Search by app, host, IP or proxy name.
  - Show only: **Added by you**, **From the gate**, **Blocks**, **Via proxy**.
  - Sort newest first or by precedence.
  - Each row shows where the policy came from and when it was made.
- **Export and import:** through the clipboard as JSON, and from other tools ([section 10](#10-importing-from-adguard-pi-hole-and-hosts-files)).

## 3. Modes

| Mode | New connections without a policy |
|---|---|
| **Guarded** | wait at the gate |
| **Open** | pass quietly and are logged |
| **Lockdown** | are blocked |

Open and Lockdown can end on their own: until you change it, after 15 minutes, or after 1 hour. The tray menu also has "Open for 1 hour".

## 4. Enforcement

Watching and asking need no root. To actually **block**, install [citadel-helper](https://github.com/NeatOuk/citadel-helper) and switch **Settings → Enforcement** on.

- **Per app, not per address:**
  - Rules match the app's own systemd scope (nftables `socket cgroupv2`), so "block Chromium" stops Chromium while other apps can still reach the same server.
  - Command-line tools inside a terminal share the terminal's scope. Their policies are enforced per destination within that scope, and the policy is marked so.
- **Open connections:** blocking something also closes its open connections. The helper closes only your own sockets, one exact connection at a time.
- **Never touched:**
  - system services (other users' traffic, e.g. VPN daemons, NetworkManager, DNS)
  - established connections, unless you block them
  - LAN, loopback and CGNAT ranges, which are never blocked by IP feeds
- **The helper:** one small root program behind polkit. It:
  - validates every IP, port and cgroup it receives
  - only touches its own nftables table
  - only acts for your own apps
  - is version-checked before every privileged call
- **Passwords:** members of `wheel` (Arch, Fedora) or `sudo` (Debian, Ubuntu) aren't asked for one.
- **Boot and emergencies:** your policies are restored at boot, before the network is up. `citadel-off` removes every rule at once, from any terminal.

## 5. Who started it

Many connections come from tools that something else started. Citadel shows the **launcher**:

- `curl via backup.sh` for a script
- `git in ghostty` when you started it in a terminal
- the full launch chain, under **Adjust**

Around that:
- **Launcher policies:** a policy can cover an app **only when started by that launcher**, so allowing `curl` for your backup script doesn't allow `curl` for everything.
- **Masked command lines:** the command line is shown with passwords, tokens, `Authorization` headers, URL credentials and request bodies masked.
- **Short-lived connections:**
  - Connections too short to see between two checks are caught from the kernel log that citadel-helper writes.
  - They're matched to the process that made them and labelled by how sure the match is: **matched**, **likely** or **app unclear**.
  - Only confident matches go to the gate.

## 6. Integrity checks

A stand-in for code signing: each program is compared with the checksum its package recorded.

| Level | Meaning |
|---|---|
| verified | the file matches its package (pacman, dpkg or rpm) |
| modified | it differs from its package |
| not packaged | not from a system package (e.g. installed by hand, or by a language package manager) |
| suspicious | runs from a temporary folder, or was deleted while running |

On macOS the levels come from code signing and notarization: Apple, App Store, notarized developer, signed but not notarized, ad-hoc, unsigned.

## 7. Traffic

- **Live connections grouped by app,** each with:
  - its launcher
  - destination, country and port
  - bytes and rates in both directions
  - why it's allowed or blocked
  - the proxy it goes through, if any
- **Per-app actions:** allow or block a whole app or one destination, and kill an app's processes (never the desktop's own, and only yours).
- **Just now:** the short-lived connections caught from the kernel log.
- **Proxy tab:** each proxy's health, what it carries now and in the last 5 minutes, the policies that route through it, and recent failures.

## 8. History

- **Charts:** traffic over the last hour.
- **Tops:** apps and hosts (today or 7 days), and countries today.
- **Decision log:** every verdict, and who made it (you, a policy, a feed, a mode, the timeout).
- **Storage:** kept in a local SQLite database for 30 days (adjustable).

## 9. Threat feeds

| Feed | Kind |
|---|---|
| FireHOL Level 1 | IP ranges: attacks, malware |
| Spamhaus DROP | IP ranges: hijacked networks |
| StevenBlack hosts | domains: ads, malware |
| HaGeZi Light | domains: trackers |
| any URL you add | IP or domain list, including AdGuard syntax |

- **Matching:** IP feeds go straight into the firewall. Domain feeds block connections whose host name Citadel knows.
- **Refresh:** daily.
- **Safety:** LAN, loopback, link-local, CGNAT/Tailscale and multicast ranges are always removed from IP feeds, so a feed can't cut you off from your own network.

## 10. Importing from AdGuard, Pi-hole and hosts files

**Policies → Import ▸** takes pasted text or a URL. A GitHub page link is turned into its raw file.

| Input | Becomes |
|---|---|
| AdGuard `\|\|ads.example.com^`, also with `$important` | a Block policy |
| AdGuard `@@\|\|good.example.com^` | an Allow policy; it wins over a block of the same domain |
| hosts file `0.0.0.0 ads.example.com` | a Block policy |
| plain domain list (e.g. a Pi-hole list) | Block or Allow, as you choose |
| Citadel's own export | the same policies |

- **Big lists:**
  - Up to 200 blocked domains become policies you can see and edit.
  - Bigger lists become a **feed**. From a URL it's a subscription that refreshes daily; pasted, it's a local list.
- **Skipped, and counted in the result:** regex rules, cosmetic filters, and options that change a rule's meaning (`$client=`, `$dnsrewrite`, …).

## 11. Per-app proxy routing

Like Proxifier: chosen apps go through a proxy, everything else goes direct.

- **Proxies:** HTTP, HTTPS (CONNECT over TLS) and SOCKS5, with an optional username and password kept in your keyring. **Check** tests one end to end.
- **Routes:**
  - **Allow via proxy** on a policy sends that traffic through a proxy.
  - **Everything else** sets the default route.
  - Plain Allows don't override a broader policy's route.
- **Fails closed:** if the proxy is down or refuses, the app's connection is reset, never sent direct, and the failure is logged.
- **Host names:**
  - Many proxies refuse a bare IP, so Citadel asks the proxy for the host name the app requested.
  - It does so only when that name resolves to the address the firewall let through, so an app can't name another host to get around a block.
- **Moving connections:** when a route changes, the app's open connections are closed so they reconnect the new way.
- **Health:** a status dot per proxy, and a log of recent failures.

## 12. Explain

- **Owner:** every destination shows its network owner at once, from the free DB-IP ASN database, e.g. *Owner: Google LLC*.
- **Explain button:** asks an AI agent who runs the destination, what the connection is for, and whether to allow or block it.
- **Which agent:**
  - your choice in Settings
  - otherwise your Omarchy default agent, or the first one installed
  - supported: claude, codex, gemini, pi, opencode, crush, copilot, cursor-agent, or any command you set
- **On request only:** it sends the app, its launcher, the masked command line and the destination to that agent.
- **Saved answers:** answers are cached for 30 days, and **Ask again** gets a fresh one.

## 13. Zones

- **Zones:** Link networks to zones (e.g. Home, Work, Public). Citadel switches zones as you move, and a policy can apply to one zone or to all.
- **Networks:**
  - Wi-Fi and wired connections are recognised through NetworkManager or iwd, and wired links work without either.
  - On macOS: the Wi-Fi name and active Ethernet ports.
- **Manual choice:** you can always pick a zone by hand.

## 14. Service, window, tray and CLI

- **`citadel-daemon`:** a systemd user service (a launchd agent on macOS). It watches, decides and enforces with the window closed.
- **`citadel-app`:** the window and a tray icon (menu-bar icon on macOS).
  - The icon shows the mode, a waiting count, and whether Citadel is enforcing.
  - Its menu switches modes.
  - Only one window runs at a time; `citadel-app --gate` opens it on the Gate tab.
- **`citadel`:** the CLI, e.g. `citadel status`, `citadel alerts`, `citadel lockdown`, `citadel open 60`, `citadel guard`, `citadel enforce on|off`.
- **Socket:** everything talks over a local socket that only your user can open.

## 15. Living next to the Omarchy plugin

The [Omarchy plugin](https://github.com/NeatOuk/citadel) and this app are separate products over **the same policies**.

- **Only one runs at a time:** while the plugin is active, the service pauses by itself: no monitoring, no firewall changes, no writes to your policies. The window says so.
- **Switching:** `omarchy plugin disable neat.citadel` hands over to the app within seconds. Enabling the plugin again makes the service step aside.

## 16. Privacy

- **No account and no telemetry:** nothing leaves your machine on its own.
- **Downloads only on request:** feeds and the country and network-owner databases download only when you turn them on.
- **Explain:** sends nothing until you press it, and only to the agent you use.
- **Proxy logins:** stay in your keyring. They never appear in Citadel's files.
- **Stored locally:** policies, history and settings are in `~/.local/share/citadel`.

## 17. Platforms

| Platform | Status |
|---|---|
| Linux: Arch / Omarchy, Debian 13 / Ubuntu, Fedora; any desktop | everything above |
| macOS 15+ (Apple Silicon) | watching, the gate, history, zones and Explain work from a checkout. Blocking, pausing new connections at the gate, feeds, launcher policies and proxy routing are built as a Network Extension and wait for signing ([macos/](macos/README.md)) |

## 18. Limits

- **The first packet may leave (Linux).** Citadel sees a new connection within one check, and a moment before it answers. Every later attempt follows your verdict. On macOS the Network Extension holds even the first packet.
- **Host names:**
  - Host names come from reverse DNS, name lookups for your policies, and what apps ask for.
  - CDNs may show their own names, and domain feeds only match names Citadel knows.
  - Citadel isn't a DNS ad blocker. Use it next to Pi-hole or AdGuard Home, not instead of them.
- **Shared processes:**
  - Web apps that run inside a browser share its process, so they can only be told apart by destination.
  - Blocking an interpreter (e.g. `python3`) blocks every program running on it.
- **Proxy routing** carries TCP only. A routed app's UDP (e.g. QUIC) is blocked, except DNS, so apps fall back to TCP.
- **macOS:** a Block applies to new connections. Connections already open end when they close.
