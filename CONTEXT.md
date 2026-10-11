# Citadel

Citadel watches which apps on this machine connect where, asks at the gate about new ones, and turns the user's answers into per-app policies that citadel-helper enforces.

## Language

**Tick**:
One sampling cycle of the monitor, every couple of seconds, that reports the live connections, apps and totals.
_Avoid_: poll, refresh

**Socket cgroup**:
The cgroup a socket was created in. It is fixed for the life of the socket, and it is what the firewall's per-app rules match.
_Avoid_: app cgroup, process cgroup (when the socket is meant)

**Process cgroup**:
The cgroup a process is in right now. It can change after start-up (launchers move apps into their own scope), so it can differ from the **Socket cgroup** of sockets the process opened earlier.

**Feature parity**:
An optimization keeps feature parity when every connection, owner, cgroup, byte count and decision Citadel reports is the same as before. Resource savings never justify dropping, delaying or approximating any of them.
_Avoid_: "close enough", "mostly the same"

## Relationships

- A **Tick** reports each connection with its **Socket cgroup**; the firewall matches rules against that same **Socket cgroup**, so the two must never disagree.
- A process may own sockets whose **Socket cgroup** is not its current **Process cgroup**.

## Example dialogue

> **Dev:** "Can the monitor just read the app's cgroup from /proc to save work?"
> **Domain expert:** "That's the **Process cgroup**. The firewall matches the **Socket cgroup**, so that would break **Feature parity** for any app that was moved after it opened a connection."

## Flagged ambiguities

- "cgroup" alone was used for both the **Socket cgroup** and the **Process cgroup**. Resolved: these are distinct, and connection reports always mean the **Socket cgroup**.
