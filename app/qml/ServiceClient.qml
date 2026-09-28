import QtQuick

import "Model.js" as Model

// The daemon, as the views know it: the same properties and functions as the
// Omarchy plugin's Service.qml, fed from citadel-daemon's socket (`link`,
// a Python DaemonLink). Actions are sent to the daemon; the answers that the
// views need at once (a new rule's id, a validation error) are worked out
// here with the same Model.js the daemon's logic was ported from.
QtObject {
  id: root
  property var link: null
  signal openRequested(string view)

  // ------------------------------------------------- mirrored state
  property bool connected: link ? link.connected : false
  property var rules: []
  property var profiles: [{ name: "Default", networks: [] }]
  property string profileOverride: ""
  property string mode: "guarded"
  property real silentUntil: 0
  property bool enforce: false
  property var lists: []
  property var defaultLists: []
  property var decisionLog: []
  property var prefs: ({ interval: 2, alertTimeout: 90, alertDefault: "allow", retentionDays: 30, notify: true,
                         catchShort: true, explainCommand: "", explainModel: "", explainAgent: "" })
  property var conns: []
  property var apps: ({})
  property var network: ({ names: [], ssid: "" })
  property var decisions: ({})
  property var groups: []
  property var alerts: []
  property var session: ({})
  property var resolved: ({})
  property var stats: ({ series: [], topAppsToday: [], topHostsToday: [], countriesToday: [], topApps7d: [] })
  property var listStatus: ({})
  property int ipCidrCount: 0
  readonly property var ipCidrs: { var a = []; a.length = ipCidrCount; return a }
  property var geoip: ({ installed: false, error: "" })
  property var approx: ({})
  property var protectedPids: ({})
  property var recentShort: []
  property var kernelLog: ({ running: false, error: "", seen: 0 })
  property string helperVersion: ""
  property bool helperLogging: false
  property var learned: ({})
  property var rate: ({ up: 0, down: 0 })
  property var totals: ({ connections: 0, apps: 0, denied: 0 })
  property string monitorError: ""
  property bool monitorUp: false
  property int ticks: 0
  property real now: Date.now() / 1000
  property string activeProfile: "Default"
  property bool inWheel: true
  property string privilegedGroup: "wheel"
  property bool helperInstalled: false
  property bool enforceActive: false
  property bool enforceBusy: false
  property string enforceError: ""
  property real enforceAppliedAt: 0
  property int enforceDrops: 0
  property var proxies: []
  property string defaultRoute: "direct"
  property var proxyStatus: ({})
  property var proxyLog: []
  property var proxyCarried: []
  property var proxyCheck: ({})
  property string proxyError: ""
  property var explanations: ({})
  property var explainTestResult: ({})
  property string defaultAgent: ""
  property var installedAgents: []
  property int uid: -1
  property string daemonVersion: ""
  property bool helperUsable: false
  property bool helperOutdated: false
  property string helperProblem: ""
  property bool proxyCapable: false
  property string minHelper: "1.1.1"
  property string minProxyHelper: "1.3.0"

  // ------------------------------------------------- derived (as in Service.qml)
  readonly property bool silent: mode !== "guarded"
  readonly property bool helperSupportsShort: helperVersion !== "" && Number(helperVersion.split(".")[1]) >= 2
  readonly property string testedOmarchy: ""
  readonly property string omarchyVersion: ""
  readonly property bool omarchySupported: true
  readonly property bool explainCustom: String(prefs.explainCommand || "").trim() !== ""
  readonly property string autoAgent: defaultAgent || (installedAgents.length ? installedAgents[0] : "")
  readonly property string explainAgent: explainCustom ? "custom command" : (String(prefs.explainAgent || "").trim() || autoAgent)
  readonly property bool explainAvailable: explainAgent !== ""

  // ------------------------------------------------- the socket
  property int _nextId: 1
  property var _pending: ({})
  property Connections _conn: Connections {
    target: root.link
    function onMessage(text) { root._onMessage(text) }
  }
  Component.onCompleted: {}

  function _onMessage(text) {
    var m
    try { m = JSON.parse(text) } catch (e) { return }
    if (m.type === "state") {
      var d = m.data || {}
      for (var k in d) if (k in root) root[k] = d[k]
    } else if (m.type === "reply") {
      var cb = _pending[m.id]
      if (cb) { delete _pending[m.id]; cb(m) }
      if (!m.ok) console.warn("[citadel] daemon:", m.error)
    } else if (m.type === "open") {
      openRequested(m.view || "gate")
    }
  }
  function call(cmd, args, done) {
    if (!link) return
    var id = _nextId++
    if (done) _pending[id] = done
    link.send(JSON.stringify({ id: id, cmd: cmd, args: args || [] }))
  }

  // ------------------------------------------------- actions (sent to the daemon)
  function answer(key, action, scope, duration, source, viaScoped, route) {
    // leave the card at once; the daemon's state follows
    alerts = alerts.filter(function(a) { return a.key !== key })
    call("answer", [key, action, scope || "host", duration || "forever", source || "", viaScoped === true, route || null])
  }
  function addRule(rule) {
    var r = Model.makeRule(rule)
    rules = rules.filter(function(x) {
      return !(x.profile === r.profile && x.app === r.app && (x.via || "*") === r.via && x.host === r.host && x.port === r.port)
    }).concat([r])
    call("addRule", [r])
    return r
  }
  function updateRule(id, fields) { call("updateRule", [id, fields]) }
  function removeRule(id) { rules = rules.filter(function(r) { return r.id !== id }); call("removeRule", [id]) }
  function allowApp(exe, viaId) { return addRule({ app: exe, via: viaId || "*", action: "allow" }) }
  function denyApp(exe, viaId) { return addRule({ app: exe, via: viaId || "*", action: "deny" }) }
  function denyConn(conn) { return addRule({ app: conn.exe || "*", via: conn.viaId || "*", host: conn.host || conn.raddr, action: "deny" }) }
  function allowConn(conn) { return addRule({ app: conn.exe || "*", via: conn.viaId || "*", host: conn.host || conn.raddr, action: "allow" }) }
  function clearLog() { decisionLog = []; call("clearLog") }
  function exportRules() { return JSON.stringify({ version: 2, rules: rules }, null, 2) }
  function importRules(text) {
    var p
    try { p = JSON.parse(text) } catch (e) { return "not valid JSON" }
    var list = Array.isArray(p) ? p : (p.rules || [])
    if (!Array.isArray(list)) return "no rules found"
    call("importRules", [JSON.stringify(list)])
    return ""
  }
  function setMode(m, minutes) { mode = m; call("setMode", [m, minutes || 0]) }
  function setProfileOverride(name) { call("setProfileOverride", [name || ""]) }
  function addProfile(name) { call("addProfile", [name]) }
  function removeProfile(name) { call("removeProfile", [name]) }
  function toggleProfileNetwork(name, net) { call("toggleProfileNetwork", [name, net]) }
  function setPref(key, value) { var p = Object.assign({}, prefs); p[key] = value; prefs = p; call("setPref", [key, value]) }
  function setListEnabled(id, on) { call("setListEnabled", [id, !!on]) }
  function addList(name, url, kind) { call("addList", [name, url, kind]) }
  function removeList(id) { call("removeList", [id]) }
  function refreshLists() { call("refreshLists") }
  function downloadGeoip() { geoip = Object.assign({}, geoip, { downloading: true }); call("downloadGeoip") }
  function requestStats() { call("requestStats") }
  function setEnforce(on) { call("setEnforce", [!!on]) }
  function refreshEnforceStatus() { call("refreshEnforceStatus") }
  function verifyHelper() { call("verifyHelper") }
  function checkProxy(id) { var ck = Object.assign({}, proxyCheck); ck[id] = { pending: true }; proxyCheck = ck; call("checkProxy", [id]) }
  function setDefaultRoute(route) { call("setDefaultRoute", [route]) }
  function removeProxy(id) { call("removeProxy", [id]) }
  // fields: {id?, name, type, host, port, verifyTls}; "" user keeps the stored login, null removes it
  function saveProxy(fields, user, password) {
    var port = Math.round(Number(fields.port))
    var host = String(fields.host || "").trim()
    if (!host || !(port >= 1 && port <= 65535)) return "Enter a host and a port (1–65535)."
    call("saveProxy", [fields, user === undefined ? "" : user, password || ""])
    return ""
  }
  function explain(conn, fresh) {
    if (!conn || !explainAvailable) return
    var e = Object.assign({}, explanations); e[explainKey(conn)] = { state: "pending", agent: explainAgent }; explanations = e
    call("explain", [conn, !!fresh])
  }
  function testExplain() { explainTestResult = { state: "pending", agent: explainAgent }; call("testExplain") }
  function killGroup(group, force) { var n = killablePids(group).length; call("killGroup", [group, !!force]); return n }

  // ------------------------------------------------- answered here (pure)
  function _ctx() {
    var alive = {}
    for (var exe in apps) (apps[exe].pids || []).forEach(function(p) { alive[p] = true })
    return { profile: activeProfile, mode: mode, resolved: resolved, alivePids: alive, session: session,
             learned: Model.learnedIps(learned), learnedCg: Model.learnedCgroups(learned) }
  }
  function routeOf(conn) { return Model.routeFor(conn, rules, _ctx(), defaultRoute, proxies) }
  function proxyName(route) {
    if (!route || route === "direct") return ""
    var px = proxies.filter(function(x) { return x.id === route })[0]
    return px ? px.name : "missing proxy"
  }
  function proxyCarried5m(id) {
    var n = 0
    proxyCarried.forEach(function(x) { if (x.ts > now - 300) n += Number(x.counts[id] || 0) })
    return n
  }
  function explainKey(conn) { return (conn.exe || conn.app || "?") + "|" + (conn.host || conn.raddr || "") + "|" + (conn.rport || "") }
  function explanationOf(conn) { return conn ? explanations[explainKey(conn)] || null : null }

  readonly property var protectedNames: ["quickshell", "qs", "Hyprland", "hyprland", "systemd", "uwsm", "dbus-broker",
    "dbus-broker-launch", "dbus-daemon", "pipewire", "pipewire-pulse", "wireplumber", "Xwayland", "Xorg",
    "xdg-desktop-portal", "gnome-shell", "plasmashell", "kwin_wayland", "kwin_x11", "sway", "niri", "labwc",
    "gnome-keyring-daemon", "citadel-daemon", "citadel-app"]
  function _isProtectedCmd(cmd) {
    var first = String(cmd || "").split(" ").slice(0, 3).join(" ")
    return protectedNames.some(function(n) { return new RegExp("(^|[/\\s])" + n + "(\\s|$)").test(first) })
  }
  function killablePids(group) {
    if (!group || group.system || !group.exe) return []
    var name = group.exe.split("/").pop()
    if (protectedNames.indexOf(name) !== -1) return []
    var interpreter = /^(python|node|perl|ruby|bash|sh|dash|zsh|fish|lua|luajit|deno|bun|php)[0-9.]*$/.test(name)
    var pids = []
    if (group.viaId || interpreter)
      group.conns.forEach(function(c) { if (c.pid && !_isProtectedCmd(c.cmd)) pids.push(c.pid) })
    else pids = ((apps[group.exe] || {}).pids || []).slice()
    var seen = {}
    return pids.filter(function(p) {
      if (!p || seen[p] || protectedPids[p]) return false
      seen[p] = true
      return true
    })
  }
  function stillRunning(pids) {
    var alive = {}
    for (var exe in apps) (apps[exe].pids || []).forEach(function(p) { alive[p] = true })
    return (pids || []).filter(function(p) { return alive[p] }).length
  }
}
