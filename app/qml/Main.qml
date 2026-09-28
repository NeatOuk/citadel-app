import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Ui

import "Model.js" as Model
import "views"

// Citadel's window: the same tabs as the Omarchy panel (Gate, Traffic,
// Policies, History, Settings), talking to citadel-daemon. It also serves as
// the `p` object the views expect (colors, fonts, view switching, clipboard).
ApplicationWindow {
  id: root
  title: citadel.alerts.length > 0 ? "Citadel · " + citadel.alerts.length + " at the gate" : "Citadel"
  width: 620
  height: 820
  minimumWidth: 460
  minimumHeight: 480
  color: Color.background

  // ---- what the views read from `p`
  readonly property color foreground: Color.foreground
  readonly property color urgent: Color.urgent
  readonly property color dim: Qt.rgba(Color.foreground.r, Color.foreground.g, Color.foreground.b, 0.6)
  readonly property string fontFamily: Style.font.family
  property string view: "traffic"
  function open() { root.show(); root.raise(); root.requestActivate() }
  function scrollToTop() { flick.contentY = 0 }
  function openPolicy(id) {
    var r = citadel.rules.filter(function(x) { return x.id === id })[0]
    if (!r) return false
    root.view = "policies"; root.open()
    Qt.callLater(function() { policiesView.edit(r) })
    return true
  }
  function copyText(text) { clipboard.copy(text) }
  function pasteText() { return clipboard.paste() }

  readonly property int waiting: citadel.alerts.length
  readonly property bool enforcing: citadel.enforce && citadel.enforceActive
  readonly property var modes: [
    { value: "guarded", label: "Guarded" }, { value: "open", label: "Open" }, { value: "lockdown", label: "Lockdown" }
  ]
  function modeLabel(m) {
    for (var i = 0; i < modes.length; i++) if (modes[i].value === m) return modes[i].label
    return m
  }
  onWaitingChanged: if (waiting > 0 && !root.active && view !== "gate") view = "gate"

  ServiceClient {
    id: citadel
    link: daemonLink
    onOpenRequested: function(v) { root.view = v; root.open() }
  }
  Connections {
    target: appControl
    function onShowRequested(v) { if (v) root.view = v; root.open() }
  }
  // the tray follows the state
  Binding { target: appControl; property: "trayState"; value: citadel.mode + (root.enforcing ? "" : ":watching") }
  Binding { target: appControl; property: "trayWaiting"; value: root.waiting }
  Connections {
    target: appControl
    function onModeRequested(m, minutes) { citadel.setMode(m, minutes) }
  }

  Flickable {
    id: flick
    anchors.fill: parent
    anchors.margins: Style.space(16)
    contentWidth: width
    contentHeight: column.implicitHeight
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

    Column {
      id: column
      width: flick.width - Style.space(10)
      spacing: Style.space(12)

      // ------------------------------------------------ header
      RowLayout {
        width: parent.width
        spacing: Style.space(12)
        CitadelIcon {
          iconSize: Style.space(34)
          color: root.enforcing ? root.foreground : root.dim
          badgeColor: root.urgent
          mode: citadel.mode
          pendingCount: root.waiting
        }
        Column {
          Layout.fillWidth: true
          spacing: Style.space(3)
          Lbl { p: root; text: "CITADEL"; strong: true; font.pixelSize: Style.font.title; font.letterSpacing: 4 }
          Lbl {
            p: root
            width: parent.width
            dim: true
            font.pixelSize: Style.font.caption
            text: !citadel.connected ? "Not connected to citadel-daemon"
                  : citadel.pluginActive ? "Paused: the Omarchy plugin is running Citadel"
                  : root.modeLabel(citadel.mode)
                    + (citadel.silentUntil > 0 ? " until " + Model.clock(citadel.silentUntil) : "")
                    + "  ·  " + citadel.activeProfile + " zone"
                    + "  ·  " + (root.enforcing ? "enforcing" : "watching only")
          }
        }
      }

      // ------------------------------------------------ daemon missing
      Rectangle {
        visible: !citadel.connected
        width: parent.width
        height: offline.implicitHeight + Style.space(20)
        radius: Style.cornerRadius
        color: Qt.rgba(root.urgent.r, root.urgent.g, root.urgent.b, 0.12)
        Column {
          id: offline
          anchors.left: parent.left; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter
          anchors.margins: Style.space(12)
          spacing: Style.space(4)
          Lbl { p: root; text: "citadel-daemon is not running"; strong: true; font.pixelSize: Style.font.body }
          Lbl {
            p: root
            width: parent.width
            wrapMode: Text.WordWrap
            maximumLineCount: 4
            dim: true
            text: "Citadel's service watches and enforces even while this window is closed. Start it with\n"
                  + "systemctl --user enable --now citadel\nThis window reconnects on its own."
          }
        }
      }

      // ------------------------------------------------ paused beside the plugin
      Rectangle {
        visible: citadel.connected && citadel.pluginActive
        width: parent.width
        height: paused.implicitHeight + Style.space(20)
        radius: Style.cornerRadius
        color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.14)
        Column {
          id: paused
          anchors.left: parent.left; anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter
          anchors.margins: Style.space(12)
          spacing: Style.space(4)
          Lbl { p: root; text: "Citadel is running as the Omarchy plugin"; strong: true; font.pixelSize: Style.font.body }
          Lbl {
            p: root
            width: parent.width
            wrapMode: Text.WordWrap
            maximumLineCount: 5
            dim: true
            text: "Use the tower in your Omarchy bar. This service is paused so the two never fight over the firewall "
                  + "or your policies. To use this app instead, remove Citadel from the bar (omarchy plugin disable neat.citadel); "
                  + "it takes over within a few seconds, with the same policies."
          }
        }
      }

      Column {
        visible: citadel.connected && !citadel.pluginActive
        width: parent.width
        spacing: Style.space(12)
        ButtonGroup {
          options: root.modes
          value: citadel.mode
          foreground: root.foreground
          fontFamily: root.fontFamily
          fontSize: Style.font.bodySmall
          onChanged: function(v) { citadel.setMode(v, v === "guarded" ? 0 : Number(citadel.prefs.modeMinutes) || 0) }
        }
        PanelSeparator { foreground: root.foreground }
        ButtonGroup {
          options: [{ value: "gate", label: root.waiting > 0 ? "Gate · " + root.waiting : "Gate" },
                    { value: "traffic", label: "Traffic" }, { value: "policies", label: "Policies" },
                    { value: "history", label: "History" }, { value: "settings", label: "Settings" }]
          value: root.view
          foreground: root.foreground
          fontFamily: root.fontFamily
          fontSize: Style.font.body
          onChanged: function(v) { root.view = v; flick.contentY = 0; if (v === "history") citadel.requestStats() }
        }

        // ------------------------------------------------ gate
        Column {
          visible: root.view === "gate"
          width: parent.width
          spacing: Style.space(14)
          Column {
            visible: root.waiting === 0
            width: parent.width
            spacing: Style.space(4)
            Lbl { p: root; text: "The gate is quiet."; strong: true; font.pixelSize: Style.font.body }
            Lbl {
              p: root
              width: parent.width
              dim: true
              wrapMode: Text.WordWrap
              maximumLineCount: 3
              text: citadel.mode === "guarded" ? "New connections without a policy wait here for your verdict (and as a notification)."
                  : citadel.mode === "open" ? "Open mode: new connections pass quietly and are logged in History."
                  : "Lockdown: anything without an allow policy is blocked."
            }
          }
          Repeater {
            model: root.view === "gate" ? citadel.alerts : []
            delegate: Column {
              required property var modelData
              required property int index
              width: column.width
              spacing: Style.space(10)
              PanelSeparator { visible: index > 0; foreground: root.foreground }
              VerdictCard { width: parent.width; p: root; s: citadel; alert: modelData }
            }
          }
        }
        TrafficView { id: trafficView; visible: root.view === "traffic"; width: parent.width; p: root; s: citadel }
        PoliciesView { id: policiesView; visible: root.view === "policies"; width: parent.width; p: root; s: citadel }
        HistoryView { visible: root.view === "history"; width: parent.width; p: root; s: citadel }
        SettingsView { visible: root.view === "settings"; width: parent.width; p: root; s: citadel }
      }
    }
  }
}
