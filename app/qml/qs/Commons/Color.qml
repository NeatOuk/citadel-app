pragma Singleton
import QtQuick

// Colors from the desktop's palette (light or dark), in the roles Citadel's
// views know from Omarchy: foreground, background, accent, urgent.
QtObject {
  id: root
  readonly property SystemPalette pal: SystemPalette { colorGroup: SystemPalette.Active }
  readonly property bool dark: pal.window.hslLightness < 0.5
  readonly property color foreground: pal.windowText
  readonly property color background: pal.window
  readonly property color base: pal.base
  readonly property color accent: pal.highlight
  readonly property color urgent: dark ? "#e06c6c" : "#c0392b"
  readonly property color muted: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.6)
  readonly property QtObject popups: QtObject {
    readonly property color background: root.base
    readonly property color text: root.foreground
    readonly property color border: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.25)
  }
}
