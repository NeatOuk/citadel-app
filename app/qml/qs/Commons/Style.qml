pragma Singleton
import QtQuick

// The subset of Omarchy's qs.Commons.Style that Citadel's views use, sized
// for a desktop window. Space and font sizes scale with `scale`.
QtObject {
  id: root
  property real scale: 1.0
  property int cornerRadius: 6
  function space(px) { return Math.round(px * scale) }
  function spaceReal(px) { return px * scale }
  readonly property QtObject font: QtObject {
    readonly property string family: Qt.application.font.family
    readonly property int caption: Math.round(11 * root.scale)
    readonly property int bodySmall: Math.round(12 * root.scale)
    readonly property int body: Math.round(13 * root.scale)
    readonly property int subtitle: Math.round(14 * root.scale)
    readonly property int title: Math.round(17 * root.scale)
    readonly property int icon: Math.round(18 * root.scale)
    readonly property int iconSmall: Math.round(14 * root.scale)
  }
}
