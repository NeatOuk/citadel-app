import QtQuick
import qs.Commons
import qs.Commons as C   // Qt 6.12's QtQuick has its own Color type, which hides ours

Rectangle {
  property color foreground: C.Color.foreground
  property real strength: 0.12
  width: parent ? parent.width : 100
  height: 1
  color: Qt.rgba(foreground.r, foreground.g, foreground.b, strength)
}
