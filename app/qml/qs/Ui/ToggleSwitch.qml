import QtQuick
import qs.Commons
import qs.Commons as C   // Qt 6.12's QtQuick has its own Color type, which hides ours

// A switch; `toggled()` asks the owner to flip `checked`.
Item {
  id: root
  property bool checked: false
  property bool busy: false
  property bool interactive: true
  property color foreground: C.Color.foreground
  property color accent: C.Color.accent
  signal toggled()
  implicitWidth: Style.space(40)
  implicitHeight: Style.space(22)
  opacity: busy ? 0.6 : 1
  Rectangle {
    anchors.fill: parent
    radius: height / 2
    color: root.checked ? root.accent : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.18)
    Rectangle {
      width: parent.height - Style.space(6); height: width; radius: width / 2
      y: Style.space(3)
      x: root.checked ? parent.width - width - Style.space(3) : Style.space(3)
      color: root.checked ? C.Color.background : root.foreground
      Behavior on x { NumberAnimation { duration: 120 } }
    }
  }
  MouseArea {
    anchors.fill: parent
    enabled: root.interactive && !root.busy
    cursorShape: Qt.PointingHandCursor
    onClicked: root.toggled()
  }
}
