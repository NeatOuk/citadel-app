import QtQuick
import QtQuick.Layouts
import qs.Commons

// A labelled setting row with a description and a switch; emits clicked().
Item {
  id: root
  property string label: ""
  property string description: ""
  property bool checked: false
  property color foreground: Color.foreground
  property color accent: Color.accent
  property string fontFamily: Style.font.family
  signal clicked()
  implicitHeight: row.implicitHeight + Style.space(6)
  RowLayout {
    id: row
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    spacing: Style.space(10)
    Column {
      Layout.fillWidth: true
      spacing: Style.space(1)
      Text { width: parent.width; text: root.label; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.body; elide: Text.ElideRight }
      Text {
        width: parent.width
        visible: root.description !== ""
        text: root.description
        color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.65)
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
      }
    }
    ToggleSwitch { checked: root.checked; foreground: root.foreground; accent: root.accent; onToggled: root.clicked() }
  }
}
