import QtQuick
import QtQuick.Controls as C
import qs.Commons

// Omarchy-style flat button: text, optional border, "selected" fill, tooltip.
Item {
  id: root
  property string text: ""
  property string tooltipText: ""
  property bool selected: false
  property bool bordered: false
  property color foreground: Color.foreground
  property color accent: Color.accent
  property string fontFamily: Style.font.family
  property real fontSize: Style.font.body
  property real horizontalPadding: Style.space(10)
  property real verticalPadding: Style.space(5)
  signal clicked()
  signal rightClicked()

  implicitWidth: label.implicitWidth + horizontalPadding * 2
  implicitHeight: label.implicitHeight + verticalPadding * 2
  opacity: enabled ? 1 : 0.45

  Rectangle {
    anchors.fill: parent
    radius: Style.cornerRadius
    color: root.selected ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.16)
         : area.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent"
    border.width: root.bordered ? 1 : 0
    border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, root.selected ? 0.5 : 0.28)
  }
  Text {
    id: label
    anchors.centerIn: parent
    text: root.text
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: root.fontSize
    font.bold: root.selected
  }
  MouseArea {
    id: area
    anchors.fill: parent
    hoverEnabled: true
    enabled: root.enabled
    acceptedButtons: Qt.LeftButton | Qt.RightButton
    cursorShape: Qt.PointingHandCursor
    onClicked: function(e) { if (e.button === Qt.RightButton) root.rightClicked(); else root.clicked() }
  }
  C.ToolTip.visible: area.containsMouse && root.tooltipText !== ""
  C.ToolTip.text: root.tooltipText
  C.ToolTip.delay: 500
}
