import QtQuick
import qs.Commons

Text {
  property color foreground: Color.foreground
  property string fontFamily: Style.font.family
  property real fontSize: Style.font.caption
  color: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.7)
  font.family: fontFamily
  font.pixelSize: fontSize
  font.bold: true
  font.letterSpacing: 1.2
  topPadding: Style.space(4)
}
