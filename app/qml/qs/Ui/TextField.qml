import QtQuick
import QtQuick.Controls as C
import qs.Commons

C.TextField {
  id: root
  property color foreground: Color.foreground
  property bool password: false
  echoMode: password ? TextInput.Password : TextInput.Normal
  color: foreground
  font.family: Style.font.family
  font.pixelSize: Style.font.bodySmall
  selectByMouse: true
}
