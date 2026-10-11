import QtQuick
import QtQuick.Controls as C
import qs.Commons
import qs.Commons as C   // Qt 6.12's QtQuick has its own Color type, which hides ours

C.TextField {
  id: root
  property color foreground: C.Color.foreground
  property bool password: false
  echoMode: password ? TextInput.Password : TextInput.Normal
  color: foreground
  font.family: Style.font.family
  font.pixelSize: Style.font.bodySmall
  selectByMouse: true
}
