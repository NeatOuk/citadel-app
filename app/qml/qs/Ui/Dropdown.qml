import QtQuick
import QtQuick.Controls as C
import qs.Commons

// Labelled combo box over [{value, label}]; emits changed(value).
Column {
  id: root
  property string label: ""
  property string value: ""
  property var options: []
  property color foreground: Color.foreground
  property string fontFamily: Style.font.family
  property bool showLabel: true
  signal changed(string value)
  spacing: Style.space(3)
  function indexOf(v) {
    for (var i = 0; i < options.length; i++) if (options[i].value === v) return i
    return -1
  }
  Text {
    visible: root.showLabel && root.label !== ""
    text: root.label
    color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.72)
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    font.bold: true
  }
  C.ComboBox {
    id: box
    width: root.width
    model: root.options
    textRole: "label"
    valueRole: "value"
    currentIndex: root.indexOf(root.value)
    font.family: root.fontFamily
    font.pixelSize: Style.font.bodySmall
    onActivated: function(i) {
      var v = root.options[i] ? root.options[i].value : ""
      root.value = v
      root.changed(v)
    }
  }
}
