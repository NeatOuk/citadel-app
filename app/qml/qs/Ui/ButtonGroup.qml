import QtQuick
import qs.Commons
import qs.Commons as C   // Qt 6.12's QtQuick has its own Color type, which hides ours

// Segmented choice: options [{value, label}], emits changed(value).
Row {
  id: root
  property var options: []
  property string value: ""
  property color foreground: C.Color.foreground
  property color accent: C.Color.accent
  property string fontFamily: Style.font.family
  property real fontSize: Style.font.body
  signal changed(string value)
  spacing: Style.space(4)
  Repeater {
    model: root.options
    delegate: Button {
      required property var modelData
      text: modelData.label
      selected: root.value === modelData.value
      bordered: true
      foreground: root.foreground
      fontFamily: root.fontFamily
      fontSize: root.fontSize
      onClicked: root.changed(modelData.value)
    }
  }
}
