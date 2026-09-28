import QtQuick
import qs.Commons

// A rectangle whose border comes from a Border spec {color, width}.
Rectangle {
  property var borderSpec: null
  border.color: borderSpec ? borderSpec.color : "transparent"
  border.width: borderSpec ? borderSpec.width : 0
}
