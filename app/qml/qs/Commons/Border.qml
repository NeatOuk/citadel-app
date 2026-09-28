pragma Singleton
import QtQuick

// Border specs for BorderSurface: {color, width}
QtObject {
  function flat(color, width) { return { color: color, width: width === undefined ? 1 : width } }
  function controlSpec(state, foreground, accent) {
    var c = state === "focus" ? accent : Qt.rgba(foreground.r, foreground.g, foreground.b, state === "hover-cursor" ? 0.5 : 0.28)
    return { color: c, width: 1 }
  }
}
