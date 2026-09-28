// Citadel's system extension: runs the network filter (and, later, the
// transparent proxy) that the host app activated.
import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
