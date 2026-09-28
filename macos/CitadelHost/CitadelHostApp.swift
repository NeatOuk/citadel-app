// Citadel's macOS host app: installs and enables the network filter system
// extension. Phase 2 skeleton; later it also bridges the extension to
// citadel-daemon (policies in, gate questions out) and posts notifications
// with Allow / Block buttons.
import NetworkExtension
import SwiftUI
import SystemExtensions

@main
struct CitadelHostApp: App {
    @StateObject private var ext = ExtensionController()

    var body: some Scene {
        WindowGroup("Citadel") {
            VStack(alignment: .leading, spacing: 12) {
                Text("Citadel network filter").font(.title2).bold()
                Text(ext.status).foregroundStyle(.secondary)
                HStack {
                    Button("Install and enable") { ext.activate() }
                    Button("Disable") { ext.setFilter(enabled: false) }
                }
            }
            .padding(24)
            .frame(minWidth: 420)
        }
    }
}

final class ExtensionController: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    static let extensionID = "io.github.neatouk.Citadel.Filter"
    @Published var status = "Not installed"

    func activate() {
        status = "Asking macOS to install the extension…"
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.extensionID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func setFilter(enabled: Bool) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error { self.report("Could not load the filter settings: \(error.localizedDescription)"); return }
            if manager.providerConfiguration == nil {
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true
                config.filterPackets = false
                manager.providerConfiguration = config
            }
            manager.localizedDescription = "Citadel"
            manager.isEnabled = enabled
            manager.saveToPreferences { error in
                self.report(error.map { "Could not save the filter: \($0.localizedDescription)" }
                            ?? (enabled ? "Filter enabled" : "Filter disabled"))
            }
        }
    }

    private func report(_ text: String) { DispatchQueue.main.async { self.status = text } }

    // MARK: OSSystemExtensionRequestDelegate
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        report("Approve Citadel in System Settings → General → Login Items & Extensions → Network Extensions")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        report("Extension installed")
        setFilter(enabled: true)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        report("Install failed: \(error.localizedDescription)")
    }
}
