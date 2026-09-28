// Gate requests as macOS notifications with buttons. citadel-daemon asks the
// host to post one ("notify"); a button sends the answer back to the daemon,
// which answers the gate request like the window would.
import Foundation
import UserNotifications

final class GateNotifications: NSObject, UNUserNotificationCenterDelegate {
    static let shared = GateNotifications()
    static let category = "citadel.gate"
    private let center = UNUserNotificationCenter.current()

    func start() {
        center.delegate = self
        let actions = [
            UNNotificationAction(identifier: "once", title: "Allow once"),
            UNNotificationAction(identifier: "always", title: "Always allow"),
            UNNotificationAction(identifier: "block", title: "Block", options: [.destructive]),
        ]
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.category, actions: actions,
                                                                 intentIdentifiers: [])])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Post (or replace) the notification for a gate request.
    func post(key: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.categoryIdentifier = Self.category
        content.userInfo = ["key": key]
        center.add(UNNotificationRequest(identifier: key, content: content, trigger: nil))
    }

    /// The request was answered elsewhere (window, policy, timeout).
    func remove(key: String) {
        center.removeDeliveredNotifications(withIdentifiers: [key])
        center.removePendingNotificationRequests(withIdentifiers: [key])
    }

    // MARK: UNUserNotificationCenterDelegate
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        let key = response.notification.request.content.userInfo["key"] as? String ?? ""
        let choice: String
        switch response.actionIdentifier {
        case "once", "always", "block": choice = response.actionIdentifier
        default: choice = "open"                       // clicked the notification itself
        }
        HostBridge.shared.sendEvent(["type": "answer", "key": key, "choice": choice])
        done()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .sound])                          // show it even while Citadel is in front
    }
}
