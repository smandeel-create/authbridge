import SwiftUI
import UIKit
import UserNotifications

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Task { @MainActor in AppModel.shared.setupPush() }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in AppModel.shared.pushTokenChanged(hex) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // Push is best-effort; the app still polls /v1/pending.
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        await AppModel.shared.refreshPending()
        return [.banner, .sound, .list]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let id = response.notification.request.content.userInfo["request_id"] as? String else { return }
        await AppModel.shared.openRequest(id: id)
    }
}

@main
struct AuthBridgeApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel.shared
    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model)
        }
    }
}
