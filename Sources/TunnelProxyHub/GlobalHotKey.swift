import Carbon.HIToolbox
import Foundation

/// Системный hotkey работает, даже когда окно закрыто, приложение скрыто или
/// фокус находится в другой программе. Carbon не требует Accessibility access.
@MainActor
final class GlobalHotKeyController {
    enum RegistrationError: LocalizedError {
        case handler(OSStatus)
        case hotKey(OSStatus)

        var errorDescription: String? {
            switch self {
            case .handler(let status):
                "Не удалось подготовить глобальный хоткей (код \(status))"
            case .hotKey(let status):
                "⌘⇧V уже занят другой программой (код \(status))"
            }
        }
    }

    private static let signature: OSType = 0x5450_4856 // TPHV
    private static let identifier: UInt32 = 1

    private var hotKey: EventHotKeyRef?
    private var eventHandler: EventHandlerRef?
    private var action: (@MainActor () -> Void)?
    private var lastActivation = Date.distantPast

    func registerVPNAction(_ action: @escaping @MainActor () -> Void) throws {
        self.action = action
        unregisterHotKey()

        if eventHandler == nil {
            var eventType = EventTypeSpec(
                eventClass: OSType(kEventClassKeyboard),
                eventKind: UInt32(kEventHotKeyPressed)
            )
            let status = InstallEventHandler(
                GetApplicationEventTarget(),
                { _, _, userData in
                    guard let userData else { return noErr }
                    let controller = Unmanaged<GlobalHotKeyController>
                        .fromOpaque(userData)
                        .takeUnretainedValue()
                    MainActor.assumeIsolated {
                        controller.handleActivation()
                    }
                    return noErr
                },
                1,
                &eventType,
                Unmanaged.passUnretained(self).toOpaque(),
                &eventHandler
            )
            guard status == noErr else { throw RegistrationError.handler(status) }
        }

        let identifier = EventHotKeyID(
            signature: Self.signature,
            id: Self.identifier
        )
        let status = RegisterEventHotKey(
            UInt32(kVK_ANSI_V),
            UInt32(cmdKey | shiftKey),
            identifier,
            GetApplicationEventTarget(),
            0,
            &hotKey
        )
        guard status == noErr else { throw RegistrationError.hotKey(status) }
    }

    func unregisterHotKey() {
        if let hotKey { UnregisterEventHotKey(hotKey) }
        hotKey = nil
    }

    func invalidate() {
        unregisterHotKey()
        if let eventHandler { RemoveEventHandler(eventHandler) }
        eventHandler = nil
        action = nil
    }

    private func handleActivation() {
        // Защита от key repeat: одно удержание клавиш не должно несколько раз
        // запустить и тут же остановить системный VPN.
        let now = Date()
        guard now.timeIntervalSince(lastActivation) >= 0.55 else { return }
        lastActivation = now
        action?()
    }
}
