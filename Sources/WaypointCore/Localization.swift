import Foundation

public enum AppLanguage: String, CaseIterable, Identifiable, Sendable {
    case system
    case russian = "ru"
    case english = "en"

    public static let storageKey = "appLanguage"

    public var id: String { rawValue }

    public var locale: Locale {
        switch self {
        case .system: .autoupdatingCurrent
        case .russian: Locale(identifier: "ru")
        case .english: Locale(identifier: "en")
        }
    }

    public var displayName: String {
        switch self {
        case .system: L10n.string("Автоматически")
        case .russian: L10n.string("Русский")
        case .english: "English"
        }
    }

    public static var selected: AppLanguage {
        let value = UserDefaults.standard.string(forKey: storageKey) ?? system.rawValue
        return AppLanguage(rawValue: value) ?? .system
    }

    fileprivate var effectiveIdentifier: String {
        switch self {
        case .russian: "ru"
        case .english: "en"
        case .system:
            Locale.preferredLanguages.first?.lowercased().hasPrefix("ru") == true ? "ru" : "en"
        }
    }
}

public enum L10n {
    public static func string(
        _ key: String,
        language: AppLanguage = .selected
    ) -> String {
        let identifier = language.effectiveIdentifier
        guard let bundle = localizedBundle(for: identifier) else { return key }
        return bundle.localizedString(forKey: key, value: key, table: nil)
    }

    public static func format(
        _ key: String,
        _ arguments: CVarArg...,
        language: AppLanguage = .selected
    ) -> String {
        String(
            format: string(key, language: language),
            locale: language.locale,
            arguments: arguments
        )
    }

    private static func localizedBundle(for identifier: String) -> Bundle? {
        if let path = Bundle.main.path(forResource: identifier, ofType: "lproj"),
           let bundle = Bundle(path: path) {
            return bundle
        }

        if let path = Bundle.module.path(forResource: identifier, ofType: "lproj") {
            return Bundle(path: path)
        }

        return nil
    }
}
