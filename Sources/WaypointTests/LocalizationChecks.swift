import Foundation
import WaypointCore

enum LocalizationChecks {
    static func run(_ h: Harness) {
        h.suite("локализация")

        h.check("русский и английский ресурсы доступны") {
            try expectEqual(
                L10n.string("Настройки", language: .russian),
                "Настройки",
                "русская строка"
            )
            try expectEqual(
                L10n.string("Настройки", language: .english),
                "Settings",
                "английская строка"
            )
            try expectEqual(
                L10n.string("Режим VPN", language: .english),
                "VPN mode",
                "быстрые настройки VPN"
            )
        }

        h.check("форматируемые статусы переводятся с аргументами") {
            try expectEqual(
                L10n.format("%lld мс", 42, language: .english),
                "42 ms",
                "задержка"
            )
            try expectEqual(
                L10n.format("Через %@", "utun90", language: .english),
                "Via utun90",
                "интерфейс VPN"
            )
        }

        h.check("неизвестные пользовательские значения не изменяются") {
            try expectEqual(
                L10n.string("My custom tunnel", language: .english),
                "My custom tunnel",
                "имя пользователя"
            )
        }

        h.check("поддерживаемые языки имеют стабильные идентификаторы") {
            try expectEqual(AppLanguage.allCases.map(\.rawValue), ["system", "ru", "en"])
        }
    }
}
