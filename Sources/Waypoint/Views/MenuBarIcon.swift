import AppKit
import SwiftUI
import WaypointCore

/// Значок строки меню должен быть настоящим template-изображением.
///
/// `MenuBarExtra` размещает label в отдельной AppKit-сцене. `Canvas` внутри
/// этого label на части версий macOS получает место, но не растеризуется —
/// поэтому кликабельная область есть, а сам значок остаётся пустым.
struct MenuBarIcon: View {
    let active: Bool

    var body: some View {
        Image(nsImage: MenuBarIconImage.make(active: active))
            .accessibilityLabel(L10n.string(active ? "Туннель работает" : "Туннель остановлен"))
    }
}

@MainActor
private enum MenuBarIconImage {
    private static let size = NSSize(width: 18, height: 18)

    static func make(active: Bool) -> NSImage {
        let image = NSImage(size: size, flipped: false) { _ in
            let cx: CGFloat = 10.5
            let cy: CGFloat = 9
            let radius: CGFloat = 3.45
            let hubLeft = cx - radius * 0.9

            NSColor.black.setStroke()
            NSColor.black.setFill()

            let incoming = NSBezierPath()
            incoming.lineWidth = 1.5
            incoming.lineCapStyle = .round
            incoming.lineJoinStyle = .round

            for dy in [-5.0, 0.0, 5.0] as [CGFloat] {
                let y = cy + dy
                incoming.move(to: NSPoint(x: 1, y: y))

                if dy == 0 {
                    incoming.line(to: NSPoint(x: hubLeft, y: y))
                } else {
                    let midX = (1 + hubLeft) / 2
                    incoming.line(to: NSPoint(x: midX - 0.5, y: y))
                    incoming.curve(
                        to: NSPoint(x: hubLeft, y: cy + dy * 0.2),
                        controlPoint1: NSPoint(x: midX + 1.2, y: y),
                        controlPoint2: NSPoint(x: hubLeft - 1, y: cy + dy * 0.5)
                    )
                }
            }
            incoming.stroke()

            let outgoing = NSBezierPath()
            outgoing.lineWidth = 1.5
            outgoing.lineCapStyle = .round
            outgoing.move(to: NSPoint(x: cx + radius * 0.9, y: cy))
            outgoing.line(to: NSPoint(x: 17, y: cy))
            outgoing.stroke()

            let hub = NSBezierPath()
            hub.lineWidth = 1.5
            hub.lineJoinStyle = .round
            for index in 0..<6 {
                let angle = CGFloat(index) * .pi / 3 - .pi / 6
                let point = NSPoint(
                    x: cx + radius * cos(angle),
                    y: cy + radius * sin(angle)
                )
                index == 0 ? hub.move(to: point) : hub.line(to: point)
            }
            hub.close()

            active ? hub.fill() : hub.stroke()
            return true
        }

        // AppKit красит template-маску под тему и состояние pressed/highlighted.
        image.isTemplate = true
        return image
    }
}
