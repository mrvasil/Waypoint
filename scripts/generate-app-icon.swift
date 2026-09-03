#!/usr/bin/env swift

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 2 else {
    fputs("usage: generate-app-icon.swift OUTPUT.png\n", stderr)
    exit(2)
}

let canvas: CGFloat = 1024
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!

guard let context = CGContext(
    data: nil,
    width: Int(canvas),
    height: Int(canvas),
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fputs("cannot create bitmap context\n", stderr)
    exit(1)
}

context.setAllowsAntialiasing(true)
context.setShouldAntialias(true)

func color(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: colorSpace, components: [red, green, blue, alpha])!
}

func signedPower(_ value: CGFloat, _ exponent: CGFloat) -> CGFloat {
    value < 0 ? -pow(-value, exponent) : pow(value, exponent)
}

/// Стандартный macOS keyline: 824 × 824 с непрерывной кривизной.
func appIconPath() -> CGPath {
    let path = CGMutablePath()
    let center = CGPoint(x: canvas / 2, y: canvas / 2)
    let radius: CGFloat = 412
    let exponent: CGFloat = 2 / 4.8
    let segments = 720

    for index in 0...segments {
        let angle = CGFloat(index) / CGFloat(segments) * 2 * .pi
        let point = CGPoint(
            x: center.x + radius * signedPower(cos(angle), exponent),
            y: center.y + radius * signedPower(sin(angle), exponent)
        )
        index == 0 ? path.move(to: point) : path.addLine(to: point)
    }
    path.closeSubpath()
    return path
}

let icon = appIconPath()

// Спокойная системная тень отделяет иконку от светлого и тёмного Dock.
context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: color(0, 0, 0, 0.38))
context.addPath(icon)
context.setFillColor(color(0.025, 0.03, 0.038))
context.fillPath()
context.restoreGState()

context.saveGState()
context.addPath(icon)
context.clip()

// Нейтральный графитовый фон остаётся спокойным в любой теме Dock.
let background = CGGradient(
    colorsSpace: colorSpace,
    colors: [
        color(0.27, 0.29, 0.32),
        color(0.12, 0.13, 0.15),
        color(0.045, 0.05, 0.06),
    ] as CFArray,
    locations: [0, 0.52, 1]
)!
context.drawLinearGradient(
    background,
    start: CGPoint(x: 300, y: 900),
    end: CGPoint(x: 720, y: 120),
    options: [.drawsBeforeStartLocation, .drawsAfterEndLocation]
)

// Едва заметный свет сверху создаёт глубину, сохраняя чистый силуэт.
let highlight = CGGradient(
    colorsSpace: colorSpace,
    colors: [color(0.78, 0.84, 0.90, 0.14), color(0.78, 0.84, 0.90, 0)] as CFArray,
    locations: [0, 1]
)!
context.drawRadialGradient(
    highlight,
    startCenter: CGPoint(x: 350, y: 790),
    startRadius: 0,
    endCenter: CGPoint(x: 350, y: 790),
    endRadius: 520,
    options: []
)

context.setLineCap(.round)
context.setLineJoin(.round)

// Единый знак: портал-туннель и маршрут, проходящий через него.
let portal = CGMutablePath()
portal.move(to: CGPoint(x: 340, y: 330))
portal.addLine(to: CGPoint(x: 340, y: 530))
portal.addCurve(
    to: CGPoint(x: 512, y: 720),
    control1: CGPoint(x: 340, y: 665),
    control2: CGPoint(x: 417, y: 720)
)
portal.addCurve(
    to: CGPoint(x: 684, y: 530),
    control1: CGPoint(x: 607, y: 720),
    control2: CGPoint(x: 684, y: 665)
)
portal.addLine(to: CGPoint(x: 684, y: 330))

context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -8), blur: 18, color: color(0.02, 0.12, 0.42, 0.28))
context.addPath(portal)
context.setStrokeColor(color(0.97, 0.99, 1.0, 0.97))
context.setLineWidth(62)
context.strokePath()
context.restoreGState()

// Короткая стрелка читается даже в размере 16 px и обозначает трафик.
let route = CGMutablePath()
route.move(to: CGPoint(x: 512, y: 318))
route.addLine(to: CGPoint(x: 512, y: 570))
route.move(to: CGPoint(x: 428, y: 492))
route.addLine(to: CGPoint(x: 512, y: 584))
route.addLine(to: CGPoint(x: 596, y: 492))

context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -6), blur: 14, color: color(0.02, 0.12, 0.42, 0.24))
context.addPath(route)
context.setStrokeColor(color(0.97, 0.99, 1.0, 0.97))
context.setLineWidth(48)
context.strokePath()
context.restoreGState()

// Тонкая верхняя грань поддерживает системную материальность macOS.
context.addPath(icon)
context.setStrokeColor(color(1, 1, 1, 0.22))
context.setLineWidth(3)
context.strokePath()

context.restoreGState()

guard let image = context.makeImage() else {
    fputs("cannot render icon\n", stderr)
    exit(1)
}

let outputURL = URL(fileURLWithPath: CommandLine.arguments[1])
guard let destination = CGImageDestinationCreateWithURL(
    outputURL as CFURL,
    UTType.png.identifier as CFString,
    1,
    nil
) else {
    fputs("cannot create \(outputURL.path)\n", stderr)
    exit(1)
}

CGImageDestinationAddImage(destination, image, nil)
guard CGImageDestinationFinalize(destination) else {
    fputs("cannot write \(outputURL.path)\n", stderr)
    exit(1)
}
