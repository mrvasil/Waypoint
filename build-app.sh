#!/bin/bash
# Сборка .app-бандла.
#
# SwiftUI-приложению нужен бандл с Info.plist: голый бинарник из swift build
# запускается как фоновый процесс без окна и без иконки в Dock.
set -euo pipefail

CONFIG="${1:-release}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/build/Waypoint.app"

cd "$ROOT"
echo "▶ Сборка ($CONFIG)…"
swift build -c "$CONFIG" --product Waypoint
swift build -c "$CONFIG" --product WaypointVPNHelper
swift build -c "$CONFIG" --product WaypointVPNLauncher

BIN_DIR="$(swift build -c "$CONFIG" --show-bin-path)"
BIN="$BIN_DIR/Waypoint"
VPN_HELPER="$BIN_DIR/WaypointVPNHelper"
VPN_LAUNCHER="$BIN_DIR/WaypointVPNLauncher"
[ -f "$BIN" ] || { echo "не найден бинарник: $BIN" >&2; exit 1; }
[ -f "$VPN_HELPER" ] || { echo "не найден VPN helper: $VPN_HELPER" >&2; exit 1; }
[ -f "$VPN_LAUNCHER" ] || { echo "не найден VPN launcher: $VPN_LAUNCHER" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Helpers"
cp "$BIN" "$APP/Contents/MacOS/Waypoint"
cp "$VPN_HELPER" "$APP/Contents/Helpers/WaypointVPNHelper"
cp "$VPN_LAUNCHER" "$APP/Contents/Helpers/WaypointVPNLauncher"

# Иконка приложения
if [ -f "$ROOT/Resources/AppIcon.icns" ]; then
    cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
fi

# Локализации лежат в основном bundle, чтобы SwiftUI мог менять язык без
# перезапуска и без зависимости от пути сборки SwiftPM.
for localization in "$ROOT"/Sources/WaypointCore/Resources/*.lproj; do
    [ -d "$localization" ] || continue
    cp -R "$localization" "$APP/Contents/Resources/"
done

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>Waypoint</string>
    <key>CFBundleDisplayName</key>     <string>Waypoint</string>
    <key>CFBundleIdentifier</key>      <string>ru.mrvasil.waypoint</string>
    <key>CFBundleVersion</key>         <string>1.0</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleExecutable</key>      <string>Waypoint</string>
    <key>CFBundleIconFile</key>        <string>AppIcon</string>
    <key>CFBundleDevelopmentRegion</key><string>ru</string>
    <key>CFBundleLocalizations</key>
    <array>
        <string>ru</string>
        <string>en</string>
    </array>
    <key>LSMinimumSystemVersion</key>  <string>15.0</string>
    <key>NSHighResolutionCapable</key> <true/>
    <!-- Приложение живёт в Dock: менюбар — дополнение, а не единственный вход. -->
    <key>LSUIElement</key>             <false/>
</dict>
</plist>
PLIST

# Вложенный helper подписывается первым, затем весь bundle.
codesign --force --sign - "$APP/Contents/Helpers/WaypointVPNHelper" 2>/dev/null \
    || echo "⚠ подпись VPN helper не удалась (не критично)"
codesign --force --sign - "$APP/Contents/Helpers/WaypointVPNLauncher" 2>/dev/null \
    || echo "⚠ подпись VPN launcher не удалась (не критично)"

# Подпись ad-hoc: без неё macOS не даёт приложению сетевой доступ и
# показывает предупреждение при запуске.
codesign --force --sign - "$APP" 2>/dev/null || echo "⚠ подпись не удалась (не критично)"

echo "✓ Готово: $APP"
