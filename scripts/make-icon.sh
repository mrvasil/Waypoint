#!/bin/bash
# Пересборка AppIcon.icns из Resources/AppIcon.png (1024x1024 с альфой).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/Resources/AppIcon.png"
SET="$(mktemp -d)/AppIcon.iconset"

[ -f "$SRC" ] || { echo "не найден $SRC" >&2; exit 1; }
mkdir -p "$SET"

gen() { sips -z "$1" "$1" "$SRC" --out "$SET/$2.png" >/dev/null; }
gen 16   icon_16x16
gen 32   icon_16x16@2x
gen 32   icon_32x32
gen 64   icon_32x32@2x
gen 128  icon_128x128
gen 256  icon_128x128@2x
gen 256  icon_256x256
gen 512  icon_256x256@2x
gen 512  icon_512x512
gen 1024 icon_512x512@2x

iconutil -c icns "$SET" -o "$ROOT/Resources/AppIcon.icns"
echo "✓ Resources/AppIcon.icns пересобран"
