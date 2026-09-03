# Сокращения для частых команд.
.PHONY: build run test live app install clean

build:            ## собрать (debug)
	swift build

run:              ## запустить из исходников
	swift run Waypoint

test:             ## прогнать проверки
	swift run waypoint-tests

live:             ## живая проверка: xray, реальный туннель, обход VPN
	swift run waypoint-tests --live

app:              ## собрать Waypoint.app
	./build-app.sh release

install: app      ## собрать и установить в /Applications
	@pkill -f '/Applications/Waypoint.app/Contents/MacOS/Waypoint' 2>/dev/null || true
	@sleep 1
	rm -rf /Applications/Waypoint.app
	cp -R build/Waypoint.app /Applications/
	@echo "✓ Установлено: /Applications/Waypoint.app"

icon:             ## пересобрать AppIcon.icns из Resources/AppIcon.png
	./scripts/make-icon.sh

clean:
	rm -rf .build build
