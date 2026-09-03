# Сокращения для частых команд.
.PHONY: build run test live app install clean

build:            ## собрать (debug)
	swift build

run:              ## запустить из исходников
	swift run TunnelProxyHub

test:             ## прогнать проверки
	swift run tph-tests

live:             ## живая проверка: xray, реальный туннель, обход VPN
	swift run tph-tests --live

app:              ## собрать TunnelProxyHub.app
	./build-app.sh release

install: app      ## собрать и установить в /Applications
	@pkill -f TunnelProxyHub 2>/dev/null || true
	@sleep 1
	rm -rf /Applications/TunnelProxyHub.app
	cp -R build/TunnelProxyHub.app /Applications/
	@echo "✓ Установлено: /Applications/TunnelProxyHub.app"

icon:             ## пересобрать AppIcon.icns из Resources/AppIcon.png
	./scripts/make-icon.sh

clean:
	rm -rf .build build
