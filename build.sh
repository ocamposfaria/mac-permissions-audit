#!/bin/zsh
# Monta o Auditar Permissões.app e instala em /Applications.
# Ao remontar, o macOS trata como app novo: ligue de novo o Acesso Total ao Disco.
set -e
cd "$(dirname "$0")"
APP="/Applications/Auditar Permissões.app"

rm -rf "$APP"
osacompile -o "$APP" app.applescript
cp audit.py "$APP/Contents/Resources/"
plutil -replace CFBundleIdentifier -string "local.auditar-permissoes" "$APP/Contents/Info.plist"
plutil -replace CFBundleName -string "Auditar Permissões" "$APP/Contents/Info.plist"
codesign --force --sign - "$APP"
echo "Instalado: $APP"
