#!/bin/sh
# Builds CertKeeper.app into ./build. Usage: ./build-app.sh [signing identity]
#
# Keychain remembers "Always Allow" (and its partition list) by team ID only for code signed with an
# Apple-issued certificate. Anything else — ad hoc or self-signed — is remembered by the exact build
# hash, so every rebuild asks again, once per stored secret. The identity is, in order: the argument,
# $CERTKEEPER_SIGNING_IDENTITY, an "Apple Development"/"Developer ID Application" identity in your
# keychain (a free Apple ID in Xcode › Settings › Accounts can create one), a self-signed
# "CertKeeper Local Signing" certificate, or ad hoc.
set -eu
cd "$(dirname "$0")"
LOCAL_IDENTITY="CertKeeper Local Signing"
IDENTITY="${1:-${CERTKEEPER_SIGNING_IDENTITY:-}}"
if [ -z "$IDENTITY" ]; then
  IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
    | sed -nE 's/.*"((Apple Development|Developer ID Application): [^"]*)".*/\1/p' | head -n 1)
fi
if [ -z "$IDENTITY" ] && security find-certificate -c "$LOCAL_IDENTITY" >/dev/null 2>&1; then
  IDENTITY="$LOCAL_IDENTITY"
fi
case "$IDENTITY" in
  "Apple Development:"*|"Developer ID Application:"*) ;;
  *) echo "note: not signed with an Apple-issued identity; Keychain will ask again after each rebuild (see README)." >&2 ;;
esac
[ -n "$IDENTITY" ] || IDENTITY="-"
swift build -c release --product CertKeeper
BIN="$(swift build -c release --show-bin-path)/CertKeeper"
APP=build/CertKeeper.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/CertKeeper"
# SwiftPM records the deployment target (15.0) as the SDK version, and AppKit uses that to pick
# legacy behaviour: macOS 26+ then draws the pre-Liquid Glass window chrome, including a stray
# line across the sidebar's title bar. Record the SDK we actually built against.
xcrun vtool -set-build-version macos 15.0 "$(xcrun --show-sdk-version)" -replace \
  -output "$APP/Contents/MacOS/CertKeeper" "$APP/Contents/MacOS/CertKeeper"
cp Support/Info.plist "$APP/Contents/Info.plist"
# App icon: the layered Icon Composer icon compiles to Assets.car (macOS 26+ renders it with Liquid
# Glass) plus a flattened CertKeeper.icns for older systems.
# (actool resolves relative paths against the input's folder, so pass absolute ones.)
if ! xcrun actool "$PWD/Support/Icons/CertKeeper.icon" --compile "$PWD/$APP/Contents/Resources" --platform macosx \
     --minimum-deployment-target 15.0 --app-icon CertKeeper \
     --output-partial-info-plist "$(mktemp -t certkeeper-icon).plist" --errors --warnings > "$APP.actool.log"; then
  cat "$APP.actool.log" >&2
  exit 1
fi
grep -q '<string>.*Assets.car</string>' "$APP.actool.log" || { cat "$APP.actool.log" >&2; echo "icon compile produced no Assets.car" >&2; exit 1; }
rm -f "$APP.actool.log"
codesign --force --options runtime --sign "$IDENTITY" "$APP"
echo "Built $APP (signed with: $IDENTITY)"
codesign -d -r- "$APP" 2>&1 | sed -n 's/^designated => /designated requirement: /p'
