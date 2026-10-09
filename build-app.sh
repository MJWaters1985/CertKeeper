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
cp Support/Info.plist "$APP/Contents/Info.plist"
codesign --force --options runtime --sign "$IDENTITY" "$APP"
echo "Built $APP (signed with: $IDENTITY)"
codesign -d -r- "$APP" 2>&1 | sed -n 's/^designated => /designated requirement: /p'
