#!/bin/bash
# Builds build/Codebar.app (ad-hoc signed, sandboxed, no network entitlements).
set -euo pipefail
cd "$(dirname "$0")"
APP="build/Codebar.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc Core.swift App.swift -parse-as-library -O \
  -target "$(uname -m)-apple-macos13.0" -o "$APP/Contents/MacOS/Codebar"
cp assets/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.github.ammarshah1n.codebar</string>
<key>CFBundleName</key><string>Codebar</string>
<key>CFBundleExecutable</key><string>Codebar</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PL
cat > build/entitlements.plist <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.files.user-selected.read-only</key><true/>
</dict></plist>
PL
codesign --force --sign - --entitlements build/entitlements.plist "$APP"
codesign --verify --strict "$APP"
echo "Built $APP"
