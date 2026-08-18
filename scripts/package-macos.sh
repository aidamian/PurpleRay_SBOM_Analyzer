#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi

version=$1
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

app_directory='dist/SBOM Analyzer.app'
macos_directory="$app_directory/Contents/MacOS"
resources_directory="$app_directory/Contents/Resources"
iconset_directory=build/macos/AppIcon.iconset
package="dist/sbom-analyzer-v${version}-macos.zip"

rm -rf -- "$app_directory" "$iconset_directory"
rm -f -- "$package"
mkdir -p "$macos_directory" "$resources_directory" "$iconset_directory"
cp build/release/sbom-analyzer "$macos_directory/sbom-analyzer"
chmod 755 "$macos_directory/sbom-analyzer"

for size in 16 32 128 256 512; do
  sips -z "$size" "$size" assets/app-icon.png \
    --out "$iconset_directory/icon_${size}x${size}.png" >/dev/null
  double_size=$((size * 2))
  sips -z "$double_size" "$double_size" assets/app-icon.png \
    --out "$iconset_directory/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset_directory" -o "$resources_directory/AppIcon.icns"

sed "s/@VERSION@/${version}/g" packaging/macos/Info.plist.in > \
  "$app_directory/Contents/Info.plist"
plutil -lint "$app_directory/Contents/Info.plist"

executable_count=$(find "$macos_directory" -type f | wc -l | tr -d ' ')
if [[ $executable_count != 1 ]]; then
  echo "the application bundle must contain exactly one application executable" >&2
  exit 1
fi
if ! file "$macos_directory/sbom-analyzer" | grep -q 'Mach-O 64-bit'; then
  echo "the application executable is not a 64-bit Mach-O binary" >&2
  exit 1
fi

ditto -c -k --keepParent "$app_directory" "$package"
archive_executable_count=$(unzip -Z1 "$package" |
  grep -Ec '^SBOM Analyzer\.app/Contents/MacOS/[^/]+$' || true)
if [[ $archive_executable_count != 1 ]]; then
  echo "the macOS archive does not contain exactly one application executable" >&2
  exit 1
fi
