#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under Apache-2.0. Retain LICENSE and NOTICE, and cite the project as
# described in NOTICE when redistributing or creating derivative works.

set -euo pipefail
export LC_ALL=C

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$script_directory/.." && pwd)
version=${1:-}
binary=${2:-"$repository_root/build/release/purpleray-sbom-analyzer"}
output_directory=${3:-"$repository_root/dist"}

version_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! "$version" =~ $version_pattern ]]; then
  echo "Usage: $0 MAJOR.MINOR.PATCH [linux-binary] [output-directory]" >&2
  exit 2
fi
if [[ ! -f "$binary" || ! -x "$binary" ]]; then
  echo "Linux release executable is missing or not executable: $binary" >&2
  exit 1
fi
if ! command -v readelf >/dev/null 2>&1; then
  echo 'readelf is required to verify the published GLIBC compatibility floor.' >&2
  exit 1
fi
maximum_glibc_version=$(
  readelf --version-info "$binary" |
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' |
    sed 's/^GLIBC_//' |
    sort --version-sort --unique |
    tail -n 1
)
if [[ -z "$maximum_glibc_version" ]]; then
  echo 'The Linux executable exposes no verifiable GLIBC symbol requirement.' >&2
  exit 1
fi
if [[ $(printf '%s\n' '2.34' "$maximum_glibc_version" |
    sort --version-sort | tail -n 1) != '2.34' ]]; then
  echo "Linux executable requires GLIBC_$maximum_glibc_version; the published floor is GLIBC_2.34." >&2
  exit 1
fi
mapfile -t native_dependencies < <(
  readelf --dynamic --wide "$binary" |
    sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p'
)
if ! printf '%s\n' "${native_dependencies[@]}" |
    grep --fixed-strings --line-regexp --quiet 'libgtk-x11-2.0.so.0'; then
  echo 'Linux executable is not linked to the supported GTK2 runtime.' >&2
  exit 1
fi
if printf '%s\n' "${native_dependencies[@]}" |
    grep --fixed-strings --line-regexp --quiet 'libgtk-3.so.0'; then
  echo 'Linux executable unexpectedly links to the unsupported GTK3 runtime.' >&2
  exit 1
fi
for required_file in LICENSE NOTICE \
  packaging/linux/io.github.aidamian.PurpleRaySBOMAnalyzer.desktop \
  packaging/linux/io.github.aidamian.PurpleRaySBOMAnalyzer.metainfo.xml.in \
  packaging/linux/io.github.aidamian.PurpleRaySBOMAnalyzer.png; do
  if [[ ! -f "$repository_root/$required_file" ]]; then
    echo "Required packaging file is missing: $required_file" >&2
    exit 1
  fi
done

source_date_epoch=${SOURCE_DATE_EPOCH:-$(date +%s)}
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a non-negative integer: $source_date_epoch" >&2
  exit 2
fi
release_date=$(date --utc --date="@$source_date_epoch" +%F)
package_root="purpleray-sbom-analyzer-v${version}-linux-x64"
tarball="$output_directory/${package_root}.tar.gz"
debian_package="$output_directory/purpleray-sbom-analyzer_${version}_amd64.deb"
desktop_id='io.github.aidamian.PurpleRaySBOMAnalyzer'

temporary_directory=$(mktemp -d -t purpleray-package-linux.XXXXXXXX)
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

portable_stage="$temporary_directory/portable/$package_root"
debian_stage="$temporary_directory/debian"
metainfo="$temporary_directory/${desktop_id}.metainfo.xml"
sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@RELEASE_DATE@/$release_date/g" \
  "$repository_root/packaging/linux/${desktop_id}.metainfo.xml.in" > "$metainfo"

if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate "$repository_root/packaging/linux/${desktop_id}.desktop"
fi
if command -v appstreamcli >/dev/null 2>&1; then
  appstreamcli validate --no-net "$metainfo"
fi

install -Dm755 "$binary" "$portable_stage/purpleray-sbom-analyzer"
install -Dm644 "$repository_root/LICENSE" "$portable_stage/LICENSE"
install -Dm644 "$repository_root/NOTICE" "$portable_stage/NOTICE"
install -Dm644 "$repository_root/packaging/linux/${desktop_id}.desktop" \
  "$portable_stage/share/applications/${desktop_id}.desktop"
install -Dm644 "$repository_root/packaging/linux/${desktop_id}.png" \
  "$portable_stage/share/icons/hicolor/256x256/apps/${desktop_id}.png"
install -Dm644 "$metainfo" \
  "$portable_stage/share/metainfo/${desktop_id}.metainfo.xml"

find "$temporary_directory/portable" -exec touch --date="@$source_date_epoch" {} +
mkdir -p "$output_directory"
tar --create --gzip --file "$tarball" \
  --sort=name --format=posix \
  --pax-option=delete=atime,delete=ctime \
  --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
  --directory "$temporary_directory/portable" "$package_root"

mapfile -t tar_files < <(tar --list --gzip --file "$tarball" | sed -n '/\/$/!p')
expected_tar_files=(
  "$package_root/LICENSE"
  "$package_root/NOTICE"
  "$package_root/purpleray-sbom-analyzer"
  "$package_root/share/applications/${desktop_id}.desktop"
  "$package_root/share/icons/hicolor/256x256/apps/${desktop_id}.png"
  "$package_root/share/metainfo/${desktop_id}.metainfo.xml"
)
mapfile -t expected_tar_files < <(printf '%s\n' "${expected_tar_files[@]}" | sort)
mapfile -t tar_files < <(printf '%s\n' "${tar_files[@]}" | sort)
if [[ "${tar_files[*]}" != "${expected_tar_files[*]}" ]]; then
  echo 'Linux tarball contains an unexpected file set.' >&2
  printf 'Expected: %s\nActual:   %s\n' "${expected_tar_files[*]}" "${tar_files[*]}" >&2
  exit 1
fi
tar --extract --gzip --to-stdout --file "$tarball" \
  "$package_root/purpleray-sbom-analyzer" | file - | grep -E 'ELF 64-bit.*x86-64'
tar --extract --gzip --to-stdout --file "$tarball" "$package_root/LICENSE" | \
  cmp --silent - "$repository_root/LICENSE"
tar --extract --gzip --to-stdout --file "$tarball" "$package_root/NOTICE" | \
  cmp --silent - "$repository_root/NOTICE"
tar_mode=$(tar --list --verbose --gzip --file "$tarball" \
  "$package_root/purpleray-sbom-analyzer" | awk '{print $1}')
if [[ "$tar_mode" != '-rwxr-xr-x' ]]; then
  echo "Linux tarball executable has unexpected mode: $tar_mode" >&2
  exit 1
fi

install -Dm755 "$binary" "$debian_stage/usr/bin/purpleray-sbom-analyzer"
install -Dm644 "$repository_root/packaging/linux/${desktop_id}.desktop" \
  "$debian_stage/usr/share/applications/${desktop_id}.desktop"
install -Dm644 "$repository_root/packaging/linux/${desktop_id}.png" \
  "$debian_stage/usr/share/icons/hicolor/256x256/apps/${desktop_id}.png"
install -Dm644 "$metainfo" \
  "$debian_stage/usr/share/metainfo/${desktop_id}.metainfo.xml"
install -Dm644 "$repository_root/LICENSE" \
  "$debian_stage/usr/share/doc/purpleray-sbom-analyzer/LICENSE"
install -Dm644 "$repository_root/NOTICE" \
  "$debian_stage/usr/share/doc/purpleray-sbom-analyzer/NOTICE"
mkdir -p "$debian_stage/DEBIAN"

cat > "$debian_stage/usr/share/doc/purpleray-sbom-analyzer/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: PurpleRay SBOM Analyzer
Source: https://github.com/aidamian/PurpleRay_SBOM_Analyzer

Files: *
Copyright: 2026 Andrei Ionut Damian
License: Apache-2.0
 On Debian systems, the complete text of the Apache License, Version 2.0,
 is available in /usr/share/common-licenses/Apache-2.0.
EOF

installed_size=$(du --summarize --block-size=1024 "$debian_stage/usr" | awk '{print $1}')
cat > "$debian_stage/DEBIAN/control" <<EOF
Package: purpleray-sbom-analyzer
Version: $version
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: $installed_size
Depends: ca-certificates, libc6 (>= 2.34), libgtk2.0-0, libssl3
Maintainer: Andrei Ionut Damian <aidamian@users.noreply.github.com>
Homepage: https://github.com/aidamian/PurpleRay_SBOM_Analyzer
Description: local CycloneDX SBOM generator and comparison tool
 PurpleRay SBOM Analyzer scans application folders, records component
 evidence, exports CycloneDX JSON, and compares completed scans locally.
EOF

find "$debian_stage" -exec touch --date="@$source_date_epoch" {} +
SOURCE_DATE_EPOCH="$source_date_epoch" \
  dpkg-deb --root-owner-group --build "$debian_stage" "$debian_package"

expected_dependencies='ca-certificates, libc6 (>= 2.34), libgtk2.0-0, libssl3'
if [[ $(dpkg-deb --field "$debian_package" Package) != 'purpleray-sbom-analyzer' ||
      $(dpkg-deb --field "$debian_package" Version) != "$version" ||
      $(dpkg-deb --field "$debian_package" Architecture) != 'amd64' ||
      $(dpkg-deb --field "$debian_package" Depends) != "$expected_dependencies" ]]; then
  echo 'Debian control metadata verification failed.' >&2
  exit 1
fi

mapfile -t deb_files < <(
  dpkg-deb --fsys-tarfile "$debian_package" |
    tar --list --file - |
    sed -n -e 's#^\./##' -e '/\/$/!p' |
    sed '/^$/d' |
    sort
)
expected_deb_files=(
  "usr/bin/purpleray-sbom-analyzer"
  "usr/share/applications/${desktop_id}.desktop"
  "usr/share/doc/purpleray-sbom-analyzer/LICENSE"
  "usr/share/doc/purpleray-sbom-analyzer/NOTICE"
  "usr/share/doc/purpleray-sbom-analyzer/copyright"
  "usr/share/icons/hicolor/256x256/apps/${desktop_id}.png"
  "usr/share/metainfo/${desktop_id}.metainfo.xml"
)
mapfile -t expected_deb_files < <(printf '%s\n' "${expected_deb_files[@]}" | sort)
if [[ "${deb_files[*]}" != "${expected_deb_files[*]}" ]]; then
  echo 'Debian package contains an unexpected file set.' >&2
  printf 'Expected: %s\nActual:   %s\n' "${expected_deb_files[*]}" "${deb_files[*]}" >&2
  exit 1
fi
dpkg-deb --fsys-tarfile "$debian_package" |
  tar --extract --to-stdout --file - ./usr/bin/purpleray-sbom-analyzer |
  file - | grep -E 'ELF 64-bit.*x86-64'
debian_mode=$(
  dpkg-deb --fsys-tarfile "$debian_package" |
    tar --list --verbose --file - ./usr/bin/purpleray-sbom-analyzer |
    awk '{print $1}'
)
if [[ "$debian_mode" != '-rwxr-xr-x' ]]; then
  echo "Debian executable has unexpected mode: $debian_mode" >&2
  exit 1
fi

printf 'Created and verified %s\n' "$tarball"
printf 'Created and verified %s\n' "$debian_package"
