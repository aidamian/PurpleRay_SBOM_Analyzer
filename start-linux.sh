#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under the Apache License, Version 2.0; see LICENSE.
# Please retain the applicable attribution notices and cite the project using
# the BibTeX entry in NOTICE.

set -Eeuo pipefail

readonly PROJECT_URL='https://github.com/aidamian/PurpleRay_SBOM_Analyzer'
readonly PROJECT_REPOSITORY='aidamian/PurpleRay_SBOM_Analyzer'
readonly DESKTOP_ID='io.github.aidamian.PurpleRaySBOMAnalyzer'
readonly MINIMUM_GLIBC_MAJOR=2
readonly MINIMUM_GLIBC_MINOR=34

RELEASE_VERSION=''
TAG_NAME=''
APPLICATION_ARGUMENTS=()
DOWNLOAD_PATH=''
CHECKSUM_PATH=''
EXTRACT_DIRECTORY=''
DESKTOP_STAGE_PATH=''

fail() {
  printf 'start-linux.sh: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' was not found"
}

is_canonical_version() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

cleanup() {
  if [[ -n "$DOWNLOAD_PATH" ]]; then
    rm -f -- "$DOWNLOAD_PATH"
  fi
  if [[ -n "$CHECKSUM_PATH" ]]; then
    rm -f -- "$CHECKSUM_PATH"
  fi
  if [[ -n "$DESKTOP_STAGE_PATH" ]]; then
    rm -f -- "$DESKTOP_STAGE_PATH"
  fi
  if [[ -n "$EXTRACT_DIRECTORY" ]]; then
    rm -rf -- "$EXTRACT_DIRECTORY"
  fi
}

parse_arguments() {
  local argument_version=''

  RELEASE_VERSION="${PURPLERAY_VERSION:-}"
  while (($# > 0)); do
    case "$1" in
      --release-version)
        (($# >= 2)) || fail '--release-version requires MAJOR.MINOR.PATCH'
        argument_version="$2"
        shift 2
        ;;
      --release-version=*)
        argument_version="${1#*=}"
        [[ -n "$argument_version" ]] ||
          fail '--release-version requires MAJOR.MINOR.PATCH'
        shift
        ;;
      --)
        shift
        APPLICATION_ARGUMENTS=("$@")
        break
        ;;
      *)
        APPLICATION_ARGUMENTS=("$@")
        break
        ;;
    esac
  done

  if [[ -n "$argument_version" ]]; then
    RELEASE_VERSION="$argument_version"
  fi
  if [[ -n "$RELEASE_VERSION" ]] && ! is_canonical_version "$RELEASE_VERSION"; then
    fail "release version must be canonical MAJOR.MINOR.PATCH without a v prefix: $RELEASE_VERSION"
  fi
}

check_ui_prerequisites() {
  local glibc_major
  local glibc_minor
  local glibc_version
  local ldconfig_command=''

  [[ "$(uname -s)" == 'Linux' ]] || fail 'this script must be run on Linux'
  [[ "$(uname -m)" == 'x86_64' ]] || fail 'the published release requires x86-64 Linux'
  [[ -n "${DISPLAY:-}" ]] ||
    fail 'no X11 display is available; run this script from an X11 or XWayland-enabled Linux desktop session'

  glibc_version="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  [[ "$glibc_version" =~ ^glibc[[:space:]]+([0-9]+)\.([0-9]+) ]] ||
    fail 'could not determine the GNU C Library version; the release requires glibc 2.34 or newer'
  glibc_major="${BASH_REMATCH[1]}"
  glibc_minor="${BASH_REMATCH[2]}"
  if ((10#$glibc_major < MINIMUM_GLIBC_MAJOR ||
       (10#$glibc_major == MINIMUM_GLIBC_MAJOR && 10#$glibc_minor < MINIMUM_GLIBC_MINOR))); then
    fail "glibc $glibc_major.$glibc_minor is too old; the release requires glibc 2.34 or newer"
  fi

  if command -v ldconfig >/dev/null 2>&1; then
    ldconfig_command="$(command -v ldconfig)"
  elif [[ -x /sbin/ldconfig ]]; then
    ldconfig_command='/sbin/ldconfig'
  elif [[ -x /usr/sbin/ldconfig ]]; then
    ldconfig_command='/usr/sbin/ldconfig'
  fi
  if [[ -n "$ldconfig_command" ]]; then
    "$ldconfig_command" -p 2>/dev/null |
      awk '$1 == "libgtk-x11-2.0.so.0" { found = 1 } END { exit !found }' ||
      fail 'the GTK2 runtime is missing; install your distribution package that provides libgtk-x11-2.0.so.0'
  elif [[ ! -e /usr/lib/x86_64-linux-gnu/libgtk-x11-2.0.so.0 &&
          ! -e /usr/lib64/libgtk-x11-2.0.so.0 &&
          ! -e /usr/lib/libgtk-x11-2.0.so.0 ]]; then
    fail 'could not find the GTK2 runtime (libgtk-x11-2.0.so.0)'
  fi
}

resolve_release() {
  local latest_release_url

  if [[ -n "$RELEASE_VERSION" ]]; then
    TAG_NAME="v$RELEASE_VERSION"
    return
  fi

  latest_release_url="$(
    curl --fail --show-error --silent --location \
      --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 \
      --output /dev/null --write-out '%{url_effective}' \
      "$PROJECT_URL/releases/latest"
  )" || fail 'could not determine the latest release'
  latest_release_url="${latest_release_url%/}"
  TAG_NAME="${latest_release_url##*/}"
  [[ "$TAG_NAME" == v* ]] || fail "GitHub returned an invalid release tag: $TAG_NAME"
  RELEASE_VERSION="${TAG_NAME#v}"
  is_canonical_version "$RELEASE_VERSION" ||
    fail "GitHub returned a non-canonical release tag: $TAG_NAME"
}

checksum_for_asset() {
  local asset_name="$1"

  awk -v asset="$asset_name" \
    '$2 == asset || $2 == ("*" asset) { print tolower($1); exit }' \
    "$CHECKSUM_PATH"
}

verify_or_download_package() {
  local actual_sha256
  local asset_name="$1"
  local expected_sha256="$2"
  local package_path="$3"
  local asset_url="$PROJECT_URL/releases/download/$TAG_NAME/$asset_name"

  if [[ -f "$package_path" ]]; then
    actual_sha256="$(sha256sum "$package_path" | awk '{ print tolower($1) }')"
    if [[ "$actual_sha256" == "$expected_sha256" ]]; then
      printf 'Using checksum-verified cached package: %s\n' "$package_path"
      return
    fi
    printf 'Cached package failed checksum verification; downloading a fresh copy.\n' >&2
  fi

  DOWNLOAD_PATH="$package_path.download"
  printf 'Downloading %s\n' "$asset_name"
  curl --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 300 \
    --output "$DOWNLOAD_PATH" "$asset_url" || fail 'release download failed'
  actual_sha256="$(sha256sum "$DOWNLOAD_PATH" | awk '{ print tolower($1) }')"
  [[ "$actual_sha256" == "$expected_sha256" ]] ||
    fail 'release checksum verification failed'
  mv -f -- "$DOWNLOAD_PATH" "$package_path"
  DOWNLOAD_PATH=''
}

report_checksum_verified() {
  local package_path="$1"

  # No extra tooling is required to run the application. Provenance can be
  # checked manually with the GitHub CLI if desired.
  printf 'Checksum verification succeeded for %s\n' "${package_path##*/}"
  printf '%s\n' \
    "Optional provenance check: gh attestation verify '$package_path' --repo '$PROJECT_REPOSITORY'"
}

validate_tar_package() {
  local package_path="$1"
  local package_root="$2"
  local entry
  local license_count=0
  local notice_count=0
  local binary_count=0
  local desktop_count=0
  local icon_count=0
  local metainfo_count=0

  tar --list --verbose --gzip --file "$package_path" |
    awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { exit 1 }' ||
    fail 'the Linux archive contains a link or unsupported member type'

  while IFS= read -r entry; do
    case "$entry" in
      "$package_root/"|\
      "$package_root/share/"|\
      "$package_root/share/applications/"|\
      "$package_root/share/icons/"|\
      "$package_root/share/icons/hicolor/"|\
      "$package_root/share/icons/hicolor/256x256/"|\
      "$package_root/share/icons/hicolor/256x256/apps/"|\
      "$package_root/share/metainfo/")
        ;;
      "$package_root/LICENSE")
        ((license_count += 1))
        ;;
      "$package_root/NOTICE")
        ((notice_count += 1))
        ;;
      "$package_root/purpleray-sbom-analyzer")
        ((binary_count += 1))
        ;;
      "$package_root/share/applications/$DESKTOP_ID.desktop")
        ((desktop_count += 1))
        ;;
      "$package_root/share/icons/hicolor/256x256/apps/$DESKTOP_ID.png")
        ((icon_count += 1))
        ;;
      "$package_root/share/metainfo/$DESKTOP_ID.metainfo.xml")
        ((metainfo_count += 1))
        ;;
      *)
        fail "the Linux archive contains an unexpected member: $entry"
        ;;
    esac
  done < <(tar --list --gzip --file "$package_path")

  ((license_count == 1 && notice_count == 1 && binary_count == 1 &&
    desktop_count == 1 && icon_count == 1 && metainfo_count == 1)) ||
    fail 'the Linux archive is incomplete or contains duplicate files'
}

install_desktop_files() {
  local source_root="$1"
  local binary_path="$2"
  local local_share_directory="${HOME:?HOME is not set}/.local/share"
  local applications_directory="$local_share_directory/applications"
  local icons_directory="$local_share_directory/icons/hicolor/256x256/apps"
  local metainfo_directory="$local_share_directory/metainfo"
  local desktop_source="$source_root/share/applications/$DESKTOP_ID.desktop"
  local desktop_target="$applications_directory/$DESKTOP_ID.desktop"
  local escaped_binary_path="$binary_path"
  local line

  [[ "$binary_path" != *$'\n'* && "$binary_path" != *$'\r'* ]] ||
    fail 'the install path cannot contain a newline'
  escaped_binary_path="${escaped_binary_path//\\/\\\\}"
  escaped_binary_path="${escaped_binary_path//\"/\\\"}"
  escaped_binary_path="${escaped_binary_path//\`/\\\`}"
  escaped_binary_path="${escaped_binary_path//\$/\\\$}"

  mkdir -p "$applications_directory" "$icons_directory" "$metainfo_directory"
  DESKTOP_STAGE_PATH="$applications_directory/.$DESKTOP_ID.desktop.staged"
  : > "$DESKTOP_STAGE_PATH"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == Exec=* ]]; then
      printf 'Exec="%s"\n' "$escaped_binary_path" >> "$DESKTOP_STAGE_PATH"
    else
      printf '%s\n' "$line" >> "$DESKTOP_STAGE_PATH"
    fi
  done < "$desktop_source"
  install -m 0644 "$DESKTOP_STAGE_PATH" "$desktop_target"
  rm -f -- "$DESKTOP_STAGE_PATH"
  DESKTOP_STAGE_PATH=''
  install -m 0644 \
    "$source_root/share/icons/hicolor/256x256/apps/$DESKTOP_ID.png" \
    "$icons_directory/$DESKTOP_ID.png"
  install -m 0644 "$source_root/share/metainfo/$DESKTOP_ID.metainfo.xml" \
    "$metainfo_directory/$DESKTOP_ID.metainfo.xml"

  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_directory" >/dev/null 2>&1 || true
  fi
  printf 'Installed the desktop entry, icon, and AppStream metadata under %s\n' "$local_share_directory"
}

install_tar_package() {
  local package_path="$1"
  local install_directory="$2"
  local binary_path="$3"
  local package_root="purpleray-sbom-analyzer-$TAG_NAME-linux-x64"
  local source_root
  local staged_binary="$install_directory/.purpleray-sbom-analyzer.staged"

  validate_tar_package "$package_path" "$package_root"
  EXTRACT_DIRECTORY="$(mktemp -d "$install_directory/.extract.XXXXXX")"
  tar --extract --gzip --file "$package_path" --directory "$EXTRACT_DIRECTORY" \
    --no-same-owner --no-same-permissions
  source_root="$EXTRACT_DIRECTORY/$package_root"

  install -m 0755 "$source_root/purpleray-sbom-analyzer" "$staged_binary"
  mv -f -- "$staged_binary" "$binary_path"
  install -m 0644 "$source_root/LICENSE" "$install_directory/LICENSE"
  install -m 0644 "$source_root/NOTICE" "$install_directory/NOTICE"
  install_desktop_files "$source_root" "$binary_path"
  rm -rf -- "$EXTRACT_DIRECTORY"
  EXTRACT_DIRECTORY=''
}

main() {
  local asset_name
  local binary_path
  local checksum_url
  local data_directory
  local expected_sha256
  local install_directory
  local legacy_asset_name
  local package_path
  local tar_asset_name

  parse_arguments "$@"
  for required_command in awk curl getconf install mkdir mktemp mv rm sha256sum tar uname; do
    require_command "$required_command"
  done
  check_ui_prerequisites
  resolve_release

  install_directory="$PWD/PurpleRay_SBOM_Analyzer_$TAG_NAME"
  data_directory="${HOME:?HOME is not set}/.purpleray/sbom-analyzer"
  binary_path="$install_directory/purpleray-sbom-analyzer"
  checksum_url="$PROJECT_URL/releases/download/$TAG_NAME/SHA256SUMS.txt"
  CHECKSUM_PATH="$install_directory/.SHA256SUMS.txt.download"
  tar_asset_name="purpleray-sbom-analyzer-$TAG_NAME-linux-x64.tar.gz"
  legacy_asset_name="purpleray-sbom-analyzer-$TAG_NAME-linux-x64"

  mkdir -p "$install_directory" "$data_directory"
  trap cleanup EXIT
  curl --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 \
    --output "$CHECKSUM_PATH" "$checksum_url" || fail 'checksum download failed'

  expected_sha256="$(checksum_for_asset "$tar_asset_name")"
  if [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    asset_name="$tar_asset_name"
  else
    expected_sha256="$(checksum_for_asset "$legacy_asset_name")"
    [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] ||
      fail 'the release checksums contain neither the Linux tar package nor the legacy Linux executable'
    asset_name="$legacy_asset_name"
  fi

  package_path="$install_directory/$asset_name"
  printf 'Preparing PurpleRay SBOM Analyzer %s in %s\n' "$TAG_NAME" "$install_directory"
  verify_or_download_package "$asset_name" "$expected_sha256" "$package_path"
  report_checksum_verified "$package_path"

  if [[ "$asset_name" == "$tar_asset_name" ]]; then
    install_tar_package "$package_path" "$install_directory" "$binary_path"
  else
    install -m 0755 "$package_path" "$install_directory/.purpleray-sbom-analyzer.staged"
    mv -f -- "$install_directory/.purpleray-sbom-analyzer.staged" "$binary_path"
    printf 'This older release predates the portable archive, so desktop metadata was not installed.\n'
  fi

  rm -f -- "$CHECKSUM_PATH"
  CHECKSUM_PATH=''
  trap - EXIT
  printf 'Shared application data: %s\n' "$data_directory"
  printf 'Launching %s\n' "$binary_path"
  cd "$install_directory"
  exec "$binary_path" "${APPLICATION_ARGUMENTS[@]}"
}

main "$@"
