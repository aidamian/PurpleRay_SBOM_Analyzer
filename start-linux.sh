#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
#
# SBOM Analyzer is open source, but this notice and the project's BibTeX
# citation must be retained and the original work cited in derivative works.

set -Eeuo pipefail

readonly PROJECT_URL='https://github.com/aidamian/SBOM_Analyzer'

fail() {
  printf 'start-linux.sh: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' was not found"
}

check_ui_prerequisites() {
  local ldconfig_command

  [[ "$(uname -s)" == 'Linux' ]] || fail 'this script must be run on Linux'
  [[ "$(uname -m)" == 'x86_64' ]] || fail 'the published release requires x86-64 Linux'
  [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]] ||
    fail 'no Wayland or X11 display is configured'

  ldconfig_command="$(command -v ldconfig 2>/dev/null || true)"
  [[ -n "$ldconfig_command" ]] || fail "'ldconfig' was not found"
  "$ldconfig_command" -p 2>/dev/null |
    awk '$1 == "libgtk-3.so.0" { found = 1 } END { exit !found }' ||
    fail 'the GTK3 runtime is missing from this Linux system'
}

main() {
  local actual_sha256
  local asset_name
  local asset_url
  local binary_path
  local checksum_path
  local checksum_url
  local data_directory
  local download_path
  local expected_sha256
  local install_directory
  local latest_release_url
  local staged_path
  local tag_name

  for required_command in awk curl install mkdir mv rm sha256sum uname; do
    require_command "$required_command"
  done
  check_ui_prerequisites

  latest_release_url="$(
    curl --fail --show-error --silent --location \
      --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 \
      --output /dev/null --write-out '%{url_effective}' \
      "$PROJECT_URL/releases/latest"
  )" || fail 'could not determine the latest release'
  tag_name="${latest_release_url##*/}"
  [[ "$tag_name" == v+([0-9]).+([0-9]).+([0-9]) ]] ||
    fail "GitHub returned an invalid release tag: $tag_name"

  asset_name="sbom-analyzer-${tag_name}-linux-x64"
  asset_url="$PROJECT_URL/releases/download/$tag_name/$asset_name"
  checksum_url="$PROJECT_URL/releases/download/$tag_name/SHA256SUMS.txt"
  install_directory="$PWD/SBOM_Analyzer_${tag_name}"
  data_directory="${HOME:?HOME is not set}/.sbom-analyzer"
  binary_path="$install_directory/sbom-analyzer"
  download_path="$install_directory/.$asset_name.download"
  checksum_path="$install_directory/.SHA256SUMS.txt.download"
  staged_path="$install_directory/.sbom-analyzer.staged"

  mkdir -p "$install_directory" "$data_directory"
  trap 'rm -f -- "$download_path" "$checksum_path" "$staged_path"' EXIT

  printf 'Downloading SBOM Analyzer %s into %s\n' "$tag_name" "$install_directory"
  curl --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 300 \
    --output "$download_path" "$asset_url" || fail 'release download failed'
  curl --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 60 \
    --output "$checksum_path" "$checksum_url" || fail 'checksum download failed'

  expected_sha256="$(
    awk -v asset="$asset_name" \
      '$2 == asset || $2 == ("*" asset) { print tolower($1); exit }' \
      "$checksum_path"
  )"
  [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    fail "no valid checksum was published for $asset_name"
  actual_sha256="$(sha256sum "$download_path" | awk '{ print $1 }')"
  [[ "$actual_sha256" == "$expected_sha256" ]] || fail 'release checksum verification failed'

  install -m 0755 "$download_path" "$staged_path"
  mv -f "$staged_path" "$binary_path"
  rm -f -- "$download_path" "$checksum_path"
  trap - EXIT

  printf 'Shared application data: %s\n' "$data_directory"
  printf 'Launching %s\n' "$binary_path"
  cd "$install_directory"
  exec "$binary_path" "$@"
}

shopt -s extglob
main "$@"
