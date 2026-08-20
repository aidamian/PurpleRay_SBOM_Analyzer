#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under the Apache License, Version 2.0; see ../LICENSE.

set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version_file="$repository_root/VERSION"
unit_file="$repository_root/src/uVersionInfo.pas"
project_file="$repository_root/src/purpleray_sbom_analyzer.lpi"

fail() {
  echo "$1" >&2
  exit 1
}

require_once() {
  local value=$1
  local file=$2
  local description=$3
  local count

  count=$(grep -Fc -- "$value" "$file" || true)
  if [[ $count -ne 1 ]]; then
    fail "$description must occur exactly once in ${file#"$repository_root/"}"
  fi
}

[[ -f $version_file ]] || fail 'The tracked VERSION file is missing.'
[[ -f $unit_file ]] || fail 'The tracked uVersionInfo.pas fallback is missing.'
[[ -f $project_file ]] || fail 'The tracked Lazarus project is missing.'
if [[ $(awk 'END { print NR }' "$version_file") -ne 1 ]]; then
  fail 'VERSION must contain exactly one line.'
fi

version=$(<"$version_file")
version_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
if [[ ! $version =~ $version_pattern ]]; then
  fail "VERSION must contain MAJOR.MINOR.PATCH without prefixes, suffixes, or leading zeros: '$version'"
fi

IFS=. read -r major_version minor_version revision_version <<<"$version"
for version_part in "$major_version" "$minor_version" "$revision_version"; do
  if (( 10#$version_part > 65535 )); then
    fail "VERSION component exceeds the Windows resource limit: $version_part"
  fi
done

require_once "  AppVersion = '$version';" "$unit_file" 'Pascal AppVersion fallback'
require_once "  AppCommit = 'unknown';" "$unit_file" 'Pascal AppCommit fallback'
require_once '<UseVersionInfo Value="True"/>' "$project_file" 'Lazarus UseVersionInfo setting'
require_once "<MajorVersionNr Value=\"$major_version\"/>" "$project_file" 'Lazarus major version fallback'
require_once "<MinorVersionNr Value=\"$minor_version\"/>" "$project_file" 'Lazarus minor version fallback'
require_once "<RevisionNr Value=\"$revision_version\"/>" "$project_file" 'Lazarus revision fallback'
require_once '<BuildNr Value="0"/>' "$project_file" 'Lazarus build-number fallback'
require_once "FileVersion=\"$version.0\"" "$project_file" 'Lazarus FileVersion fallback'
require_once "ProductVersion=\"$version\"" "$project_file" 'Lazarus ProductVersion fallback'

echo "Tracked version fallbacks match VERSION $version."
