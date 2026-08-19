#!/usr/bin/env bash
# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under the Apache License, Version 2.0; see ../LICENSE.

set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo 'usage: write-version.sh VERSION COMMIT [UNIT_DESTINATION] [PROJECT_FILE]' >&2
  exit 2
fi

version=$1
commit=$2
unit_destination=${3:-src/uVersionInfo.pas}
project_file=${4:-src/purpleray_sbom_analyzer.lpi}

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid application version: $version" >&2
  exit 2
fi
if [[ ! $commit =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "invalid Git commit: $commit" >&2
  exit 2
fi
if [[ ! -f $project_file ]]; then
  echo "Lazarus project was not found: $project_file" >&2
  exit 2
fi

numeric_version=${version%%[-+]*}
IFS=. read -r major_version minor_version revision_version extra_version <<<"$numeric_version"
if [[ -n ${extra_version:-} ]]; then
  echo "invalid numeric application version: $numeric_version" >&2
  exit 2
fi
for version_part in "$major_version" "$minor_version" "$revision_version"; do
  if [[ ! $version_part =~ ^[0-9]+$ ]] || (( 10#$version_part > 65535 )); then
    echo "version component is outside the Windows resource range: $version_part" >&2
    exit 2
  fi
done

unit_temporary="${unit_destination}.tmp"
project_temporary="${project_file}.tmp"
trap 'rm -f -- "$unit_temporary" "$project_temporary"' EXIT

# shellcheck disable=SC2016
pascal_mode_directive='{$mode objfpc}{$H+}'
printf '%s\n' \
  '(**' \
  '  PurpleRay SBOM Analyzer build-version unit.' \
  '' \
  '  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under' \
  '  the Apache License, Version 2.0; see LICENSE.' \
  '' \
  '  Description' \
  '  -----------' \
  '  Exposes the application identity and formats the generated version and commit' \
  '  metadata shown in the UI and embedded in generated SBOMs.' \
  '' \
  '  Citation request' \
  '  ----------------' \
  '  Please retain this notice and cite the project as follows:' \
  '' \
  '  @misc{damian2026purpleraysbomanalyzer,' \
  '    author = {Andrei Ionut Damian},' \
  '    title  = {{PurpleRay SBOM Analyzer}},' \
  '    year   = {2026},' \
  '    url    = {https://github.com/aidamian/SBOM_Analyzer}' \
  '  }' \
  '*)' \
  'unit uVersionInfo;' \
  '' \
  "$pascal_mode_directive" \
  '' \
  'interface' \
  '' \
  'const' \
  "  AppName = 'PurpleRay SBOM Analyzer';" \
  "  AppExecutableName = 'purpleray-sbom-analyzer';" \
  "  AppVersion = '${version}';" \
  "  AppCommit = '${commit}';" \
  '' \
  '{**' \
  '  Returns a display-safe short form of the configured commit identifier.' \
  '' \
  '  Parameters' \
  '  ----------' \
  '  None' \
  '' \
  '  Returns' \
  '  -------' \
  '  string' \
  '    Up to eight commit characters, or an empty string when unknown.' \
  '' \
  '  Raises' \
  '  ------' \
  '  None' \
  '}' \
  'function AbbreviatedCommit: string;' \
  '' \
  '{**' \
  '  Combines semantic version and abbreviated commit metadata for the UI.' \
  '' \
  '  Parameters' \
  '  ----------' \
  '  None' \
  '' \
  '  Returns' \
  '  -------' \
  '  string' \
  '    Version alone or version followed by the short commit in parentheses.' \
  '' \
  '  Raises' \
  '  ------' \
  '  None' \
  '}' \
  'function DisplayVersion: string;' \
  '' \
  'implementation' \
  '' \
  'function AbbreviatedCommit: string;' \
  'begin' \
  '  Result := AppCommit;' \
  "  if Result = 'unknown' then" \
  "    Result := '';" \
  '  if Length(Result) > 8 then' \
  '    SetLength(Result, 8);' \
  'end;' \
  '' \
  'function DisplayVersion: string;' \
  'var' \
  '  CommitValue: string;' \
  'begin' \
  '  Result := AppVersion;' \
  '  CommitValue := AbbreviatedCommit;' \
  "  if CommitValue <> '' then" \
  "    Result := Result + ' (' + CommitValue + ')';" \
  'end;' \
  '' \
  'end.' >"$unit_temporary"

for version_field in MajorVersionNr MinorVersionNr RevisionNr BuildNr; do
  if [[ $(grep -Ec "<$version_field Value=\"[^\"]*\"/>" "$project_file") -ne 1 ]]; then
    echo "Lazarus project has an invalid $version_field field" >&2
    exit 2
  fi
done
if [[ $(grep -Ec '<StringTable .*FileVersion="[^"]*".*ProductVersion="[^"]*"/>' "$project_file") -ne 1 ]]; then
  echo 'Lazarus project has an invalid version StringTable' >&2
  exit 2
fi

file_version="${major_version}.${minor_version}.${revision_version}.0"
LC_ALL=C sed -E \
  -e "s|(<MajorVersionNr Value=\")[^\"]*(\"/>)|\\1${major_version}\\2|" \
  -e "s|(<MinorVersionNr Value=\")[^\"]*(\"/>)|\\1${minor_version}\\2|" \
  -e "s|(<RevisionNr Value=\")[^\"]*(\"/>)|\\1${revision_version}\\2|" \
  -e 's|<BuildNr Value="[^"]*"/>|<BuildNr Value="0"/>|' \
  -e "s|(FileVersion=\")[^\"]*(\")|\\1${file_version}\\2|" \
  -e "s|(ProductVersion=\")[^\"]*(\")|\\1${version}\\2|" \
  "$project_file" >"$project_temporary"

grep -Fq "<MajorVersionNr Value=\"$major_version\"/>" "$project_temporary"
grep -Fq "<MinorVersionNr Value=\"$minor_version\"/>" "$project_temporary"
grep -Fq "<RevisionNr Value=\"$revision_version\"/>" "$project_temporary"
grep -Fq '<BuildNr Value="0"/>' "$project_temporary"
grep -Fq "FileVersion=\"$file_version\"" "$project_temporary"
grep -Fq "ProductVersion=\"$version\"" "$project_temporary"

mv "$unit_temporary" "$unit_destination"
mv "$project_temporary" "$project_file"
trap - EXIT
