#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 VERSION COMMIT [DESTINATION]" >&2
  exit 2
fi

version=$1
commit=$2
destination=${3:-src/uVersionInfo.pas}

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid application version: $version" >&2
  exit 2
fi
if [[ ! $commit =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "invalid Git commit: $commit" >&2
  exit 2
fi

temporary="${destination}.tmp"
# shellcheck disable=SC2016
pascal_mode_directive='{$mode objfpc}{$H+}'
printf '%s\n' \
  'unit uVersionInfo;' \
  '' \
  '{ This unit is generated in CI. The committed copy is a local fallback. }' \
  '' \
  "$pascal_mode_directive" \
  '' \
  'interface' \
  '' \
  'const' \
  "  AppName = 'SBOM Analyzer';" \
  "  AppExecutableName = 'sbom-analyzer';" \
  "  AppVersion = '${version}';" \
  "  AppCommit = '${commit}';" \
  '' \
  'function AbbreviatedCommit: string;' \
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
  'end.' > "$temporary"
mv "$temporary" "$destination"
