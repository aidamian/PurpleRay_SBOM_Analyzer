#!/usr/bin/env bash
# Cross-builds the Windows x64 release binary on Linux.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

if ! command -v lazbuild >/dev/null 2>&1; then
  printf '%s\n' 'Windows cross-build cannot start: lazbuild was not found in PATH. Make lazbuild available in PATH and retry.' >&2
  exit 1
fi

if ! command -v ppcrossx64 >/dev/null 2>&1; then
  printf '%s\n' 'Windows cross-build cannot start: ppcrossx64 was not found in PATH. Make the Free Pascal Win64 cross-compiler available in PATH and retry.' >&2
  exit 1
fi

if ! command -v x86_64-w64-mingw32-ld >/dev/null 2>&1; then
  printf '%s\n' 'Windows cross-build cannot start: x86_64-w64-mingw32-ld was not found in PATH. Make the x86_64 MinGW-w64 linker available in PATH and retry.' >&2
  exit 1
fi

cross_probe_directory=$(mktemp -d)
trap 'rm -rf -- "$cross_probe_directory"' EXIT
cross_probe_source="$cross_probe_directory/win64_rtl_probe.pas"
printf '%s\n' 'program Win64RTLProbe;' 'begin' 'end.' >"$cross_probe_source"
if ! ppcrossx64 -Twin64 -Px86_64 -Cn -FU"$cross_probe_directory" \
  -FE"$cross_probe_directory" "$cross_probe_source" >/dev/null 2>&1; then
  printf '%s\n' 'Windows cross-build cannot start: Free Pascal Win64 RTL units are unavailable to ppcrossx64. Make the x86_64-win64 RTL units available to ppcrossx64 and retry.' >&2
  exit 1
fi

lazbuild -B --build-mode=Release --operating-system=win64 --cpu=x86_64 \
  --widgetset=win32 src/purpleray_sbom_analyzer.lpi
