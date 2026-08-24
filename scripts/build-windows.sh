#!/usr/bin/env bash
# Cross-builds the Windows x64 release binary on Linux. Requires the FPC
# win64 cross-compiler (ppcrossx64 plus x86_64-win64 units) installed in
# the distro FPC tree and the mingw-w64 binutils; lazbuild compiles the LCL
# Win32 widgetset for the target on first use.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

if ! command -v ppcrossx64 >/dev/null 2>&1; then
  echo "ppcrossx64 (FPC win64 cross-compiler) is not installed; see internal migration notes" >&2
  exit 1
fi

lazbuild -B --build-mode=Release --operating-system=win64 --cpu=x86_64 \
  --widgetset=win32 src/purpleray_sbom_analyzer.lpi
