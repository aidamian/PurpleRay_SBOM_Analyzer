#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

lazbuild -B --build-mode=Release --widgetset=gtk2 src/purpleray_sbom_analyzer.lpi
