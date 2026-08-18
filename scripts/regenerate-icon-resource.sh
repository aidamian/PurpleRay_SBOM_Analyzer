#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

if ! command -v lazres >/dev/null 2>&1; then
  echo "lazres was not found; install Lazarus before regenerating resources" >&2
  exit 1
fi
lazres src/app_icon.res assets/app-icon.ico=MAINICON
