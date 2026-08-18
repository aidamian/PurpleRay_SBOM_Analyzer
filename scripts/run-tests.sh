#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

compiler_arguments=("$@")
host_os=$(fpc -iTO)
target_cpu=$(fpc "${compiler_arguments[@]}" -iTP)
target_os=$(fpc "${compiler_arguments[@]}" -iTO)
unit_directory="build/test-units/${target_cpu}-${target_os}"
mkdir -p "$unit_directory" tests/bin

fpc -Fu./src -FU"$unit_directory" -FE./tests/bin \
  -Mobjfpc -Sh -O2 -g -gl -B "${compiler_arguments[@]}" tests/test_runner.lpr

test_executable=tests/bin/test_runner
case "$target_os" in
  win32|win64|wince)
  test_executable=tests/bin/test_runner.exe
  ;;
esac

if [[ "$target_os" == "$host_os" ||
  ( "$target_os" == win64 && -n "${WSL_INTEROP:-}" ) ]]; then
  "$test_executable"
elif [[ "$target_os" == win64 ]] && command -v wine64 >/dev/null 2>&1; then
  wine64 "$test_executable"
elif [[ "$target_os" == win64 ]] && command -v wine >/dev/null 2>&1; then
  wine "$test_executable"
else
  echo "compiled tests for ${target_cpu}-${target_os}, but no local runner is available" >&2
  exit 3
fi
