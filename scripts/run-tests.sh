#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

target_cpu=$(fpc -iTP)
target_os=$(fpc -iTO)
unit_directory="build/test-units/${target_cpu}-${target_os}"
mkdir -p "$unit_directory" tests/bin

fpc -Fu./src -FU"$unit_directory" -FE./tests/bin \
  -Mobjfpc -Sh -O2 -g -gl -B "$@" tests/test_runner.lpr

test_executable=tests/bin/test_runner
if [[ -f tests/bin/test_runner.exe ]]; then
  test_executable=tests/bin/test_runner.exe
fi
"$test_executable"
