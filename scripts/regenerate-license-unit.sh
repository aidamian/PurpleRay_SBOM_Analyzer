#!/usr/bin/env bash
# Regenerates src/uLicenseContent.pas from the canonical root LICENSE so the
# complete license remains available inside the self-contained executable.
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

python3 - <<'PY'
import io

source_path = 'LICENSE'
target_path = 'src/uLicenseContent.pas'

with io.open(source_path, 'r', encoding='utf-8', newline='') as handle:
    text = handle.read()
lines = text.split('\n')

def pascal_literal(line):
    escaped = line.replace("'", "''")
    if escaped == '':
        return "''"
    pieces = [escaped[i:i + 200] for i in range(0, len(escaped), 200)]
    return " +\n    ".join("'" + piece + "'" for piece in pieces)

with io.open(target_path, 'w', encoding='utf-8', newline='\n') as out:
    out.write('''(**
  PurpleRay SBOM Analyzer embedded license content.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  GENERATED FILE - do not edit by hand. Regenerate from the root LICENSE
  with scripts/regenerate-license-unit.sh. Holds the complete license text
  so the About dialog works without a runtime file lookup.
*)
unit uLicenseContent;

{$mode objfpc}{$H+}

interface

const
  LicenseLineCount = ''' + str(len(lines)) + ''';

  LicenseLines: array[0..LicenseLineCount - 1] of string = (
''')
    for index, line in enumerate(lines):
        separator = ',' if index < len(lines) - 1 else ''
        out.write('    ' + pascal_literal(line) + separator + '\n')
    out.write(''');

{**
  Returns the canonical Apache-2.0 license as embedded LF-delimited text.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Complete byte-preserving text of the tracked root LICENSE.

  Raises
  ------
  EOutOfMemory
    Propagated if the result cannot be allocated.
}
function ApacheLicenseText: string;

implementation

uses
  SysUtils;

function ApacheLicenseText: string;
var
  Builder: TAnsiStringBuilder;
  I: Integer;
begin
  Builder := TAnsiStringBuilder.Create;
  try
    for I := 0 to LicenseLineCount - 1 do
    begin
      if I > 0 then
        Builder.Append(#10);
      Builder.Append(LicenseLines[I]);
    end;
    Result := Builder.ToString;
  finally
    Builder.Free;
  end;
end;

end.
''')
print('wrote', target_path, 'with', len(lines), 'lines')
PY
