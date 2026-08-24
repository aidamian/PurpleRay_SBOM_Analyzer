#!/usr/bin/env bash
# Regenerates src/uGlossaryContent.pas from docs/GLOSSARY.md so the
# Knowledge Base ships inside the self-contained executable.
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

python3 - <<'PY'
import io

source_path = 'docs/GLOSSARY.md'
target_path = 'src/uGlossaryContent.pas'

with io.open(source_path, 'r', encoding='utf-8', newline='') as handle:
    text = handle.read()
lines = text.split('\n')
if lines and lines[-1] == '':
    lines.pop()

def pascal_literal(line):
    escaped = line.replace("'", "''")
    if escaped == '':
        return "''"
    pieces = [escaped[i:i + 200] for i in range(0, len(escaped), 200)]
    return " +\n    ".join("'" + piece + "'" for piece in pieces)

with io.open(target_path, 'w', encoding='utf-8', newline='\n') as out:
    out.write('''(**
  PurpleRay SBOM Analyzer embedded glossary content.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  GENERATED FILE - do not edit by hand. Regenerate from docs/GLOSSARY.md
  with scripts/regenerate-glossary-unit.sh. Holds the Knowledge Base
  glossary text so the shipped executable stays self-contained.
*)
unit uGlossaryContent;

{$mode objfpc}{$H+}

interface

const
  GlossaryLineCount = ''' + str(len(lines)) + ''';

  GlossaryLines: array[0..GlossaryLineCount - 1] of string = (
''')
    for index, line in enumerate(lines):
        separator = ',' if index < len(lines) - 1 else ''
        out.write('    ' + pascal_literal(line) + separator + '\n')
    out.write(''');

{**
  Returns the embedded glossary markdown as one newline-joined text.

  Parameters
  ----------
  None

  Returns
  -------
  string
    UTF-8 markdown content of docs/GLOSSARY.md at generation time.

  Raises
  ------
  None
}
function GlossaryMarkdown: string;

implementation

uses
  SysUtils;

function GlossaryMarkdown: string;
var
  Builder: TAnsiStringBuilder;
  I: Integer;
begin
  Builder := TAnsiStringBuilder.Create;
  try
    for I := 0 to GlossaryLineCount - 1 do
    begin
      if I > 0 then
        Builder.Append(#10);
      Builder.Append(GlossaryLines[I]);
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
