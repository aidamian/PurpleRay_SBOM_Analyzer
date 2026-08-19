(**
  SBOM Analyzer build-version unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Exposes the application identity and formats the generated version and commit
  metadata shown in the UI and embedded in generated SBOMs.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026sbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uVersionInfo;

{$mode objfpc}{$H+}

interface

const
  AppName = 'SBOM Analyzer';
  AppExecutableName = 'sbom-analyzer';
  AppVersion = '0.1.0-dev';
  AppCommit = 'unknown';

{**
  Returns a display-safe short form of the configured commit identifier.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Up to eight commit characters, or an empty string when unknown.

  Raises
  ------
  None
}
function AbbreviatedCommit: string;

{**
  Combines semantic version and abbreviated commit metadata for the UI.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Version alone or version followed by the short commit in parentheses.

  Raises
  ------
  None
}
function DisplayVersion: string;

implementation

uses
  SysUtils;

function AbbreviatedCommit: string;
begin
  Result := AppCommit;
  if Result = 'unknown' then
    Result := '';
  if Length(Result) > 8 then
    SetLength(Result, 8);
end;

function DisplayVersion: string;
var
  CommitValue: string;
begin
  Result := AppVersion;
  CommitValue := AbbreviatedCommit;
  if CommitValue <> '' then
    Result := Result + ' (' + CommitValue + ')';
end;

end.
