(**
  PurpleRay SBOM Analyzer build-version unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Exposes the application identity and formats the generated version and commit
  metadata shown in the UI and embedded in generated SBOMs.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026purpleraysbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{PurpleRay SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/PurpleRay_SBOM_Analyzer}
  }
*)
unit uVersionInfo;

{$mode objfpc}{$H+}

interface

const
  AppName = 'PurpleRay SBOM Analyzer';
  AppExecutableName = 'purpleray-sbom-analyzer';
  AppVersion = '0.8.3';
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
  Returns the operator-managed product version for display in the UI.

  Parameters
  ----------
  None

  Returns
  -------
  string
    The exact product version embedded in generated release metadata.

  Raises
  ------
  None
}
function DisplayVersion: string;

implementation

function AbbreviatedCommit: string;
begin
  Result := AppCommit;
  if Result = 'unknown' then
    Result := '';
  if Length(Result) > 8 then
    SetLength(Result, 8);
end;

function DisplayVersion: string;
begin
  Result := AppVersion;
end;

end.
