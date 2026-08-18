unit uVersionInfo;

{$mode objfpc}{$H+}

interface

const
  AppName = 'SBOM Analyzer';
  AppExecutableName = 'sbom-analyzer';
  AppVersion = '0.1.0-dev';
  AppCommit = 'unknown';

function AbbreviatedCommit: string;
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
