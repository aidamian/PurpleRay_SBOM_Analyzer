(**
  PurpleRay SBOM Analyzer operating-system inspection unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Reconciles native binary enrichment behind one compatibility boundary. Scan
  analysis uses only stream-native internal ELF and PE parsers; the legacy
  pathname entry point is retained temporarily but deliberately performs no
  inspection and launches no external program.

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
unit uSystemInspector;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TSystemInspectionCancelCheck = function: Boolean of object;

  TSystemInspection = class
  public
    ToolName: string;
    ComponentVersion: string;
    FileVersion: string;
    ProductVersion: string;
    CompanyName: string;
    ProductName: string;
    SONAME: string;
    BuildID: string;
    Dependencies: TStringList;
    Details: TStringList;

    {**
      Creates sorted, duplicate-free dependency and detail collections.

      Parameters
      ----------
      None

      Returns
      -------
      TSystemInspection
        Newly initialized evidence container.

      Raises
      ------
      EOutOfMemory
        Propagated if the collections cannot be allocated.
    *}
    constructor Create;

    {**
      Releases the owned dependency and detail collections.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    destructor Destroy; override;

    {**
      Formats parser provenance and native evidence for artifact messages.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Compact deterministic single-line inspection summary.

      Raises
      ------
      EOutOfMemory
        Propagated if summary construction cannot be allocated.
    *}
    function Summary: string;
  end;

{**
  Parses historical readelf text for backward-compatible persisted tests.

  Parameters
  ----------
  AOutput
    Previously captured readelf dynamic-section and GNU build-ID output.
  AInspection
    Evidence container receiving recognized fields.

  Returns
  -------
  Boolean
    True when at least one recognized evidence item is found.

  Raises
  ------
  EOutOfMemory
    Propagated if bounded line parsing storage cannot be allocated.

  Notes
  -----
  Runtime scanning no longer invokes readelf. This parser remains solely for
  compatibility with historical data and unit-level regression coverage.
*}
function ParseReadElfOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;

{**
  Retains the legacy pathname inspection signature without reopening a file.

  Parameters
  ----------
  AFileName
    Ignored legacy pathname.
  AFormatName
    Ignored legacy format name.
  AInspection
    Always receives nil.
  ACancelCheck
    Ignored legacy cancellation callback.

  Returns
  -------
  Boolean
    Always False; callers must migrate to InspectBinarySystemEvidence.

  Raises
  ------
  None
*}
function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck = nil): Boolean;

{**
  Applies internal bounded native enrichment to a verified binary stream.

  Parameters
  ----------
  AStream
    Caller-owned verified and bounded binary stream.
  AFormatName
    Previously detected PE, ELF, or Mach-O format name.
  AInspection
    Receives a newly allocated evidence object on success, otherwise nil.
  ACancelCheck
    Optional callback checked before and after bounded parsing.

  Returns
  -------
  Boolean
    True when dependencies, versions, PE names, SONAME, or build ID are found.

  Raises
  ------
  None
    Malformed inputs and stream errors return False so a scan can retain its
    already established binary-header evidence.
*}
function InspectBinarySystemEvidence(AStream: TStream;
  const AFormatName: string; out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck = nil): Boolean;

implementation

uses
  uNativeDependencyInspector, uPEVersionInfo;

constructor TSystemInspection.Create;
begin
  inherited Create;
  Dependencies := TStringList.Create;
  Dependencies.Sorted := True;
  Dependencies.Duplicates := dupIgnore;
  Details := TStringList.Create;
  Details.Sorted := True;
  Details.Duplicates := dupIgnore;
end;

destructor TSystemInspection.Destroy;
begin
  Details.Free;
  Dependencies.Free;
  inherited Destroy;
end;

function TSystemInspection.Summary: string;
begin
  Result := '';
  if ToolName <> '' then
    Result := 'native inspection: ' + ToolName;
  if ComponentVersion <> '' then
    Result := Result + '; component version: ' + ComponentVersion;
  if CompanyName <> '' then
    Result := Result + '; company: ' + CompanyName;
  if ProductName <> '' then
    Result := Result + '; product: ' + ProductName;
  if SONAME <> '' then
    Result := Result + '; SONAME: ' + SONAME;
  if BuildID <> '' then
    Result := Result + '; build ID: ' + BuildID;
  if Dependencies.Count > 0 then
    Result := Result + '; linked libraries: ' +
      StringReplace(Dependencies.CommaText, ',', ', ', [rfReplaceAll]);
  if Details.Count > 0 then
    Result := Result + '; ' + StringReplace(Details.Text, LineEnding, '; ',
      [rfReplaceAll]);
  while (Length(Result) >= 2) and
    (Copy(Result, Length(Result) - 1, 2) = '; ') do
    Delete(Result, Length(Result) - 1, 2);
end;

function ParseReadElfOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;
var
  Lines: TStringList;
  I, OpenAt, CloseAt, MarkerAt: Integer;
  LineValue, Value: string;
begin
  Result := False;
  if AInspection = nil then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := AOutput;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      MarkerAt := Pos('(NEEDED)', LineValue);
      if MarkerAt > 0 then
      begin
        OpenAt := Pos('[', LineValue);
        CloseAt := Pos(']', LineValue);
        if (OpenAt > 0) and (CloseAt > OpenAt + 1) then
        begin
          Value := Copy(LineValue, OpenAt + 1, CloseAt - OpenAt - 1);
          AInspection.Dependencies.Add(Value);
          Result := True;
        end;
      end;
      MarkerAt := Pos('(SONAME)', LineValue);
      if MarkerAt > 0 then
      begin
        OpenAt := Pos('[', LineValue);
        CloseAt := Pos(']', LineValue);
        if (OpenAt > 0) and (CloseAt > OpenAt + 1) then
        begin
          Value := Copy(LineValue, OpenAt + 1, CloseAt - OpenAt - 1);
          AInspection.SONAME := Value;
          AInspection.ComponentVersion := NativeDependencyVersion(Value);
          Result := True;
        end;
      end;
      MarkerAt := Pos('Build ID:', LineValue);
      if MarkerAt > 0 then
      begin
        Value := Trim(Copy(LineValue, MarkerAt + Length('Build ID:'), MaxInt));
        if Value <> '' then
        begin
          AInspection.BuildID := Value;
          AInspection.Details.Add('build ID: ' + Value);
          Result := True;
        end;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck): Boolean;
begin
  AInspection := nil;
  Result := False;
end;

{**
  Copies parsed PE resource fields into the common inspection container.

  Parameters
  ----------
  AEvidence
    Stream-native PE VERSIONINFO values.
  AInspection
    Destination inspection object.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if detail strings cannot be allocated.
*}
procedure ApplyPEEvidence(const AEvidence: TPEVersionInfoEvidence;
  AInspection: TSystemInspection);
begin
  AInspection.FileVersion := AEvidence.FixedFileVersion;
  AInspection.ProductVersion := AEvidence.FixedProductVersion;
  AInspection.CompanyName := AEvidence.CompanyName;
  AInspection.ProductName := AEvidence.ProductName;
  if AInspection.ProductVersion <> '' then
    AInspection.ComponentVersion := AInspection.ProductVersion
  else
    AInspection.ComponentVersion := AInspection.FileVersion;
  if AInspection.FileVersion <> '' then
    AInspection.Details.Add('fixed file version: ' +
      AInspection.FileVersion);
  if AInspection.ProductVersion <> '' then
    AInspection.Details.Add('fixed product version: ' +
      AInspection.ProductVersion);
end;

function InspectBinarySystemEvidence(AStream: TStream;
  const AFormatName: string; out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck): Boolean;
var
  NativeMetadata: TNativeBinaryMetadata;
  PEEvidence: TPEVersionInfoEvidence;
  HasNativeEvidence, HasPEEvidence: Boolean;
begin
  Result := False;
  AInspection := nil;
  if (AStream = nil) or
    (Assigned(ACancelCheck) and ACancelCheck()) then
    Exit;
  AInspection := TSystemInspection.Create;
  try
    { PE imports are case-insensitive; ELF and Mach-O dependency identities are
      byte/case-sensitive and must not collapse distinct library names. }
    AInspection.Dependencies.CaseSensitive := not SameText(AFormatName, 'PE');
    HasNativeEvidence := False;
    HasPEEvidence := False;
    try
      HasNativeEvidence := InspectNativeEvidence(AStream, AFormatName,
        AInspection.Dependencies, NativeMetadata);
      AInspection.SONAME := NativeMetadata.SONAME;
      AInspection.BuildID := NativeMetadata.BuildID;
      if SameText(AFormatName, 'ELF') then
      begin
        AInspection.ToolName := 'internal ELF parser';
        if AInspection.SONAME <> '' then
          AInspection.ComponentVersion := NativeDependencyVersion(
            AInspection.SONAME);
      end
      else if SameText(AFormatName, 'PE') then
      begin
        HasPEEvidence := InspectPEVersionInfo(AStream, PEEvidence);
        if HasPEEvidence then
          ApplyPEEvidence(PEEvidence, AInspection);
        AInspection.ToolName := 'internal PE parser';
      end
      else if Pos('Mach-O', AFormatName) = 1 then
        AInspection.ToolName := 'internal Mach-O parser';
    except
      on E: Exception do
      begin
        FreeAndNil(AInspection);
        Exit(False);
      end;
    end;
    if Assigned(ACancelCheck) and ACancelCheck() then
    begin
      FreeAndNil(AInspection);
      Exit(False);
    end;
    Result := HasNativeEvidence or HasPEEvidence;
    if not Result then
      FreeAndNil(AInspection);
  except
    FreeAndNil(AInspection);
    raise;
  end;
end;

end.
