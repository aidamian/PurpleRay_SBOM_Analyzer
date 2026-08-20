(**
  PurpleRay SBOM Analyzer manifest-parser unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Parses supported package manifests and lock files into conservative component
  evidence without running package managers or evaluating build scripts.

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
unit uManifestParsers;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels, uArtifactIdentifier;

{**
  Returns the maximum byte size accepted by a manifest parser.

  Parameters
  ----------
  AParserKind
    Parser whose bounded input policy is requested.

  Returns
  -------
  Int64
    Zero for pkNone, otherwise the deterministic maximum input size in bytes.

  Raises
  ------
  None
}
function ManifestSizeLimit(AParserKind: TParserKind): Int64;

{**
  Dispatches one recognized artifact to its conservative format parser.

  Parameters
  ----------
  AFileName
    Local file to read.
  ARelativePath
    Root-relative evidence path recorded on produced components.
  AParserKind
    Parser selected by the artifact-identification unit.
  AArtifact
    Artifact record updated with parser status, messages, hash-independent
    evidence, and component count.
  AComponents
    Owned list receiving newly allocated TComponent instances.

  Returns
  -------
  None

  Raises
  ------
  None
    Format and I/O exceptions are converted into failed artifact status and a
    diagnostic message.
}
procedure ParseArtifact(const AFileName, ARelativePath: string;
  AParserKind: TParserKind; AArtifact: TArtifact; AComponents: TObjectList);

{**
  Builds a Package URL only when ecosystem, name, and exact version are valid.

  Parameters
  ----------
  AEcosystem
    Package ecosystem such as npm, pypi, maven, or nuget.
  AName
    Ecosystem-native package name.
  AVersion
    Candidate exact version.

  Returns
  -------
  string
    Percent-encoded purl, or an empty string for unsupported or inexact input.

  Raises
  ------
  None
}
function BuildPackageURL(const AEcosystem, AName, AVersion: string): string;

{**
  Determines whether version text denotes one exact resolved version.

  Parameters
  ----------
  AVersion
    Version or constraint text.

  Returns
  -------
  Boolean
    True only when no range, wildcard, variable, URL, or compound constraint is
    present.

  Raises
  ------
  None
}
function IsExactVersion(const AVersion: string): Boolean;

{**
  Determines whether version text is a recognizable declarative constraint.

  Parameters
  ----------
  AVersion
    Version, range, tag, local path, or source-reference text.

  Returns
  -------
  Boolean
    True only for range/wildcard constraint syntax that is safe to retain as
    ``requested-range``; paths, URLs, variables, and tags return False.

  Raises
  ------
  None
}
function IsVersionRange(const AVersion: string): Boolean;

{**
  Applies ecosystem rules when distinguishing resolved versions from requests.

  Parameters
  ----------
  AEcosystem
    Package ecosystem label.
  AVersion
    Candidate version text.

  Returns
  -------
  Boolean
    True only for a resolved version. For npm this requires a complete
    three-segment semantic version, so partial X-ranges and dist-tags fail.

  Raises
  ------
  None
}
function IsExactEcosystemVersion(const AEcosystem,
  AVersion: string): Boolean;

{**
  Applies ecosystem rules when recognizing safe version constraints.

  Parameters
  ----------
  AEcosystem
    Package ecosystem label.
  AVersion
    Candidate version or constraint text.

  Returns
  -------
  Boolean
    True for generic constraints and npm one/two-segment X-ranges; false for
    tags, paths, URLs, variables, and resolved versions.

  Raises
  ------
  None
}
function IsEcosystemVersionRange(const AEcosystem,
  AVersion: string): Boolean;

implementation

uses
  fpjson, DOM, XMLRead, uJSONUtils;

{**
  Rejects XML files containing document-type declarations before DOM parsing.

  Parameters
  ----------
  AFileName
    XML manifest to inspect in bounded chunks.

  Returns
  -------
  None

  Raises
  ------
  EFOpenError, EReadError
    Propagated when the manifest cannot be read.
  Exception
    Raised when a DOCTYPE declaration is found.
}
procedure RejectXMLDocumentTypes(const AFileName: string);
const
  Marker = '<!DOCTYPE';
  BufferSize = 64 * 1024;
var
  Stream: TFileStream;
  Buffer: array[0..BufferSize - 1] of Byte;
  CarryValue, ChunkValue, WindowValue: RawByteString;
  Count, CarryLength: Integer;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    CarryValue := '';
    repeat
      Count := Stream.Read(Buffer, SizeOf(Buffer));
      SetLength(ChunkValue, Count);
      if Count > 0 then
        Move(Buffer[0], ChunkValue[1], Count);
      WindowValue := CarryValue + ChunkValue;
      if Pos(Marker, UpperCase(string(WindowValue))) > 0 then
        raise Exception.Create('XML document type declarations are not allowed');
      CarryLength := Length(Marker) - 1;
      if Length(WindowValue) > CarryLength then
        CarryValue := Copy(WindowValue,
          Length(WindowValue) - CarryLength + 1, CarryLength)
      else
        CarryValue := WindowValue;
    until Count = 0;
  finally
    Stream.Free;
  end;
end;

{**
  Detects source references that must not become versions or exported ranges.

  Parameters
  ----------
  AVersion
    Candidate dependency-version text.

  Returns
  -------
  Boolean
    True for URLs, VCS selectors, workspace/local paths, aliases, variables,
    and other path-bearing source references.

  Raises
  ------
  None
}
function IsVersionSourceReference(const AVersion: string): Boolean;
var
  LowerVersion, VersionValue: string;
begin
  VersionValue := Trim(AVersion);
  LowerVersion := LowerCase(VersionValue);
  Result := (Pos('://', LowerVersion) > 0) or
    (Pos('git+', LowerVersion) > 0) or
    (Pos('file:', LowerVersion) > 0) or
    (Pos('link:', LowerVersion) > 0) or
    (Pos('workspace:', LowerVersion) > 0) or
    (Pos('path:', LowerVersion) > 0) or
    (Pos('npm:', LowerVersion) = 1) or
    (Pos('github:', LowerVersion) = 1) or
    (Pos('gitlab:', LowerVersion) = 1) or
    (Pos('bitbucket:', LowerVersion) = 1) or
    (Pos('ssh:', LowerVersion) = 1) or
    (Pos('git:', LowerVersion) = 1) or
    (Pos('git@', LowerVersion) = 1) or
    (Pos('/', VersionValue) > 0) or
    (Pos('\', VersionValue) > 0) or
    (Pos('#', VersionValue) > 0) or
    (Pos('$', VersionValue) > 0) or
    (Pos('{', VersionValue) > 0) or
    (Pos('}', VersionValue) > 0);
end;

function IsVersionRange(const AVersion: string): Boolean;
const
  ConstraintCharacters = ['<', '>', '=', '~', '^', '*', '|', ',', ' ',
    '[', ']', '(', ')'];
var
  I: Integer;
  VersionValue, LowerVersion: string;
begin
  VersionValue := Trim(AVersion);
  Result := False;
  if (VersionValue = '') or IsVersionSourceReference(VersionValue) then
    Exit;
  LowerVersion := LowerCase(VersionValue);
  for I := 1 to Length(VersionValue) do
  begin
    if VersionValue[I] in ConstraintCharacters then
      Exit(True);
    if (VersionValue[I] = '+') and (I = Length(VersionValue)) then
      Exit(True);
    if (LowerVersion[I] = 'x') and
      ((I = 1) or (LowerVersion[I - 1] in ['.', '-'])) and
      ((I = Length(LowerVersion)) or (LowerVersion[I + 1] in ['.', '-'])) then
      Exit(True);
  end;
end;

function IsExactVersion(const AVersion: string): Boolean;
var
  LowerVersion, VersionValue: string;
begin
  VersionValue := Trim(AVersion);
  LowerVersion := LowerCase(VersionValue);
  Result := (VersionValue <> '') and
    not IsVersionSourceReference(VersionValue) and
    not IsVersionRange(VersionValue) and
    (LowerVersion <> 'latest') and
    (LowerVersion <> 'next') and
    (LowerVersion <> 'stable') and
    (Pos('latest.', LowerVersion) <> 1);
end;

{**
  Counts numeric npm core-version segments and validates any exact suffix.

  Parameters
  ----------
  AVersion
    Candidate npm version without range operators or source references.
  ASegmentCount
    Receives the number of numeric dot-delimited core segments.
  AHasSuffix
    Receives True when prerelease or build metadata follows the core.

  Returns
  -------
  Boolean
    True when the candidate has a numeric core and a safe SemVer suffix.

  Raises
  ------
  None
}
function ParseNPMVersionShape(const AVersion: string; out ASegmentCount: Integer;
  out AHasSuffix: Boolean): Boolean;
var
  I, CoreEnd, SegmentStart: Integer;
  VersionValue: string;
begin
  ASegmentCount := 0;
  AHasSuffix := False;
  VersionValue := Trim(AVersion);
  if (VersionValue <> '') and (VersionValue[1] in ['v', 'V']) then
    Delete(VersionValue, 1, 1);
  if VersionValue = '' then
    Exit(False);
  CoreEnd := Length(VersionValue) + 1;
  for I := 1 to Length(VersionValue) do
    if VersionValue[I] in ['-', '+'] then
    begin
      CoreEnd := I;
      AHasSuffix := True;
      Break;
    end;
  if AHasSuffix then
  begin
    if CoreEnd = Length(VersionValue) then
      Exit(False);
    for I := CoreEnd + 1 to Length(VersionValue) do
      if not (VersionValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '-', '.',
        '+']) then
        Exit(False);
  end;
  SegmentStart := 1;
  for I := 1 to CoreEnd do
    if (I = CoreEnd) or (VersionValue[I] = '.') then
    begin
      if I = SegmentStart then
        Exit(False);
      while SegmentStart < I do
      begin
        if not (VersionValue[SegmentStart] in ['0'..'9']) then
          Exit(False);
        Inc(SegmentStart);
      end;
      Inc(ASegmentCount);
      SegmentStart := I + 1;
    end;
  Result := ASegmentCount > 0;
end;

function IsExactEcosystemVersion(const AEcosystem,
  AVersion: string): Boolean;
var
  SegmentCount: Integer;
  HasSuffix: Boolean;
begin
  Result := IsExactVersion(AVersion);
  if Result and SameText(Trim(AEcosystem), 'npm') then
    Result := ParseNPMVersionShape(AVersion, SegmentCount, HasSuffix) and
      (SegmentCount = 3);
end;

function IsEcosystemVersionRange(const AEcosystem,
  AVersion: string): Boolean;
var
  SegmentCount: Integer;
  HasSuffix: Boolean;
begin
  Result := IsVersionRange(AVersion);
  if Result or not SameText(Trim(AEcosystem), 'npm') or
    not IsExactVersion(AVersion) then
    Exit;
  Result := ParseNPMVersionShape(AVersion, SegmentCount, HasSuffix) and
    not HasSuffix and (SegmentCount in [1, 2]);
end;

{**
  Percent-encodes one Package URL component using UTF-8 source bytes.

  Parameters
  ----------
  AValue
    Component text to encode.
  AKeepSlash
    True when slash separators belong to an ecosystem namespace path.

  Returns
  -------
  string
    Package URL component with reserved bytes encoded using uppercase hex.

  Raises
  ------
  EOutOfMemory
    Propagated if the result string cannot be allocated.
}
function PercentEncode(const AValue: string; AKeepSlash: Boolean): string;
const
  HexChars = '0123456789ABCDEF';
var
  I: Integer;
  B: Byte;
begin
  Result := '';
  for I := 1 to Length(AValue) do
  begin
    B := Byte(AValue[I]);
    if (B in [Ord('a')..Ord('z'), Ord('A')..Ord('Z'), Ord('0')..Ord('9'),
      Ord('.'), Ord('_'), Ord('-'), Ord('~')]) or
      (AKeepSlash and (B = Ord('/'))) then
      Result := Result + Char(B)
    else
      Result := Result + '%' + HexChars[(B shr 4) + 1] +
        HexChars[(B and $0F) + 1];
  end;
end;

{**
  Reports whether a character is an ASCII letter or decimal digit.

  Parameters
  ----------
  AValue
    Character to classify.

  Returns
  -------
  Boolean
    True for ASCII A-Z, a-z, or 0-9; otherwise False.

  Raises
  ------
  None
}
function IsASCIIAlphaNumeric(AValue: Char): Boolean;
begin
  Result := AValue in ['A'..'Z', 'a'..'z', '0'..'9'];
end;

{**
  Validates a Python distribution name before PEP-503 normalization.

  Parameters
  ----------
  AName
    Candidate PyPI project name.

  Returns
  -------
  Boolean
    True when the name has alphanumeric endpoints and contains only the
    characters permitted for Python distribution names.

  Raises
  ------
  None
}
function IsValidPyPIName(const AName: string): Boolean;
var
  I: Integer;
begin
  Result := (AName <> '') and IsASCIIAlphaNumeric(AName[1]) and
    IsASCIIAlphaNumeric(AName[Length(AName)]);
  if not Result then
    Exit;
  for I := 1 to Length(AName) do
    if not IsASCIIAlphaNumeric(AName[I]) and
      not (AName[I] in ['.', '_', '-']) then
      Exit(False);
end;

{**
  Applies Python package-name normalization defined by PEP 503.

  Parameters
  ----------
  AName
    Valid PyPI project name whose display spelling must remain untouched.

  Returns
  -------
  string
    Lowercase name with every run of period, underscore, or hyphen replaced
    by one hyphen.

  Raises
  ------
  EOutOfMemory
    Propagated if the normalized string cannot be allocated.
}
function NormalizePyPIName(const AName: string): string;
var
  I: Integer;
  InSeparatorRun: Boolean;
  CharacterValue: Char;
begin
  Result := '';
  InSeparatorRun := False;
  for I := 1 to Length(AName) do
  begin
    CharacterValue := AName[I];
    if CharacterValue in ['.', '_', '-'] then
    begin
      if not InSeparatorRun then
        Result := Result + '-';
      InSeparatorRun := True;
    end
    else
    begin
      Result := Result + LowerCase(CharacterValue);
      InSeparatorRun := False;
    end;
  end;
end;

{**
  Builds the canonical path portion for an npm package name.

  Parameters
  ----------
  AName
    Unscoped name or scoped name in ``@scope/package`` form.
  APath
    Receives the lowercase and percent-encoded purl path on success.

  Returns
  -------
  Boolean
    True when the package name is complete and structurally valid.

  Raises
  ------
  EOutOfMemory
    Propagated if temporary or result strings cannot be allocated.
}
function TryBuildNPMPath(const AName: string; out APath: string): Boolean;
var
  NameValue, ScopeValue, PackageValue: string;
  ScopeSeparator: SizeInt;
begin
  APath := '';
  NameValue := LowerCase(Trim(AName));
  if NameValue = '' then
    Exit(False);
  if NameValue[1] <> '@' then
  begin
    if Pos('/', NameValue) > 0 then
      Exit(False);
    APath := PercentEncode(NameValue, False);
    Exit(APath <> '');
  end;
  ScopeSeparator := Pos('/', NameValue);
  if (ScopeSeparator <= 2) or (ScopeSeparator = Length(NameValue)) or
    (Pos('/', Copy(NameValue, ScopeSeparator + 1, MaxInt)) > 0) then
    Exit(False);
  ScopeValue := Copy(NameValue, 1, ScopeSeparator - 1);
  PackageValue := Copy(NameValue, ScopeSeparator + 1, MaxInt);
  APath := PercentEncode(ScopeValue, False) + '/' +
    PercentEncode(PackageValue, False);
  Result := True;
end;

{**
  Converts a resolved Gradle module name into a Maven purl path.

  Parameters
  ----------
  AName
    Gradle module coordinate in exact ``group:artifact`` form.
  APath
    Receives the encoded ``group/artifact`` path on success.

  Returns
  -------
  Boolean
    True only when both coordinate parts are present and no extra colon is
    supplied.

  Raises
  ------
  EOutOfMemory
    Propagated if temporary or result strings cannot be allocated.
}
function TryBuildGradleMavenPath(const AName: string;
  out APath: string): Boolean;
var
  SeparatorAt: SizeInt;
  GroupValue, ArtifactValue: string;
begin
  APath := '';
  SeparatorAt := Pos(':', AName);
  if (SeparatorAt <= 1) or (SeparatorAt = Length(AName)) or
    (Pos(':', Copy(AName, SeparatorAt + 1, MaxInt)) > 0) then
    Exit(False);
  GroupValue := Trim(Copy(AName, 1, SeparatorAt - 1));
  ArtifactValue := Trim(Copy(AName, SeparatorAt + 1, MaxInt));
  if (GroupValue = '') or (ArtifactValue = '') then
    Exit(False);
  APath := PercentEncode(GroupValue, False) + '/' +
    PercentEncode(ArtifactValue, False);
  Result := True;
end;

function BuildPackageURL(const AEcosystem, AName, AVersion: string): string;
var
  EcosystemValue, TypeName, NameValue, PackageName, VersionValue: string;
begin
  Result := '';
  NameValue := '';
  PackageName := Trim(AName);
  VersionValue := Trim(AVersion);
  EcosystemValue := LowerCase(Trim(AEcosystem));
  if (PackageName = '') or
    not IsExactEcosystemVersion(EcosystemValue, VersionValue) then
    Exit;
  case EcosystemValue of
    'npm':
      begin
        TypeName := 'npm';
        if not TryBuildNPMPath(PackageName, NameValue) then
          Exit;
      end;
    'pypi':
      begin
        TypeName := 'pypi';
        if not IsValidPyPIName(PackageName) then
          Exit;
        NameValue := PercentEncode(NormalizePyPIName(PackageName), False);
      end;
    'gradle':
      begin
        TypeName := 'maven';
        if not TryBuildGradleMavenPath(PackageName, NameValue) then
          Exit;
      end;
    'conda':
      begin
        TypeName := 'conda';
        NameValue := PercentEncode(PackageName, False);
      end;
    'go': TypeName := 'golang';
    'cargo': TypeName := 'cargo';
    'nuget': TypeName := 'nuget';
    'composer': TypeName := 'composer';
    'rubygems': TypeName := 'gem';
    'cocoapods': TypeName := 'cocoapods';
    'swift': TypeName := 'swift';
    'vcpkg': TypeName := 'generic';
    'conan': TypeName := 'conan';
  else
    Exit;
  end;
  if NameValue = '' then
    NameValue := PercentEncode(PackageName, (TypeName = 'composer') or
      (TypeName = 'golang') or (TypeName = 'swift'));
  Result := 'pkg:' + TypeName + '/' + NameValue + '@' +
    PercentEncode(VersionValue, False);
end;

{**
  Creates one component record from parser evidence and appends it to a list.

  Parameters
  ----------
  AComponents
    Owned list that receives the new component.
  AName
    Package name; blank names are ignored.
  AVersion
    Exact version or unresolved constraint text.
  AEcosystem
    Package ecosystem label.
  ARelativePath
    Root-relative evidence path.
  AParser
    Parser identifier that produced the evidence.
  AScope
    Dependency scope such as runtime, development, or resolved.
  AComponentType
    CycloneDX component type; defaults to library.
  APURL
    Explicit Package URL, or blank to derive one conservatively.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated when the component or its evidence storage cannot be allocated.
}
procedure AddComponent(AComponents: TObjectList; const AName, AVersion,
  AEcosystem, ARelativePath, AParser, AScope: string;
  const AComponentType: string = 'library'; const APURL: string = '');
var
  Component: TComponent;
begin
  if Trim(AName) = '' then
    Exit;
  Component := TComponent.Create;
  Component.Name := Trim(AName);
  Component.Version := Trim(AVersion);
  Component.Ecosystem := AEcosystem;
  Component.SourceArtifact := ARelativePath;
  Component.SourceParser := AParser;
  Component.DependencyScope := AScope;
  Component.ComponentType := AComponentType;
  if APURL <> '' then
    Component.PackageURL := APURL
  else if SameText(AParser, 'conservative-cargo-toml') then
    Component.PackageURL := ''
  else
    Component.PackageURL := BuildPackageURL(AEcosystem, Component.Name,
      Component.Version);
  Component.EvidencePaths.Add(ARelativePath);
  AComponents.Add(Component);
end;

function ScalarJSONValue(AData: TJSONData): string;
begin
  if (AData = nil) or (AData.JSONType in [jtObject, jtArray, jtNull]) then
    Result := ''
  else
    Result := AData.AsString;
end;

procedure ParseNamedJSONDependencies(AObject: TJSONObject;
  AComponents: TObjectList; const AEcosystem, ARelativePath, AParser,
  AScope: string);
var
  I: Integer;
begin
  if AObject = nil then
    Exit;
  for I := 0 to AObject.Count - 1 do
    AddComponent(AComponents, AObject.Names[I],
      ScalarJSONValue(AObject.Items[I]), AEcosystem, ARelativePath, AParser,
      AScope);
end;

{**
  Parses an npm package.json manifest and its declared dependency sections.

  Parameters
  ----------
  AFileName
    JSON manifest to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving parsed project and dependency components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for invalid JSON, an invalid root type, or file I/O failure.
}
procedure ParsePackageJSON(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The package manifest root must be a JSON object');
    Root := TJSONObject(Data);
    NameValue := JSONString(Root, 'name');
    VersionValue := JSONString(Root, 'version');
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'npm', ARelativePath,
        'package-json', 'project', 'application');
    ParseNamedJSONDependencies(JSONObject(Root, 'dependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'runtime');
    ParseNamedJSONDependencies(JSONObject(Root, 'devDependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'development');
    ParseNamedJSONDependencies(JSONObject(Root, 'optionalDependencies'),
      AComponents, 'npm', ARelativePath, 'package-json', 'optional');
    ParseNamedJSONDependencies(JSONObject(Root, 'peerDependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'peer');
  finally
    Data.Free;
  end;
end;

function NPMNameFromPackagePath(const APath: string): string;
var
  Marker: SizeInt;
begin
  Result := APath;
  Marker := Pos('node_modules/', Result);
  while Marker > 0 do
  begin
    Delete(Result, 1, Marker + Length('node_modules/') - 1);
    Marker := Pos('node_modules/', Result);
  end;
end;

procedure ParseLegacyPackageLockDependencies(AObject: TJSONObject;
  AComponents: TObjectList; const ARelativePath: string);
var
  I: Integer;
  Entry, Nested: TJSONObject;
begin
  if AObject = nil then
    Exit;
  for I := 0 to AObject.Count - 1 do
  begin
    if AObject.Items[I].JSONType <> jtObject then
      Continue;
    Entry := TJSONObject(AObject.Items[I]);
    AddComponent(AComponents, AObject.Names[I], JSONString(Entry, 'version'),
      'npm', ARelativePath, 'package-lock-json', 'resolved');
    Nested := JSONObject(Entry, 'dependencies');
    if Nested <> nil then
      ParseLegacyPackageLockDependencies(Nested, AComponents, ARelativePath);
  end;
end;

{**
  Parses modern and legacy npm package-lock.json dependency layouts.

  Parameters
  ----------
  AFileName
    Lock file to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved npm components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for invalid JSON, an invalid root type, or file I/O failure.
}
procedure ParsePackageLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root, Packages, Entry: TJSONObject;
  I: Integer;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The package lock root must be a JSON object');
    Root := TJSONObject(Data);
    Packages := JSONObject(Root, 'packages');
    if Packages <> nil then
      for I := 0 to Packages.Count - 1 do
      begin
        if Packages.Items[I].JSONType <> jtObject then
          Continue;
        Entry := TJSONObject(Packages.Items[I]);
        NameValue := JSONString(Entry, 'name');
        if (NameValue = '') and (Packages.Names[I] <> '') then
          NameValue := NPMNameFromPackagePath(Packages.Names[I]);
        VersionValue := JSONString(Entry, 'version');
        if Packages.Names[I] = '' then
          AddComponent(AComponents, NameValue, VersionValue, 'npm',
            ARelativePath, 'package-lock-json', 'project', 'application')
        else
          AddComponent(AComponents, NameValue, VersionValue, 'npm',
            ARelativePath, 'package-lock-json', 'resolved');
      end;
    if Packages = nil then
      ParseLegacyPackageLockDependencies(JSONObject(Root, 'dependencies'),
        AComponents, ARelativePath);
  finally
    Data.Free;
  end;
end;

function StripInlineComment(const ALine: string): string;
var
  I: Integer;
begin
  Result := ALine;
  for I := 2 to Length(Result) do
    if (Result[I] = '#') and (Result[I - 1] in [' ', #9]) then
    begin
      Result := Copy(Result, 1, I - 1);
      Break;
    end;
  Result := Trim(Result);
end;

procedure ParseRequirementLine(const ALine, ARelativePath: string;
  AComponents: TObjectList);
var
  LineValue, NameValue, VersionValue: string;
  OperatorAt, ExtrasAt, MarkerAt, DirectAt, I: SizeInt;
begin
  LineValue := StripInlineComment(ALine);
  if (LineValue = '') or (LineValue[1] in ['#', '-']) then
    Exit;
  MarkerAt := Pos(';', LineValue);
  if MarkerAt > 0 then
    LineValue := Trim(Copy(LineValue, 1, MarkerAt - 1));
  DirectAt := Pos(' @ ', LineValue);
  if DirectAt > 0 then
  begin
    NameValue := Trim(Copy(LineValue, 1, DirectAt - 1));
    AddComponent(AComponents, NameValue, '', 'PyPI', ARelativePath,
      'requirements-text', 'runtime');
    Exit;
  end;
  OperatorAt := Pos('===', LineValue);
  if OperatorAt > 0 then
  begin
    NameValue := Trim(Copy(LineValue, 1, OperatorAt - 1));
    VersionValue := Trim(Copy(LineValue, OperatorAt + 3, MaxInt));
  end
  else
  begin
    OperatorAt := Pos('==', LineValue);
    if OperatorAt > 0 then
    begin
      NameValue := Trim(Copy(LineValue, 1, OperatorAt - 1));
      VersionValue := Trim(Copy(LineValue, OperatorAt + 2, MaxInt));
    end
    else
    begin
      OperatorAt := 0;
      for I := 1 to Length(LineValue) do
        if LineValue[I] in ['<', '>', '~', '!', '='] then
        begin
          OperatorAt := I;
          Break;
        end;
      if OperatorAt > 0 then
      begin
        NameValue := Trim(Copy(LineValue, 1, OperatorAt - 1));
        VersionValue := Trim(Copy(LineValue, OperatorAt, MaxInt));
      end
      else
      begin
        NameValue := LineValue;
        VersionValue := '';
      end;
    end;
  end;
  ExtrasAt := Pos('[', NameValue);
  if ExtrasAt > 0 then
    NameValue := Copy(NameValue, 1, ExtrasAt - 1);
  AddComponent(AComponents, NameValue, VersionValue, 'PyPI', ARelativePath,
    'requirements-text', 'runtime');
end;

{**
  Parses Python requirements text without resolving ranges or direct URLs.

  Parameters
  ----------
  AFileName
    Requirements file to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving declared Python components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated when the file cannot be read or a component cannot be allocated.
}
procedure ParseRequirements(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I: Integer;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    for I := 0 to Lines.Count - 1 do
      ParseRequirementLine(Lines[I], ARelativePath, AComponents);
  finally
    Lines.Free;
  end;
end;

{**
  Parses direct and block-form Go module requirements.

  Parameters
  ----------
  AFileName
    go.mod file to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving Go modules.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated when the file cannot be read or results cannot be allocated.
}
procedure ParseGoMod(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines, Parts: TStringList;
  I: Integer;
  LineValue, ScopeValue: string;
  InRequire: Boolean;
begin
  Lines := TStringList.Create;
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ' ';
    Parts.StrictDelimiter := True;
    Lines.LoadFromFile(AFileName);
    InRequire := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      if LineValue = 'require (' then
      begin
        InRequire := True;
        Continue;
      end;
      if InRequire and (LineValue = ')') then
      begin
        InRequire := False;
        Continue;
      end;
      if (not InRequire) and (Pos('require ', LineValue) = 1) then
        Delete(LineValue, 1, Length('require '))
      else if not InRequire then
        Continue;
      ScopeValue := 'runtime';
      if Pos('// indirect', LineValue) > 0 then
      begin
        ScopeValue := 'indirect';
        LineValue := Trim(Copy(LineValue, 1, Pos('// indirect', LineValue) - 1));
      end;
      while Pos('  ', LineValue) > 0 do
        LineValue := StringReplace(LineValue, '  ', ' ', [rfReplaceAll]);
      Parts.DelimitedText := LineValue;
      if Parts.Count >= 2 then
        AddComponent(AComponents, Parts[0], Parts[1], 'Go', ARelativePath,
          'go-mod-text', ScopeValue);
    end;
  finally
    Parts.Free;
    Lines.Free;
  end;
end;

function LocalNodeName(ANode: TDOMNode): string;
var
  ColonAt: SizeInt;
begin
  Result := UTF8Encode(ANode.NodeName);
  ColonAt := LastDelimiter(':', Result);
  if ColonAt > 0 then
    Result := Copy(Result, ColonAt + 1, MaxInt);
end;

function ChildElement(ANode: TDOMNode; const AName: string): TDOMElement;
var
  Child: TDOMNode;
begin
  Result := nil;
  if ANode = nil then
    Exit;
  Child := ANode.FirstChild;
  while Child <> nil do
  begin
    if (Child is TDOMElement) and SameText(LocalNodeName(Child), AName) then
      Exit(TDOMElement(Child));
    Child := Child.NextSibling;
  end;
end;

function ChildText(ANode: TDOMNode; const AName: string): string;
var
  Element: TDOMElement;
begin
  Element := ChildElement(ANode, AName);
  if Element <> nil then
    Result := Trim(UTF8Encode(Element.TextContent))
  else
    Result := '';
end;

function AttributeValue(AElement: TDOMElement; const AName: string): string;
begin
  Result := '';
  if (AElement <> nil) and AElement.HasAttribute(UTF8Decode(AName)) then
    Result := UTF8Encode(AElement.GetAttribute(UTF8Decode(AName)));
end;

{**
  Converts Maven dependency metadata to the analyzer's stable scope vocabulary.

  Parameters
  ----------
  AScope
    Raw Maven scope; blank means Maven's default compile scope.
  AOptional
    Raw Maven optional flag.

  Returns
  -------
  string
    ``runtime``, ``development``, ``optional``, or a retained Maven scope such
    as ``provided`` or ``system``.

  Raises
  ------
  None
}
function MavenDependencyScope(const AScope, AOptional: string): string;
begin
  if SameText(Trim(AOptional), 'true') then
    Exit('optional');
  Result := LowerCase(Trim(AScope));
  if (Result = '') or (Result = 'compile') or (Result = 'runtime') then
    Result := 'runtime'
  else if Result = 'test' then
    Result := 'development';
end;

procedure WalkMavenDependencies(ANode: TDOMNode; AComponents: TObjectList;
  const ARelativePath: string);
var
  Child: TDOMNode;
  GroupID, ArtifactID, VersionValue, ScopeValue, OptionalValue, PURL: string;
begin
  if ANode = nil then
    Exit;
  if (ANode is TDOMElement) and SameText(LocalNodeName(ANode), 'dependency') then
  begin
    GroupID := ChildText(ANode, 'groupId');
    ArtifactID := ChildText(ANode, 'artifactId');
    VersionValue := ChildText(ANode, 'version');
    ScopeValue := LowerCase(ChildText(ANode, 'scope'));
    if ScopeValue = 'import' then
      Exit;
    OptionalValue := ChildText(ANode, 'optional');
    ScopeValue := MavenDependencyScope(ScopeValue, OptionalValue);
    PURL := '';
    if (GroupID <> '') and (ArtifactID <> '') and IsExactVersion(VersionValue) then
      PURL := 'pkg:maven/' + PercentEncode(GroupID, False) + '/' +
        PercentEncode(ArtifactID, False) + '@' + PercentEncode(VersionValue, False);
    AddComponent(AComponents, ArtifactID, VersionValue, 'Maven', ARelativePath,
      'maven-pom-xml', ScopeValue, 'library', PURL);
    Exit;
  end;
  Child := ANode.FirstChild;
  while Child <> nil do
  begin
    WalkMavenDependencies(Child, AComponents, ARelativePath);
    Child := Child.NextSibling;
  end;
end;

{**
  Parses dependency elements from a Maven POM after the XML safety check.

  Parameters
  ----------
  AFileName
    Maven XML manifest to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving Maven dependencies.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for unsafe or malformed XML and file I/O failures.
}
procedure ParseMavenPOM(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Document: TXMLDocument;
begin
  RejectXMLDocumentTypes(AFileName);
  ReadXMLFile(Document, AFileName);
  try
    WalkMavenDependencies(Document.DocumentElement, AComponents, ARelativePath);
  finally
    Document.Free;
  end;
end;

procedure WalkMSBuildReferences(ANode: TDOMNode; AComponents: TObjectList;
  const ARelativePath, AParser: string; ACentral: Boolean);
var
  Child: TDOMNode;
  Element: TDOMElement;
  NameValue, VersionValue: string;
begin
  if ANode = nil then
    Exit;
  if ANode is TDOMElement then
  begin
    Element := TDOMElement(ANode);
    if (not ACentral and SameText(LocalNodeName(ANode), 'PackageReference')) or
      (ACentral and SameText(LocalNodeName(ANode), 'PackageVersion')) then
    begin
      NameValue := AttributeValue(Element, 'Include');
      if NameValue = '' then
        NameValue := AttributeValue(Element, 'Update');
      VersionValue := AttributeValue(Element, 'Version');
      if VersionValue = '' then
        VersionValue := ChildText(Element, 'Version');
      AddComponent(AComponents, NameValue, VersionValue, 'NuGet', ARelativePath,
        AParser, 'runtime');
    end;
  end;
  Child := ANode.FirstChild;
  while Child <> nil do
  begin
    WalkMSBuildReferences(Child, AComponents, ARelativePath, AParser, ACentral);
    Child := Child.NextSibling;
  end;
end;

{**
  Parses NuGet references from MSBuild or central package-management XML.

  Parameters
  ----------
  AFileName
    XML project or package-properties file to read.
  ARelativePath
    Root-relative evidence path.
  AParser
    Parser identifier stored as component evidence.
  AComponents
    Owned list receiving NuGet references.
  ACentral
    True for PackageVersion elements; False for PackageReference elements.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for unsafe or malformed XML and file I/O failures.
}
procedure ParseMSBuild(const AFileName, ARelativePath, AParser: string;
  AComponents: TObjectList; ACentral: Boolean);
var
  Document: TXMLDocument;
begin
  RejectXMLDocumentTypes(AFileName);
  ReadXMLFile(Document, AFileName);
  try
    WalkMSBuildReferences(Document.DocumentElement, AComponents, ARelativePath,
      AParser, ACentral);
  finally
    Document.Free;
  end;
end;

procedure ParseNuGetFramework(AFramework: TJSONObject;
  AComponents: TObjectList; const ARelativePath: string);
var
  I: Integer;
  Entry: TJSONObject;
  VersionValue: string;
begin
  if AFramework = nil then
    Exit;
  for I := 0 to AFramework.Count - 1 do
  begin
    if AFramework.Items[I].JSONType <> jtObject then
      Continue;
    Entry := TJSONObject(AFramework.Items[I]);
    VersionValue := JSONString(Entry, 'resolved');
    if VersionValue = '' then
      VersionValue := JSONString(Entry, 'requested');
    AddComponent(AComponents, AFramework.Names[I], VersionValue, 'NuGet',
      ARelativePath, 'nuget-lock-json', JSONString(Entry, 'type', 'resolved'));
  end;
end;

procedure ParseNuGetLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Dependencies: TJSONObject;
  I: Integer;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The NuGet lock root must be a JSON object');
    Dependencies := JSONObject(TJSONObject(Data), 'dependencies');
    if Dependencies <> nil then
      for I := 0 to Dependencies.Count - 1 do
        if Dependencies.Items[I].JSONType = jtObject then
          ParseNuGetFramework(TJSONObject(Dependencies.Items[I]), AComponents,
            ARelativePath);
  finally
    Data.Free;
  end;
end;

procedure ParseComposerJSON(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The Composer manifest root must be a JSON object');
    Root := TJSONObject(Data);
    ParseNamedJSONDependencies(JSONObject(Root, 'require'), AComponents,
      'Composer', ARelativePath, 'composer-json', 'runtime');
    ParseNamedJSONDependencies(JSONObject(Root, 'require-dev'), AComponents,
      'Composer', ARelativePath, 'composer-json', 'development');
  finally
    Data.Free;
  end;
end;

procedure ParseComposerPackageArray(AArray: TJSONArray; AComponents: TObjectList;
  const ARelativePath, AScope: string);
var
  I: Integer;
  Entry: TJSONObject;
begin
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if AArray.Items[I].JSONType = jtObject then
    begin
      Entry := TJSONObject(AArray.Items[I]);
      AddComponent(AComponents, JSONString(Entry, 'name'),
        JSONString(Entry, 'version'), 'Composer', ARelativePath,
        'composer-lock-json', AScope);
    end;
end;

procedure ParseComposerLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The Composer lock root must be a JSON object');
    Root := TJSONObject(Data);
    ParseComposerPackageArray(JSONArray(Root, 'packages'), AComponents,
      ARelativePath, 'runtime');
    ParseComposerPackageArray(JSONArray(Root, 'packages-dev'), AComponents,
      ARelativePath, 'development');
  finally
    Data.Free;
  end;
end;

{**
  Walks Lazarus project XML and records declared required packages.

  Parameters
  ----------
  ANode
    Current DOM node to inspect recursively.
  AComponents
    Owned list receiving Free Pascal package components.
  ARelativePath
    Root-relative evidence path recorded on produced components.
  AInRequiredPackages
    True when the current traversal branch is already beneath a
    RequiredPackages element.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated when component or traversal data cannot be allocated.
}
procedure WalkLazarusRequirements(ANode: TDOMNode; AComponents: TObjectList;
  const ARelativePath: string; AInRequiredPackages: Boolean);
var
  Child: TDOMNode;
  Element: TDOMElement;
  NameElement: TDOMElement;
  NameValue: string;
  InRequired: Boolean;
begin
  if ANode = nil then
    Exit;
  InRequired := AInRequiredPackages or
    SameText(LocalNodeName(ANode), 'RequiredPackages');
  if InRequired and (ANode is TDOMElement) and
    (Pos('Item', LocalNodeName(ANode)) = 1) then
  begin
    Element := TDOMElement(ANode);
    NameElement := ChildElement(Element, 'PackageName');
    if NameElement = nil then
      NameElement := ChildElement(Element, 'Name');
    NameValue := '';
    if NameElement <> nil then
    begin
      NameValue := AttributeValue(NameElement, 'Value');
      if NameValue = '' then
        NameValue := Trim(UTF8Encode(NameElement.TextContent));
    end;
    AddComponent(AComponents, NameValue, '', 'FreePascal', ARelativePath,
      'lazarus-project-xml', 'build');
  end;
  Child := ANode.FirstChild;
  while Child <> nil do
  begin
    WalkLazarusRequirements(Child, AComponents, ARelativePath, InRequired);
    Child := Child.NextSibling;
  end;
end;

procedure ParseLazarusXML(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Document: TXMLDocument;
begin
  RejectXMLDocumentTypes(AFileName);
  ReadXMLFile(Document, AFileName);
  try
    WalkLazarusRequirements(Document.DocumentElement, AComponents,
      ARelativePath, False);
  finally
    Document.Free;
  end;
end;

procedure ParsePipfileSection(AObject: TJSONObject; AComponents: TObjectList;
  const ARelativePath, AScope: string);
var
  I: Integer;
  Entry: TJSONData;
  VersionValue: string;
begin
  if AObject = nil then
    Exit;
  for I := 0 to AObject.Count - 1 do
  begin
    Entry := AObject.Items[I];
    if Entry.JSONType = jtObject then
      VersionValue := JSONString(TJSONObject(Entry), 'version')
    else
      VersionValue := ScalarJSONValue(Entry);
    if Pos('==', VersionValue) = 1 then
      Delete(VersionValue, 1, 2);
    AddComponent(AComponents, AObject.Names[I], VersionValue, 'PyPI',
      ARelativePath, 'pipfile-lock-json', AScope);
  end;
end;

procedure ParsePipfileLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The Pipfile lock root must be a JSON object');
    Root := TJSONObject(Data);
    ParsePipfileSection(JSONObject(Root, 'default'), AComponents,
      ARelativePath, 'runtime');
    ParsePipfileSection(JSONObject(Root, 'develop'), AComponents,
      ARelativePath, 'development');
  finally
    Data.Free;
  end;
end;

procedure ParseGoSum(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines, Parts: TStringList;
  I: Integer;
  LineValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ' ';
    Parts.StrictDelimiter := True;
    Lines.LoadFromFile(AFileName);
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      while Pos('  ', LineValue) > 0 do
        LineValue := StringReplace(LineValue, '  ', ' ', [rfReplaceAll]);
      Parts.DelimitedText := LineValue;
      if Parts.Count < 2 then
        Continue;
      VersionValue := Parts[1];
      if Pos('/go.mod', VersionValue) > 0 then
        Delete(VersionValue, Pos('/go.mod', VersionValue), MaxInt);
      AddComponent(AComponents, Parts[0], VersionValue, 'Go', ARelativePath,
        'conservative-go-sum', 'resolved');
    end;
  finally
    Parts.Free;
    Lines.Free;
  end;
end;

function Unquote(const AValue: string): string;
begin
  Result := Trim(AValue);
  if (Length(Result) >= 2) and
    (((Result[1] = '"') and (Result[Length(Result)] = '"')) or
    ((Result[1] = '''') and (Result[Length(Result)] = ''''))) then
    Result := Copy(Result, 2, Length(Result) - 2);
end;

procedure ParseLockNameVersionBlocks(const AFileName, ARelativePath,
  AEcosystem, AParser: string; AComponents: TObjectList);
var
  Lines: TStringList;
  I, EqualsAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InPackage: Boolean;

  procedure Emit;
  begin
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, AEcosystem,
        ARelativePath, AParser, 'resolved');
    NameValue := '';
    VersionValue := '';
  end;

begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    NameValue := '';
    VersionValue := '';
    InPackage := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      if (LineValue = '[[package]]') then
      begin
        Emit;
        InPackage := True;
        Continue;
      end;
      if not InPackage then
        Continue;
      EqualsAt := Pos('=', LineValue);
      if EqualsAt = 0 then
        Continue;
      if SameText(Trim(Copy(LineValue, 1, EqualsAt - 1)), 'name') then
        NameValue := Unquote(Copy(LineValue, EqualsAt + 1, MaxInt))
      else if SameText(Trim(Copy(LineValue, 1, EqualsAt - 1)), 'version') then
        VersionValue := Unquote(Copy(LineValue, EqualsAt + 1, MaxInt));
    end;
    Emit;
  finally
    Lines.Free;
  end;
end;

procedure ParseCargoTOML(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, EqualsAt: Integer;
  LineValue, SectionValue, NameValue, VersionValue, ScopeValue: string;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    SectionValue := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := StripInlineComment(Lines[I]);
      if (Length(LineValue) >= 2) and (LineValue[1] = '[') and
        (LineValue[Length(LineValue)] = ']') then
      begin
        SectionValue := LowerCase(Copy(LineValue, 2, Length(LineValue) - 2));
        Continue;
      end;
      if (SectionValue <> 'dependencies') and
        (SectionValue <> 'dev-dependencies') and
        (SectionValue <> 'build-dependencies') then
        Continue;
      EqualsAt := Pos('=', LineValue);
      if EqualsAt = 0 then
        Continue;
      NameValue := Trim(Copy(LineValue, 1, EqualsAt - 1));
      VersionValue := Trim(Copy(LineValue, EqualsAt + 1, MaxInt));
      if Pos('{', VersionValue) = 1 then
      begin
        EqualsAt := Pos('version', LowerCase(VersionValue));
        if EqualsAt > 0 then
        begin
          Delete(VersionValue, 1, EqualsAt + Length('version') - 1);
          EqualsAt := Pos('=', VersionValue);
          if EqualsAt > 0 then
            Delete(VersionValue, 1, EqualsAt);
          EqualsAt := Pos(',', VersionValue);
          if EqualsAt > 0 then
            VersionValue := Copy(VersionValue, 1, EqualsAt - 1);
        end
        else
          VersionValue := '';
      end;
      case SectionValue of
        'dependencies': ScopeValue := 'runtime';
        'dev-dependencies': ScopeValue := 'development';
        'build-dependencies': ScopeValue := 'build';
      else
        ScopeValue := SectionValue;
      end;
      AddComponent(AComponents, Unquote(NameValue), Unquote(VersionValue),
        'Cargo', ARelativePath, 'conservative-cargo-toml', ScopeValue);
    end;
  finally
    Lines.Free;
  end;
end;

procedure ParseYarnLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, AtPos, CommaAt: Integer;
  LineValue, NameValue, VersionValue: string;

  procedure Emit;
  begin
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'npm', ARelativePath,
        'conservative-yarn-lock', 'resolved');
    NameValue := '';
    VersionValue := '';
  end;

begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    NameValue := '';
    VersionValue := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Lines[I];
      if (LineValue <> '') and not (LineValue[1] in [' ', #9, '#']) and
        (LineValue[Length(LineValue)] = ':') then
      begin
        Emit;
        Delete(LineValue, Length(LineValue), 1);
        CommaAt := Pos(',', LineValue);
        if CommaAt > 0 then
          LineValue := Copy(LineValue, 1, CommaAt - 1);
        LineValue := Unquote(LineValue);
        if (Length(LineValue) > 0) and (LineValue[1] = '@') then
          AtPos := Pos('@', LineValue, 2)
        else
          AtPos := Pos('@', LineValue);
        if AtPos > 0 then
          NameValue := Copy(LineValue, 1, AtPos - 1)
        else
          NameValue := LineValue;
      end
      else if Pos('version ', Trim(LineValue)) = 1 then
        VersionValue := Unquote(Trim(Copy(Trim(LineValue), 9, MaxInt)));
    end;
    Emit;
  finally
    Lines.Free;
  end;
end;

procedure ParseGradleLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines, Parts: TStringList;
  I, EqualsAt: Integer;
  LineValue, NameValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  Parts := TStringList.Create;
  try
    Parts.Delimiter := ':';
    Parts.StrictDelimiter := True;
    Lines.LoadFromFile(AFileName);
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      if (LineValue = '') or (LineValue[1] = '#') then
        Continue;
      EqualsAt := Pos('=', LineValue);
      if EqualsAt > 0 then
        LineValue := Copy(LineValue, 1, EqualsAt - 1);
      Parts.DelimitedText := LineValue;
      if Parts.Count >= 3 then
      begin
        NameValue := Parts[0] + ':' + Parts[1];
        VersionValue := Parts[2];
        AddComponent(AComponents, NameValue, VersionValue, 'Gradle',
          ARelativePath, 'conservative-gradle-lock', 'resolved');
      end;
    end;
  finally
    Parts.Free;
    Lines.Free;
  end;
end;

procedure ParseGemLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, OpenAt, CloseAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InSpecs: Boolean;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    InSpecs := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Lines[I];
      if Trim(LineValue) = 'specs:' then
      begin
        InSpecs := True;
        Continue;
      end;
      if InSpecs and (LineValue <> '') and not (LineValue[1] = ' ') then
        InSpecs := False;
      if not InSpecs or (Pos('    ', LineValue) <> 1) or
        (Pos('      ', LineValue) = 1) then
        Continue;
      LineValue := Trim(LineValue);
      OpenAt := Pos(' (', LineValue);
      CloseAt := Pos(')', LineValue);
      if (OpenAt > 0) and (CloseAt > OpenAt) then
      begin
        NameValue := Copy(LineValue, 1, OpenAt - 1);
        VersionValue := Copy(LineValue, OpenAt + 2, CloseAt - OpenAt - 2);
        AddComponent(AComponents, NameValue, VersionValue, 'RubyGems',
          ARelativePath, 'conservative-gemfile-lock', 'resolved');
      end;
    end;
  finally
    Lines.Free;
  end;
end;

procedure ParseEnvironmentYAML(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, EqualsAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InDependencies: Boolean;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    InDependencies := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Lines[I];
      if Trim(LineValue) = 'dependencies:' then
      begin
        InDependencies := True;
        Continue;
      end;
      if InDependencies and (LineValue <> '') and not (LineValue[1] in [' ', #9]) then
        InDependencies := False;
      if not InDependencies then
        Continue;
      LineValue := Trim(LineValue);
      if Pos('- ', LineValue) <> 1 then
        Continue;
      Delete(LineValue, 1, 2);
      if (LineValue = 'pip:') or (LineValue = '') then
        Continue;
      EqualsAt := Pos('=', LineValue);
      if EqualsAt > 0 then
      begin
        NameValue := Copy(LineValue, 1, EqualsAt - 1);
        VersionValue := Copy(LineValue, EqualsAt + 1, MaxInt);
        EqualsAt := Pos('=', VersionValue);
        if EqualsAt > 0 then
          VersionValue := Copy(VersionValue, 1, EqualsAt - 1);
      end
      else
      begin
        NameValue := LineValue;
        VersionValue := '';
      end;
      AddComponent(AComponents, NameValue, VersionValue, 'Conda',
        ARelativePath, 'conservative-conda-yaml', 'runtime');
    end;
  finally
    Lines.Free;
  end;
end;

procedure ParseSwiftPins(AArray: TJSONArray; AComponents: TObjectList;
  const ARelativePath: string);
var
  I: Integer;
  Entry, State: TJSONObject;
  NameValue, VersionValue: string;
begin
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if AArray.Items[I].JSONType = jtObject then
    begin
      Entry := TJSONObject(AArray.Items[I]);
      NameValue := JSONString(Entry, 'identity');
      if NameValue = '' then
        NameValue := JSONString(Entry, 'package');
      State := JSONObject(Entry, 'state');
      VersionValue := JSONString(State, 'version');
      if VersionValue = '' then
        VersionValue := JSONString(State, 'revision');
      AddComponent(AComponents, NameValue, VersionValue, 'Swift',
        ARelativePath, 'conservative-swift-resolved-json', 'resolved');
    end;
end;

procedure ParsePackageResolved(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root, ObjectValue: TJSONObject;
  Pins: TJSONArray;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The Swift resolved root must be a JSON object');
    Root := TJSONObject(Data);
    Pins := JSONArray(Root, 'pins');
    if Pins = nil then
    begin
      ObjectValue := JSONObject(Root, 'object');
      Pins := JSONArray(ObjectValue, 'pins');
    end;
    ParseSwiftPins(Pins, AComponents, ARelativePath);
  finally
    Data.Free;
  end;
end;

procedure ParsePodfileLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, OpenAt, CloseAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InPods: Boolean;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    InPods := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Lines[I];
      if Trim(LineValue) = 'PODS:' then
      begin
        InPods := True;
        Continue;
      end;
      if InPods and (LineValue <> '') and not (LineValue[1] in [' ', #9]) then
        InPods := False;
      if not InPods or (Pos('  - ', LineValue) <> 1) then
        Continue;
      LineValue := Trim(Copy(LineValue, 5, MaxInt));
      OpenAt := Pos(' (', LineValue);
      CloseAt := Pos(')', LineValue);
      if (OpenAt > 0) and (CloseAt > OpenAt) then
      begin
        NameValue := Copy(LineValue, 1, OpenAt - 1);
        VersionValue := Copy(LineValue, OpenAt + 2, CloseAt - OpenAt - 2);
        if Pos('/', NameValue) > 0 then
          NameValue := Copy(NameValue, 1, Pos('/', NameValue) - 1);
        AddComponent(AComponents, NameValue, VersionValue, 'CocoaPods',
          ARelativePath, 'conservative-podfile-lock', 'resolved');
      end;
    end;
  finally
    Lines.Free;
  end;
end;

procedure ParseVcpkgJSON(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Data, Entry: TJSONData;
  Root: TJSONObject;
  Dependencies: TJSONArray;
  I: Integer;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONFile(AFileName);
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The vcpkg manifest root must be a JSON object');
    Root := TJSONObject(Data);
    Dependencies := JSONArray(Root, 'dependencies');
    if Dependencies <> nil then
      for I := 0 to Dependencies.Count - 1 do
      begin
        Entry := Dependencies.Items[I];
        if Entry.JSONType = jtObject then
        begin
          NameValue := JSONString(TJSONObject(Entry), 'name');
          VersionValue := JSONString(TJSONObject(Entry), 'version>=');
        end
        else
        begin
          NameValue := ScalarJSONValue(Entry);
          VersionValue := '';
        end;
        AddComponent(AComponents, NameValue, VersionValue, 'vcpkg',
          ARelativePath, 'conservative-vcpkg-json', 'runtime');
      end;
  finally
    Data.Free;
  end;
end;

procedure ParseConanText(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, SlashAt: Integer;
  LineValue, SectionValue, NameValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    SectionValue := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      if (Length(LineValue) > 2) and (LineValue[1] = '[') then
      begin
        SectionValue := LowerCase(LineValue);
        Continue;
      end;
      if (SectionValue <> '[requires]') or (LineValue = '') or
        (LineValue[1] = '#') then
        Continue;
      SlashAt := Pos('/', LineValue);
      if SlashAt > 0 then
      begin
        NameValue := Copy(LineValue, 1, SlashAt - 1);
        VersionValue := Copy(LineValue, SlashAt + 1, MaxInt);
        if Pos('@', VersionValue) > 0 then
          VersionValue := Copy(VersionValue, 1, Pos('@', VersionValue) - 1);
        AddComponent(AComponents, NameValue, VersionValue, 'Conan',
          ARelativePath, 'conservative-conan-text', 'runtime');
      end;
    end;
  finally
    Lines.Free;
  end;
end;

procedure ParsePNPMLock(const AFileName, ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, SlashAt: Integer;
  LineValue, NameValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(AFileName);
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      if (Length(LineValue) < 4) or (LineValue[1] <> '/') or
        (LineValue[Length(LineValue)] <> ':') then
        Continue;
      Delete(LineValue, Length(LineValue), 1);
      Delete(LineValue, 1, 1);
      SlashAt := LastDelimiter('/', LineValue);
      if SlashAt <= 0 then
        Continue;
      NameValue := Copy(LineValue, 1, SlashAt - 1);
      VersionValue := Copy(LineValue, SlashAt + 1, MaxInt);
      if Pos('(', VersionValue) > 0 then
        VersionValue := Copy(VersionValue, 1, Pos('(', VersionValue) - 1);
      AddComponent(AComponents, NameValue, VersionValue, 'npm', ARelativePath,
        'conservative-pnpm-lock', 'resolved');
    end;
  finally
    Lines.Free;
  end;
end;

function ManifestSizeLimit(AParserKind: TParserKind): Int64;
const
  SmallManifestLimit: Int64 = 8 * 1024 * 1024;
  JSONLockLimit: Int64 = 32 * 1024 * 1024;
  LineLockLimit: Int64 = 64 * 1024 * 1024;
begin
  case AParserKind of
    pkNone:
      Result := 0;
    pkPackageLockJSON, pkNuGetLock, pkComposerLock, pkPipfileLock,
    pkPackageResolved:
      Result := JSONLockLimit;
    pkGoSum, pkCargoLock, pkPoetryLock, pkYarnLock, pkGradleLock, pkGemLock,
    pkPodfileLock, pkPNPMLock:
      Result := LineLockLimit;
    else
      Result := SmallManifestLimit;
  end;
end;

function IsPartialParser(AKind: TParserKind): Boolean;
begin
  Result := AKind in [pkPipfileLock, pkGoSum, pkCargoLock, pkCargoTOML,
    pkPoetryLock, pkYarnLock, pkGradleLock, pkGemLock, pkEnvironmentYAML,
    pkPackageResolved, pkPodfileLock, pkVcpkgJSON, pkConanText, pkPNPMLock];
end;

procedure ParseArtifact(const AFileName, ARelativePath: string;
  AParserKind: TParserKind; AArtifact: TArtifact; AComponents: TObjectList);
var
  InitialCount: Integer;
begin
  InitialCount := AComponents.Count;
  if AParserKind = pkNone then
  begin
    AArtifact.Status := arsUnsupported;
    if AArtifact.ArtifactType = 'license evidence' then
      AArtifact.MessageText := 'Possible license evidence only; no package '+
        'license is inferred.'
    else
      AArtifact.MessageText := 'Detected format is not parsed by this version.';
    Exit;
  end;
  try
    case AParserKind of
      pkPackageJSON: ParsePackageJSON(AFileName, ARelativePath, AComponents);
      pkPackageLockJSON: ParsePackageLock(AFileName, ARelativePath, AComponents);
      pkRequirements: ParseRequirements(AFileName, ARelativePath, AComponents);
      pkGoMod: ParseGoMod(AFileName, ARelativePath, AComponents);
      pkMavenPOM: ParseMavenPOM(AFileName, ARelativePath, AComponents);
      pkMSBuildProject: ParseMSBuild(AFileName, ARelativePath,
        'msbuild-package-reference', AComponents, False);
      pkNuGetLock: ParseNuGetLock(AFileName, ARelativePath, AComponents);
      pkDirectoryPackages: ParseMSBuild(AFileName, ARelativePath,
        'msbuild-central-package-xml', AComponents, True);
      pkComposerJSON: ParseComposerJSON(AFileName, ARelativePath, AComponents);
      pkComposerLock: ParseComposerLock(AFileName, ARelativePath, AComponents);
      pkLazarusXML: ParseLazarusXML(AFileName, ARelativePath, AComponents);
      pkPipfileLock: ParsePipfileLock(AFileName, ARelativePath, AComponents);
      pkGoSum: ParseGoSum(AFileName, ARelativePath, AComponents);
      pkCargoLock: ParseLockNameVersionBlocks(AFileName, ARelativePath,
        'Cargo', 'conservative-cargo-lock', AComponents);
      pkPoetryLock: ParseLockNameVersionBlocks(AFileName, ARelativePath,
        'PyPI', 'conservative-poetry-lock', AComponents);
      pkCargoTOML: ParseCargoTOML(AFileName, ARelativePath, AComponents);
      pkYarnLock: ParseYarnLock(AFileName, ARelativePath, AComponents);
      pkGradleLock: ParseGradleLock(AFileName, ARelativePath, AComponents);
      pkGemLock: ParseGemLock(AFileName, ARelativePath, AComponents);
      pkEnvironmentYAML: ParseEnvironmentYAML(AFileName, ARelativePath,
        AComponents);
      pkPackageResolved: ParsePackageResolved(AFileName, ARelativePath,
        AComponents);
      pkPodfileLock: ParsePodfileLock(AFileName, ARelativePath, AComponents);
      pkVcpkgJSON: ParseVcpkgJSON(AFileName, ARelativePath, AComponents);
      pkConanText: ParseConanText(AFileName, ARelativePath, AComponents);
      pkPNPMLock: ParsePNPMLock(AFileName, ARelativePath, AComponents);
    else
      raise Exception.Create('No parser is registered for the detected artifact');
    end;
    if IsPartialParser(AParserKind) then
    begin
      AArtifact.Status := arsPartiallyParsed;
      AArtifact.MessageText := 'Conservative parser: the format may contain '+
        'additional dependency evidence.';
    end
    else
      AArtifact.Status := arsParsed;
  except
    on E: Exception do
    begin
      while AComponents.Count > InitialCount do
        AComponents.Delete(AComponents.Count - 1);
      AArtifact.Status := arsFailed;
      AArtifact.MessageText := E.Message;
    end;
  end;
  AArtifact.ComponentCount := AComponents.Count - InitialCount;
  if (AArtifact.Status in [arsParsed, arsPartiallyParsed]) and
    (AArtifact.ComponentCount = 0) then
  begin
    if AArtifact.MessageText <> '' then
      AArtifact.MessageText := AArtifact.MessageText + ' ';
    AArtifact.MessageText := AArtifact.MessageText +
      'No dependency components were identified.';
  end;
end;

end.
