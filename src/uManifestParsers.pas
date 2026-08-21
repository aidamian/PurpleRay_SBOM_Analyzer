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
  AParserKind: TParserKind; AArtifact: TArtifact;
  AComponents: TObjectList); overload;

{**
  Dispatches one verified manifest stream to its conservative format parser.

  Parameters
  ----------
  AStream
    Caller-owned bounded stream; parsing starts at offset zero.
  ARelativePath
    Root-relative evidence path recorded on produced components.
  AParserKind
    Parser selected by the artifact-identification unit.
  AArtifact
    Artifact record updated with parser status and component count.
  AComponents
    Owned list receiving newly allocated TComponent instances.

  Returns
  -------
  None

  Raises
  ------
  None
    Format and stream exceptions become failed artifact diagnostics.
*}
procedure ParseArtifact(AStream: TStream; const ARelativePath: string;
  AParserKind: TParserKind; AArtifact: TArtifact;
  AComponents: TObjectList); overload;

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
  base64, fpjson, DOM, XMLRead, streamex, uJSONUtils;

const
  MaximumManifestJSONBytes = Int64(32) * 1024 * 1024;

{**
  Rewinds and parses one JSON value from a caller-owned bounded stream.

  Parameters
  ----------
  AStream
    Seekable input stream.

  Returns
  -------
  TJSONData
    Newly allocated JSON value owned by the caller.

  Raises
  ------
  EArgumentNilException, EStreamError, EJSONParser
    Raised for nil input, stream failure, or malformed JSON.
*}
function ReadJSONStream(AStream: TStream): TJSONData;
begin
  if AStream = nil then
    raise EArgumentNilException.Create('Manifest input stream is nil');
  AStream.Position := 0;
  Result := uJSONUtils.ReadJSONStream(AStream, MaximumManifestJSONBytes);
end;

{**
  Rewinds and loads text lines from a caller-owned bounded stream.

  Parameters
  ----------
  AStream
    Seekable input stream.
  ALines
    Caller-owned destination string list.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException, EStreamError
    Raised for nil inputs or stream read/seek failure.
*}
procedure LoadLinesFromStream(AStream: TStream; ALines: TStrings);
begin
  if (AStream = nil) or (ALines = nil) then
    raise EArgumentNilException.Create('Manifest stream or line list is nil');
  AStream.Position := 0;
  ALines.LoadFromStream(AStream);
end;

{**
  Parses one XML manifest with document types and entity expansion disabled.

  Parameters
  ----------
  AStream
    XML manifest stream retained through the complete parse.
  ADocument
    Receives the newly allocated DOM document owned by the caller.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException, EReadError, EStreamError
    Raised for nil input or propagated when the stream cannot be read or
    rewound.
  EXMLReadError, Exception
    Raised for malformed XML or any document-type declaration, including
    declarations encoded as UTF-16.
  EOutOfMemory
    Propagated if parser or DOM storage cannot be allocated.
}
procedure ReadSafeXMLStream(AStream: TStream;
  out ADocument: TXMLDocument);
const
  MaximumDecodedCharacters = 16 * 1024 * 1024;
var
  InputSource: TXMLInputSource;
  Parser: TDOMParser;
begin
  ADocument := nil;
  if AStream = nil then
    raise EArgumentNilException.Create('XML manifest stream is nil');
  AStream.Position := 0;
  InputSource := TXMLInputSource.Create(AStream);
  try
    InputSource.BaseURI := 'stream:';
    Parser := TDOMParser.Create;
    try
      Parser.Options.DisallowDoctype := True;
      Parser.Options.ExpandEntities := False;
      Parser.Options.MaxChars := MaximumDecodedCharacters;
      try
        Parser.Parse(InputSource, ADocument);
      except
        on E: EXMLReadError do
        begin
          FreeAndNil(ADocument);
          if Pos('document type', LowerCase(E.Message)) > 0 then
            raise Exception.Create(
              'XML document type declarations are not allowed');
          raise;
        end;
        else
        begin
          FreeAndNil(ADocument);
          raise;
        end;
      end;
    finally
      Parser.Free;
    end;
  finally
    InputSource.Free;
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
  ADeclaredLicenses
    Optional explicit manifest license strings copied to the component.
  ADeclaredPublishers
    Optional explicit manifest publisher strings copied to the component.

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
  const AComponentType: string = 'library'; const APURL: string = '';
  ADeclaredLicenses: TStrings = nil; ADeclaredPublishers: TStrings = nil);
var
  Component: TComponent;
  I: Integer;
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
  else if SameText(AParser, 'conservative-cargo-toml') and
    not SameText(Trim(AScope), 'project') then
    Component.PackageURL := ''
  else
    Component.PackageURL := BuildPackageURL(AEcosystem, Component.Name,
      Component.Version);
  Component.EvidencePaths.Add(ARelativePath);
  if ADeclaredLicenses <> nil then
    for I := 0 to ADeclaredLicenses.Count - 1 do
      if Trim(ADeclaredLicenses[I]) <> '' then
        Component.DeclaredLicenses.Add(Trim(ADeclaredLicenses[I]));
  if ADeclaredPublishers <> nil then
    for I := 0 to ADeclaredPublishers.Count - 1 do
      if Trim(ADeclaredPublishers[I]) <> '' then
        Component.DeclaredPublishers.Add(Trim(ADeclaredPublishers[I]));
  AComponents.Add(Component);
end;

function BytesToLowerHex(const AValue: string): string;
const
  HexDigits = '0123456789abcdef';
var
  I: Integer;
  ByteValue: Byte;
begin
  SetLength(Result, Length(AValue) * 2);
  for I := 1 to Length(AValue) do
  begin
    ByteValue := Ord(AValue[I]);
    Result[(I * 2) - 1] := HexDigits[(ByteValue shr 4) + 1];
    Result[I * 2] := HexDigits[(ByteValue and $0F) + 1];
  end;
end;

function TryDecodeSRIHash(const AToken: string; out AAlgorithm,
  ADigest: string): Boolean;
var
  AlgorithmValue, EncodedValue, DecodedValue: string;
  DashAt, ExpectedBytes, ExpectedEncodedLength, I, PaddingLength: Integer;
begin
  Result := False;
  AAlgorithm := '';
  ADigest := '';
  if (AToken = '') or (Length(AToken) > 256) then
    Exit;
  DashAt := Pos('-', AToken);
  if (DashAt <= 1) or (DashAt = Length(AToken)) then
    Exit;
  AlgorithmValue := LowerCase(Copy(AToken, 1, DashAt - 1));
  EncodedValue := Copy(AToken, DashAt + 1, MaxInt);
  case AlgorithmValue of
    'sha1':
      begin
        AAlgorithm := 'SHA-1';
        ExpectedBytes := 20;
      end;
    'sha256':
      begin
        AAlgorithm := 'SHA-256';
        ExpectedBytes := 32;
      end;
    'sha384':
      begin
        AAlgorithm := 'SHA-384';
        ExpectedBytes := 48;
      end;
    'sha512':
      begin
        AAlgorithm := 'SHA-512';
        ExpectedBytes := 64;
      end;
  else
    Exit;
  end;
  ExpectedEncodedLength := ((ExpectedBytes + 2) div 3) * 4;
  PaddingLength := (3 - (ExpectedBytes mod 3)) mod 3;
  if Length(EncodedValue) <> ExpectedEncodedLength then
    Exit;
  for I := 1 to Length(EncodedValue) - PaddingLength do
    if not (EncodedValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '+', '/']) then
      Exit;
  for I := Length(EncodedValue) - PaddingLength + 1 to Length(EncodedValue) do
    if EncodedValue[I] <> '=' then
      Exit;
  try
    DecodedValue := DecodeStringBase64(EncodedValue, True);
  except
    on EBase64DecodingException do
      Exit;
  end;
  { The strict decoder checks alphabet and padding placement. A canonical
    round-trip additionally rejects nonzero unused trailing bits. }
  if (Length(DecodedValue) <> ExpectedBytes) or
    (EncodeStringBase64(DecodedValue) <> EncodedValue) then
    Exit;
  ADigest := BytesToLowerHex(DecodedValue);
  Result := True;
end;

procedure AddDeclaredHash(AComponent: TComponent; const AAlgorithm,
  ADigest, ASubject, ARelativePath, AParser: string);
var
  HashValue: TDeclaredHash;
begin
  if AComponent = nil then
    Exit;
  HashValue := TDeclaredHash.Create;
  HashValue.Algorithm := AAlgorithm;
  HashValue.Digest := LowerCase(ADigest);
  HashValue.Subject := ASubject;
  HashValue.SourceArtifact := ARelativePath;
  HashValue.SourceParser := AParser;
  AComponent.DeclaredHashes.Add(HashValue);
end;

procedure AddNPMIntegrityHashes(AComponent: TComponent;
  const AIntegrity, ASubject, ARelativePath: string);
const
  MaximumIntegrityLength = 16 * 1024;
var
  PositionValue, TokenStart, OptionAt: Integer;
  TokenValue, AlgorithmValue, DigestValue: string;
begin
  if (AComponent = nil) or (ASubject = '') or (AIntegrity = '') or
    (Length(AIntegrity) > MaximumIntegrityLength) then
    Exit;
  PositionValue := 1;
  while PositionValue <= Length(AIntegrity) do
  begin
    while (PositionValue <= Length(AIntegrity)) and
      (AIntegrity[PositionValue] in [' ', #9, #10, #13]) do
      Inc(PositionValue);
    TokenStart := PositionValue;
    while (PositionValue <= Length(AIntegrity)) and
      not (AIntegrity[PositionValue] in [' ', #9, #10, #13]) do
      Inc(PositionValue);
    if PositionValue = TokenStart then
      Continue;
    TokenValue := Copy(AIntegrity, TokenStart, PositionValue - TokenStart);
    OptionAt := Pos('?', TokenValue);
    if OptionAt > 0 then
      TokenValue := Copy(TokenValue, 1, OptionAt - 1);
    if TryDecodeSRIHash(TokenValue, AlgorithmValue, DigestValue) then
      AddDeclaredHash(AComponent, AlgorithmValue, DigestValue, ASubject,
        ARelativePath, 'package-lock-json');
  end;
end;

function ScalarJSONValue(AData: TJSONData): string;
begin
  if (AData = nil) or (AData.JSONType in [jtObject, jtArray, jtNull]) then
    Result := ''
  else
    Result := AData.AsString;
end;

{**
  Adds one bounded explicit declaration to a deterministic string set.

  Parameters
  ----------
  AValue
    Manifest value to trim and retain when it contains no control characters.
  AValues
    Sorted declaration list that receives the value.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the retained declaration cannot be allocated.
}
procedure AddDeclaration(const AValue: string; AValues: TStrings);
const
  MaxDeclarationLength = 4096;
var
  I: Integer;
  ValueText: string;
begin
  if AValues = nil then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit;
  ValueText := Trim(AValue);
  if (ValueText <> '') and (Length(ValueText) <= MaxDeclarationLength) then
    AValues.Add(ValueText);
end;

{**
  Collects scalar strings from a JSON value or one-dimensional JSON array.

  Parameters
  ----------
  AData
    JSON string or one-dimensional array of strings containing explicit
    manifest declarations; all other JSON types are ignored.
  AValues
    Declaration list receiving bounded, non-empty values.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a declaration cannot be allocated.
}
procedure CollectJSONDeclarations(AData: TJSONData; AValues: TStrings);
var
  I: Integer;
begin
  if (AData = nil) or (AValues = nil) then
    Exit;
  if AData.JSONType = jtArray then
  begin
    for I := 0 to TJSONArray(AData).Count - 1 do
      if TJSONArray(AData).Items[I].JSONType = jtString then
        AddDeclaration(TJSONArray(AData).Items[I].AsString, AValues);
    Exit;
  end;
  if AData.JSONType = jtString then
    AddDeclaration(AData.AsString, AValues);
end;

{**
  Collects explicitly declared publisher names from common JSON author forms.

  Parameters
  ----------
  AData
    String author, author object with a string name/email, or a
    one-dimensional array of either form. Nested arrays and other JSON types
    are ignored.
  AValues
    Publisher list receiving names, with email used only as an object fallback.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a publisher value cannot be allocated.
}
procedure CollectJSONPublishers(AData: TJSONData; AValues: TStrings);
var
  I: Integer;
  FieldValue: TJSONData;
  ValueText: string;
begin
  if (AData = nil) or (AValues = nil) then
    Exit;
  case AData.JSONType of
    jtArray:
      for I := 0 to TJSONArray(AData).Count - 1 do
        if TJSONArray(AData).Items[I].JSONType in [jtObject, jtString] then
          CollectJSONPublishers(TJSONArray(AData).Items[I], AValues);
    jtObject:
      begin
        ValueText := '';
        FieldValue := TJSONObject(AData).Find('name');
        if (FieldValue <> nil) and (FieldValue.JSONType = jtString) then
          ValueText := FieldValue.AsString
        else if FieldValue = nil then
        begin
          FieldValue := TJSONObject(AData).Find('email');
          if (FieldValue <> nil) and (FieldValue.JSONType = jtString) then
            ValueText := FieldValue.AsString;
        end;
        AddDeclaration(ValueText, AValues);
      end;
    jtNull:
      Exit;
    jtString:
      AddDeclaration(AData.AsString, AValues);
  end;
end;

{**
  Creates a sorted, duplicate-free list for manifest declarations.

  Parameters
  ----------
  None

  Returns
  -------
  TStringList
    Newly allocated declaration set owned by the caller.

  Raises
  ------
  EOutOfMemory
    Propagated if the list cannot be allocated.
}
function CreateDeclarationList: TStringList;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.Duplicates := dupIgnore;
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
  AStream
    Bounded JSON manifest stream to read.
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
    Propagated for invalid JSON, an invalid root type, stream access, or
    allocation failure.
}
procedure ParsePackageJSON(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
  NameValue, VersionValue: string;
  Licenses, Publishers: TStringList;
begin
  Data := ReadJSONStream(AStream);
  Licenses := CreateDeclarationList;
  Publishers := CreateDeclarationList;
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The package manifest root must be a JSON object');
    Root := TJSONObject(Data);
    NameValue := JSONString(Root, 'name');
    VersionValue := JSONString(Root, 'version');
    CollectJSONDeclarations(Root.Find('license'), Licenses);
    CollectJSONPublishers(Root.Find('author'), Publishers);
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'npm', ARelativePath,
        'package-json', 'project', 'application', '', Licenses, Publishers);
    ParseNamedJSONDependencies(JSONObject(Root, 'dependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'runtime');
    ParseNamedJSONDependencies(JSONObject(Root, 'devDependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'development');
    ParseNamedJSONDependencies(JSONObject(Root, 'optionalDependencies'),
      AComponents, 'npm', ARelativePath, 'package-json', 'optional');
    ParseNamedJSONDependencies(JSONObject(Root, 'peerDependencies'), AComponents,
      'npm', ARelativePath, 'package-json', 'peer');
  finally
    Publishers.Free;
    Licenses.Free;
    Data.Free;
  end;
end;

{**
  Validates the conservative installed npm package-name subset.

  Parameters
  ----------
  AName
    Declared package name exactly as stored in package.json.

  Returns
  -------
  Boolean
    True for an unscoped name or ``@scope/name`` whose nonempty segments have
    alphanumeric endpoints and contain only ASCII alphanumerics, dot,
    underscore, tilde, or hyphen.

  Raises
  ------
  None
*}
function IsValidInstalledNPMName(const AName: string): Boolean;
const
  MaximumInstalledIdentityBytes = 512;
var
  PackageName, ScopeName: string;
  SlashAt: SizeInt;

  {**
    Validates one unscoped npm name or scope segment.

    Parameters
    ----------
    AValue
      Nonempty candidate segment without a slash or leading at-sign.

    Returns
    -------
    Boolean
      True when endpoints are alphanumeric and all bytes use the accepted
      conservative ASCII package-name alphabet.

    Raises
    ------
    None
  *}
  function IsValidNameSegment(const AValue: string): Boolean;
  var
    CharacterIndex: Integer;
  begin
    Result := (AValue <> '') and IsASCIIAlphaNumeric(AValue[1]) and
      IsASCIIAlphaNumeric(AValue[Length(AValue)]);
    if not Result then
      Exit;
    for CharacterIndex := 1 to Length(AValue) do
      if not IsASCIIAlphaNumeric(AValue[CharacterIndex]) and
        not (AValue[CharacterIndex] in ['.', '_', '~', '-']) then
        Exit(False);
  end;

begin
  Result := (AName <> '') and (Length(AName) <= MaximumInstalledIdentityBytes)
    and (AName = Trim(AName));
  if not Result then
    Exit;
  if AName[1] <> '@' then
    Exit((Pos('/', AName) = 0) and IsValidNameSegment(AName));
  SlashAt := Pos('/', AName);
  if (SlashAt <= 2) or (SlashAt = Length(AName)) or
    (Pos('/', Copy(AName, SlashAt + 1, MaxInt)) > 0) then
    Exit(False);
  ScopeName := Copy(AName, 2, SlashAt - 2);
  PackageName := Copy(AName, SlashAt + 1, MaxInt);
  Result := IsValidNameSegment(ScopeName) and
    IsValidNameSegment(PackageName);
end;

{**
  Validates one exact installed npm semantic version.

  Parameters
  ----------
  AVersion
    Declared installed package version without normalization.

  Returns
  -------
  Boolean
    True for a three-part SemVer core with optional valid prerelease and build
    identifier lists.

  Raises
  ------
  None
*}
function IsValidInstalledNPMVersion(const AVersion: string): Boolean;
const
  MaximumInstalledIdentityBytes = 512;
var
  BuildValue, CoreValue, PreReleaseValue, VersionValue: string;
  DashAt, PlusAt: SizeInt;

  {**
    Validates the three numeric segments of an installed npm SemVer core.

    Parameters
    ----------
    AValue
      Candidate major, minor, and patch text without suffixes.

    Returns
    -------
    Boolean
      True for exactly three dot-separated numeric segments with no forbidden
      leading zero.

    Raises
    ------
    None
  *}
  function ValidateCore(const AValue: string): Boolean;
  var
    CharacterIndex, SegmentCount, SegmentStart: Integer;
  begin
    Result := False;
    SegmentCount := 0;
    SegmentStart := 1;
    for CharacterIndex := 1 to Length(AValue) + 1 do
      if (CharacterIndex > Length(AValue)) or
        (AValue[CharacterIndex] = '.') then
      begin
        if CharacterIndex = SegmentStart then
          Exit;
        if (CharacterIndex - SegmentStart > 1) and
          (AValue[SegmentStart] = '0') then
          Exit;
        while SegmentStart < CharacterIndex do
        begin
          if not (AValue[SegmentStart] in ['0'..'9']) then
            Exit;
          Inc(SegmentStart);
        end;
        Inc(SegmentCount);
        SegmentStart := CharacterIndex + 1;
      end;
    Result := SegmentCount = 3;
  end;

  {**
    Validates a dot-separated SemVer prerelease or build identifier list.

    Parameters
    ----------
    AValue
      Candidate identifier list.
    ARejectNumericLeadingZero
      True to reject leading zeroes in all-numeric identifiers.

    Returns
    -------
    Boolean
      True for a nonempty list using only ASCII alphanumerics and hyphens.

    Raises
    ------
    None
  *}
  function ValidateIdentifiers(const AValue: string;
    ARejectNumericLeadingZero: Boolean): Boolean;
  var
    AllNumeric: Boolean;
    CharacterIndex, IdentifierStart, SegmentStart: Integer;
  begin
    Result := False;
    SegmentStart := 1;
    for CharacterIndex := 1 to Length(AValue) + 1 do
      if (CharacterIndex > Length(AValue)) or
        (AValue[CharacterIndex] = '.') then
      begin
        if CharacterIndex = SegmentStart then
          Exit;
        IdentifierStart := SegmentStart;
        AllNumeric := True;
        while SegmentStart < CharacterIndex do
        begin
          if not (AValue[SegmentStart] in ['A'..'Z', 'a'..'z', '0'..'9',
            '-']) then
            Exit;
          if not (AValue[SegmentStart] in ['0'..'9']) then
            AllNumeric := False;
          Inc(SegmentStart);
        end;
        if ARejectNumericLeadingZero and AllNumeric and
          (CharacterIndex - IdentifierStart > 1) and
          (AValue[IdentifierStart] = '0') then
          Exit;
        SegmentStart := CharacterIndex + 1;
      end;
    Result := AValue <> '';
  end;

begin
  VersionValue := AVersion;
  Result := (VersionValue <> '') and
    (Length(VersionValue) <= MaximumInstalledIdentityBytes) and
    (VersionValue = Trim(VersionValue));
  if not Result then
    Exit;
  PlusAt := Pos('+', VersionValue);
  if PlusAt > 0 then
  begin
    BuildValue := Copy(VersionValue, PlusAt + 1, MaxInt);
    if (BuildValue = '') or (Pos('+', BuildValue) > 0) or
      not ValidateIdentifiers(BuildValue, False) then
      Exit(False);
    Delete(VersionValue, PlusAt, MaxInt);
  end;
  DashAt := Pos('-', VersionValue);
  if DashAt > 0 then
  begin
    PreReleaseValue := Copy(VersionValue, DashAt + 1, MaxInt);
    if not ValidateIdentifiers(PreReleaseValue, True) then
      Exit(False);
    Delete(VersionValue, DashAt, MaxInt);
  end;
  CoreValue := VersionValue;
  Result := ValidateCore(CoreValue);
end;

{**
  Parses only an installed npm package's own exact identity and declarations.

  Parameters
  ----------
  AStream
    Bounded ``node_modules`` package.json stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving exactly one installed package component on success.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised for malformed JSON or missing, inexact, or invalid package identity.

  Notes
  -----
  Dependency sections are deliberately ignored because their values are
  declarations and ranges, not evidence of what is installed.
*}
procedure ParseInstalledPackageJSON(AStream: TStream;
  const ARelativePath: string; AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
  NameValue, VersionValue, PackageURL: string;
  Licenses, Publishers: TStringList;
begin
  Data := ReadJSONStream(AStream);
  Licenses := CreateDeclarationList;
  Publishers := CreateDeclarationList;
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create(
        'The installed package manifest root must be a JSON object');
    Root := TJSONObject(Data);
    NameValue := JSONString(Root, 'name');
    VersionValue := JSONString(Root, 'version');
    PackageURL := BuildPackageURL('npm', NameValue, VersionValue);
    if not IsValidInstalledNPMName(NameValue) or
      not IsValidInstalledNPMVersion(VersionValue) or (PackageURL = '') then
      raise Exception.Create('Installed package.json requires a valid name ' +
        'and exact npm version');
    CollectJSONDeclarations(Root.Find('license'), Licenses);
    CollectJSONPublishers(Root.Find('author'), Publishers);
    AddComponent(AComponents, NameValue, VersionValue, 'npm', ARelativePath,
      'installed-package-json', 'resolved', 'library', PackageURL, Licenses,
      Publishers);
  finally
    Publishers.Free;
    Licenses.Free;
    Data.Free;
  end;
end;

{**
  Conservatively validates an exact installed Python version token.

  Parameters
  ----------
  AVersion
    Value from the installed distribution's Version header.

  Returns
  -------
  Boolean
    True for an optional ``v``, optional numeric epoch, dot-separated numeric
    release, optional ``a``/``b``/``rc`` number, optional ``.post`` number,
    optional ``.dev`` number, and optional dot-separated ASCII-alphanumeric
    local identifiers. Other PEP-440-compatible spellings fail conservatively.

  Raises
  ------
  None
*}
function IsExactInstalledPythonVersion(const AVersion: string): Boolean;
var
  CharacterIndex: Integer;
  PreReleaseSeen: Boolean;
  VersionValue: string;

  {**
    Consumes one or more decimal digits from the enclosing version string.

    Parameters
    ----------
    AIndex
      One-based cursor advanced past the consumed digits.

    Returns
    -------
    Boolean
      True when at least one digit was consumed.

    Raises
    ------
    None
  *}
  function ConsumeDigits(var AIndex: Integer): Boolean;
  var
    StartIndex: Integer;
  begin
    StartIndex := AIndex;
    while (AIndex <= Length(VersionValue)) and
      (VersionValue[AIndex] in ['0'..'9']) do
      Inc(AIndex);
    Result := AIndex > StartIndex;
  end;

  {**
    Consumes one exact literal from the enclosing normalized version string.

    Parameters
    ----------
    AIndex
      One-based cursor advanced only on a match.
    AValue
      Literal bytes required at the current cursor.

    Returns
    -------
    Boolean
      True when AValue matches and was consumed.

    Raises
    ------
    None
  *}
  function ConsumeLiteral(var AIndex: Integer;
    const AValue: string): Boolean;
  begin
    Result := Copy(VersionValue, AIndex, Length(AValue)) = AValue;
    if Result then
      Inc(AIndex, Length(AValue));
  end;

begin
  VersionValue := LowerCase(AVersion);
  Result := (VersionValue <> '') and (Length(VersionValue) <= 512) and
    (VersionValue = Trim(VersionValue)) and IsExactVersion(VersionValue);
  if not Result then
    Exit;
  CharacterIndex := 1;
  if VersionValue[CharacterIndex] = 'v' then
    Inc(CharacterIndex);
  if not ConsumeDigits(CharacterIndex) then
    Exit(False);
  if (CharacterIndex <= Length(VersionValue)) and
    (VersionValue[CharacterIndex] = '!') then
  begin
    Inc(CharacterIndex);
    if not ConsumeDigits(CharacterIndex) then
      Exit(False);
  end;
  while (CharacterIndex <= Length(VersionValue)) and
    (VersionValue[CharacterIndex] = '.') and
    (CharacterIndex < Length(VersionValue)) and
    (VersionValue[CharacterIndex + 1] in ['0'..'9']) do
  begin
    Inc(CharacterIndex);
    if not ConsumeDigits(CharacterIndex) then
      Exit(False);
  end;
  if CharacterIndex <= Length(VersionValue) then
  begin
    PreReleaseSeen := False;
    if VersionValue[CharacterIndex] in ['a', 'b'] then
    begin
      Inc(CharacterIndex);
      PreReleaseSeen := True;
    end
    else if ConsumeLiteral(CharacterIndex, 'rc') then
      PreReleaseSeen := True;
    if PreReleaseSeen and not ConsumeDigits(CharacterIndex) then
      Exit(False);
  end;
  if ConsumeLiteral(CharacterIndex, '.post') and
    not ConsumeDigits(CharacterIndex) then
    Exit(False);
  if ConsumeLiteral(CharacterIndex, '.dev') and
    not ConsumeDigits(CharacterIndex) then
    Exit(False);
  if (CharacterIndex <= Length(VersionValue)) and
    (VersionValue[CharacterIndex] = '+') then
  begin
    Inc(CharacterIndex);
    repeat
      if (CharacterIndex > Length(VersionValue)) or
        not IsASCIIAlphaNumeric(VersionValue[CharacterIndex]) then
        Exit(False);
      while (CharacterIndex <= Length(VersionValue)) and
        IsASCIIAlphaNumeric(VersionValue[CharacterIndex]) do
        Inc(CharacterIndex);
      if CharacterIndex > Length(VersionValue) then
        Break;
      if VersionValue[CharacterIndex] <> '.' then
        Exit(False);
      Inc(CharacterIndex);
    until False;
  end;
  Result := CharacterIndex > Length(VersionValue);
end;

{**
  Validates one bounded installed Python distribution name without trimming it.

  Parameters
  ----------
  AName
    Value from the installed distribution's Name header.

  Returns
  -------
  Boolean
    True for at most 512 ASCII bytes satisfying Python distribution-name
    syntax with no leading or trailing whitespace.

  Raises
  ------
  None
*}
function IsValidInstalledPythonName(const AName: string): Boolean;
begin
  Result := (AName <> '') and (Length(AName) <= 512) and
    (AName = Trim(AName)) and IsValidPyPIName(AName);
end;

{**
  Parses the RFC-822 identity header of Python ``dist-info/METADATA``.

  Parameters
  ----------
  AStream
    Bounded installed-distribution metadata stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving exactly one installed Python component on success.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised for oversized or malformed headers, duplicate identity fields, or
    missing, inexact, or invalid Name/Version evidence.

  Notes
  -----
  Parsing stops at the first blank line. ``Requires-Dist`` and all other
  dependency declarations are intentionally ignored.
*}
procedure ParsePythonDistInfoMetadata(AStream: TStream;
  const ARelativePath: string; AComponents: TObjectList);
const
  MaximumIdentityHeaderBytes = 256 * 1024;
  MaximumIdentityLineBytes = 8 * 1024;
var
  Reader: TStreamReader;
  LineValue, HeaderName, HeaderValue, NameValue, VersionValue,
    PackageURL: string;
  HeaderBytes: Int64;
  ColonAt, CharacterIndex, ActiveIdentityHeader: Integer;
  NameSeen, VersionSeen: Boolean;
begin
  if AStream = nil then
    raise EArgumentNilException.Create(
      'Python installed metadata stream is nil');
  AStream.Position := 0;
  Reader := TStreamReader.Create(AStream);
  try
    HeaderBytes := 0;
    ActiveIdentityHeader := 0;
    NameSeen := False;
    VersionSeen := False;
    NameValue := '';
    VersionValue := '';
    while not Reader.Eof do
    begin
      Reader.ReadLine(LineValue);
      Inc(HeaderBytes, Length(LineValue) + 1);
      if HeaderBytes > MaximumIdentityHeaderBytes then
        raise Exception.Create(
          'Python installed metadata header exceeds the safe limit');
      if Length(LineValue) > MaximumIdentityLineBytes then
        raise Exception.Create(
          'Python installed metadata contains an oversized header line');
      if LineValue = '' then
        Break;
      for CharacterIndex := 1 to Length(LineValue) do
        if (((Ord(LineValue[CharacterIndex]) < 32) and
          (LineValue[CharacterIndex] <> #9)) or
          (Ord(LineValue[CharacterIndex]) = 127)) then
          raise Exception.Create(
            'Python installed metadata contains a control character');
      if LineValue[1] in [' ', #9] then
      begin
        HeaderValue := Trim(LineValue);
        if HeaderValue = '' then
          Continue;
        case ActiveIdentityHeader of
          1: NameValue := NameValue + ' ' + HeaderValue;
          2: VersionValue := VersionValue + ' ' + HeaderValue;
        end;
        Continue;
      end;
      ColonAt := Pos(':', LineValue);
      if ColonAt <= 1 then
        raise Exception.Create(
          'Python installed metadata contains a malformed header');
      HeaderName := LowerCase(Trim(Copy(LineValue, 1, ColonAt - 1)));
      HeaderValue := Trim(Copy(LineValue, ColonAt + 1, MaxInt));
      ActiveIdentityHeader := 0;
      if HeaderName = 'name' then
      begin
        if NameSeen then
          raise Exception.Create(
            'Python installed metadata contains duplicate Name headers');
        NameSeen := True;
        NameValue := HeaderValue;
        ActiveIdentityHeader := 1;
      end
      else if HeaderName = 'version' then
      begin
        if VersionSeen then
          raise Exception.Create(
            'Python installed metadata contains duplicate Version headers');
        VersionSeen := True;
        VersionValue := HeaderValue;
        ActiveIdentityHeader := 2;
      end;
    end;
  finally
    Reader.Free;
  end;
  PackageURL := BuildPackageURL('PyPI', NameValue, VersionValue);
  if (not NameSeen) or (not VersionSeen) or
    not IsValidInstalledPythonName(NameValue) or
    not IsExactInstalledPythonVersion(VersionValue) or (PackageURL = '') then
    raise Exception.Create('Python installed metadata requires valid Name ' +
      'and exact Version headers');
  AddComponent(AComponents, NameValue, VersionValue, 'PyPI', ARelativePath,
    'python-dist-info-metadata', 'resolved', 'library', PackageURL);
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

procedure AddPackageLockComponent(AComponents: TObjectList;
  const AName, AVersion, ARelativePath, AScope,
  AComponentType: string; AEntry: TJSONObject);
var
  PreviousCount: Integer;
  Component: TComponent;
begin
  PreviousCount := AComponents.Count;
  AddComponent(AComponents, AName, AVersion, 'npm', ARelativePath,
    'package-lock-json', AScope, AComponentType);
  if (AComponents.Count <= PreviousCount) or
    not IsExactEcosystemVersion('npm', AVersion) then
    Exit;
  Component := TComponent(AComponents[AComponents.Count - 1]);
  AddNPMIntegrityHashes(Component, JSONString(AEntry, 'integrity'),
    Trim(AName) + '@' + Trim(AVersion), ARelativePath);
end;

procedure ParseLegacyPackageLockDependencies(AObject: TJSONObject;
  AComponents: TObjectList; const ARelativePath: string);
var
  I: Integer;
  Entry, Nested: TJSONObject;
  VersionValue: string;
begin
  if AObject = nil then
    Exit;
  for I := 0 to AObject.Count - 1 do
  begin
    if AObject.Items[I].JSONType <> jtObject then
      Continue;
    Entry := TJSONObject(AObject.Items[I]);
    VersionValue := JSONString(Entry, 'version');
    AddPackageLockComponent(AComponents, AObject.Names[I], VersionValue,
      ARelativePath, 'resolved', 'library', Entry);
    Nested := JSONObject(Entry, 'dependencies');
    if Nested <> nil then
      ParseLegacyPackageLockDependencies(Nested, AComponents, ARelativePath);
  end;
end;

{**
  Parses modern and legacy npm package-lock.json dependency layouts.

  Parameters
  ----------
  AStream
    Bounded lock-file stream to read.
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
    Propagated for invalid JSON, an invalid root type, stream access, or
    allocation failure.
}
procedure ParsePackageLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root, Packages, Entry: TJSONObject;
  I: Integer;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONStream(AStream);
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
          AddPackageLockComponent(AComponents, NameValue, VersionValue,
            ARelativePath, 'project', 'application', Entry)
        else
          AddPackageLockComponent(AComponents, NameValue, VersionValue,
            ARelativePath, 'resolved', 'library', Entry);
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
  AStream
    Bounded requirements stream to read.
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
procedure ParseRequirements(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I: Integer;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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
  AStream
    Bounded go.mod stream to read.
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
procedure ParseGoMod(AStream: TStream; const ARelativePath: string;
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
    LoadLinesFromStream(AStream, Lines);
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

{**
  Finds an XML child using the case-sensitive element names required by XML.

  Parameters
  ----------
  ANode
    Parent whose immediate element children are inspected.
  AName
    Exact local element name to match.

  Returns
  -------
  TDOMElement
    Borrowed matching child element, or nil when absent.

  Raises
  ------
  None
}
function ExactChildElement(ANode: TDOMNode;
  const AName: string): TDOMElement;
var
  Child: TDOMNode;
begin
  Result := nil;
  if ANode = nil then
    Exit;
  Child := ANode.FirstChild;
  while Child <> nil do
  begin
    if (Child is TDOMElement) and
      (CompareStr(LocalNodeName(Child), AName) = 0) then
      Exit(TDOMElement(Child));
    Child := Child.NextSibling;
  end;
end;

{**
  Reads trimmed text from one case-sensitive immediate XML child.

  Parameters
  ----------
  ANode
    Parent element.
  AName
    Exact local child name.

  Returns
  -------
  string
    Trimmed UTF-8 text, or an empty string when the child is absent.

  Raises
  ------
  EOutOfMemory
    Propagated if DOM text conversion cannot allocate its result.
}
function ExactChildText(ANode: TDOMNode; const AName: string): string;
var
  Element: TDOMElement;
begin
  Element := ExactChildElement(ANode, AName);
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

{**
  Retains a Maven declaration only when it is literal manifest evidence.

  Parameters
  ----------
  AValue
    Maven license or organization text to inspect.
  AValues
    Declaration set receiving literal values.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a literal declaration cannot be allocated.
}
procedure AddMavenDeclaration(const AValue: string; AValues: TStrings);
begin
  if Pos('${', AValue) > 0 then
    Exit;
  AddDeclaration(AValue, AValues);
end;

{**
  Collects license names declared directly by a Maven project.

  Parameters
  ----------
  AProject
    Maven project root element.
  AValues
    Declaration set receiving direct ``licenses/license/name`` values.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a license declaration cannot be allocated.
}
procedure CollectMavenLicenses(AProject: TDOMElement; AValues: TStrings);
var
  LicensesElement: TDOMElement;
  Child: TDOMNode;
begin
  LicensesElement := ExactChildElement(AProject, 'licenses');
  if LicensesElement = nil then
    Exit;
  Child := LicensesElement.FirstChild;
  while Child <> nil do
  begin
    if (Child is TDOMElement) and
      (CompareStr(LocalNodeName(Child), 'license') = 0) then
      AddMavenDeclaration(ExactChildText(Child, 'name'), AValues);
    Child := Child.NextSibling;
  end;
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
  Parses project declarations and dependency elements from a safe Maven POM.

  Parameters
  ----------
  AStream
    Bounded Maven XML stream to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving the declared Maven project and its dependencies.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for unsafe or malformed XML, stream access, or allocation
    failure.
}
procedure ParseMavenPOM(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Document: TXMLDocument;
  ProjectElement, ParentElement, OrganizationElement: TDOMElement;
  GroupID, ArtifactID, VersionValue, PURL: string;
  Licenses, Publishers: TStringList;
begin
  ReadSafeXMLStream(AStream, Document);
  Licenses := CreateDeclarationList;
  Publishers := CreateDeclarationList;
  try
    ProjectElement := Document.DocumentElement;
    CollectMavenLicenses(ProjectElement, Licenses);
    OrganizationElement := ExactChildElement(ProjectElement, 'organization');
    if OrganizationElement <> nil then
      AddMavenDeclaration(ExactChildText(OrganizationElement, 'name'),
        Publishers);
    ArtifactID := ChildText(ProjectElement, 'artifactId');
    GroupID := ChildText(ProjectElement, 'groupId');
    VersionValue := ChildText(ProjectElement, 'version');
    ParentElement := ChildElement(ProjectElement, 'parent');
    if ParentElement <> nil then
    begin
      if GroupID = '' then
        GroupID := ChildText(ParentElement, 'groupId');
      if VersionValue = '' then
        VersionValue := ChildText(ParentElement, 'version');
    end;
    if (ArtifactID <> '') and
      ((Licenses.Count > 0) or (Publishers.Count > 0)) then
    begin
      PURL := '';
      if (GroupID <> '') and IsExactVersion(VersionValue) then
        PURL := 'pkg:maven/' + PercentEncode(GroupID, False) + '/' +
          PercentEncode(ArtifactID, False) + '@' +
          PercentEncode(VersionValue, False);
      AddComponent(AComponents, ArtifactID, VersionValue, 'Maven',
        ARelativePath, 'maven-pom-xml', 'project', 'application', PURL,
        Licenses, Publishers);
    end;
    WalkMavenDependencies(ProjectElement, AComponents, ARelativePath);
  finally
    Publishers.Free;
    Licenses.Free;
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
  AStream
    Bounded XML project or package-properties stream to read.
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
    Propagated for unsafe or malformed XML, stream access, or allocation
    failure.
}
procedure ParseMSBuild(AStream: TStream; const ARelativePath, AParser: string;
  AComponents: TObjectList; ACentral: Boolean);
var
  Document: TXMLDocument;
begin
  ReadSafeXMLStream(AStream, Document);
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

{**
  Parses resolved package entries from every NuGet target framework.

  Parameters
  ----------
  AStream
    Bounded ``packages.lock.json`` stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved NuGet components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, an invalid root type, stream failure, or
    allocation failure.
*}
procedure ParseNuGetLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Dependencies: TJSONObject;
  I: Integer;
begin
  Data := ReadJSONStream(AStream);
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

{**
  Parses a Composer manifest and its declared project metadata.

  Parameters
  ----------
  AStream
    Bounded Composer JSON manifest stream to read.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving the declared project and runtime/development
    dependencies.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, stream access, or allocation failure.
}
procedure ParseComposerJSON(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
  Licenses, Publishers: TStringList;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONStream(AStream);
  Licenses := CreateDeclarationList;
  Publishers := CreateDeclarationList;
  try
    if Data.JSONType <> jtObject then
      raise Exception.Create('The Composer manifest root must be a JSON object');
    Root := TJSONObject(Data);
    NameValue := JSONString(Root, 'name');
    VersionValue := JSONString(Root, 'version');
    CollectJSONDeclarations(Root.Find('license'), Licenses);
    CollectJSONPublishers(Root.Find('authors'), Publishers);
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'Composer',
        ARelativePath, 'composer-json', 'project', 'application', '', Licenses,
        Publishers);
    ParseNamedJSONDependencies(JSONObject(Root, 'require'), AComponents,
      'Composer', ARelativePath, 'composer-json', 'runtime');
    ParseNamedJSONDependencies(JSONObject(Root, 'require-dev'), AComponents,
      'Composer', ARelativePath, 'composer-json', 'development');
  finally
    Publishers.Free;
    Licenses.Free;
    Data.Free;
  end;
end;

{**
  Adds declared packages from one Composer lock-file package array.

  Parameters
  ----------
  AArray
    One-dimensional array of Composer package objects; nil is ignored.
  AComponents
    Owned list receiving locked package components.
  ARelativePath
    Root-relative lock-file evidence path.
  AScope
    Stable dependency scope assigned to every accepted package.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if component or declaration storage cannot be allocated.
}
procedure ParseComposerPackageArray(AArray: TJSONArray; AComponents: TObjectList;
  const ARelativePath, AScope: string);
var
  I: Integer;
  Entry: TJSONObject;
  Licenses, Publishers: TStringList;
begin
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if AArray.Items[I].JSONType = jtObject then
    begin
      Entry := TJSONObject(AArray.Items[I]);
      Licenses := CreateDeclarationList;
      Publishers := CreateDeclarationList;
      try
        CollectJSONDeclarations(Entry.Find('license'), Licenses);
        CollectJSONPublishers(Entry.Find('authors'), Publishers);
        AddComponent(AComponents, JSONString(Entry, 'name'),
          JSONString(Entry, 'version'), 'Composer', ARelativePath,
          'composer-lock-json', AScope, 'library', '', Licenses, Publishers);
      finally
        Publishers.Free;
        Licenses.Free;
      end;
    end;
end;

{**
  Parses runtime and development packages from a Composer lock document.

  Parameters
  ----------
  AStream
    Bounded ``composer.lock`` JSON stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved Composer components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, an invalid root type, stream failure, or
    allocation failure.
*}
procedure ParseComposerLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  Data := ReadJSONStream(AStream);
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

{**
  Parses required-package names from a Lazarus project XML document.

  Parameters
  ----------
  AStream
    Bounded Lazarus project stream parsed with document types disabled.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving declared Free Pascal package components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for unsafe or malformed XML, stream failure, or allocation
    failure.
*}
procedure ParseLazarusXML(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Document: TXMLDocument;
begin
  ReadSafeXMLStream(AStream, Document);
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

{**
  Parses resolved default and development sections from ``Pipfile.lock``.

  Parameters
  ----------
  AStream
    Bounded lock-document JSON stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved PyPI components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, an invalid root type, stream failure, or
    allocation failure.
*}
procedure ParsePipfileLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  Data := ReadJSONStream(AStream);
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

{**
  Conservatively parses module and version pairs from a Go checksum file.

  Parameters
  ----------
  AStream
    Bounded ``go.sum`` text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved Go module components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParseGoSum(AStream: TStream; const ARelativePath: string;
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
    LoadLinesFromStream(AStream, Lines);
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

{**
  Removes a TOML comment while respecting single- and double-quoted strings.

  Parameters
  ----------
  ALine
    One physical TOML line.

  Returns
  -------
  string
    Trimmed line content before the first unquoted comment marker.

  Raises
  ------
  EOutOfMemory
    Propagated if the returned substring cannot be allocated.
}
function StripTOMLComment(const ALine: string): string;
var
  I: Integer;
  QuoteValue: Char;
  Escaped: Boolean;
begin
  QuoteValue := #0;
  Escaped := False;
  for I := 1 to Length(ALine) do
  begin
    if QuoteValue <> #0 then
    begin
      if (QuoteValue = '"') and (ALine[I] = '\') and not Escaped then
      begin
        Escaped := True;
        Continue;
      end;
      if (ALine[I] = QuoteValue) and not Escaped then
        QuoteValue := #0;
      Escaped := False;
      Continue;
    end;
    if ALine[I] in ['"', ''''] then
      QuoteValue := ALine[I]
    else if ALine[I] = '#' then
      Exit(Trim(Copy(ALine, 1, I - 1)));
  end;
  Result := Trim(ALine);
end;

{**
  Reads the raw right-hand side of one direct TOML assignment.

  Parameters
  ----------
  ALine
    One physical TOML line.
  AKey
    Exact unquoted key expected before the equals sign.
  AValue
    Receives the trimmed, comment-free right-hand side.

  Returns
  -------
  Boolean
    True when the requested direct assignment is present and non-empty.

  Raises
  ------
  EOutOfMemory
    Propagated if temporary strings cannot be allocated.
}
function TryTOMLAssignmentValue(const ALine, AKey: string;
  out AValue: string): Boolean;
var
  LineValue: string;
  EqualsAt: SizeInt;
begin
  AValue := '';
  LineValue := StripTOMLComment(ALine);
  EqualsAt := Pos('=', LineValue);
  Result := (EqualsAt > 1) and
    (CompareStr(Trim(Copy(LineValue, 1, EqualsAt - 1)), AKey) = 0);
  if not Result then
    Exit;
  AValue := Trim(Copy(LineValue, EqualsAt + 1, MaxInt));
  Result := AValue <> '';
end;

{**
  Consumes one deliberately restricted TOML literal string.

  Parameters
  ----------
  AText
    Complete single-line TOML value being parsed.
  APosition
    One-based input position; advanced past the closing quote on success.
  AValue
    Receives the exact unquoted text without escape interpretation.

  Returns
  -------
  Boolean
    True only for a bounded single-line literal. Double-quoted escape
    sequences are rejected because this conservative parser does not decode
    them and must never alter declaration evidence.

  Raises
  ------
  EOutOfMemory
    Propagated if the returned value cannot be allocated.
}
function TryConsumeTOMLLiteralString(const AText: string;
  var APosition: Integer; out AValue: string): Boolean;
const
  MaximumDeclarationLength = 4096;
var
  QuoteValue: Char;
  ValueStart: Integer;
begin
  Result := False;
  AValue := '';
  if (APosition < 1) or (APosition > Length(AText)) or
    not (AText[APosition] in ['"', '''']) then
    Exit;
  QuoteValue := AText[APosition];
  Inc(APosition);
  ValueStart := APosition;
  while (APosition <= Length(AText)) and
    (AText[APosition] <> QuoteValue) do
  begin
    if (Ord(AText[APosition]) < 32) or
      (Ord(AText[APosition]) = 127) or
      ((QuoteValue = '"') and (AText[APosition] = '\')) then
      Exit;
    Inc(APosition);
  end;
  if APosition > Length(AText) then
    Exit;
  AValue := Copy(AText, ValueStart, APosition - ValueStart);
  Inc(APosition);
  Result := Length(AValue) <= MaximumDeclarationLength;
end;

{**
  Parses one conservative single-line TOML string assignment.

  Parameters
  ----------
  ALine
    Physical TOML line containing the assignment.
  AKey
    Exact key to match.
  AValue
    Receives the unquoted literal string.

  Returns
  -------
  Boolean
    True only for a bounded single- or double-quoted, non-multiline literal.

  Raises
  ------
  EOutOfMemory
    Propagated if temporary strings cannot be allocated.
}
function TryTOMLStringAssignment(const ALine, AKey: string;
  out AValue: string): Boolean;
var
  RawValue: string;
  PositionValue: Integer;
begin
  AValue := '';
  RawValue := '';
  if not TryTOMLAssignmentValue(ALine, AKey, RawValue) then
    Exit(False);
  PositionValue := 1;
  Result := TryConsumeTOMLLiteralString(RawValue, PositionValue, AValue) and
    (AValue <> '') and (PositionValue > Length(RawValue));
end;

{**
  Collects a one-line TOML array of literal strings.

  Parameters
  ----------
  ALine
    Physical TOML assignment line.
  AKey
    Exact array key to match.
  AValues
    Declaration set receiving each bounded quoted string.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if tokenization or declaration allocation fails.
}
procedure CollectTOMLStringArray(const ALine, AKey: string;
  AValues: TStrings);
var
  RawValue, ItemValue: string;
  Items: TStringList;
  PositionValue: Integer;
begin
  if not TryTOMLAssignmentValue(ALine, AKey, RawValue) or
    (Length(RawValue) < 2) or (RawValue[1] <> '[') or
    (RawValue[Length(RawValue)] <> ']') then
    Exit;
  Items := CreateDeclarationList;
  try
    PositionValue := 2;
    while PositionValue <= Length(RawValue) do
    begin
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if (PositionValue = Length(RawValue)) and
        (RawValue[PositionValue] = ']') then
      begin
        Inc(PositionValue);
        Break;
      end;
      if not TryConsumeTOMLLiteralString(RawValue, PositionValue,
        ItemValue) or (ItemValue = '') then
        Exit;
      AddDeclaration(ItemValue, Items);
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if PositionValue > Length(RawValue) then
        Exit;
      if RawValue[PositionValue] = ']' then
      begin
        Inc(PositionValue);
        Break;
      end;
      if RawValue[PositionValue] <> ',' then
        Exit;
      Inc(PositionValue);
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if (PositionValue = Length(RawValue)) and
        (RawValue[PositionValue] = ']') then
      begin
        Inc(PositionValue);
        Break;
      end;
      if PositionValue > Length(RawValue) then
          Exit;
    end;
    if PositionValue > Length(RawValue) then
      AValues.AddStrings(Items);
  finally
    Items.Free;
  end;
end;

{**
  Collects ``name`` strings from a one-line PEP-621 author-table array.

  Parameters
  ----------
  ALine
    Physical authors assignment containing one-line inline tables.
  AValues
    Publisher declaration set receiving bounded author names.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a publisher declaration cannot be allocated.
}
procedure CollectTOMLInlineAuthorNames(const ALine: string;
  AValues: TStrings);
var
  RawValue, KeyValue, NameValue, StringValue: string;
  Items: TStringList;
  PositionValue, KeyStart: Integer;
  HasName, HasEmail: Boolean;
begin
  if not TryTOMLAssignmentValue(ALine, 'authors', RawValue) then
    Exit;
  if (Length(RawValue) < 2) or (RawValue[1] <> '[') or
    (RawValue[Length(RawValue)] <> ']') then
    Exit;
  Items := CreateDeclarationList;
  try
    PositionValue := 2;
    while PositionValue <= Length(RawValue) do
    begin
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if (PositionValue = Length(RawValue)) and
        (RawValue[PositionValue] = ']') then
      begin
        Inc(PositionValue);
        Break;
      end;
      if (PositionValue > Length(RawValue)) or
        (RawValue[PositionValue] <> '{') then
        Exit;
      Inc(PositionValue);
      HasName := False;
      HasEmail := False;
      NameValue := '';
      while True do
      begin
        while (PositionValue <= Length(RawValue)) and
          (RawValue[PositionValue] in [' ', #9]) do
          Inc(PositionValue);
        KeyStart := PositionValue;
        while (PositionValue <= Length(RawValue)) and
          (RawValue[PositionValue] in ['A'..'Z', 'a'..'z', '0'..'9',
          '_', '-']) do
          Inc(PositionValue);
        if PositionValue = KeyStart then
          Exit;
        KeyValue := Copy(RawValue, KeyStart, PositionValue - KeyStart);
        while (PositionValue <= Length(RawValue)) and
          (RawValue[PositionValue] in [' ', #9]) do
          Inc(PositionValue);
        if (PositionValue > Length(RawValue)) or
          (RawValue[PositionValue] <> '=') then
          Exit;
        Inc(PositionValue);
        while (PositionValue <= Length(RawValue)) and
          (RawValue[PositionValue] in [' ', #9]) do
          Inc(PositionValue);
        if not TryConsumeTOMLLiteralString(RawValue, PositionValue,
          StringValue) then
          Exit;
        if KeyValue = 'name' then
        begin
          if HasName then
            Exit;
          HasName := True;
          NameValue := StringValue;
        end
        else if KeyValue = 'email' then
        begin
          if HasEmail then
            Exit;
          HasEmail := True;
        end
        else
          Exit;
        while (PositionValue <= Length(RawValue)) and
          (RawValue[PositionValue] in [' ', #9]) do
          Inc(PositionValue);
        if (PositionValue > Length(RawValue)) then
          Exit;
        if RawValue[PositionValue] = '}' then
        begin
          Inc(PositionValue);
          Break;
        end;
        if RawValue[PositionValue] <> ',' then
          Exit;
        Inc(PositionValue);
      end;
      if HasName and (NameValue <> '') then
        AddDeclaration(NameValue, Items);
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if PositionValue > Length(RawValue) then
        Exit;
      if RawValue[PositionValue] = ']' then
      begin
        Inc(PositionValue);
        Break;
      end;
      if RawValue[PositionValue] <> ',' then
        Exit;
      Inc(PositionValue);
      while (PositionValue <= Length(RawValue)) and
        (RawValue[PositionValue] in [' ', #9]) do
        Inc(PositionValue);
      if (PositionValue = Length(RawValue)) and
        (RawValue[PositionValue] = ']') then
      begin
        Inc(PositionValue);
        Break;
      end;
    end;
    if PositionValue > Length(RawValue) then
      AValues.AddStrings(Items);
  finally
    Items.Free;
  end;
end;

function TryCanonicalSHA256Hex(const AValue: string;
  out ADigest: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  ADigest := '';
  if Length(AValue) <> 64 then
    Exit;
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit;
  ADigest := LowerCase(AValue);
  Result := True;
end;

procedure ParseCargoLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, PreviousCount: Integer;
  LineValue, NameValue, VersionValue, ChecksumValue, DigestValue: string;
  InPackage: Boolean;
  Component: TComponent;

  procedure Emit;
  begin
    PreviousCount := AComponents.Count;
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'Cargo',
        ARelativePath, 'conservative-cargo-lock', 'resolved');
    if (AComponents.Count > PreviousCount) and
      IsExactEcosystemVersion('Cargo', VersionValue) and
      TryCanonicalSHA256Hex(ChecksumValue, DigestValue) then
    begin
      Component := TComponent(AComponents[AComponents.Count - 1]);
      AddDeclaredHash(Component, 'SHA-256', DigestValue,
        Trim(NameValue) + '@' + Trim(VersionValue), ARelativePath,
        'conservative-cargo-lock');
    end;
    NameValue := '';
    VersionValue := '';
    ChecksumValue := '';
  end;

begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
    NameValue := '';
    VersionValue := '';
    ChecksumValue := '';
    InPackage := False;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := StripTOMLComment(Lines[I]);
      if LineValue = '[[package]]' then
      begin
        Emit;
        InPackage := True;
        Continue;
      end;
      if not InPackage then
        Continue;
      if TryTOMLStringAssignment(LineValue, 'name', DigestValue) then
        NameValue := DigestValue
      else if TryTOMLStringAssignment(LineValue, 'version', DigestValue) then
        VersionValue := DigestValue
      else if TryTOMLStringAssignment(LineValue, 'checksum', DigestValue) then
        ChecksumValue := DigestValue;
    end;
    Emit;
  finally
    Lines.Free;
  end;
end;

procedure SkipTOMLWhitespace(const AText: string; var APosition: Integer);
begin
  while (APosition <= Length(AText)) and
    (AText[APosition] in [' ', #9, #10, #13]) do
    Inc(APosition);
end;

function IsPoetryArchiveSubject(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := (AValue <> '') and
    (Length(AValue) <= MaximumDeclaredHashSubjectLength) and
    (Pos('/', AValue) = 0) and (Pos('\', AValue) = 0) and
    (Pos('://', AValue) = 0);
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(False);
end;

function ParsePoetryFilesValue(const AValue, ARelativePath: string;
  AHashes: TDeclaredHashList): Boolean;
var
  Pending: TDeclaredHashList;
  PositionValue, KeyStart: Integer;
  KeyValue, StringValue, FileValue, HashValue, DigestValue: string;
  FileSeen, HashSeen: Boolean;
  DeclaredHash: TDeclaredHash;
begin
  Result := False;
  if (AHashes = nil) or (AValue = '') then
    Exit;
  Pending := TDeclaredHashList.Create;
  try
    PositionValue := 1;
    SkipTOMLWhitespace(AValue, PositionValue);
    if (PositionValue > Length(AValue)) or
      (AValue[PositionValue] <> '[') then
      Exit;
    Inc(PositionValue);
    while True do
    begin
      SkipTOMLWhitespace(AValue, PositionValue);
      if PositionValue > Length(AValue) then
        Exit;
      if AValue[PositionValue] = ']' then
      begin
        Inc(PositionValue);
        Break;
      end;
      if AValue[PositionValue] <> '{' then
        Exit;
      Inc(PositionValue);
      FileSeen := False;
      HashSeen := False;
      FileValue := '';
      HashValue := '';
      while True do
      begin
        SkipTOMLWhitespace(AValue, PositionValue);
        KeyStart := PositionValue;
        while (PositionValue <= Length(AValue)) and
          (AValue[PositionValue] in ['A'..'Z', 'a'..'z', '0'..'9',
          '_', '-']) do
          Inc(PositionValue);
        if PositionValue = KeyStart then
          Exit;
        KeyValue := Copy(AValue, KeyStart, PositionValue - KeyStart);
        SkipTOMLWhitespace(AValue, PositionValue);
        if (PositionValue > Length(AValue)) or
          (AValue[PositionValue] <> '=') then
          Exit;
        Inc(PositionValue);
        SkipTOMLWhitespace(AValue, PositionValue);
        if not TryConsumeTOMLLiteralString(AValue, PositionValue,
          StringValue) then
          Exit;
        if KeyValue = 'file' then
        begin
          if FileSeen then
            Exit;
          FileSeen := True;
          FileValue := StringValue;
        end
        else if KeyValue = 'hash' then
        begin
          if HashSeen then
            Exit;
          HashSeen := True;
          HashValue := StringValue;
        end
        else
          Exit;
        SkipTOMLWhitespace(AValue, PositionValue);
        if PositionValue > Length(AValue) then
          Exit;
        if AValue[PositionValue] = '}' then
        begin
          Inc(PositionValue);
          Break;
        end;
        if AValue[PositionValue] <> ',' then
          Exit;
        Inc(PositionValue);
      end;
      if FileSeen and HashSeen and IsPoetryArchiveSubject(FileValue) and
        (Length(HashValue) > 7) and
        (LowerCase(Copy(HashValue, 1, 7)) = 'sha256:') and
        TryCanonicalSHA256Hex(Copy(HashValue, 8, MaxInt), DigestValue) then
      begin
        DeclaredHash := TDeclaredHash.Create;
        DeclaredHash.Algorithm := 'SHA-256';
        DeclaredHash.Digest := DigestValue;
        DeclaredHash.Subject := FileValue;
        DeclaredHash.SourceArtifact := ARelativePath;
        DeclaredHash.SourceParser := 'conservative-poetry-lock';
        Pending.Add(DeclaredHash);
      end;
      SkipTOMLWhitespace(AValue, PositionValue);
      if PositionValue > Length(AValue) then
        Exit;
      if AValue[PositionValue] = ']' then
      begin
        Inc(PositionValue);
        Break;
      end;
      if AValue[PositionValue] <> ',' then
        Exit;
      Inc(PositionValue);
    end;
    SkipTOMLWhitespace(AValue, PositionValue);
    if PositionValue <= Length(AValue) then
      Exit;
    AHashes.AddClones(Pending);
    Result := True;
  finally
    Pending.Free;
  end;
end;

procedure UpdateTOMLArrayDepth(const AText: string; var ADepth: Integer;
  var AValid: Boolean);
var
  I: Integer;
  QuoteValue: Char;
  Escaped: Boolean;
begin
  QuoteValue := #0;
  Escaped := False;
  for I := 1 to Length(AText) do
  begin
    if QuoteValue <> #0 then
    begin
      if (QuoteValue = '"') and (AText[I] = '\') and not Escaped then
      begin
        Escaped := True;
        Continue;
      end;
      if (AText[I] = QuoteValue) and not Escaped then
        QuoteValue := #0;
      Escaped := False;
      Continue;
    end;
    if AText[I] in ['"', ''''] then
      QuoteValue := AText[I]
    else if AText[I] = '[' then
      Inc(ADepth)
    else if AText[I] = ']' then
    begin
      Dec(ADepth);
      if ADepth < 0 then
      begin
        AValid := False;
        Exit;
      end;
    end;
  end;
  if QuoteValue <> #0 then
    AValid := False;
end;

function CollectPoetryFilesArray(ALines: TStrings; var ALineIndex: Integer;
  const AFirstValue: string; out AValue: string): Boolean;
const
  MaximumPoetryFilesArrayLength = 1024 * 1024;
var
  Depth, NextIndex: Integer;
  Valid, Retain: Boolean;
  LineValue: string;
begin
  Result := False;
  AValue := '';
  Depth := 0;
  Valid := True;
  Retain := Length(AFirstValue) <= MaximumPoetryFilesArrayLength;
  if Retain then
    AValue := AFirstValue;
  UpdateTOMLArrayDepth(AFirstValue, Depth, Valid);
  while Valid and (Depth > 0) do
  begin
    NextIndex := ALineIndex + 1;
    if NextIndex >= ALines.Count then
      Exit;
    LineValue := StripTOMLComment(ALines[NextIndex]);
    if LineValue = '[[package]]' then
      Exit;
    ALineIndex := NextIndex;
    if Retain then
    begin
      if Length(AValue) + Length(LineValue) + 1 >
        MaximumPoetryFilesArrayLength then
      begin
        Retain := False;
        AValue := '';
      end
      else
        AValue := AValue + #10 + LineValue;
    end;
    UpdateTOMLArrayDepth(LineValue, Depth, Valid);
  end;
  Result := Valid and Retain and (Depth = 0);
end;

procedure ParsePoetryLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  PendingHashes: TDeclaredHashList;
  I, PreviousCount: Integer;
  LineValue, NameValue, VersionValue, AssignmentValue,
    FilesValue: string;
  InPackage: Boolean;
  Component: TComponent;

  procedure Emit;
  begin
    PreviousCount := AComponents.Count;
    if NameValue <> '' then
      AddComponent(AComponents, NameValue, VersionValue, 'PyPI',
        ARelativePath, 'conservative-poetry-lock', 'resolved');
    if (AComponents.Count > PreviousCount) and
      IsExactEcosystemVersion('PyPI', VersionValue) then
    begin
      Component := TComponent(AComponents[AComponents.Count - 1]);
      Component.DeclaredHashes.AddClones(PendingHashes);
    end;
    NameValue := '';
    VersionValue := '';
    PendingHashes.Clear;
  end;

begin
  Lines := TStringList.Create;
  PendingHashes := TDeclaredHashList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
    NameValue := '';
    VersionValue := '';
    InPackage := False;
    I := 0;
    while I < Lines.Count do
    begin
      LineValue := StripTOMLComment(Lines[I]);
      if LineValue = '[[package]]' then
      begin
        Emit;
        InPackage := True;
        Inc(I);
        Continue;
      end;
      if InPackage then
      begin
        if TryTOMLStringAssignment(LineValue, 'name', AssignmentValue) then
          NameValue := AssignmentValue
        else if TryTOMLStringAssignment(LineValue, 'version',
          AssignmentValue) then
          VersionValue := AssignmentValue
        else if TryTOMLAssignmentValue(LineValue, 'files',
          AssignmentValue) and (AssignmentValue <> '') and
          (AssignmentValue[1] = '[') and
          CollectPoetryFilesArray(Lines, I, AssignmentValue, FilesValue) then
          ParsePoetryFilesValue(FilesValue, ARelativePath, PendingHashes);
      end;
      Inc(I);
    end;
    Emit;
  finally
    PendingHashes.Free;
    Lines.Free;
  end;
end;

{**
  Conservatively parses Cargo package declarations and dependency sections.

  Parameters
  ----------
  AStream
    Cargo.toml stream to read without evaluating workspace inheritance.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving the project and declared dependencies.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated when stream access or component allocation fails.
}
procedure ParseCargoTOML(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, EqualsAt: Integer;
  LineValue, SectionValue, NameValue, VersionValue, ScopeValue: string;
  ProjectName, ProjectVersion, DeclarationValue: string;
  Licenses, Publishers: TStringList;
begin
  Lines := TStringList.Create;
  Licenses := CreateDeclarationList;
  Publishers := CreateDeclarationList;
  try
    LoadLinesFromStream(AStream, Lines);
    SectionValue := '';
    ProjectName := '';
    ProjectVersion := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := StripTOMLComment(Lines[I]);
      if (Length(LineValue) >= 2) and (LineValue[1] = '[') and
        (LineValue[Length(LineValue)] = ']') then
      begin
        SectionValue := Trim(Copy(LineValue, 2,
          Length(LineValue) - 2));
        Continue;
      end;
      if SectionValue <> 'package' then
        Continue;
      if TryTOMLStringAssignment(LineValue, 'name', DeclarationValue) then
        ProjectName := DeclarationValue
      else if TryTOMLStringAssignment(LineValue, 'version',
        DeclarationValue) then
        ProjectVersion := DeclarationValue
      else if TryTOMLStringAssignment(LineValue, 'license',
        DeclarationValue) then
        AddDeclaration(DeclarationValue, Licenses)
      else
        CollectTOMLStringArray(LineValue, 'authors', Publishers);
    end;
    if ProjectName <> '' then
      AddComponent(AComponents, ProjectName, ProjectVersion, 'Cargo',
        ARelativePath, 'conservative-cargo-toml', 'project', 'application',
        '', Licenses, Publishers);

    SectionValue := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := StripTOMLComment(Lines[I]);
      if (Length(LineValue) >= 2) and (LineValue[1] = '[') and
        (LineValue[Length(LineValue)] = ']') then
      begin
        SectionValue := Trim(Copy(LineValue, 2, Length(LineValue) - 2));
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
    Publishers.Free;
    Licenses.Free;
    Lines.Free;
  end;
end;

{**
  Conservatively parses direct PEP-621 or Poetry project declarations.

  Parameters
  ----------
  AStream
    pyproject.toml stream to read without executing a build backend.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving at most one project component.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated when stream access or component allocation fails.

  Notes
  -----
  Only bounded single-line literal fields are accepted. License file
  references, dynamic values, multiline values, and dependency tables are not
  interpreted.
}
procedure ParsePyProjectTOML(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  ProjectLicenses, ProjectPublishers, PoetryLicenses,
    PoetryPublishers: TStringList;
  I: Integer;
  LineValue, SectionValue, DeclarationValue: string;
  ProjectName, ProjectVersion, PoetryName, PoetryVersion: string;
begin
  Lines := TStringList.Create;
  ProjectLicenses := CreateDeclarationList;
  ProjectPublishers := CreateDeclarationList;
  PoetryLicenses := CreateDeclarationList;
  PoetryPublishers := CreateDeclarationList;
  try
    LoadLinesFromStream(AStream, Lines);
    SectionValue := '';
    ProjectName := '';
    ProjectVersion := '';
    PoetryName := '';
    PoetryVersion := '';
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := StripTOMLComment(Lines[I]);
      if (Length(LineValue) >= 2) and (LineValue[1] = '[') and
        (LineValue[Length(LineValue)] = ']') then
      begin
        SectionValue := Trim(Copy(LineValue, 2,
          Length(LineValue) - 2));
        Continue;
      end;
      if SectionValue = 'project' then
      begin
        if TryTOMLStringAssignment(LineValue, 'name', DeclarationValue) then
          ProjectName := DeclarationValue
        else if TryTOMLStringAssignment(LineValue, 'version',
          DeclarationValue) then
          ProjectVersion := DeclarationValue
        else if TryTOMLStringAssignment(LineValue, 'license',
          DeclarationValue) then
          AddDeclaration(DeclarationValue, ProjectLicenses)
        else
          CollectTOMLInlineAuthorNames(LineValue, ProjectPublishers);
      end
      else if SectionValue = 'tool.poetry' then
      begin
        if TryTOMLStringAssignment(LineValue, 'name', DeclarationValue) then
          PoetryName := DeclarationValue
        else if TryTOMLStringAssignment(LineValue, 'version',
          DeclarationValue) then
          PoetryVersion := DeclarationValue
        else if TryTOMLStringAssignment(LineValue, 'license',
          DeclarationValue) then
          AddDeclaration(DeclarationValue, PoetryLicenses)
        else
          CollectTOMLStringArray(LineValue, 'authors', PoetryPublishers);
      end;
    end;
    if ProjectName <> '' then
      AddComponent(AComponents, ProjectName, ProjectVersion, 'PyPI',
        ARelativePath, 'conservative-pyproject-toml', 'project',
        'application', '', ProjectLicenses, ProjectPublishers)
    else if PoetryName <> '' then
      AddComponent(AComponents, PoetryName, PoetryVersion, 'PyPI',
        ARelativePath, 'conservative-pyproject-toml', 'project',
        'application', '', PoetryLicenses, PoetryPublishers);
  finally
    PoetryPublishers.Free;
    PoetryLicenses.Free;
    ProjectPublishers.Free;
    ProjectLicenses.Free;
    Lines.Free;
  end;
end;

{**
  Conservatively parses package keys and resolved versions from ``yarn.lock``.

  Parameters
  ----------
  AStream
    Bounded Yarn lock text stream.
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
    Propagated for stream access or allocation failure.
*}
procedure ParseYarnLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, AtPos, CommaAt: Integer;
  LineValue, NameValue, VersionValue: string;

  {**
    Emits the enclosing Yarn entry and resets its captured identity fields.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Raises
    ------
    EOutOfMemory
      Propagated if component evidence cannot be allocated.
  *}
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
    LoadLinesFromStream(AStream, Lines);
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

{**
  Conservatively parses Maven coordinates from a Gradle lock stream.

  Parameters
  ----------
  AStream
    Bounded Gradle lock text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved Gradle components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParseGradleLock(AStream: TStream; const ARelativePath: string;
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
    LoadLinesFromStream(AStream, Lines);
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

{**
  Conservatively parses resolved gem entries from ``Gemfile.lock``.

  Parameters
  ----------
  AStream
    Bounded RubyGems lock text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved RubyGems components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParseGemLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, OpenAt, CloseAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InSpecs: Boolean;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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

{**
  Conservatively parses top-level conda dependencies from environment YAML.

  Parameters
  ----------
  AStream
    Bounded ``environment.yml`` or ``environment.yaml`` text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving declared conda components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParseEnvironmentYAML(AStream: TStream;
  const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, EqualsAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InDependencies: Boolean;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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

{**
  Parses either supported Swift ``Package.resolved`` JSON layout.

  Parameters
  ----------
  AStream
    Bounded Swift resolved-package JSON stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved Swift package components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, an invalid root type, stream failure, or
    allocation failure.
*}
procedure ParsePackageResolved(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data: TJSONData;
  Root, ObjectValue: TJSONObject;
  Pins: TJSONArray;
begin
  Data := ReadJSONStream(AStream);
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

{**
  Conservatively parses resolved pod entries from ``Podfile.lock``.

  Parameters
  ----------
  AStream
    Bounded CocoaPods lock text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving resolved CocoaPods components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParsePodfileLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, OpenAt, CloseAt: Integer;
  LineValue, NameValue, VersionValue: string;
  InPods: Boolean;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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

{**
  Parses dependency names and minimum versions from ``vcpkg.json``.

  Parameters
  ----------
  AStream
    Bounded vcpkg manifest JSON stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving declared vcpkg components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for malformed JSON, an invalid root type, stream failure, or
    allocation failure.
*}
procedure ParseVcpkgJSON(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Data, Entry: TJSONData;
  Root: TJSONObject;
  Dependencies: TJSONArray;
  I: Integer;
  NameValue, VersionValue: string;
begin
  Data := ReadJSONStream(AStream);
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

{**
  Conservatively parses direct requirements from ``conanfile.txt``.

  Parameters
  ----------
  AStream
    Bounded Conan manifest text stream.
  ARelativePath
    Root-relative evidence path.
  AComponents
    Owned list receiving declared Conan components.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Propagated for stream access or allocation failure.
*}
procedure ParseConanText(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, SlashAt: Integer;
  LineValue, SectionValue, NameValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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

{**
  Conservatively parses resolved package keys from ``pnpm-lock.yaml``.

  Parameters
  ----------
  AStream
    Bounded pnpm lock text stream.
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
    Propagated for stream access or allocation failure.
*}
procedure ParsePNPMLock(AStream: TStream; const ARelativePath: string;
  AComponents: TObjectList);
var
  Lines: TStringList;
  I, SlashAt: Integer;
  LineValue, NameValue, VersionValue: string;
begin
  Lines := TStringList.Create;
  try
    LoadLinesFromStream(AStream, Lines);
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
  InstalledManifestLimit: Int64 = 2 * 1024 * 1024;
  JSONLockLimit: Int64 = 32 * 1024 * 1024;
  LineLockLimit: Int64 = 64 * 1024 * 1024;
begin
  case AParserKind of
    pkNone:
      Result := 0;
    pkInstalledPackageJSON, pkPythonDistInfoMetadata:
      Result := InstalledManifestLimit;
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
    pkPackageResolved, pkPodfileLock, pkVcpkgJSON, pkConanText, pkPNPMLock,
    pkPyProjectTOML];
end;

procedure ParseArtifact(AStream: TStream; const ARelativePath: string;
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
      pkPackageJSON: ParsePackageJSON(AStream, ARelativePath, AComponents);
      pkInstalledPackageJSON: ParseInstalledPackageJSON(AStream,
        ARelativePath, AComponents);
      pkPythonDistInfoMetadata: ParsePythonDistInfoMetadata(AStream,
        ARelativePath, AComponents);
      pkPackageLockJSON: ParsePackageLock(AStream, ARelativePath, AComponents);
      pkRequirements: ParseRequirements(AStream, ARelativePath, AComponents);
      pkGoMod: ParseGoMod(AStream, ARelativePath, AComponents);
      pkMavenPOM: ParseMavenPOM(AStream, ARelativePath, AComponents);
      pkMSBuildProject: ParseMSBuild(AStream, ARelativePath,
        'msbuild-package-reference', AComponents, False);
      pkNuGetLock: ParseNuGetLock(AStream, ARelativePath, AComponents);
      pkDirectoryPackages: ParseMSBuild(AStream, ARelativePath,
        'msbuild-central-package-xml', AComponents, True);
      pkComposerJSON: ParseComposerJSON(AStream, ARelativePath, AComponents);
      pkComposerLock: ParseComposerLock(AStream, ARelativePath, AComponents);
      pkLazarusXML: ParseLazarusXML(AStream, ARelativePath, AComponents);
      pkPipfileLock: ParsePipfileLock(AStream, ARelativePath, AComponents);
      pkGoSum: ParseGoSum(AStream, ARelativePath, AComponents);
      pkCargoLock: ParseCargoLock(AStream, ARelativePath, AComponents);
      pkPoetryLock: ParsePoetryLock(AStream, ARelativePath, AComponents);
      pkCargoTOML: ParseCargoTOML(AStream, ARelativePath, AComponents);
      pkYarnLock: ParseYarnLock(AStream, ARelativePath, AComponents);
      pkGradleLock: ParseGradleLock(AStream, ARelativePath, AComponents);
      pkGemLock: ParseGemLock(AStream, ARelativePath, AComponents);
      pkEnvironmentYAML: ParseEnvironmentYAML(AStream, ARelativePath,
        AComponents);
      pkPackageResolved: ParsePackageResolved(AStream, ARelativePath,
        AComponents);
      pkPodfileLock: ParsePodfileLock(AStream, ARelativePath, AComponents);
      pkVcpkgJSON: ParseVcpkgJSON(AStream, ARelativePath, AComponents);
      pkConanText: ParseConanText(AStream, ARelativePath, AComponents);
      pkPNPMLock: ParsePNPMLock(AStream, ARelativePath, AComponents);
      pkPyProjectTOML: ParsePyProjectTOML(AStream, ARelativePath,
        AComponents);
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

procedure ParseArtifact(const AFileName, ARelativePath: string;
  AParserKind: TParserKind; AArtifact: TArtifact; AComponents: TObjectList);
var
  Stream: TFileStream;
begin
  Stream := nil;
  try
    try
      Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
      ParseArtifact(Stream, ARelativePath, AParserKind, AArtifact,
        AComponents);
    except
      on E: Exception do
      begin
        AArtifact.Status := arsFailed;
        AArtifact.MessageText := E.Message;
        AArtifact.ComponentCount := 0;
      end;
    end;
  finally
    Stream.Free;
  end;
end;

end.
