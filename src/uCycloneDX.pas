(**
  PurpleRay SBOM Analyzer CycloneDX serialization unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Converts a completed scan task into deterministic, path-conscious CycloneDX
  1.6 or 1.7 JSON with scanner, evidence, subject, and dependency metadata.

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
unit uCycloneDX;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

type
  TCycloneDXSpecVersion = (cdxSpec16, cdxSpec17);

{**
  Serializes a scan task as deterministic CycloneDX 1.7 JSON.

  Parameters
  ----------
  ATask
    Completed or partial task whose metadata and components are serialized.

  Returns
  -------
  UTF8String
    Pretty-printed CycloneDX JSON with normalized line endings.

  Raises
  ------
  EAccessViolation
    Raised if ATask is nil; callers must supply a valid task.
  EJSON
    May propagate if JSON object construction fails.
}
function GenerateCycloneDX(ATask: TScanTask): UTF8String; overload;

{**
  Serializes a scan task using an explicitly selected CycloneDX version.

  Parameters
  ----------
  ATask
    Completed or partial task whose metadata and components are serialized.
  ASpecVersion
    Supported CycloneDX schema/specification version to emit.

  Returns
  -------
  UTF8String
    Pretty-printed CycloneDX JSON with normalized line endings.

  Raises
  ------
  EAccessViolation
    Raised if ATask is nil; callers must supply a valid task.
  EJSON
    May propagate if JSON object construction fails.
}
function GenerateCycloneDX(ATask: TScanTask;
  ASpecVersion: TCycloneDXSpecVersion): UTF8String; overload;

implementation

uses
  Classes, Contnrs, fpjson, uJSONUtils, uManifestParsers, uSHA256,
  uSPDXExpressions, uVersionInfo;

type
  TArtifactReferenceList = class(TList);

{**
  Orders artifact references by exact relative path and then artifact type.

  Parameters
  ----------
  Item1, Item2
    Artifact pointers supplied by ``TList.Sort``.

  Returns
  -------
  Integer
    Negative, zero, or positive according to deterministic ordinal ordering.

  Raises
  ------
  EAccessViolation
    Raised if either list item is not a valid artifact.
}
function CompareArtifacts(Item1, Item2: Pointer): Integer;
var
  Left, Right: TArtifact;
begin
  Left := TArtifact(Item1);
  Right := TArtifact(Item2);
  Result := CompareStr(Left.RelativePath, Right.RelativePath);
  if Result = 0 then
    Result := CompareStr(Left.ArtifactType, Right.ArtifactType);
end;

{**
  Applies the task's absolute-path export policy to one evidence path.

  Parameters
  ----------
  ATask
    Task supplying the target directory and path-export setting.
  ARelativePath
    Root-relative evidence path.

  Returns
  -------
  string
    Absolute platform path when explicitly enabled, otherwise a slash-normalized
    relative path.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
}
function OutputPath(ATask: TScanTask; const ARelativePath: string): string;
begin
  if ATask.Settings.IncludeAbsolutePaths then
    Result := ExpandFileName(IncludeTrailingPathDelimiter(
      ATask.TargetDirectory) + StringReplace(ARelativePath, '/',
      DirectorySeparator, [rfReplaceAll]))
  else
    Result := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
end;

{**
  Appends one nonempty CycloneDX name/value property.

  Parameters
  ----------
  AProperties
    JSON array that takes ownership of the new property object.
  AName, AValue
    Property identity and value; an empty value is ignored.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when AProperties is nil and AValue is nonempty.
  EOutOfMemory
    Propagated when the property cannot be allocated.
}
procedure AddProperty(AProperties: TJSONArray; const AName, AValue: string);
var
  Item: TJSONObject;
begin
  if AValue = '' then
    Exit;
  Item := TJSONObject.Create;
  Item.Add('name', AName);
  Item.Add('value', AValue);
  AProperties.Add(Item);
end;

{**
  Joins sorted declaration values without changing their individual text.

  Parameters
  ----------
  AValues
    Sorted manifest-declaration list.

  Returns
  -------
  string
    Values separated by a semicolon and one space, or an empty string.

  Raises
  ------
  EOutOfMemory
    Propagated if the joined string cannot be allocated.
}
function JoinDeclarations(AValues: TStrings): string;
var
  I: Integer;
begin
  Result := '';
  if AValues = nil then
    Exit;
  for I := 0 to AValues.Count - 1 do
  begin
    if I > 0 then
      Result := Result + '; ';
    Result := Result + AValues[I];
  end;
end;

{**
  Builds the CycloneDX license choice for explicit manifest declarations.

  Parameters
  ----------
  AComponent
    Component supplying sorted, unique raw license declarations.

  Returns
  -------
  TJSONArray
    Newly allocated license choice, or nil when nothing was declared. One
    valid SPDX declaration becomes an expression; multiple or non-SPDX values
    become named license objects without an invented Boolean relationship.

  Raises
  ------
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildDeclaredLicenses(AComponent: uModels.TComponent): TJSONArray;
var
  I: Integer;
  Choice, LicenseValue: TJSONObject;
begin
  Result := nil;
  if (AComponent = nil) or (AComponent.DeclaredLicenses.Count = 0) then
    Exit;
  Result := TJSONArray.Create;
  if (AComponent.DeclaredLicenses.Count = 1) and
    IsValidSPDXExpression(AComponent.DeclaredLicenses[0]) then
  begin
    Choice := TJSONObject.Create;
    Choice.Add('expression', AComponent.DeclaredLicenses[0]);
    Choice.Add('acknowledgement', 'declared');
    Result.Add(Choice);
    Exit;
  end;
  for I := 0 to AComponent.DeclaredLicenses.Count - 1 do
  begin
    LicenseValue := TJSONObject.Create;
    LicenseValue.Add('name', AComponent.DeclaredLicenses[I]);
    LicenseValue.Add('acknowledgement', 'declared');
    Choice := TJSONObject.Create;
    Choice.Add('license', LicenseValue);
    Result.Add(Choice);
  end;
end;

{**
  Adds explicit publisher and license declarations to a CycloneDX component.

  Parameters
  ----------
  AJSON
    Component JSON object to augment.
  AComponent
    Model component containing manifest declarations.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when either argument is nil.
  EOutOfMemory
    Propagated if JSON allocation fails.
}
procedure AddDeclaredComponentMetadata(AJSON: TJSONObject;
  AComponent: uModels.TComponent);
var
  LicenseValues: TJSONArray;
  PublisherValue: string;
begin
  PublisherValue := JoinDeclarations(AComponent.DeclaredPublishers);
  if PublisherValue <> '' then
    AJSON.Add('publisher', PublisherValue);
  LicenseValues := BuildDeclaredLicenses(AComponent);
  if LicenseValues <> nil then
    AJSON.Add('licenses', LicenseValues);
end;

{**
  Determines whether a component carries one resolved product version.

  Parameters
  ----------
  AComponent
    Component whose version and parser provenance are inspected.

  Returns
  -------
  Boolean
    True only for a resolved version that is safe to serialize as CycloneDX
    ``version`` and to use in a Package URL identity.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
}
function ComponentHasExactVersion(AComponent: uModels.TComponent): Boolean;
  forward;

{**
  Builds the stable BOM-local reference for one normalized component.

  Parameters
  ----------
  AComponent
    Component with a canonical purl or normalized identity fields.

  Returns
  -------
  string
    The purl when present, otherwise a deterministic PurpleRay URN.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
}
function ComponentReference(AComponent: uModels.TComponent): string;
var
  KeyValue: RawByteString;
begin
  if (AComponent.PackageURL <> '') and
    ComponentHasExactVersion(AComponent) then
    Exit(AComponent.PackageURL);
  KeyValue := UTF8Encode(LowerCase(AComponent.Ecosystem) + #1 +
    LowerCase(AComponent.Name) + #1 + AComponent.Version + #1 +
    LowerCase(AComponent.ComponentType));
  Result := 'urn:purpleray-sbom-analyzer:component:' + Copy(SHA256String(KeyValue), 1, 32);
end;

{**
  Tests whether a component dependency-scope list contains an exact token.

  Parameters
  ----------
  AComponent
    Component whose comma-delimited dependency scopes are inspected.
  AScope
    Scope token to match without regard to case or surrounding whitespace.

  Returns
  -------
  Boolean
    True when AScope occurs as a complete dependency-scope token.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
  EOutOfMemory
    Propagated if the temporary token list cannot be allocated.
}
function HasDependencyScope(AComponent: uModels.TComponent;
  const AScope: string): Boolean;
var
  StartAt, EndAt: SizeInt;
  ScopeValue: string;
begin
  Result := False;
  StartAt := 1;
  while StartAt <= Length(AComponent.DependencyScope) + 1 do
  begin
    EndAt := StartAt;
    while (EndAt <= Length(AComponent.DependencyScope)) and
      (AComponent.DependencyScope[EndAt] <> ',') do
      Inc(EndAt);
    ScopeValue := Trim(Copy(AComponent.DependencyScope, StartAt,
      EndAt - StartAt));
    if SameText(ScopeValue, AScope) then
      Exit(True);
    StartAt := EndAt + 1;
  end;
end;

{**
  Maps the richer internal dependency scopes to CycloneDX scope semantics.

  Parameters
  ----------
  AComponent
    Component whose comma-delimited scope evidence is mapped.

  Returns
  -------
  string
    ``optional`` or ``excluded`` when that narrower meaning is justified;
    otherwise an empty string so CycloneDX uses its required default.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
  EOutOfMemory
    Propagated if dependency-scope tokenization cannot be allocated.
}
function CycloneComponentScope(AComponent: uModels.TComponent): string;
begin
  Result := '';
  if HasDependencyScope(AComponent, 'runtime') or
    HasDependencyScope(AComponent, 'build') or
    HasDependencyScope(AComponent, 'build-dependencies') or
    HasDependencyScope(AComponent, 'project') or
    HasDependencyScope(AComponent, 'resolved') or
    HasDependencyScope(AComponent, 'compile') or
    HasDependencyScope(AComponent, 'provided') or
    HasDependencyScope(AComponent, 'system') or
    HasDependencyScope(AComponent, 'dependencies') then
    Exit;
  if HasDependencyScope(AComponent, 'optional') or
    HasDependencyScope(AComponent, 'peer') then
    Exit('optional');
  if HasDependencyScope(AComponent, 'development') or
    HasDependencyScope(AComponent, 'dev-dependencies') or
    HasDependencyScope(AComponent, 'test') or
    HasDependencyScope(AComponent, 'import') then
    Result := 'excluded';
end;

{**
  Determines the stable display name of the scanned root application.

  Parameters
  ----------
  ATask
    Scan task supplying the target directory and persisted root name.

  Returns
  -------
  string
    Target-folder basename, a persisted basename fallback, or
    ``scanned-project`` when neither source contains a usable name.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
}
function TargetComponentName(ATask: TScanTask): string;

  {**
    Extracts a path basename without exposing filesystem-root spellings.

    Parameters
    ----------
    AValue
      Native or slash-normalized path candidate.

    Returns
    -------
    string
      Safe final path segment, or an empty string for roots and dot segments.

    Raises
    ------
    None
  }
  function SafeBaseName(const AValue: string): string;
  var
    PathValue: string;
    SeparatorAt: SizeInt;
  begin
    PathValue := StringReplace(Trim(AValue), '\', '/', [rfReplaceAll]);
    while (PathValue <> '') and
      (PathValue[Length(PathValue)] = '/') do
      Delete(PathValue, Length(PathValue), 1);
    SeparatorAt := LastDelimiter('/', PathValue);
    Result := Copy(PathValue, SeparatorAt + 1, MaxInt);
    if (Result = '.') or (Result = '..') or
      ((Length(Result) = 2) and (Result[2] = ':') and
      (Result[1] in ['A'..'Z', 'a'..'z'])) then
      Result := '';
  end;

begin
  Result := SafeBaseName(ATask.TargetDirectory);
  if Result = '' then
    Result := SafeBaseName(ATask.TargetRootName);
  if Result = '' then
    Result := 'scanned-project';
end;

{**
  Finds the sole parsed component explicitly identified as the project.

  Parameters
  ----------
  ATask
    Task whose normalized component inventory is searched.

  Returns
  -------
  TComponent
    The unique project-scoped component, or nil when none or more than one
    project component exists.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil or its component list contains an invalid item.
}
function SoleProjectComponent(ATask: TScanTask): uModels.TComponent;
var
  I, MatchCount: Integer;
  Candidate: uModels.TComponent;
begin
  Result := nil;
  MatchCount := 0;
  for I := 0 to ATask.Components.Count - 1 do
  begin
    Candidate := uModels.TComponent(ATask.Components[I]);
    if (Trim(Candidate.SourceParser) = '') or
      not HasDependencyScope(Candidate, 'project') then
      Continue;
    Inc(MatchCount);
    if MatchCount = 1 then
      Result := Candidate
    else
      Exit(nil);
  end;
end;

{**
  Builds a stable reference for a synthesized root application component.

  Parameters
  ----------
  AName
    Target-folder basename used as the root application identity.

  Returns
  -------
  string
    Deterministic PurpleRay URN derived without machine-specific paths.

  Raises
  ------
  None
}
function SyntheticRootReference(const AName: string): string;
var
  KeyValue: RawByteString;
begin
  KeyValue := UTF8Encode('application' + #1 + LowerCase(Trim(AName)));
  Result := 'urn:purpleray-sbom-analyzer:application:' +
    Copy(SHA256String(KeyValue), 1, 32);
end;

{**
  Extracts a bare ELF SONAME ABI level without treating it as a product version.

  Parameters
  ----------
  AComponent
    Native component whose complete filename remains its display name.

  Returns
  -------
  string
    Numeric text following ``.so.`` when it is exactly one integer segment;
    otherwise an empty string.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
}
function SONAMEABIVersion(AComponent: uModels.TComponent): string;
var
  FileNameValue, LowerName, Candidate: string;
  Marker, I: Integer;
begin
  Result := '';
  if not SameText(Trim(AComponent.Ecosystem), 'native') then
    Exit;
  FileNameValue := ExtractFileName(StringReplace(Trim(AComponent.Name), '\',
    DirectorySeparator, [rfReplaceAll]));
  LowerName := LowerCase(FileNameValue);
  Marker := Pos('.so.', LowerName);
  if Marker = 0 then
    Exit;
  Candidate := Copy(FileNameValue, Marker + Length('.so.'), MaxInt);
  if (Candidate = '') or (Pos('.', Candidate) > 0) then
    Exit;
  for I := 1 to Length(Candidate) do
    if not (Candidate[I] in ['0'..'9']) then
      Exit;
  Result := Candidate;
end;

function ComponentHasExactVersion(AComponent: uModels.TComponent): Boolean;
var
  ABIValue: string;
begin
  Result := IsExactEcosystemVersion(AComponent.Ecosystem,
    AComponent.Version);
  if not Result then
    Exit;
  if SameText(Trim(AComponent.SourceParser), 'conservative-cargo-toml') and
    not HasDependencyScope(AComponent, 'project') then
    Exit(False);
  ABIValue := SONAMEABIVersion(AComponent);
  if (ABIValue <> '') and SameText(Trim(AComponent.Version), ABIValue) then
    Result := False;
end;

{**
  Returns a safe declarative version constraint for export.

  Parameters
  ----------
  AComponent
    Component whose version and parser provenance are inspected.

  Returns
  -------
  string
    A recognized range, including Cargo manifest shorthand requirements, or
    an empty string for resolved versions, tags, URLs, variables, and paths.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
}
function ComponentRequestedRange(AComponent: uModels.TComponent): string;
begin
  Result := '';
  if IsEcosystemVersionRange(AComponent.Ecosystem, AComponent.Version) or
    (SameText(Trim(AComponent.SourceParser), 'conservative-cargo-toml') and
    not HasDependencyScope(AComponent, 'project') and
    IsExactVersion(AComponent.Version)) then
    Result := Trim(AComponent.Version);
end;

{**
  Adds deterministic provenance and honest unresolved-version properties.

  Parameters
  ----------
  ATask
    Task supplying the evidence-path export policy.
  AComponent
    Component supplying ecosystem, parser, scope, range, ABI, and paths.
  AProperties
    JSON array that receives sorted unique properties.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when an input object is nil.
  EOutOfMemory
    Propagated if temporary sorting or JSON allocation fails.
}
procedure AddSortedComponentProperties(ATask: TScanTask;
  AComponent: uModels.TComponent; AProperties: TJSONArray);
var
  Values: TStringList;
  I, SplitAt: Integer;
  NameValue, ValueValue, ABIValue, RequestedRange: string;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    if AComponent.Ecosystem <> '' then
      Values.Add('purpleray-sbom-analyzer:ecosystem' + #1 + AComponent.Ecosystem);
    if AComponent.SourceArtifact <> '' then
      Values.Add('purpleray-sbom-analyzer:source-artifact' + #1 +
        OutputPath(ATask, AComponent.SourceArtifact));
    if AComponent.SourceParser <> '' then
      Values.Add('purpleray-sbom-analyzer:source-parser' + #1 + AComponent.SourceParser);
    if AComponent.DependencyScope <> '' then
      Values.Add('purpleray-sbom-analyzer:dependency-scope' + #1 +
        AComponent.DependencyScope);
    ABIValue := SONAMEABIVersion(AComponent);
    RequestedRange := ComponentRequestedRange(AComponent);
    if RequestedRange <> '' then
      Values.Add('purpleray-sbom-analyzer:requested-range' + #1 +
        RequestedRange);
    if ABIValue <> '' then
      Values.Add('purpleray-sbom-analyzer:soname-abi-version' + #1 +
        ABIValue);
    for I := 0 to AComponent.EvidencePaths.Count - 1 do
      Values.Add('purpleray-sbom-analyzer:evidence-path' + #1 +
        OutputPath(ATask, AComponent.EvidencePaths[I]));
    for I := 0 to Values.Count - 1 do
    begin
      SplitAt := Pos(#1, Values[I]);
      NameValue := Copy(Values[I], 1, SplitAt - 1);
      ValueValue := Copy(Values[I], SplitAt + 1, MaxInt);
      AddProperty(AProperties, NameValue, ValueValue);
    end;
  finally
    Values.Free;
  end;
end;

{**
  Converts one normalized component into a CycloneDX component object.

  Parameters
  ----------
  ATask
    Task supplying path-export policy.
  AComponent
    Normalized component to serialize.

  Returns
  -------
  TJSONObject
    Newly allocated CycloneDX component owned by the caller JSON tree.

  Raises
  ------
  EAccessViolation
    Raised when ATask or AComponent is nil.
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildCycloneComponent(ATask: TScanTask;
  AComponent: uModels.TComponent): TJSONObject;
var
  Hashes, Properties: TJSONArray;
  HashValue: TJSONObject;
  ScopeValue: string;
begin
  Result := TJSONObject.Create;
  Result.Add('type', AComponent.ComponentType);
  Result.Add('bom-ref', ComponentReference(AComponent));
  Result.Add('name', AComponent.Name);
  AddDeclaredComponentMetadata(Result, AComponent);
  if ComponentHasExactVersion(AComponent) then
    Result.Add('version', AComponent.Version);
  ScopeValue := CycloneComponentScope(AComponent);
  if ScopeValue <> '' then
    Result.Add('scope', ScopeValue);
  if (AComponent.PackageURL <> '') and
    ComponentHasExactVersion(AComponent) then
    Result.Add('purl', AComponent.PackageURL);
  if AComponent.SHA256 <> '' then
  begin
    Hashes := TJSONArray.Create;
    HashValue := TJSONObject.Create;
    HashValue.Add('alg', 'SHA-256');
    HashValue.Add('content', LowerCase(AComponent.SHA256));
    Hashes.Add(HashValue);
    Result.Add('hashes', Hashes);
  end;
  Properties := TJSONArray.Create;
  AddSortedComponentProperties(ATask, AComponent, Properties);
  if Properties.Count > 0 then
    Result.Add('properties', Properties)
  else
    Properties.Free;
end;

{**
  Builds the CycloneDX metadata component representing the scanned root.

  Parameters
  ----------
  ATask
    Task supplying the target basename and path-export policy.
  AProjectComponent
    Sole parsed project component to promote, or nil to synthesize the root.

  Returns
  -------
  TJSONObject
    Newly allocated application component owned by the caller JSON tree. Its
    display name is always the target-folder basename. When promoted, version,
    purl, hash, declared licenses, publisher, evidence, and provenance come
    from AProjectComponent.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildPrimaryComponent(ATask: TScanTask;
  AProjectComponent: uModels.TComponent): TJSONObject;
var
  Hashes, Properties: TJSONArray;
  HashValue: TJSONObject;
  NameValue, ScopeValue: string;
begin
  NameValue := TargetComponentName(ATask);
  Result := TJSONObject.Create;
  Result.Add('type', 'application');
  if AProjectComponent <> nil then
    Result.Add('bom-ref', ComponentReference(AProjectComponent))
  else
    Result.Add('bom-ref', SyntheticRootReference(NameValue));
  Result.Add('name', NameValue);
  if AProjectComponent = nil then
    Exit;
  AddDeclaredComponentMetadata(Result, AProjectComponent);
  if ComponentHasExactVersion(AProjectComponent) then
    Result.Add('version', AProjectComponent.Version);
  ScopeValue := CycloneComponentScope(AProjectComponent);
  if ScopeValue <> '' then
    Result.Add('scope', ScopeValue);
  if (AProjectComponent.PackageURL <> '') and
    ComponentHasExactVersion(AProjectComponent) then
    Result.Add('purl', AProjectComponent.PackageURL);
  if AProjectComponent.SHA256 <> '' then
  begin
    Hashes := TJSONArray.Create;
    HashValue := TJSONObject.Create;
    HashValue.Add('alg', 'SHA-256');
    HashValue.Add('content', LowerCase(AProjectComponent.SHA256));
    Hashes.Add(HashValue);
    Result.Add('hashes', Hashes);
  end;
  Properties := TJSONArray.Create;
  AddSortedComponentProperties(ATask, AProjectComponent, Properties);
  if Properties.Count > 0 then
    Result.Add('properties', Properties)
  else
    Properties.Free;
end;

{**
  Extracts the final segment from a portable root-relative artifact path.

  Parameters
  ----------
  APath
    Path using native, slash, or backslash separators.

  Returns
  -------
  string
    Final path segment, or an empty string for an empty/root path.

  Raises
  ------
  None
}
function ArtifactBaseName(const APath: string): string;
var
  PathValue: string;
  SeparatorAt: SizeInt;
begin
  PathValue := StringReplace(Trim(APath), '\', '/', [rfReplaceAll]);
  while (PathValue <> '') and (PathValue[Length(PathValue)] = '/') do
    Delete(PathValue, Length(PathValue), 1);
  SeparatorAt := LastDelimiter('/', PathValue);
  Result := Copy(PathValue, SeparatorAt + 1, MaxInt);
end;

{**
  Creates the deterministic path/name key used to recover binary owners.

  Parameters
  ----------
  APath
    Exact root-relative evidence path.
  AName
    Component display name.

  Returns
  -------
  string
    Case-preserving path plus case-folded component name.

  Raises
  ------
  None
}
function ComponentEvidenceKey(const APath, AName: string): string;
begin
  Result := APath + #1 + LowerCase(Trim(AName));
end;

{**
  Adds all retained path/name pairs for a component to a lookup index.

  Parameters
  ----------
  AIndex
    Sorted index retaining the first deterministic component per key.
  AComponent
    Component whose primary and merged evidence paths are indexed.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when an argument is nil.
  EOutOfMemory
    Propagated if an index key cannot be allocated.
}
procedure IndexComponentEvidence(AIndex: TStringList;
  AComponent: uModels.TComponent);
var
  I: Integer;
begin
  if AComponent.SourceArtifact <> '' then
    AIndex.AddObject(ComponentEvidenceKey(AComponent.SourceArtifact,
      AComponent.Name), AComponent);
  for I := 0 to AComponent.EvidencePaths.Count - 1 do
    if AComponent.EvidencePaths[I] <> '' then
      AIndex.AddObject(ComponentEvidenceKey(AComponent.EvidencePaths[I],
        AComponent.Name), AComponent);
end;

{**
  Tests whether any retained component path belongs to a sorted path set.

  Parameters
  ----------
  AComponent
    Component whose primary and merged evidence paths are inspected.
  APaths
    Sorted exact path set.

  Returns
  -------
  Boolean
    True when at least one component path occurs in APaths.

  Raises
  ------
  EAccessViolation
    Raised when an argument is nil.
}
function ComponentHasIndexedEvidence(AComponent: uModels.TComponent;
  APaths: TStringList): Boolean;
var
  I, Index: Integer;
begin
  Result := (AComponent.SourceArtifact <> '') and
    APaths.Find(AComponent.SourceArtifact, Index);
  if Result then
    Exit;
  for I := 0 to AComponent.EvidencePaths.Count - 1 do
    if APaths.Find(AComponent.EvidencePaths[I], Index) then
      Exit(True);
end;

{**
  Classifies component evidence using indexed binary-artifact paths.

  Parameters
  ----------
  AComponent
    Component whose parser and evidence are inspected.
  ABinaryPaths
    Sorted paths known to identify scanned native binaries.

  Returns
  -------
  Boolean
    True for binary headers, dependency-table evidence, and normalized
    components retaining any binary-artifact path.

  Raises
  ------
  EAccessViolation
    Raised when an argument is nil.
}
function IsBinaryDerivedComponent(AComponent: uModels.TComponent;
  ABinaryPaths: TStringList): Boolean;
begin
  Result := SameText(AComponent.SourceParser, 'binary-header') or
    SameText(AComponent.SourceParser, 'binary-dependency-table') or
    ComponentHasIndexedEvidence(AComponent, ABinaryPaths);
end;

{**
  Returns or creates the sorted dependency set for one binary owner reference.

  Parameters
  ----------
  AOwnerDependencies
    Sorted bom-ref index whose objects are owned TStringList dependency sets.
  AOwnerReference
    Binary owner's deterministic bom-ref.

  Returns
  -------
  TStringList
    Borrowed sorted unique dependency set.

  Raises
  ------
  EAccessViolation
    Raised when AOwnerDependencies is nil.
  EOutOfMemory
    Propagated if the set cannot be allocated.
}
function EnsureOwnerDependencySet(AOwnerDependencies: TStringList;
  const AOwnerReference: string): TStringList;
var
  Index: Integer;
begin
  if AOwnerDependencies.Find(AOwnerReference, Index) then
    Exit(TStringList(AOwnerDependencies.Objects[Index]));
  Result := TStringList.Create;
  try
    Result.Sorted := True;
    Result.CaseSensitive := True;
    Result.Duplicates := dupIgnore;
    AOwnerDependencies.AddObject(AOwnerReference, Result);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Adds one candidate dependency edge for an exact binary evidence path.

  Parameters
  ----------
  AArtifactOwners
    Sorted path-to-owner-component index.
  AOwnerDependencies
    Sorted owner-reference-to-dependency-set index.
  ACandidate
    Runtime native component observed at APath.
  APath
    Exact root-relative binary path carrying the direct evidence.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when an index or component is nil.
  EOutOfMemory
    Propagated if a dependency reference cannot be allocated.
}
procedure AddBinaryEdgeForPath(AArtifactOwners,
  AOwnerDependencies: TStringList; ACandidate: uModels.TComponent;
  const APath: string);
var
  OwnerIndex: Integer;
  Owner: uModels.TComponent;
  OwnerReference, CandidateReference: string;
begin
  if (APath = '') or not AArtifactOwners.Find(APath, OwnerIndex) then
    Exit;
  Owner := uModels.TComponent(AArtifactOwners.Objects[OwnerIndex]);
  OwnerReference := ComponentReference(Owner);
  CandidateReference := ComponentReference(ACandidate);
  if CompareStr(OwnerReference, CandidateReference) <> 0 then
    EnsureOwnerDependencySet(AOwnerDependencies, OwnerReference).Add(
      CandidateReference);
end;

{**
  Builds one deterministic CycloneDX dependency-graph entry.

  Parameters
  ----------
  AReference
    bom-ref of the graph node.
  ADependsOn
    Sorted unique set of direct dependency bom-refs.

  Returns
  -------
  TJSONObject
    Newly allocated dependency object owned by the caller JSON tree.

  Raises
  ------
  EAccessViolation
    Raised when ADependsOn is nil.
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildDependencyEntry(const AReference: string;
  ADependsOn: TStringList): TJSONObject;
var
  References: TJSONArray;
  I: Integer;
begin
  Result := TJSONObject.Create;
  Result.Add('ref', AReference);
  References := TJSONArray.Create;
  for I := 0 to ADependsOn.Count - 1 do
    References.Add(ADependsOn[I]);
  Result.Add('dependsOn', References);
end;

{**
  Builds reliable direct dependency edges from manifest and binary evidence.

  Parameters
  ----------
  ATask
    Task containing normalized component and artifact evidence.
  ARootReference
    bom-ref assigned to the metadata root component.
  APromotedProject
    Project component moved into metadata and omitted from components, or nil.

  Returns
  -------
  TJSONArray
    Newly allocated dependency array. The root entry is first; binary-owner
    entries then follow in sorted bom-ref order. Every dependsOn set is sorted
    and unique, and only direct evidence is represented.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil or its lists contain invalid items.
  EOutOfMemory
    Propagated if temporary sets or JSON nodes cannot be allocated.
}
function BuildDependencies(ATask: TScanTask; const ARootReference: string;
  APromotedProject: uModels.TComponent): TJSONArray;
var
  RootReferences, BinaryPaths, ComponentIndex, ArtifactOwners,
    OwnerDependencies: TStringList;
  I, Pass, Index: Integer;
  Artifact: TArtifact;
  Component, Candidate, Owner: uModels.TComponent;
  PathValue, KeyValue, OwnerReference: string;
begin
  Result := TJSONArray.Create;
  RootReferences := TStringList.Create;
  BinaryPaths := TStringList.Create;
  ComponentIndex := TStringList.Create;
  ArtifactOwners := TStringList.Create;
  OwnerDependencies := TStringList.Create;
  try
    RootReferences.Sorted := True;
    RootReferences.CaseSensitive := True;
    RootReferences.Duplicates := dupIgnore;
    BinaryPaths.Sorted := True;
    BinaryPaths.CaseSensitive := True;
    BinaryPaths.Duplicates := dupIgnore;
    ComponentIndex.Sorted := True;
    ComponentIndex.CaseSensitive := True;
    ComponentIndex.Duplicates := dupIgnore;
    ArtifactOwners.Sorted := True;
    ArtifactOwners.CaseSensitive := True;
    ArtifactOwners.Duplicates := dupIgnore;
    OwnerDependencies.Sorted := True;
    OwnerDependencies.CaseSensitive := True;
    OwnerDependencies.Duplicates := dupError;

    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      if SameText(Artifact.ParserName, 'binary-header') and
        (Artifact.RelativePath <> '') then
        BinaryPaths.Add(Artifact.RelativePath);
    end;

    { Prefer unmerged header provenance when present. Normalized components
      whose header/parser pair was collapsed are indexed on the second pass. }
    for Pass := 0 to 1 do
      for I := 0 to ATask.Components.Count - 1 do
      begin
        Component := uModels.TComponent(ATask.Components[I]);
        if ((Pass = 0) and not SameText(Component.SourceParser,
          'binary-header')) or ((Pass = 1) and
          SameText(Component.SourceParser, 'binary-header')) then
          Continue;
        IndexComponentEvidence(ComponentIndex, Component);
      end;

    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      if not SameText(Artifact.ParserName, 'binary-header') then
        Continue;
      PathValue := Artifact.RelativePath;
      KeyValue := ComponentEvidenceKey(PathValue,
        ArtifactBaseName(PathValue));
      if ComponentIndex.Find(KeyValue, Index) then
      begin
        Owner := uModels.TComponent(ComponentIndex.Objects[Index]);
        if not ArtifactOwners.Find(PathValue, Index) then
          ArtifactOwners.AddObject(PathValue, Owner);
        EnsureOwnerDependencySet(OwnerDependencies,
          ComponentReference(Owner));
      end;
    end;

    { Reconstructed legacy tasks can lack artifact detail but still retain an
      unmerged binary-header component. }
    for I := 0 to ATask.Components.Count - 1 do
    begin
      Component := uModels.TComponent(ATask.Components[I]);
      if not SameText(Component.SourceParser, 'binary-header') then
        Continue;
      PathValue := Component.SourceArtifact;
      if PathValue <> '' then
      begin
        BinaryPaths.Add(PathValue);
        if not ArtifactOwners.Find(PathValue, Index) then
          ArtifactOwners.AddObject(PathValue, Component);
      end;
      EnsureOwnerDependencySet(OwnerDependencies,
        ComponentReference(Component));
    end;

    for I := 0 to ATask.Components.Count - 1 do
    begin
      Component := uModels.TComponent(ATask.Components[I]);
      if (Component <> APromotedProject) and
        (Trim(Component.SourceParser) <> '') and
        not IsBinaryDerivedComponent(Component, BinaryPaths) then
        RootReferences.Add(ComponentReference(Component));
    end;
    Result.Add(BuildDependencyEntry(ARootReference, RootReferences));

    for I := 0 to ATask.Components.Count - 1 do
    begin
      Candidate := uModels.TComponent(ATask.Components[I]);
      if not HasDependencyScope(Candidate, 'runtime') or
        not IsBinaryDerivedComponent(Candidate, BinaryPaths) then
        Continue;
      AddBinaryEdgeForPath(ArtifactOwners, OwnerDependencies, Candidate,
        Candidate.SourceArtifact);
      for Pass := 0 to Candidate.EvidencePaths.Count - 1 do
        AddBinaryEdgeForPath(ArtifactOwners, OwnerDependencies, Candidate,
          Candidate.EvidencePaths[Pass]);
    end;

    for I := 0 to OwnerDependencies.Count - 1 do
    begin
      OwnerReference := OwnerDependencies[I];
      Result.Add(BuildDependencyEntry(OwnerReference,
        TStringList(OwnerDependencies.Objects[I])));
    end;
  finally
    for I := 0 to OwnerDependencies.Count - 1 do
      OwnerDependencies.Objects[I].Free;
    OwnerDependencies.Free;
    ArtifactOwners.Free;
    ComponentIndex.Free;
    BinaryPaths.Free;
    RootReferences.Free;
  end;
end;

{**
  Builds the CycloneDX tool component describing this scanner build.

  Parameters
  ----------
  ATask
    Task carrying the scanner version and optional commit identifier.

  Returns
  -------
  TJSONObject
    Newly allocated tool component owned by the caller JSON tree.

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function ToolComponent(ATask: TScanTask): TJSONObject;
var
  Properties: TJSONArray;
begin
  Result := TJSONObject.Create;
  Result.Add('type', 'application');
  Result.Add('name', AppName);
  Result.Add('version', ATask.ScannerVersion);
  if (ATask.ScannerCommit <> '') and (ATask.ScannerCommit <> 'unknown') then
  begin
    Properties := TJSONArray.Create;
    AddProperty(Properties, 'purpleray-sbom-analyzer:commit', ATask.ScannerCommit);
    Result.Add('properties', Properties);
  end;
end;

{**
  Adds deterministic, path-policy-aware artifact evidence to SBOM metadata.

  Parameters
  ----------
  ATask
    Task containing artifacts and export settings.
  AProperties
    Metadata property array to augment.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when arguments are nil or contain incompatible objects.
}
procedure AddArtifactProperties(ATask: TScanTask; AProperties: TJSONArray);
var
  Sorted: TArtifactReferenceList;
  I: Integer;
  Artifact: TArtifact;
  ValueValue: string;
begin
  Sorted := TArtifactReferenceList.Create;
  try
    for I := 0 to ATask.Artifacts.Count - 1 do
      Sorted.Add(ATask.Artifacts[I]);
    Sorted.Sort(@CompareArtifacts);
    for I := 0 to Sorted.Count - 1 do
    begin
      Artifact := TArtifact(Sorted[I]);
      ValueValue := OutputPath(ATask, Artifact.RelativePath) + ' | ' +
        Artifact.ArtifactType + ' | ' + ArtifactStatusToString(Artifact.Status);
      if Artifact.ParserName <> '' then
        ValueValue := ValueValue + ' | ' + Artifact.ParserName;
      AddProperty(AProperties, 'purpleray-sbom-analyzer:artifact', ValueValue);
    end;
  finally
    Sorted.Free;
  end;
end;

{**
  Converts the supported CycloneDX version selector to its wire value.

  Parameters
  ----------
  ASpecVersion
    Supported CycloneDX version selector.

  Returns
  -------
  string
    ``1.6`` or ``1.7``.

  Raises
  ------
  None
}
function CycloneDXSpecVersionText(ASpecVersion: TCycloneDXSpecVersion): string;
begin
  Result := '1.7';
  case ASpecVersion of
    cdxSpec16: Result := '1.6';
    cdxSpec17: Result := '1.7';
  end;
end;

{**
  Applies a conservative syntax check before emitting an SBOM author email.

  Parameters
  ----------
  AValue
    Candidate email address from persisted scan settings.

  Returns
  -------
  Boolean
    True for one bounded address with non-empty local and domain parts and no
    whitespace or delimiter characters.

  Raises
  ------
  None
}
function IsValidAuthorEmail(const AValue: string): Boolean;
var
  ValueText, LocalValue, DomainValue: string;
  AtPos, I: Integer;
begin
  ValueText := Trim(AValue);
  Result := (ValueText <> '') and (Length(ValueText) <= 254);
  if not Result then
    Exit;
  AtPos := Pos('@', ValueText);
  if (AtPos <= 1) or (AtPos = Length(ValueText)) or
    (Pos('@', Copy(ValueText, AtPos + 1, MaxInt)) > 0) then
    Exit(False);
  LocalValue := Copy(ValueText, 1, AtPos - 1);
  DomainValue := Copy(ValueText, AtPos + 1, MaxInt);
  if (LocalValue[1] = '.') or (LocalValue[Length(LocalValue)] = '.') or
    (DomainValue[1] in ['.', '-']) or
    (DomainValue[Length(DomainValue)] in ['.', '-']) or
    (Pos('..', LocalValue) > 0) or (Pos('..', DomainValue) > 0) then
    Exit(False);
  for I := 1 to Length(ValueText) do
    if (Ord(ValueText[I]) <= 32) or
      (ValueText[I] in ['<', '>', '(', ')', '[', ']', ',', ';']) then
      Exit(False);
  Result := True;
end;

{**
  Builds optional CycloneDX metadata authors from frozen scan settings.

  Parameters
  ----------
  ASettings
    Scan settings containing optional author organization and email values.

  Returns
  -------
  TJSONArray
    Newly allocated one-contact array, or nil when no safe value is present.

  Raises
  ------
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildMetadataAuthors(ASettings: TScanSettings): TJSONArray;
const
  MaxOrganizationLength = 4096;
var
  OrganizationValue, EmailValue: string;
  AuthorValue: TJSONObject;
begin
  Result := nil;
  OrganizationValue := Trim(ASettings.SBOMAuthorOrganization);
  if Length(OrganizationValue) > MaxOrganizationLength then
    OrganizationValue := '';
  EmailValue := Trim(ASettings.SBOMAuthorEmail);
  if not IsValidAuthorEmail(EmailValue) then
    EmailValue := '';
  if (OrganizationValue = '') and (EmailValue = '') then
    Exit;
  Result := TJSONArray.Create;
  AuthorValue := TJSONObject.Create;
  if OrganizationValue <> '' then
    AuthorValue.Add('name', OrganizationValue);
  if EmailValue <> '' then
    AuthorValue.Add('email', EmailValue);
  Result.Add(AuthorValue);
end;

{**
  Builds the fixed analysis-time CycloneDX lifecycle declaration.

  Parameters
  ----------
  None

  Returns
  -------
  TJSONArray
    Newly allocated array containing the ``post-build`` phase.

  Raises
  ------
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildMetadataLifecycles: TJSONArray;
var
  LifecycleValue: TJSONObject;
begin
  Result := TJSONArray.Create;
  LifecycleValue := TJSONObject.Create;
  LifecycleValue.Add('phase', 'post-build');
  Result.Add(LifecycleValue);
end;

{**
  Builds the machine-readable best-effort completeness declaration.

  Parameters
  ----------
  None

  Returns
  -------
  TJSONArray
    Newly allocated top-level composition with aggregate ``incomplete``.

  Raises
  ------
  EOutOfMemory
    Propagated if JSON allocation fails.
}
function BuildIncompleteCompositions: TJSONArray;
var
  CompositionValue: TJSONObject;
begin
  Result := TJSONArray.Create;
  CompositionValue := TJSONObject.Create;
  CompositionValue.Add('aggregate', 'incomplete');
  Result.Add(CompositionValue);
end;

function GenerateCycloneDX(ATask: TScanTask;
  ASpecVersion: TCycloneDXSpecVersion): UTF8String;
var
  Root, Metadata, Tools, PrimaryComponent: TJSONObject;
  ToolComponents, Components, Properties, Dependencies, Authors: TJSONArray;
  PromotedProject: uModels.TComponent;
  PrimaryReference, SpecVersionText: string;
  I: Integer;
  JSONText: string;
begin
  SpecVersionText := CycloneDXSpecVersionText(ASpecVersion);
  Root := TJSONObject.Create;
  try
    Root.Add('$schema',
      'https://cyclonedx.org/schema/bom-' + SpecVersionText +
      '.schema.json');
    Root.Add('bomFormat', 'CycloneDX');
    Root.Add('specVersion', SpecVersionText);
    Root.Add('serialNumber', 'urn:uuid:' + ATask.ID);
    Root.Add('version', 1);

    Metadata := TJSONObject.Create;
    if ATask.StartedUTC <> '' then
      Metadata.Add('timestamp', ATask.StartedUTC)
    else
      Metadata.Add('timestamp', ATask.CreatedUTC);
    Metadata.Add('lifecycles', BuildMetadataLifecycles);
    Authors := BuildMetadataAuthors(ATask.Settings);
    if Authors <> nil then
      Metadata.Add('authors', Authors);
    PromotedProject := SoleProjectComponent(ATask);
    PrimaryComponent := BuildPrimaryComponent(ATask, PromotedProject);
    PrimaryReference := JSONString(PrimaryComponent, 'bom-ref');
    Metadata.Add('component', PrimaryComponent);
    Tools := TJSONObject.Create;
    ToolComponents := TJSONArray.Create;
    ToolComponents.Add(ToolComponent(ATask));
    Tools.Add('components', ToolComponents);
    Metadata.Add('tools', Tools);
    Properties := TJSONArray.Create;
    AddProperty(Properties, 'purpleray-sbom-analyzer:inspection-method',
      'local static artifact and binary dependency-table inspection with ' +
      'safe operating-system evidence');
    if ATask.InspectionTools.Count > 0 then
      AddProperty(Properties, 'purpleray-sbom-analyzer:system-tools',
        StringReplace(ATask.InspectionTools.CommaText, ',', ', ',
          [rfReplaceAll]));
    AddProperty(Properties, 'purpleray-sbom-analyzer:completeness',
      'best effort; not a guarantee of complete dependency discovery');
    AddProperty(Properties, 'purpleray-sbom-analyzer:assessment-scope',
      'not a vulnerability or license-compliance assessment');
    AddProperty(Properties, 'purpleray-sbom-analyzer:files-inspected',
      IntToStr(ATask.FilesInspected));
    AddProperty(Properties, 'purpleray-sbom-analyzer:artifacts-detected',
      IntToStr(ATask.ArtifactsDetected));
    AddArtifactProperties(ATask, Properties);
    Metadata.Add('properties', Properties);
    Root.Add('metadata', Metadata);

    Components := TJSONArray.Create;
    for I := 0 to ATask.Components.Count - 1 do
      if uModels.TComponent(ATask.Components[I]) <> PromotedProject then
        Components.Add(BuildCycloneComponent(ATask,
          uModels.TComponent(ATask.Components[I])));
    Root.Add('components', Components);

    Dependencies := BuildDependencies(ATask, PrimaryReference,
      PromotedProject);
    Root.Add('dependencies', Dependencies);
    Root.Add('compositions', BuildIncompleteCompositions);

    JSONText := NormalizeJSONLineEndings(Root.FormatJSON([], 2));
    Result := UTF8Encode(JSONText + #10);
  finally
    Root.Free;
  end;
end;

function GenerateCycloneDX(ATask: TScanTask): UTF8String;
begin
  Result := GenerateCycloneDX(ATask, cdxSpec17);
end;

end.
