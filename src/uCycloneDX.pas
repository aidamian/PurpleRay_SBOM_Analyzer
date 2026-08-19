(**
  PurpleRay SBOM Analyzer CycloneDX serialization unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Converts a completed scan task into deterministic, path-conscious CycloneDX
  1.6 JSON with scanner and evidence metadata.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026purpleraysbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{PurpleRay SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uCycloneDX;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

{**
  Serializes a scan task as deterministic CycloneDX 1.6 JSON.

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
function GenerateCycloneDX(ATask: TScanTask): UTF8String;

implementation

uses
  Classes, Contnrs, fpjson, uJSONUtils, uSHA256, uVersionInfo;

type
  TArtifactReferenceList = class(TList);

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

function OutputPath(ATask: TScanTask; const ARelativePath: string): string;
begin
  if ATask.Settings.IncludeAbsolutePaths then
    Result := ExpandFileName(IncludeTrailingPathDelimiter(
      ATask.TargetDirectory) + StringReplace(ARelativePath, '/',
      DirectorySeparator, [rfReplaceAll]))
  else
    Result := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
end;

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

function ComponentReference(AComponent: uModels.TComponent): string;
var
  KeyValue: RawByteString;
begin
  if AComponent.PackageURL <> '' then
    Exit(AComponent.PackageURL);
  KeyValue := UTF8Encode(LowerCase(AComponent.Ecosystem) + #1 +
    LowerCase(AComponent.Name) + #1 + AComponent.Version + #1 +
    LowerCase(AComponent.ComponentType));
  Result := 'urn:purpleray-sbom-analyzer:component:' + Copy(SHA256String(KeyValue), 1, 32);
end;

procedure AddSortedComponentProperties(ATask: TScanTask;
  AComponent: uModels.TComponent; AProperties: TJSONArray);
var
  Values: TStringList;
  I, SplitAt: Integer;
  NameValue, ValueValue: string;
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
begin
  Result := TJSONObject.Create;
  Result.Add('type', AComponent.ComponentType);
  Result.Add('bom-ref', ComponentReference(AComponent));
  Result.Add('name', AComponent.Name);
  if AComponent.Version <> '' then
    Result.Add('version', AComponent.Version);
  if AComponent.PackageURL <> '' then
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

function GenerateCycloneDX(ATask: TScanTask): UTF8String;
var
  Root, Metadata, Tools: TJSONObject;
  ToolComponents, Components, Properties: TJSONArray;
  I: Integer;
  JSONText: string;
begin
  Root := TJSONObject.Create;
  try
    Root.Add('$schema',
      'https://cyclonedx.org/schema/bom-1.6.schema.json');
    Root.Add('bomFormat', 'CycloneDX');
    Root.Add('specVersion', '1.6');
    Root.Add('serialNumber', 'urn:uuid:' + ATask.ID);
    Root.Add('version', 1);

    Metadata := TJSONObject.Create;
    if ATask.StartedUTC <> '' then
      Metadata.Add('timestamp', ATask.StartedUTC)
    else
      Metadata.Add('timestamp', ATask.CreatedUTC);
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
      Components.Add(BuildCycloneComponent(ATask,
        uModels.TComponent(ATask.Components[I])));
    Root.Add('components', Components);

    JSONText := NormalizeJSONLineEndings(Root.FormatJSON([], 2));
    Result := UTF8Encode(JSONText + #10);
  finally
    Root.Free;
  end;
end;

end.
