(**
  PurpleRay SBOM Analyzer component-normalization unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Produces a stable, deduplicated component inventory while merging evidence,
  parser provenance, dependency scopes, and hashes.

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
unit uComponentNormalizer;

{$mode objfpc}{$H+}

interface

uses
  Contnrs, uModels;

{**
  Builds the deterministic identity key used by component normalization.

  Parameters
  ----------
  AComponent
    Component whose Package URL or fallback identity fields are inspected.

  Returns
  -------
  string
    Case-normalized Package URL key, or an ecosystem/name/version/type key.

  Raises
  ------
  EAccessViolation
    Raised when AComponent is nil.
*}
function ComponentNormalizationKey(AComponent: uModels.TComponent): string;

{**
  Deduplicates components and merges their evidence into owned output clones.

  Parameters
  ----------
  AInput
    Source list containing TComponent instances; ownership is unchanged.
  AOutput
    Destination list to clear and populate with normalized owned clones.

  Returns
  -------
  None

  Raises
  ------
  EStringListError
    May be raised if an internal normalized key invariant is violated.
}
procedure NormalizeComponents(AInput, AOutput: TObjectList);

{**
  Sorts a component list into deterministic ecosystem/name/version order.

  Parameters
  ----------
  AComponents
    List of TComponent instances to sort in place; nil is accepted.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure SortComponents(AComponents: TObjectList);

implementation

uses
  Classes, SysUtils;

function ComponentNormalizationKey(AComponent: uModels.TComponent): string;
begin
  if Trim(AComponent.PackageURL) <> '' then
    { Package URLs produced by the parsers are already canonical. Preserve
      their exact bytes here because version and some type-specific namespace
      or name segments are case-sensitive evidence. }
    Result := 'purl:' + Trim(AComponent.PackageURL)
  else
    Result := 'fields:' + LowerCase(Trim(AComponent.Ecosystem)) + #1 +
      LowerCase(Trim(AComponent.Name)) + #1 + Trim(AComponent.Version) + #1 +
      LowerCase(Trim(AComponent.ComponentType));
end;

{**
  Adds trimmed, non-empty comma-delimited tokens to a sorted token set.

  Parameters
  ----------
  AText
    Comma-delimited token text to parse.
  AValues
    Sorted destination list that receives normalized tokens.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if temporary token storage or a destination entry cannot be
    allocated.
}
procedure AddTokens(const AText: string; AValues: TStringList);
var
  Tokens: TStringList;
  I: Integer;
  TokenValue: string;
begin
  if Trim(AText) = '' then
    Exit;
  Tokens := TStringList.Create;
  try
    Tokens.Delimiter := ',';
    Tokens.StrictDelimiter := True;
    Tokens.DelimitedText := AText;
    for I := 0 to Tokens.Count - 1 do
    begin
      TokenValue := Trim(Tokens[I]);
      if TokenValue <> '' then
        AValues.Add(TokenValue);
    end;
  finally
    Tokens.Free;
  end;
end;

{**
  Combines two comma-delimited token sets in deterministic sorted order.

  Parameters
  ----------
  ALeft
    Existing comma-delimited tokens.
  ARight
    Additional comma-delimited tokens.

  Returns
  -------
  string
    Unique trimmed tokens joined with a comma and one space.

  Raises
  ------
  EOutOfMemory
    Propagated if token parsing or result construction cannot be allocated.
}
function MergeTokens(const ALeft, ARight: string): string;
var
  Values: TStringList;
  I: Integer;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    Values.Delimiter := ',';
    Values.StrictDelimiter := True;
    AddTokens(ALeft, Values);
    AddTokens(ARight, Values);
    Result := '';
    for I := 0 to Values.Count - 1 do
    begin
      if I > 0 then
        Result := Result + ', ';
      Result := Result + Values[I];
    end;
  finally
    Values.Free;
  end;
end;

{**
  Selects one deterministic nonempty scalar evidence value.

  Parameters
  ----------
  ATarget
    Existing normalized value, updated in place.
  ASource
    Additional value from an equal component.

  Returns
  -------
  None

  Raises
  ------
  None
*}
procedure MergeStableValue(var ATarget: string; const ASource: string);
begin
  if (ATarget = '') or ((ASource <> '') and
    (CompareStr(ASource, ATarget) < 0)) then
    ATarget := ASource;
end;

{**
  Merges declaration and provenance evidence from one equal component.

  Parameters
  ----------
  ATarget
    Normalized component that receives deterministic merged values.
  ASource
    Equal source component whose ownership is unchanged.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if a merged list value cannot be allocated.
}
procedure MergeComponent(ATarget, ASource: uModels.TComponent);
var
  I: Integer;
begin
  for I := 0 to ASource.EvidencePaths.Count - 1 do
    ATarget.EvidencePaths.Add(ASource.EvidencePaths[I]);
  for I := 0 to ASource.DeclaredLicenses.Count - 1 do
    ATarget.DeclaredLicenses.Add(ASource.DeclaredLicenses[I]);
  for I := 0 to ASource.DeclaredPublishers.Count - 1 do
    ATarget.DeclaredPublishers.Add(ASource.DeclaredPublishers[I]);
  if (ATarget.SourceArtifact = '') or
    ((ASource.SourceArtifact <> '') and
    (CompareStr(ASource.SourceArtifact, ATarget.SourceArtifact) < 0)) then
    ATarget.SourceArtifact := ASource.SourceArtifact;
  if (ATarget.SourceParser = '') or
    ((ASource.SourceParser <> '') and
    (CompareStr(ASource.SourceParser, ATarget.SourceParser) < 0)) then
    ATarget.SourceParser := ASource.SourceParser;
  ATarget.DependencyScope := MergeTokens(ATarget.DependencyScope,
    ASource.DependencyScope);
  MergeStableValue(ATarget.SHA256, ASource.SHA256);
  MergeStableValue(ATarget.CPE, ASource.CPE);
  MergeStableValue(ATarget.CPEEvidence, ASource.CPEEvidence);
  MergeStableValue(ATarget.CompanyName, ASource.CompanyName);
  MergeStableValue(ATarget.ProductName, ASource.ProductName);
  MergeStableValue(ATarget.NativeSONAME, ASource.NativeSONAME);
  MergeStableValue(ATarget.NativeBuildID, ASource.NativeBuildID);
end;

function CompareComponents(Item1, Item2: Pointer): Integer;
var
  Left, Right: uModels.TComponent;
begin
  Left := uModels.TComponent(Item1);
  Right := uModels.TComponent(Item2);
  Result := CompareText(Left.Ecosystem, Right.Ecosystem);
  if Result = 0 then
    Result := CompareText(Left.Name, Right.Name);
  if Result = 0 then
    Result := CompareStr(Left.Version, Right.Version);
  if Result = 0 then
    Result := CompareText(Left.ComponentType, Right.ComponentType);
  if Result = 0 then
    Result := CompareStr(Left.PackageURL, Right.PackageURL);
  if Result = 0 then
    Result := CompareStr(Left.SourceArtifact, Right.SourceArtifact);
end;

procedure SortComponents(AComponents: TObjectList);
begin
  if AComponents <> nil then
    AComponents.Sort(@CompareComponents);
end;

procedure NormalizeComponents(AInput, AOutput: TObjectList);
var
  Keys: TStringList;
  I, Index: Integer;
  Source, Target: uModels.TComponent;
  KeyValue: string;
begin
  AOutput.Clear;
  Keys := TStringList.Create;
  try
    Keys.Sorted := True;
    { ComponentNormalizationKey already case-folds case-insensitive fields but
      deliberately preserves exact versions. Match the live-key counter and
      keep case-variant version evidence distinct on every platform. }
    Keys.CaseSensitive := True;
    Keys.Duplicates := dupError;
    Keys.UseLocale := False;
    for I := 0 to AInput.Count - 1 do
    begin
      Source := uModels.TComponent(AInput[I]);
      KeyValue := ComponentNormalizationKey(Source);
      if Keys.Find(KeyValue, Index) then
        MergeComponent(uModels.TComponent(Keys.Objects[Index]), Source)
      else
      begin
        Target := Source.Clone;
        AOutput.Add(Target);
        Keys.AddObject(KeyValue, Target);
      end;
    end;
  finally
    Keys.Free;
  end;
  SortComponents(AOutput);
end;

end.
