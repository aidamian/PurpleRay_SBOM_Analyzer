unit uComponentNormalizer;

{$mode objfpc}{$H+}

interface

uses
  Contnrs, uModels;

procedure NormalizeComponents(AInput, AOutput: TObjectList);
procedure SortComponents(AComponents: TObjectList);

implementation

uses
  Classes, SysUtils;

function NormalizedKey(AComponent: uModels.TComponent): string;
begin
  if Trim(AComponent.PackageURL) <> '' then
    Result := 'purl:' + LowerCase(Trim(AComponent.PackageURL))
  else
    Result := 'fields:' + LowerCase(Trim(AComponent.Ecosystem)) + #1 +
      LowerCase(Trim(AComponent.Name)) + #1 + Trim(AComponent.Version) + #1 +
      LowerCase(Trim(AComponent.ComponentType));
end;

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
    if Trim(ALeft) <> '' then
    begin
      Values.DelimitedText := ALeft;
      for I := Values.Count - 1 downto 0 do
        Values[I] := Trim(Values[I]);
    end;
    if Trim(ARight) <> '' then
      Values.Add(Trim(ARight));
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

procedure MergeComponent(ATarget, ASource: uModels.TComponent);
var
  I: Integer;
begin
  for I := 0 to ASource.EvidencePaths.Count - 1 do
    ATarget.EvidencePaths.Add(ASource.EvidencePaths[I]);
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
  if (ATarget.SHA256 = '') or ((ASource.SHA256 <> '') and
    (CompareStr(ASource.SHA256, ATarget.SHA256) < 0)) then
    ATarget.SHA256 := ASource.SHA256;
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
    Keys.Duplicates := dupError;
    for I := 0 to AInput.Count - 1 do
    begin
      Source := uModels.TComponent(AInput[I]);
      KeyValue := NormalizedKey(Source);
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
