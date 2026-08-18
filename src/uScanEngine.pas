unit uScanEngine;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels, uSHA256;

type
  TScanProgress = record
    CurrentRelativePath: string;
    FilesInspected: Int64;
    BytesInspected: Int64;
    ArtifactsDetected: Int64;
    ComponentsIdentified: Int64;
    ElapsedMS: Int64;
  end;

  TScanProgressCallback = procedure(const AProgress: TScanProgress) of object;

  TScanEngine = class
  private
    FTask: TScanTask;
    FRawComponents: TObjectList;
    FVisitedDirectories: TStringList;
    FRootCanonical: string;
    FCancelCheck: TCancelCheck;
    FProgressCallback: TScanProgressCallback;
    FStartedTicks: QWord;
    FLastProgressTicks: QWord;
    FCurrentRelativePath: string;
    function IsCancelled: Boolean;
    procedure ReportProgress(AForce: Boolean = False);
    procedure HashProgress(ABytesRead: Int64);
    procedure AddWarning(const AMessage: string);
    function EnterDirectory(const ADirectory: string): Boolean;
    function ScanDirectory(const ADirectory, ARelativeDirectory: string): Boolean;
    function ProcessFile(const AFileName, ARelativePath: string;
      AFileSize: Int64): Boolean;
    procedure CountArtifactStatus(AArtifact: TArtifact);
    procedure FinalizeComponents;
  public
    constructor Create(ACancelCheck: TCancelCheck;
      AProgressCallback: TScanProgressCallback);
    destructor Destroy; override;
    function Scan(ATask: TScanTask): Boolean;
  end;

implementation

uses
  uArtifactIdentifier, uBinaryInspector, uManifestParsers, uIgnoreMatcher,
  uPlatform, uComponentNormalizer, uTimeUtils;

constructor TScanEngine.Create(ACancelCheck: TCancelCheck;
  AProgressCallback: TScanProgressCallback);
begin
  inherited Create;
  FCancelCheck := ACancelCheck;
  FProgressCallback := AProgressCallback;
  FRawComponents := TObjectList.Create(True);
  FVisitedDirectories := TStringList.Create;
  FVisitedDirectories.Sorted := True;
  FVisitedDirectories.Duplicates := dupIgnore;
  {$IFDEF Windows}
  FVisitedDirectories.CaseSensitive := False;
  {$ELSE}
  FVisitedDirectories.CaseSensitive := True;
  {$ENDIF}
end;

destructor TScanEngine.Destroy;
begin
  FVisitedDirectories.Free;
  FRawComponents.Free;
  inherited Destroy;
end;

function TScanEngine.IsCancelled: Boolean;
begin
  Result := Assigned(FCancelCheck) and FCancelCheck();
end;

procedure TScanEngine.ReportProgress(AForce: Boolean);
var
  Progress: TScanProgress;
  NowTicks: QWord;
begin
  if not Assigned(FProgressCallback) then
    Exit;
  NowTicks := GetTickCount64;
  if not AForce and (NowTicks - FLastProgressTicks < 100) then
    Exit;
  FLastProgressTicks := NowTicks;
  Progress.CurrentRelativePath := FCurrentRelativePath;
  Progress.FilesInspected := FTask.FilesInspected;
  Progress.BytesInspected := FTask.BytesInspected;
  Progress.ArtifactsDetected := FTask.ArtifactsDetected;
  Progress.ComponentsIdentified := FRawComponents.Count;
  Progress.ElapsedMS := NowTicks - FStartedTicks;
  FProgressCallback(Progress);
end;

procedure TScanEngine.HashProgress(ABytesRead: Int64);
begin
  ReportProgress(False);
end;

procedure TScanEngine.AddWarning(const AMessage: string);
begin
  if (AMessage <> '') and (FTask.Warnings.IndexOf(AMessage) < 0) then
    FTask.Warnings.Add(AMessage);
end;

function TScanEngine.EnterDirectory(const ADirectory: string): Boolean;
var
  Canonical: string;
  Index: Integer;
begin
  Canonical := CanonicalPath(ADirectory);
  if (not FTask.Settings.AllowOutsideRoot) and
    not PathIsWithin(Canonical, FRootCanonical) then
  begin
    AddWarning('Skipped symbolic-link target outside the selected root: ' +
      ADirectory);
    Exit(False);
  end;
  if FVisitedDirectories.Find(Canonical, Index) then
  begin
    AddWarning('Skipped an already visited directory (possible symbolic-link '+
      'loop): ' + ADirectory);
    Exit(False);
  end;
  FVisitedDirectories.Add(Canonical);
  Result := True;
end;

function TScanEngine.ScanDirectory(const ADirectory,
  ARelativeDirectory: string): Boolean;
var
  SearchRecord: TSearchRec;
  Names: TStringList;
  I, FindResult: Integer;
  NameValue, AbsolutePath, RelativePath: string;
  IsDirectoryValue, IsLink: Boolean;
begin
  Result := False;
  if IsCancelled then
    Exit;
  Names := TStringList.Create;
  try
    Names.Sorted := True;
    Names.Duplicates := dupIgnore;
    try
      FindResult := FindFirst(IncludeTrailingPathDelimiter(ADirectory) + '*',
        faAnyFile, SearchRecord);
      try
        while FindResult = 0 do
        begin
          if IsCancelled then
            Exit;
          if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
            Names.Add(SearchRecord.Name);
          FindResult := FindNext(SearchRecord);
        end;
      finally
        FindClose(SearchRecord);
      end;
    except
      on E: Exception do
      begin
        AddWarning('Unable to enumerate directory ' + ADirectory + ': ' +
          E.Message);
        Exit(True);
      end;
    end;

    for I := 0 to Names.Count - 1 do
    begin
      if IsCancelled then
        Exit;
      NameValue := Names[I];
      AbsolutePath := IncludeTrailingPathDelimiter(ADirectory) + NameValue;
      if ARelativeDirectory = '' then
        RelativePath := NameValue
      else
        RelativePath := ARelativeDirectory + '/' + NameValue;
      FindResult := FindFirst(AbsolutePath, faAnyFile, SearchRecord);
      if FindResult <> 0 then
      begin
        AddWarning('A directory entry disappeared during the scan: ' +
          RelativePath);
        Continue;
      end;
      try
        IsDirectoryValue := (SearchRecord.Attr and faDirectory) <> 0;
      finally
        FindClose(SearchRecord);
      end;
      if ShouldIgnorePath(RelativePath, IsDirectoryValue,
        FTask.Settings.IgnorePatterns) then
        Continue;
      IsLink := IsSymbolicLink(AbsolutePath);
      if IsLink and not FTask.Settings.FollowSymbolicLinks then
        Continue;
      if IsLink and FTask.Settings.FollowSymbolicLinks and
        (not FTask.Settings.AllowOutsideRoot) and
        not PathIsWithin(AbsolutePath, FRootCanonical) then
      begin
        AddWarning('Skipped symbolic link outside the selected root: ' +
          RelativePath);
        Continue;
      end;

      if IsDirectoryValue then
      begin
        if EnterDirectory(AbsolutePath) then
          if not ScanDirectory(AbsolutePath, RelativePath) then
            Exit;
      end
      else
      begin
        FindResult := FindFirst(AbsolutePath, faAnyFile, SearchRecord);
        if FindResult = 0 then
        begin
          try
            if not ProcessFile(AbsolutePath, RelativePath,
              SearchRecord.Size) then
              Exit;
          finally
            FindClose(SearchRecord);
          end;
        end;
      end;
    end;
    Result := True;
  finally
    Names.Free;
  end;
end;

procedure TScanEngine.CountArtifactStatus(AArtifact: TArtifact);
begin
  case AArtifact.Status of
    arsParsed: Inc(FTask.ArtifactsParsed);
    arsPartiallyParsed: Inc(FTask.ArtifactsPartiallyParsed);
    arsUnsupported: Inc(FTask.UnsupportedArtifacts);
    arsFailed: Inc(FTask.FailedArtifacts);
  end;
end;

function TScanEngine.ProcessFile(const AFileName, ARelativePath: string;
  AFileSize: Int64): Boolean;
var
  Definition: TArtifactDefinition;
  BinaryInfo: TBinaryInfo;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  HashValue: string;
  IsArtifact, IsBinary: Boolean;
begin
  Result := False;
  if IsCancelled then
    Exit;
  FCurrentRelativePath := NormalizeRelativePath(ARelativePath);
  Inc(FTask.FilesInspected);
  if AFileSize > 0 then
    Inc(FTask.BytesInspected, AFileSize);
  ReportProgress(False);

  IsArtifact := IdentifyArtifact(ExtractFileName(AFileName),
    FCurrentRelativePath, Definition);
  IsBinary := False;
  if not IsArtifact then
  begin
    try
      IsBinary := InspectBinary(AFileName, BinaryInfo);
    except
      on E: Exception do
      begin
        AddWarning('Unable to inspect ' + FCurrentRelativePath + ': ' + E.Message);
        Exit(True);
      end;
    end;
    if not IsBinary then
      Exit(True);
  end;

  Artifact := TArtifact.Create;
  Artifact.RelativePath := FCurrentRelativePath;
  Artifact.AbsolutePath := ExpandFileName(AFileName);
  Artifact.FileSize := AFileSize;
  if IsBinary then
  begin
    Artifact.ArtifactType := BinaryInfo.FormatName + ' ' +
      BinaryInfo.Classification;
    Artifact.Ecosystem := 'native';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Artifact.MessageText := BinaryInfo.FormatName + '; architecture: ' +
      BinaryInfo.Architecture + '; classification: ' +
      BinaryInfo.Classification;
  end
  else
  begin
    Artifact.ArtifactType := Definition.ArtifactType;
    Artifact.Ecosystem := Definition.Ecosystem;
    Artifact.ParserName := Definition.ParserName;
    Artifact.Status := arsUnsupported;
  end;
  FTask.Artifacts.Add(Artifact);
  Inc(FTask.ArtifactsDetected);

  try
    if FTask.Settings.CalculateSHA256 and
      (IsBinary or (Definition.ArtifactType <> 'license evidence')) then
    begin
      if not SHA256File(AFileName, HashValue, @IsCancelled, @HashProgress) then
        Exit;
      Artifact.SHA256 := HashValue;
    end;
    if IsBinary then
    begin
      Component := uModels.TComponent.Create;
      Component.Name := ExtractFileName(AFileName);
      Component.Ecosystem := 'native';
      if BinaryInfo.Classification = 'executable' then
        Component.ComponentType := 'application'
      else if BinaryInfo.Classification = 'library' then
        Component.ComponentType := 'library'
      else
        Component.ComponentType := 'file';
      Component.SourceArtifact := FCurrentRelativePath;
      Component.SourceParser := 'binary-header';
      Component.SHA256 := Artifact.SHA256;
      Component.EvidencePaths.Add(FCurrentRelativePath);
      FRawComponents.Add(Component);
      Artifact.ComponentCount := 1;
    end
    else
      ParseArtifact(AFileName, FCurrentRelativePath, Definition.ParserKind,
        Artifact, FRawComponents);
  except
    on E: Exception do
    begin
      Artifact.Status := arsFailed;
      Artifact.MessageText := E.Message;
    end;
  end;
  CountArtifactStatus(Artifact);
  ReportProgress(True);
  Result := not IsCancelled;
end;

procedure TScanEngine.FinalizeComponents;
begin
  NormalizeComponents(FRawComponents, FTask.Components);
  FTask.ComponentsIdentified := FTask.Components.Count;
end;

function TScanEngine.Scan(ATask: TScanTask): Boolean;
var
  CompletedNormally: Boolean;
begin
  FTask := ATask;
  FTask.Artifacts.Clear;
  FTask.Components.Clear;
  FTask.Warnings.Clear;
  FTask.Errors.Clear;
  FTask.FilesInspected := 0;
  FTask.BytesInspected := 0;
  FTask.ArtifactsDetected := 0;
  FTask.ArtifactsParsed := 0;
  FTask.ArtifactsPartiallyParsed := 0;
  FTask.UnsupportedArtifacts := 0;
  FTask.FailedArtifacts := 0;
  FTask.ComponentsIdentified := 0;
  FRawComponents.Clear;
  FVisitedDirectories.Clear;
  FTask.StartedUTC := UTCNowISO8601;
  FTask.CompletedUTC := '';
  FTask.Status := tsRunning;
  FStartedTicks := GetTickCount64;
  FLastProgressTicks := 0;
  FRootCanonical := CanonicalPath(FTask.TargetDirectory);
  FVisitedDirectories.Add(FRootCanonical);
  CompletedNormally := False;
  try
    if not DirectoryExists(FTask.TargetDirectory) then
      raise Exception.Create('The selected target directory does not exist');
    CompletedNormally := ScanDirectory(FTask.TargetDirectory, '');
    FinalizeComponents;
    if IsCancelled or not CompletedNormally then
      FTask.Status := tsCancelled
    else
      FTask.Status := tsCompleted;
  except
    on E: Exception do
    begin
      FinalizeComponents;
      FTask.Status := tsFailed;
      FTask.Errors.Add(E.Message);
    end;
  end;
  FTask.CompletedUTC := UTCNowISO8601;
  FTask.DurationMS := GetTickCount64 - FStartedTicks;
  ReportProgress(True);
  Result := FTask.Status = tsCompleted;
end;

end.
