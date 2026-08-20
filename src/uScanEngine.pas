(**
  PurpleRay SBOM Analyzer scanning-engine unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Traverses a target tree, applies ignore and symlink policy, hashes and parses
  artifacts, inspects binaries, and normalizes the resulting component set.

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

    {**
      Emits throttled or forced progress snapshots to the worker callback.

      Parameters
      ----------
      AForce
        Bypasses the normal 100 ms notification throttle when True.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure ReportProgress(AForce: Boolean = False);
    procedure HashProgress(ABytesRead: Int64);
    procedure AddWarning(const AMessage: string);

    {**
      Validates a directory against root boundaries and loop detection.

      Parameters
      ----------
      ADirectory
        Directory reached directly or through a symbolic link.

      Returns
      -------
      Boolean
        True when traversal may enter the directory for the first time.

      Raises
      ------
      None
        Boundary and loop failures become task warnings.
    }
    function EnterDirectory(const ADirectory: string): Boolean;

    {**
      Recursively scans one directory in deterministic filename order.

      Parameters
      ----------
      ADirectory
        Absolute directory currently being enumerated.
      ARelativeDirectory
        Root-relative directory used for evidence and ignore matching.

      Returns
      -------
      Boolean
        True when traversal completed normally; False after cancellation.

      Raises
      ------
      None
        Enumeration and per-entry failures are recorded as warnings.
    }
    function ScanDirectory(const ADirectory, ARelativeDirectory: string): Boolean;

    {**
      Identifies, hashes, parses, and records one regular file.

      Parameters
      ----------
      AFileName
        Absolute input filename.
      ARelativePath
        Root-relative evidence path.
      AFileSize
        Size reported during directory enumeration.

      Returns
      -------
      Boolean
        True while scanning should continue; False after cancellation.

      Raises
      ------
      None
        Parser and inspection exceptions become failed artifact diagnostics.
    }
    function ProcessFile(const AFileName, ARelativePath: string;
      AFileSize: Int64): Boolean;
    procedure CountArtifactStatus(AArtifact: TArtifact);

    {**
      Deduplicates and deterministically sorts all collected components.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if normalized result allocation fails.
    }
    procedure FinalizeComponents;
  public
    {**
      Creates a reusable scanner with optional cancellation and progress hooks.

      Parameters
      ----------
      ACancelCheck
        Optional callback polled throughout traversal, hashing, and OS tools.
      AProgressCallback
        Optional callback receiving throttled scan snapshots.

      Returns
      -------
      TScanEngine
        Initialized scanner owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if working collections cannot be allocated.
    }
    constructor Create(ACancelCheck: TCancelCheck;
      AProgressCallback: TScanProgressCallback);
    destructor Destroy; override;

    {**
      Executes a complete static scan and updates the supplied task in place.

      Parameters
      ----------
      ATask
        Task carrying the target directory and settings and receiving results.

      Returns
      -------
      Boolean
        True only for normal completion; False for cancellation or failure.

      Raises
      ------
      EAccessViolation
        Raised when ATask is nil.
      EOutOfMemory
        May propagate if result allocation fails.
    }
    function Scan(ATask: TScanTask): Boolean;
  end;

implementation

uses
  uArtifactIdentifier, uBinaryInspector, uManifestParsers, uIgnoreMatcher,
  uPlatform, uComponentNormalizer, uTimeUtils, uSystemInspector,
  uNativeDependencyInspector;

type
  {**
    Owns one immutable metadata snapshot from a directory enumeration.

    Attributes
    ----------
    Name
      Entry name exactly as returned by the host filesystem.
    Size
      File size from the initial FindFirst or FindNext result.
    Attributes
      Platform attributes from the initial enumeration result.
    UnixMode
      Unix file-type and permission mode, or zero on other platforms.
  }
  TDirectoryEntry = class
  public
    Name: string;
    Size: Int64;
    Attributes: LongInt;
    UnixMode: QWord;
  end;

{**
  Compares directory-entry names using deterministic ordinal ordering.

  Parameters
  ----------
  AItem1
    First TDirectoryEntry pointer.
  AItem2
    Second TDirectoryEntry pointer.

  Returns
  -------
  Integer
    Negative, zero, or positive according to CompareStr.

  Raises
  ------
  None
}
function CompareDirectoryEntries(AItem1, AItem2: Pointer): Integer;
begin
  Result := CompareStr(TDirectoryEntry(AItem1).Name,
    TDirectoryEntry(AItem2).Name);
end;

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

{**
  Reduces a native loader declaration to its library filename component.

  Parameters
  ----------
  ADeclaration
    Loader declaration, optionally including an absolute or tokenized path.

  Returns
  -------
  string
    Trimmed final path component used as the native component name.

  Raises
  ------
  None
}
function LinkedLibraryComponentName(const ADeclaration: string): string;
var
  SeparatorAt: Integer;
begin
  Result := Trim(ADeclaration);
  SeparatorAt := LastDelimiter('/\', Result);
  if (SeparatorAt > 0) and (SeparatorAt < Length(Result)) then
    Result := Copy(Result, SeparatorAt + 1, MaxInt);
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
  Entries: TObjectList;
  Entry: TDirectoryEntry;
  I, FindResult: Integer;
  AbsolutePath, RelativePath, EntryReason, EnumerationReason,
    EnumerationPath: string;
  IsDirectoryValue, IsLink: Boolean;
  EntryKind: TFileSystemEntryKind;
begin
  Result := False;
  if IsCancelled then
    Exit;
  EnumerationPath := NormalizeRelativePath(ARelativeDirectory);
  if EnumerationPath = '' then
    EnumerationPath := '.';
  Entries := TObjectList.Create(True);
  try
    try
      ResetDirectoryEnumerationError;
      FindResult := FindFirst(IncludeTrailingPathDelimiter(ADirectory) + '*',
        faAnyFile, SearchRecord);
      if FindResult <> 0 then
      begin
        if DirectoryEnumerationFailed(ADirectory, FindResult,
          EnumerationReason) then
          AddWarning('Unable to enumerate directory ' + EnumerationPath +
            ': ' + EnumerationReason);
        Exit(True);
      end;
      try
        while FindResult = 0 do
        begin
          if IsCancelled then
            Exit;
          if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
          begin
            Entry := TDirectoryEntry.Create;
            Entry.Name := SearchRecord.Name;
            Entry.Size := SearchRecord.Size;
            Entry.Attributes := SearchRecord.Attr;
            {$IFDEF UNIX}
            Entry.UnixMode := QWord(SearchRecord.Mode);
            {$ELSE}
            Entry.UnixMode := 0;
            {$ENDIF}
            Entries.Add(Entry);
          end;
          ResetDirectoryEnumerationError;
          FindResult := FindNext(SearchRecord);
        end;
        if DirectoryEnumerationContinuationFailed(FindResult,
          EnumerationReason) then
          AddWarning('Unable to finish enumerating directory ' +
            EnumerationPath + ': ' + EnumerationReason);
      finally
        FindClose(SearchRecord);
      end;
    except
      on E: Exception do
      begin
        AddWarning('Unable to enumerate directory ' + EnumerationPath +
          ': ' + E.Message);
        Exit(True);
      end;
    end;

    Entries.Sort(@CompareDirectoryEntries);
    for I := 0 to Entries.Count - 1 do
    begin
      if IsCancelled then
        Exit;
      Entry := TDirectoryEntry(Entries[I]);
      AbsolutePath := IncludeTrailingPathDelimiter(ADirectory) + Entry.Name;
      if ARelativeDirectory = '' then
        RelativePath := Entry.Name
      else
        RelativePath := ARelativeDirectory + '/' + Entry.Name;
      IsDirectoryValue := (Entry.Attributes and faDirectory) <> 0;
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

      EntryKind := ClassifyFileSystemEntry(Entry.Attributes,
        Entry.UnixMode, EntryReason);
      if EntryKind = fsekUnsupported then
      begin
        AddWarning('Skipped non-regular filesystem entry ' + RelativePath +
          ' (' + EntryReason + ')');
        Continue;
      end;

      if EntryKind = fsekDirectory then
      begin
        if EnterDirectory(AbsolutePath) then
          if not ScanDirectory(AbsolutePath, RelativePath) then
            Exit;
      end
      else
      begin
        if not ProcessFile(AbsolutePath, RelativePath, Entry.Size) then
          Exit;
      end;
    end;
    Result := True;
  finally
    Entries.Free;
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
  Component, BinaryComponent: uModels.TComponent;
  Inspection: TSystemInspection;
  NativeDependencies: TStringList;
  HashValue: string;
  InspectionSummary: string;
  I: Integer;
  ManifestLimit: Int64;
  IsArtifact, IsBinary: Boolean;
begin
  Result := False;
  BinaryComponent := nil;
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

  if not IsBinary and (Definition.ParserKind <> pkNone) then
  begin
    ManifestLimit := ManifestSizeLimit(Definition.ParserKind);
    if AFileSize < 0 then
      Artifact.MessageText :=
        'Manifest size is unavailable; parsing was not attempted.'
    else if (ManifestLimit > 0) and (AFileSize > ManifestLimit) then
      Artifact.MessageText := 'Manifest exceeds the size limit for ' +
        Definition.ParserName + ': ' + IntToStr(AFileSize) +
        ' bytes (maximum ' + IntToStr(ManifestLimit) + ' bytes).';
    if Artifact.MessageText <> '' then
    begin
      Artifact.Status := arsFailed;
      CountArtifactStatus(Artifact);
      ReportProgress(True);
      Exit(not IsCancelled);
    end;
  end;

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
      Component.Version := NativeDependencyVersion(Component.Name);
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
      BinaryComponent := Component;
      Artifact.ComponentCount := 1;
      NativeDependencies := TStringList.Create;
      try
        NativeDependencies.Sorted := True;
        NativeDependencies.Duplicates := dupIgnore;
        NativeDependencies.CaseSensitive := not SameText(
          BinaryInfo.FormatName, 'PE');
        if InspectNativeDependencies(AFileName, BinaryInfo.FormatName,
          NativeDependencies) then
        begin
          Artifact.MessageText := Artifact.MessageText +
            '; declared linked libraries: ' + StringReplace(
            NativeDependencies.CommaText, ',', ', ', [rfReplaceAll]);
          for I := 0 to NativeDependencies.Count - 1 do
          begin
            Component := uModels.TComponent.Create;
            Component.Name := LinkedLibraryComponentName(
              NativeDependencies[I]);
            Component.Version := NativeDependencyVersion(
              NativeDependencies[I]);
            Component.ComponentType := 'library';
            Component.Ecosystem := 'native';
            Component.SourceArtifact := FCurrentRelativePath;
            Component.SourceParser := 'binary-dependency-table';
            Component.DependencyScope := 'runtime';
            Component.EvidencePaths.Add(FCurrentRelativePath);
            FRawComponents.Add(Component);
            Inc(Artifact.ComponentCount);
          end;
        end;
        Inspection := nil;
        if InspectWithSystemTools(AFileName, BinaryInfo.FormatName,
          Inspection, @IsCancelled) then
        begin
          try
            FTask.InspectionTools.Add(Inspection.ToolName);
            InspectionSummary := Inspection.Summary;
            if InspectionSummary <> '' then
              Artifact.MessageText := Artifact.MessageText + '; ' +
                InspectionSummary;
            if (BinaryComponent <> nil) and
              (BinaryComponent.Version = '') and
              (Inspection.ComponentVersion <> '') then
              BinaryComponent.Version := Inspection.ComponentVersion;
            for I := 0 to Inspection.Dependencies.Count - 1 do
              if NativeDependencies.IndexOf(Inspection.Dependencies[I]) < 0 then
              begin
                Component := uModels.TComponent.Create;
                Component.Name := LinkedLibraryComponentName(
                  Inspection.Dependencies[I]);
                Component.Version := NativeDependencyVersion(
                  Inspection.Dependencies[I]);
                Component.ComponentType := 'library';
                Component.Ecosystem := 'native';
                Component.SourceArtifact := FCurrentRelativePath;
                Component.SourceParser := Inspection.ToolName;
                Component.DependencyScope := 'runtime';
                Component.EvidencePaths.Add(FCurrentRelativePath);
                FRawComponents.Add(Component);
                Inc(Artifact.ComponentCount);
              end;
          finally
            Inspection.Free;
          end;
        end;
      finally
        NativeDependencies.Free;
      end;
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
  CompletedNormally, FinalizationAttempted: Boolean;
begin
  FTask := ATask;
  FTask.Artifacts.Clear;
  FTask.Components.Clear;
  FTask.Warnings.Clear;
  FTask.Errors.Clear;
  FTask.InspectionTools.Clear;
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
  FinalizationAttempted := False;
  try
    if not DirectoryExists(FTask.TargetDirectory) then
      raise Exception.Create('The selected target directory does not exist');
    CompletedNormally := ScanDirectory(FTask.TargetDirectory, '');
    FinalizationAttempted := True;
    FinalizeComponents;
    if IsCancelled or not CompletedNormally then
      FTask.Status := tsCancelled
    else
      FTask.Status := tsCompleted;
  except
    on E: Exception do
    begin
      FTask.Status := tsFailed;
      FTask.Errors.Add(E.Message);
      if not FinalizationAttempted then
      begin
        FinalizationAttempted := True;
        try
          FinalizeComponents;
        except
          on FinalizationError: Exception do
            FTask.Errors.Add('Unable to preserve partial component results: ' +
              FinalizationError.Message);
        end;
      end;
    end;
  end;
  FTask.CompletedUTC := UTCNowISO8601;
  FTask.DurationMS := GetTickCount64 - FStartedTicks;
  ReportProgress(True);
  Result := FTask.Status = tsCompleted;
end;

end.
