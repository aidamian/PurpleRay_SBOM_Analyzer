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
  Classes, SysUtils, Contnrs, uModels, uSHA256, uPlatform, uVerifiedInput,
  uScanAnalysis, uScanPool, uScanCache;

type
  TScanOrdinalDelay = record
    Ordinal: QWord;
    Milliseconds: Cardinal;
  end;

  TScanOrdinalDelays = array of TScanOrdinalDelay;

  {**
    Selects bounded scanner execution behavior.

    WorkerCount zero selects an automatic value bounded to one through four.
    Tests may force one through four and delay selected DFS ordinals to prove
    out-of-order completion without changing publication order. A nonblank
    CacheProfileDirectory permits an explicitly enabled task to use the
    profile-local verified rescan cache; blank keeps the engine cache-free.
  *}
  TScanExecutionOptions = record
    WorkerCount: Integer;
    OrdinalDelays: TScanOrdinalDelays;
    CacheProfileDirectory: string;
  end;

{**
  Returns automatic bounded execution with no delays or cache profile.

  Parameters
  ----------
  None

  Returns
  -------
  TScanExecutionOptions
    Fresh managed record safe for caller customization.

  Raises
  ------
  None
*}
function DefaultScanExecutionOptions: TScanExecutionOptions;

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
    FLiveComponentKeys: TStringList;
    FVisitedDirectories: TStringList;
    FRootCanonical: string;
    FRootPin: TPinnedDirectory;
    FIgnoredDirectoryRoots: Int64;
    FCancelCheck: TCancelCheck;
    FProgressCallback: TScanProgressCallback;
    FStartedTicks: QWord;
    FLastProgressTicks: QWord;
    FCurrentRelativePath: string;
    FExecutionOptions: TScanExecutionOptions;
    FAnalysisPool: TScanAnalysisPool;
    FScanCache: TScanCache;
    FCacheStagingAllowed: Boolean;
    FCacheDiagnosticReported: Boolean;
    FCacheCommitted: Boolean;
    FNextAnalysisOrdinal: QWord;
    FNextCommitOrdinal: QWord;
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
    procedure AddWarning(const AMessage: string);
    procedure InitializeEngine(ACancelCheck: TCancelCheck;
      AProgressCallback: TScanProgressCallback;
      const AExecutionOptions: TScanExecutionOptions);
    function ResolveWorkerCount: Integer;
    function DelayForOrdinal(AOrdinal: QWord): Cardinal;
    function EnsureAnalysisCapacity: Boolean;
    function ConsumeNextAnalysisResult(AWait: Boolean;
      out AConsumed: Boolean): Boolean;
    function DrainAvailableAnalysisResults: Boolean;
    function DrainAllAnalysisResults: Boolean;
    procedure DrainCancelledPrefix;
    function PublishAnalysisResult(AResult: TScanAnalysisResult): Boolean;

    {**
      Creates and loads the optional cache after the scan root is pinned.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Cache setup failures become one nonfatal task warning.
    *}
    procedure InitializeRescanCache;

    {**
      Adds at most one privacy-safe warning for optional cache degradation.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Diagnostic allocation failures are contained because caching is
        optional and must not change scan success.
    *}
    procedure ReportCacheDiagnostic;

    {**
      Clones one stable ordered result into the pending cache snapshot.

      Parameters
      ----------
      AResult
        Still-owned analysis result whose evidence remains unchanged.

      Returns
      -------
      Boolean
        True when caching is disabled or staging succeeds; False when the
        optional snapshot becomes unusable.

      Raises
      ------
      None
        Cache staging exceptions become one nonfatal task warning.
    *}
    function StageAnalysisResult(AResult: TScanAnalysisResult): Boolean;

    {**
      Adds one deterministic summary for directory roots omitted by ignore rules.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if the warning collection cannot store the summary.
    *}
    procedure AddIgnoredDirectorySummary;

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
      AExpectedIdentity
        Native identity captured while the directory was enumerated.
      AWasLink
        Enumeration-time link state controlling the final-component policy.

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
      const AExpectedIdentity: TVerifiedFileIdentity;
      AWasLink: Boolean): Boolean;
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
  protected
    {**
      Provides a deterministic extension seam before a captured file is opened.

      Parameters
      ----------
      AFileName
        Enumerated absolute pathname about to be verified.
      ARelativePath
        Root-relative evidence path.
      AExpectedIdentity
        Native identity fixed during enumeration.

      Returns
      -------
      None

      Raises
      ------
      None
        The base implementation is a no-op; test subclasses may override it.
    *}
    procedure BeforeVerifiedInputOpen(const AFileName, ARelativePath: string;
      const AExpectedIdentity: TVerifiedFileIdentity); virtual;

    {**
      Provides a deterministic seam after analysis and before stable publication.

      Parameters
      ----------
      AFileName
        Enumerated absolute pathname whose pinned object was analyzed.
      ARelativePath
        Root-relative evidence path.
      AInput
        Still-open verified input awaiting final metadata validation.

      Returns
      -------
      None

      Raises
      ------
      None
        The base implementation is a no-op; test subclasses may override it.
    *}
    procedure BeforeVerifiedInputCommit(const AFileName,
      ARelativePath: string; AInput: TVerifiedInput); virtual;
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
      AProgressCallback: TScanProgressCallback); overload;
    constructor Create(ACancelCheck: TCancelCheck;
      AProgressCallback: TScanProgressCallback;
      const AExecutionOptions: TScanExecutionOptions); overload;
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

    {**
      Atomically activates the staged profile cache after SBOM output succeeds.

      Parameters
      ----------
      ADiagnostic
        Receives a bounded non-sensitive reason when the optional cache could
        not be committed.

      Returns
      -------
      Boolean
        True when caching is disabled, already committed, or activated
        successfully; False when the optional cache was not written.

      Raises
      ------
      None
        Cache failures are converted into a task warning and diagnostic.
    *}
    function CommitRescanCache(out ADiagnostic: string): Boolean;
  end;

implementation

uses
  {$IFDEF UNIX}BaseUnix,{$ENDIF}
  uIgnoreMatcher, uComponentNormalizer, uTimeUtils;

const
  { SysUtils.faSymLink / Win32 FILE_ATTRIBUTE_REPARSE_POINT. The local value
    avoids FPC's platform-symbol warning while requesting lstat-backed Unix
    enumeration and preserving the raw Windows reparse bit. }
  EnumeratedLinkAttribute = $00000400;

{**
  Returns a bounded OS/CPU token for cache-context isolation.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Stable lowercase target family and architecture token.

  Raises
  ------
  None
*}
function ScanCachePlatformToken: string;
begin
  {$IFDEF Windows}
  Result := 'windows';
  {$ELSE}
  {$IFDEF Linux}
  Result := 'linux';
  {$ELSE}
  Result := 'other';
  {$ENDIF}
  {$ENDIF}
  {$IFDEF CPUX86_64}
  Result := Result + '-x86_64';
  {$ELSE}
  {$IFDEF CPUAARCH64}
  Result := Result + '-aarch64';
  {$ELSE}
  Result := Result + '-unknown-cpu';
  {$ENDIF}
  {$ENDIF}
end;

{**
  Appends one unambiguous raw-string field to a cache hash buffer.

  Parameters
  ----------
  ABuffer
    Mutable domain-separated byte buffer receiving a length-prefixed field.
  AValue
    Field value whose exact current bytes are retained.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the buffer cannot grow.
*}
procedure AppendCacheHashField(var ABuffer: RawByteString;
  const AValue: string);
var
  RawValue: RawByteString;
begin
  RawValue := RawByteString(AValue);
  ABuffer := ABuffer + RawByteString(IntToStr(Length(RawValue))) + ':' +
    RawValue + #0;
end;

{**
  Hashes only settings that can change per-file scanner evidence.

  Cache controls, author metadata, remembered privacy policy, and absolute-path
  presentation are intentionally excluded. Ignore rules are normalized as an
  order-independent set because matching is an any-rule operation.

  Parameters
  ----------
  ASettings
    Scan settings whose evidence-affecting fields are hashed.

  Returns
  -------
  string
    Lowercase SHA-256 of the canonical analysis-settings representation.

  Raises
  ------
  EArgumentNilException
    Raised when ASettings is nil.
  EOutOfMemory
    Propagated while normalizing patterns or building the hash input.
*}
function ScanCacheSettingsSHA256(ASettings: TScanSettings): string;
var
  Buffer: RawByteString;
  Pattern, PatternValue: string;
  Patterns: TStringList;
  I: Integer;
begin
  if ASettings = nil then
    raise EArgumentNilException.Create('Scan settings must not be nil');
  Buffer := 'purpleray-analysis-settings-v1'#0;
  AppendCacheHashField(Buffer,
    BoolToStr(ASettings.FollowSymbolicLinks, True));
  AppendCacheHashField(Buffer,
    BoolToStr(ASettings.AllowOutsideRoot, True));
  AppendCacheHashField(Buffer,
    BoolToStr(ASettings.CalculateSHA256, True));
  Patterns := TStringList.Create;
  try
    Patterns.Sorted := True;
    Patterns.Duplicates := dupIgnore;
    Patterns.UseLocale := False;
    {$IFDEF Windows}
    Patterns.CaseSensitive := False;
    {$ELSE}
    Patterns.CaseSensitive := True;
    {$ENDIF}
    for I := 0 to ASettings.IgnorePatterns.Count - 1 do
    begin
      Pattern := NormalizeRelativePath(ASettings.IgnorePatterns[I]);
      if (Pattern = '') or (Pattern[1] = '#') then
        Continue;
      {$IFDEF Windows}
      PatternValue := LowerCase(Pattern);
      {$ELSE}
      PatternValue := Pattern;
      {$ENDIF}
      Patterns.Add(PatternValue);
    end;
    AppendCacheHashField(Buffer, IntToStr(Patterns.Count));
    for I := 0 to Patterns.Count - 1 do
      AppendCacheHashField(Buffer, Patterns[I]);
  finally
    Patterns.Free;
  end;
  Result := SHA256String(Buffer);
end;

type
  EScanAnalysisCoordinatorError = class(Exception);

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
    Identity
      Native regular-file identity captured during enumeration.
    IdentityCaptured
      True only when Identity is valid and safe to reopen for processing.
    IdentityReason
      Deterministic explanation retained when capture failed.
    WasLink
      Link or reparse-point state from the same directory enumeration record.
  }
  TDirectoryEntry = class
  public
    Name: string;
    Size: Int64;
    Attributes: LongInt;
    UnixMode: QWord;
    Identity: TVerifiedFileIdentity;
    IdentityCaptured: Boolean;
    IdentityReason: string;
    WasLink: Boolean;
  end;

function DefaultScanExecutionOptions: TScanExecutionOptions;
begin
  Result.WorkerCount := 0;
  SetLength(Result.OrdinalDelays, 0);
  Result.CacheProfileDirectory := '';
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
var
  Options: TScanExecutionOptions;
begin
  inherited Create;
  Options := DefaultScanExecutionOptions;
  InitializeEngine(ACancelCheck, AProgressCallback, Options);
end;

constructor TScanEngine.Create(ACancelCheck: TCancelCheck;
  AProgressCallback: TScanProgressCallback;
  const AExecutionOptions: TScanExecutionOptions);
begin
  inherited Create;
  InitializeEngine(ACancelCheck, AProgressCallback, AExecutionOptions);
end;

procedure TScanEngine.InitializeEngine(ACancelCheck: TCancelCheck;
  AProgressCallback: TScanProgressCallback;
  const AExecutionOptions: TScanExecutionOptions);
var
  I, J: Integer;
begin
  if (AExecutionOptions.WorkerCount < 0) or
    (AExecutionOptions.WorkerCount > MaximumScanWorkerCount) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'Scan worker count must be zero or between %d and %d',
      [MinimumScanWorkerCount, MaximumScanWorkerCount]);
  for I := 0 to High(AExecutionOptions.OrdinalDelays) do
    for J := 0 to I - 1 do
      if AExecutionOptions.OrdinalDelays[I].Ordinal =
        AExecutionOptions.OrdinalDelays[J].Ordinal then
        raise EArgumentException.CreateFmt(
          'Duplicate scan-analysis delay ordinal: %d',
          [AExecutionOptions.OrdinalDelays[I].Ordinal]);
  FRootPin := nil;
  FAnalysisPool := nil;
  FScanCache := nil;
  FCancelCheck := ACancelCheck;
  FProgressCallback := AProgressCallback;
  FExecutionOptions.WorkerCount := AExecutionOptions.WorkerCount;
  FExecutionOptions.OrdinalDelays := Copy(
    AExecutionOptions.OrdinalDelays, 0,
    Length(AExecutionOptions.OrdinalDelays));
  FExecutionOptions.CacheProfileDirectory :=
    AExecutionOptions.CacheProfileDirectory;
  FRawComponents := TObjectList.Create(True);
  FLiveComponentKeys := TStringList.Create;
  FLiveComponentKeys.Sorted := True;
  FLiveComponentKeys.CaseSensitive := True;
  FLiveComponentKeys.Duplicates := dupIgnore;
  FLiveComponentKeys.UseLocale := False;
  FVisitedDirectories := TStringList.Create;
  FVisitedDirectories.Sorted := True;
  FVisitedDirectories.Duplicates := dupIgnore;
  FVisitedDirectories.UseLocale := False;
  {$IFDEF Windows}
  FVisitedDirectories.CaseSensitive := False;
  {$ELSE}
  FVisitedDirectories.CaseSensitive := True;
  {$ENDIF}
end;

destructor TScanEngine.Destroy;
begin
  FAnalysisPool.Free;
  FScanCache.Free;
  FRootPin.Free;
  FVisitedDirectories.Free;
  FLiveComponentKeys.Free;
  FRawComponents.Free;
  inherited Destroy;
end;

procedure TScanEngine.BeforeVerifiedInputOpen(const AFileName,
  ARelativePath: string; const AExpectedIdentity: TVerifiedFileIdentity);
begin
  { Extension seam intentionally left blank. }
end;

procedure TScanEngine.BeforeVerifiedInputCommit(const AFileName,
  ARelativePath: string; AInput: TVerifiedInput);
begin
  { Extension seam intentionally left blank. }
end;

function TScanEngine.IsCancelled: Boolean;
begin
  Result := Assigned(FCancelCheck) and FCancelCheck();
  if Result and (FAnalysisPool <> nil) then
    FAnalysisPool.RequestCancel;
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
  Progress.ComponentsIdentified := FLiveComponentKeys.Count;
  Progress.ElapsedMS := NowTicks - FStartedTicks;
  FProgressCallback(Progress);
end;

procedure TScanEngine.AddWarning(const AMessage: string);
begin
  if (AMessage <> '') and (FTask.Warnings.IndexOf(AMessage) < 0) then
    FTask.Warnings.Add(AMessage);
end;

procedure TScanEngine.ReportCacheDiagnostic;
begin
  if FCacheDiagnosticReported then
    Exit;
  FCacheDiagnosticReported := True;
  try
    AddWarning('The optional rescan cache was unavailable or incomplete; ' +
      'scan evidence and SBOM generation continued normally.');
  except
    { Cache diagnostics never make a successful scan fail. }
  end;
end;

procedure TScanEngine.InitializeRescanCache;
var
  CacheContext: TScanCacheContext;
  CacheMode: TScanCacheMode;
  Diagnostic, ProfileHash, RootHash: string;
begin
  FreeAndNil(FScanCache);
  FCacheStagingAllowed := False;
  FCacheCommitted := False;
  if (FTask = nil) or not FTask.Settings.UseRescanCache or
    (Trim(FExecutionOptions.CacheProfileDirectory) = '') then
    Exit;
  if FTask.Settings.RefreshRescanCache then
    CacheMode := scmRefresh
  else
    CacheMode := scmUse;
  try
    ProfileHash := ScanCacheProfilePathSHA256(
      FExecutionOptions.CacheProfileDirectory);
    RootHash := SHA256String(RawByteString('purpleray-root-path-v1'#0 +
      FRootCanonical));
    InitializeScanCacheContext(CacheContext,
      ScanAnalysisContract,
      ScanCachePlatformToken, ProfileHash, RootHash,
      FRootPin.IdentityToken, ScanCacheSettingsSHA256(FTask.Settings));
    FScanCache := TScanCache.Create(CacheMode,
      FExecutionOptions.CacheProfileDirectory, CacheContext);
    FCacheStagingAllowed := True;
    if (CacheMode = scmUse) and not FScanCache.Load(Diagnostic) and
      (Diagnostic <> '') then
      ReportCacheDiagnostic;
  except
    on E: Exception do
    begin
      FreeAndNil(FScanCache);
      FCacheStagingAllowed := False;
      ReportCacheDiagnostic;
    end;
  end;
end;

function TScanEngine.StageAnalysisResult(
  AResult: TScanAnalysisResult): Boolean;
var
  Diagnostic: string;
begin
  Result := True;
  if FScanCache = nil then
    Exit;
  if AResult.CacheDiagnostic <> '' then
    ReportCacheDiagnostic;
  if not FCacheStagingAllowed then
    Exit(False);
  if AResult.ContentSHA256 = '' then
  begin
    FCacheStagingAllowed := False;
    ReportCacheDiagnostic;
    Exit(False);
  end;
  try
    Result := FScanCache.Stage(AResult.RelativePath, AResult.Input.Identity,
      AResult.ContentSHA256, AResult.Artifact, AResult.Components,
      AResult.InspectionTools, AResult.Warnings, Diagnostic);
  except
    on E: Exception do
      Result := False;
  end;
  if not Result then
  begin
    FCacheStagingAllowed := False;
    ReportCacheDiagnostic;
  end;
end;

function TScanEngine.CommitRescanCache(out ADiagnostic: string): Boolean;
begin
  ADiagnostic := '';
  if (FScanCache = nil) or FCacheCommitted then
    Exit(True);
  if (FTask = nil) or (FTask.Status <> tsCompleted) or
    not FCacheStagingAllowed then
  begin
    ADiagnostic := 'The rescan-cache snapshot was incomplete.';
    Exit(False);
  end;
  try
    Result := FScanCache.Commit(ADiagnostic);
  except
    on E: Exception do
    begin
      ADiagnostic := 'The rescan-cache snapshot could not be committed.';
      Result := False;
    end;
  end;
  if Result then
    FCacheCommitted := True
  else
    ReportCacheDiagnostic;
end;

function TScanEngine.ResolveWorkerCount: Integer;
begin
  Result := FExecutionOptions.WorkerCount;
  if Result = 0 then
  begin
    Result := Integer(TThread.ProcessorCount);
    if Result < MinimumScanWorkerCount then
      Result := MinimumScanWorkerCount;
    if Result > MaximumScanWorkerCount then
      Result := MaximumScanWorkerCount;
  end;
end;

function TScanEngine.DelayForOrdinal(AOrdinal: QWord): Cardinal;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to High(FExecutionOptions.OrdinalDelays) do
    if FExecutionOptions.OrdinalDelays[I].Ordinal = AOrdinal then
      Exit(FExecutionOptions.OrdinalDelays[I].Milliseconds);
end;

function TScanEngine.PublishAnalysisResult(
  AResult: TScanAnalysisResult): Boolean;
var
  Artifact, PublishedArtifact: TArtifact;
  StagedObject: TObject;
  InputReason: string;
  I: Integer;
  InputStable: Boolean;
begin
  Result := False;
  if AResult = nil then
    raise EArgumentNilException.Create('Analysis result must not be nil');
  if AResult.Cancelled then
    Exit;

  FCurrentRelativePath := AResult.RelativePath;
  Inc(FTask.FilesInspected);
  if AResult.Input.Size > 0 then
    Inc(FTask.BytesInspected, AResult.Input.Size);

  BeforeVerifiedInputCommit(AResult.FileName, AResult.RelativePath,
    AResult.Input);
  Artifact := AResult.Artifact;
  InputStable := AResult.Input.ValidateStable(InputReason);
  if not InputStable then
  begin
    FCacheStagingAllowed := False;
    AResult.Components.Clear;
    AResult.InspectionTools.Clear;
    if Artifact = nil then
      AddWarning('Skipped file that changed during inspection: ' +
        AResult.RelativePath + ' (' + InputReason + ')')
    else
    begin
      Artifact.ComponentCount := 0;
      Artifact.SHA256 := '';
      Artifact.Status := arsFailed;
      Artifact.MessageText := 'Input changed during bounded inspection: ' +
        InputReason;
    end;
  end;
  FRootPin.VerifyCurrentPath;

  if AResult.FatalError <> '' then
  begin
    FCacheStagingAllowed := False;
    raise Exception.Create(AResult.FatalError);
  end;
  if InputStable then
    StageAnalysisResult(AResult);
  for I := 0 to AResult.Warnings.Count - 1 do
    AddWarning(AResult.Warnings[I]);

  if Artifact <> nil then
  begin
    PublishedArtifact := AResult.ReleaseArtifact;
    FTask.Artifacts.Add(PublishedArtifact);
    Inc(FTask.ArtifactsDetected);
    while AResult.Components.Count > 0 do
    begin
      FLiveComponentKeys.Add(ComponentNormalizationKey(
        uModels.TComponent(AResult.Components[0])));
      StagedObject := TObject(AResult.Components.Extract(
        AResult.Components[0]));
      FRawComponents.Add(StagedObject);
    end;
    for I := 0 to AResult.InspectionTools.Count - 1 do
      FTask.InspectionTools.Add(AResult.InspectionTools[I]);
    CountArtifactStatus(PublishedArtifact);
  end;
  Result := True;
end;

function TScanEngine.ConsumeNextAnalysisResult(AWait: Boolean;
  out AConsumed: Boolean): Boolean;
const
  AnalysisWaitMilliseconds = 25;
var
  AnalysisResult: TScanAnalysisResult;
  WorkerFailure: string;
  Ready: Boolean;
begin
  Result := True;
  AConsumed := False;
  if FAnalysisPool = nil then
    Exit;
  repeat
    try
      Ready := FAnalysisPool.TryTakeResult(FNextCommitOrdinal,
        AnalysisResult);
    except
      on E: Exception do
        raise EScanAnalysisCoordinatorError.Create(E.Message);
    end;
    if Ready then
    begin
      AConsumed := True;
      try
        try
          Result := PublishAnalysisResult(AnalysisResult);
        except
          on E: Exception do
            raise EScanAnalysisCoordinatorError.Create(E.Message);
        end;
      finally
        AnalysisResult.Free;
      end;
      Inc(FNextCommitOrdinal);
      FCurrentRelativePath := FAnalysisPool.OldestUncommittedPath;
      ReportProgress(True);
      Exit;
    end;
    if FAnalysisPool.HasWorkerFailure(WorkerFailure) then
      raise EScanAnalysisCoordinatorError.Create(WorkerFailure);
    if not AWait then
    begin
      FCurrentRelativePath := FAnalysisPool.OldestUncommittedPath;
      Exit;
    end;
    if IsCancelled then
      Exit(False);
    FCurrentRelativePath := FAnalysisPool.OldestUncommittedPath;
    ReportProgress(False);
    FAnalysisPool.WaitForResult(AnalysisWaitMilliseconds);
  until False;
end;

function TScanEngine.DrainAvailableAnalysisResults: Boolean;
var
  Consumed: Boolean;
begin
  repeat
    Result := ConsumeNextAnalysisResult(False, Consumed);
    if not Result or not Consumed then
      Exit;
  until False;
end;

function TScanEngine.DrainAllAnalysisResults: Boolean;
var
  Consumed: Boolean;
begin
  while FNextCommitOrdinal < FNextAnalysisOrdinal do
  begin
    Result := ConsumeNextAnalysisResult(True, Consumed);
    if not Result then
      Exit;
    if not Consumed then
      raise Exception.Create('Analysis pool returned no pending result');
  end;
  Result := True;
end;

procedure TScanEngine.DrainCancelledPrefix;
var
  AnalysisResult: TScanAnalysisResult;
begin
  if FAnalysisPool = nil then
    Exit;
  while FAnalysisPool.TryTakeResult(FNextCommitOrdinal, AnalysisResult) do
  begin
    try
      if AnalysisResult.Cancelled then
        Exit;
      PublishAnalysisResult(AnalysisResult);
      Inc(FNextCommitOrdinal);
    finally
      AnalysisResult.Free;
    end;
  end;
  FCurrentRelativePath := FAnalysisPool.OldestUncommittedPath;
end;

function TScanEngine.EnsureAnalysisCapacity: Boolean;
var
  Consumed: Boolean;
begin
  if FAnalysisPool = nil then
    Exit(True);
  while FAnalysisPool.InFlight >= FAnalysisPool.MaximumInFlight do
  begin
    if not ConsumeNextAnalysisResult(True, Consumed) then
      Exit(False);
    if not Consumed then
      raise Exception.Create('Analysis pool capacity could not be released');
  end;
  Result := not IsCancelled;
end;

procedure TScanEngine.AddIgnoredDirectorySummary;
var
  CountText: string;
begin
  if FIgnoredDirectoryRoots <= 0 then
    Exit;
  if FIgnoredDirectoryRoots = 1 then
    CountText := '1 directory root'
  else
    CountText := IntToStr(FIgnoredDirectoryRoots) + ' directory roots';
  AddWarning('Skipped ' + CountText + ' due to ignore rules. Prefer ' +
    'lock-file evidence over installed dependency trees when available.');
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
  SearchAttributes: LongInt;
  AbsolutePath, RelativePath, EntryReason, EnumerationReason,
    EnumerationPath, IdentityPath, IdentityRelativePath, CaptureRoot: string;
  IsDirectoryValue, IsLink, IdentityIsDirectory: Boolean;
  EntryKind, IdentityEntryKind: TFileSystemEntryKind;
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
      { Including the link bit makes FPC's Unix FindFirst use lstat instead of
        stat, so WasLink belongs to this enumeration record rather than to a
        later pathname lookup. It does not filter out ordinary entries. }
      SearchAttributes := faAnyFile or EnumeratedLinkAttribute;
      FindResult := FindFirst(NativeFileSystemPath(
        IncludeTrailingPathDelimiter(ADirectory) + '*'), SearchAttributes,
        SearchRecord);
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
            FillChar(Entry.Identity, SizeOf(Entry.Identity), 0);
            Entry.IdentityCaptured := False;
            Entry.IdentityReason := '';
            {$IFDEF UNIX}
            Entry.WasLink := FPS_ISLNK(TMode(Entry.UnixMode));
            {$ENDIF}
            {$IFDEF Windows}
            Entry.WasLink := (Entry.Attributes and
              EnumeratedLinkAttribute) <> 0;
            {$ENDIF}
            {$IFNDEF UNIX}
            {$IFNDEF Windows}
            Entry.WasLink := False;
            {$ENDIF}
            {$ENDIF}
            if ARelativeDirectory = '' then
              IdentityRelativePath := Entry.Name
            else
              IdentityRelativePath := ARelativeDirectory + '/' + Entry.Name;
            IdentityIsDirectory := (Entry.Attributes and faDirectory) <> 0;
            IdentityEntryKind := ClassifyFileSystemEntry(Entry.Attributes,
              Entry.UnixMode, EntryReason);
            IdentityPath := IncludeTrailingPathDelimiter(ADirectory) +
              Entry.Name;
            if not IdentityIsDirectory and
              ((IdentityEntryKind = fsekRegularFile) or
               (FTask.Settings.FollowSymbolicLinks and
                Entry.WasLink)) and
              not ShouldIgnorePath(IdentityRelativePath, False,
                FTask.Settings.IgnorePatterns) then
            begin
              if FTask.Settings.AllowOutsideRoot then
                CaptureRoot := ''
              else
                CaptureRoot := FRootCanonical;
              if Entry.WasLink and (CaptureRoot <> '') and
                not PathIsWithin(IdentityPath, CaptureRoot) then
                Entry.IdentityReason :=
                  'symbolic link resolves outside the selected scan root'
              else
              begin
                { Reserve one of the pool's bounded verified-input slots before
                  identity capture opens its short-lived native handle. }
                if not EnsureAnalysisCapacity then
                  Exit;
                FRootPin.VerifyCurrentPath;
                Entry.IdentityCaptured := TryCaptureVerifiedFileIdentity(
                  IdentityPath, CaptureRoot,
                  Entry.WasLink and FTask.Settings.FollowSymbolicLinks,
                  Entry.Identity, Entry.IdentityReason);
                FRootPin.VerifyCurrentPath;
              end;
            end;
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
      on E: EScanAnalysisCoordinatorError do
        raise;
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
      if not DrainAvailableAnalysisResults then
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
      begin
        if IsDirectoryValue then
          Inc(FIgnoredDirectoryRoots);
        Continue;
      end;
      IsLink := Entry.WasLink;
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

      if IsLink and FTask.Settings.FollowSymbolicLinks and
        IsDirectoryValue then
        EntryKind := fsekDirectory
      else if IsLink and FTask.Settings.FollowSymbolicLinks and
        Entry.IdentityCaptured then
        EntryKind := fsekRegularFile
      else
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
        if not Entry.IdentityCaptured then
        begin
          AddWarning('Skipped file that could not be pinned during ' +
            'enumeration: ' + RelativePath + ' (' +
            Entry.IdentityReason + ')');
          Continue;
        end;
        if not ProcessFile(AbsolutePath, RelativePath, Entry.Identity,
          Entry.WasLink) then
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
  const AExpectedIdentity: TVerifiedFileIdentity;
  AWasLink: Boolean): Boolean;
var
  Input: TVerifiedInput;
  Job: TScanAnalysisJob;
  InputReason, VerificationRoot: string;
begin
  Result := False;
  Input := nil;
  Job := nil;
  if not EnsureAnalysisCapacity then
    Exit;

  FCurrentRelativePath := NormalizeRelativePath(ARelativePath);
  BeforeVerifiedInputOpen(AFileName, FCurrentRelativePath,
    AExpectedIdentity);
  FRootPin.VerifyCurrentPath;
  if FTask.Settings.AllowOutsideRoot then
    VerificationRoot := ''
  else
    VerificationRoot := FRootCanonical;
  if not TryOpenVerifiedInput(AFileName, VerificationRoot,
    AWasLink and FTask.Settings.FollowSymbolicLinks, AExpectedIdentity, Input,
    InputReason) then
  begin
    AddWarning('Skipped file that changed or could not be verified: ' +
      FCurrentRelativePath + ' (' + InputReason + ')');
    Exit(True);
  end;
  FRootPin.VerifyCurrentPath;

  try
    Job := TScanAnalysisJob.Create(FNextAnalysisOrdinal, AFileName,
      FCurrentRelativePath, Input, FTask.Settings.CalculateSHA256,
      DelayForOrdinal(FNextAnalysisOrdinal), FScanCache);
    Input := nil;
    if not FAnalysisPool.Submit(Job) then
    begin
      if IsCancelled then
        Exit(False);
      raise Exception.Create('Bounded analysis pool rejected an available job');
    end;
    Job := nil;
    Inc(FNextAnalysisOrdinal);
    if not DrainAvailableAnalysisResults then
      Exit;
    Result := not IsCancelled;
  finally
    Job.Free;
    Input.Free;
  end;
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
  FLiveComponentKeys.Clear;
  FVisitedDirectories.Clear;
  FIgnoredDirectoryRoots := 0;
  FTask.StartedUTC := UTCNowISO8601;
  FTask.CompletedUTC := '';
  FTask.Status := tsRunning;
  FStartedTicks := GetTickCount64;
  FLastProgressTicks := 0;
  FCurrentRelativePath := '';
  FreeAndNil(FAnalysisPool);
  FreeAndNil(FScanCache);
  FreeAndNil(FRootPin);
  FRootCanonical := '';
  FNextAnalysisOrdinal := 0;
  FNextCommitOrdinal := 0;
  FCacheStagingAllowed := False;
  FCacheDiagnosticReported := False;
  FCacheCommitted := False;
  CompletedNormally := False;
  FinalizationAttempted := False;
  try
    try
      if not DirectoryExists(NativeFileSystemPath(FTask.TargetDirectory)) then
        raise Exception.Create('The selected target directory does not exist');
      try
        FRootPin := PinExistingDirectory(FTask.TargetDirectory);
      except
        on E: EInOutError do
          AddWarning('Unable to enumerate directory .: ' + E.Message);
      end;
      if FRootPin = nil then
        CompletedNormally := True
      else
      begin
        FRootCanonical := FRootPin.DirectoryName;
        FRootPin.VerifyCurrentPath;
        FVisitedDirectories.Add(FRootCanonical);
        InitializeRescanCache;
        FAnalysisPool := TScanAnalysisPool.Create(ResolveWorkerCount);
        CompletedNormally := ScanDirectory(FRootCanonical, '');
        if CompletedNormally then
          CompletedNormally := DrainAllAnalysisResults;
        if CompletedNormally then
          FAnalysisPool.StopAndJoin
        else
        begin
          FAnalysisPool.CancelAndJoin;
          DrainCancelledPrefix;
        end;
        FCurrentRelativePath := '';
        FRootPin.VerifyCurrentPath;
      end;
      if CompletedNormally then
        AddIgnoredDirectorySummary;
      FinalizationAttempted := True;
      FinalizeComponents;
      if IsCancelled or not CompletedNormally then
      begin
        FCacheStagingAllowed := False;
        FTask.Status := tsCancelled
      end
      else
      begin
        FTask.Status := tsCompleted;
        if FTask.FilesInspected = 0 then
          AddWarning('The scan completed without inspecting any regular files. ' +
            'Review the selected folder, permissions, symbolic-link policy, and ' +
            'ignore patterns before relying on this result.');
      end;
    except
      on E: Exception do
      begin
        if FAnalysisPool <> nil then
          FAnalysisPool.CancelAndJoin;
        FCacheStagingAllowed := False;
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
  finally
    FreeAndNil(FAnalysisPool);
    FreeAndNil(FRootPin);
  end;
  FTask.CompletedUTC := UTCNowISO8601;
  FTask.DurationMS := GetTickCount64 - FStartedTicks;
  ReportProgress(True);
  Result := FTask.Status = tsCompleted;
end;

end.
