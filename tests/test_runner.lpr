(**
  PurpleRay SBOM Analyzer deterministic regression-test program.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Exercises non-visual parsing, hashing, persistence, migration, export,
  dependency inspection, normalization, traversal, and cancellation behavior.

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
program test_runner;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, BaseUnix,{$ENDIF}
  {$IFDEF Windows}Windows,{$ENDIF}
  Classes, SysUtils, Contnrs, fpjson, jsonparser, zipper,
  uModels, uSHA256, uBinaryInspector, uManifestParsers, uArtifactIdentifier,
  uTaskHistory, uJSONUtils, uComponentNormalizer, uCycloneDX, uIgnoreMatcher,
  uScanEngine, uPlatform, uSystemInspector, uNativeDependencyInspector,
  uExportUtils, uVersionInfo, uScanWorker, uPresentation, uSPDXExpressions,
  uComponentComparison, uCommandLine, uScanService, uAtomicFiles;

type
  TTestMethod = procedure;

  { Signals that a registered test is not applicable to this runtime. }
  ETestSkipped = class(Exception);

  TCancelController = class
  private
    FChecks: Integer;
    FLimit: Integer;
  public
    constructor Create(ALimit: Integer);
    function Check: Boolean;
  end;

  { Captures a queued scan-worker completion for exception-path assertions. }
  TCompletionObserver = class
  public
    Count: Integer;
    Status: TTaskStatus;
    ErrorText: string;
    CompletedUTC: string;
    procedure Complete(Sender: TObject; AResult: TScanTask);
  end;

  { Captures the latest revisioned mutation published by task history. }
  THistoryChangeObserver = class
  public
    Count: Integer;
    LastKind: TTaskHistoryChangeKind;
    LastTaskID: string;
    LastRevision: QWord;
    procedure Changed(Sender: TObject; AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);
  end;

  { Injects a deterministic failure through the worker's protected test seam. }
  TFailingScanWorker = class(TScanWorker)
  protected
    procedure PerformScan; override;
  end;

  {$IFDEF UNIX}
  { Rebinds an output parent when the scanner first polls cancellation. }
  TOutputParentRebindController = class
  private
    FLinkBackToPinnedDirectory: Boolean;
    FOriginalDirectory: string;
    FMovedDirectory: string;
  public
    ErrorText: string;
    Succeeded: Boolean;
    Triggered: Boolean;
    constructor Create(const AOriginalDirectory, AMovedDirectory: string;
      ALinkBackToPinnedDirectory: Boolean);
    function Check: Boolean;
  end;

  { Supplies one byte to a FIFO if a regressed scanner attempts to open it. }
  TFIFOWriter = class(TThread)
  private
    FPath: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const APath: string);
  end;
  {$ENDIF}

var
  TestCount: Integer = 0;
  PassCount: Integer = 0;
  FailureCount: Integer = 0;
  SkipCount: Integer = 0;
  ProjectRoot: string;
  TemporaryRoot: string;

constructor TCancelController.Create(ALimit: Integer);
begin
  inherited Create;
  FLimit := ALimit;
end;

function TCancelController.Check: Boolean;
begin
  Inc(FChecks);
  Result := FChecks >= FLimit;
end;

{$IFDEF UNIX}
{**
  Configures one deterministic output-parent rebind during a scan.

  Parameters
  ----------
  AOriginalDirectory
    Directory path pinned by the scan service before scanning starts.
  AMovedDirectory
    Test-owned sibling name to which the original directory will be moved.
  ALinkBackToPinnedDirectory
    When True, replaces the old path with a symlink back to the moved pinned
    object; when False, replaces it with a different directory object.

  Returns
  -------
  TOutputParentRebindController
    New controller owned by the test.

  Raises
  ------
  EOutOfMemory
    May propagate while allocating strings or the controller.
}
constructor TOutputParentRebindController.Create(const AOriginalDirectory,
  AMovedDirectory: string; ALinkBackToPinnedDirectory: Boolean);
begin
  inherited Create;
  FOriginalDirectory := AOriginalDirectory;
  FMovedDirectory := AMovedDirectory;
  FLinkBackToPinnedDirectory := ALinkBackToPinnedDirectory;
end;

{**
  Replaces the validated parent path on the first cancellation poll.

  Parameters
  ----------
  None

  Returns
  -------
  Boolean
    Always False so the scan continues to its protected output activation.

  Raises
  ------
  None
    Fixture setup failures are retained in ErrorText for explicit assertions.
}
function TOutputParentRebindController.Check: Boolean;
begin
  Result := False;
  if Triggered then
    Exit;
  Triggered := True;
  if not RenameFile(FOriginalDirectory, FMovedDirectory) then
  begin
    ErrorText := 'unable to move the pinned output parent';
    Exit;
  end;
  if FLinkBackToPinnedDirectory then
  begin
    if fpSymlink(PChar(FMovedDirectory), PChar(FOriginalDirectory)) <> 0 then
    begin
      ErrorText := 'unable to link the old path back to the pinned directory';
      Exit;
    end;
  end
  else if not ForceDirectories(FOriginalDirectory) then
  begin
    ErrorText := 'unable to recreate the output-parent pathname';
    Exit;
  end;
  Succeeded := True;
end;
{$ENDIF}

{**
  Records one worker completion without retaining the worker-owned task.

  Parameters
  ----------
  Sender
    Worker that queued the completion; unused by the observer.
  AResult
    Worker-owned task whose stable scalar state is copied for assertions.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure TCompletionObserver.Complete(Sender: TObject; AResult: TScanTask);
begin
  Inc(Count);
  Status := AResult.Status;
  ErrorText := AResult.Errors.Text;
  CompletedUTC := AResult.CompletedUTC;
end;

{**
  Records the scalar identity of one shared-history mutation.

  Parameters
  ----------
  Sender
    History service publishing the change; unused by this observer.
  AKind
    Reset, addition, update, or removal classification.
  ATaskID
    Stable affected identifier, or blank for a reset.
  ARevision
    Monotonically increasing service revision.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure THistoryChangeObserver.Changed(Sender: TObject;
  AKind: TTaskHistoryChangeKind; const ATaskID: string; ARevision: QWord);
begin
  Inc(Count);
  LastKind := AKind;
  LastTaskID := ATaskID;
  LastRevision := ARevision;
end;

{**
  Raises a known exception to exercise the worker's last-resort boundary.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Always raised with a stable regression-test diagnostic.
}
procedure TFailingScanWorker.PerformScan;
begin
  raise Exception.Create('intentional worker regression failure');
end;

{$IFDEF UNIX}
{**
  Creates a suspended bounded FIFO writer for the special-file regression.

  Parameters
  ----------
  APath
    FIFO path that may be opened by a regressed scanner.

  Returns
  -------
  TFIFOWriter
    Suspended writer owned by the caller.

  Raises
  ------
  EOutOfMemory
    Propagated if thread allocation fails.
}
constructor TFIFOWriter.Create(const APath: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPath := APath;
end;

{**
  Non-blockingly connects to a FIFO reader and supplies a finite payload.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
    Connection failures are retried for at most five seconds.
}
procedure TFIFOWriter.Execute;
var
  Deadline: QWord;
  FileHandle: cint;
  Payload: Byte;
begin
  Deadline := GetTickCount64 + 5000;
  repeat
    if Terminated then
      Exit;
    FileHandle := fpOpen(PChar(FPath), O_WRONLY or O_NONBLOCK);
    if FileHandle >= 0 then
    begin
      try
        Payload := Ord('x');
        fpWrite(FileHandle, Payload, 1);
      finally
        fpClose(FileHandle);
      end;
      Exit;
    end;
    Sleep(1);
  until GetTickCount64 >= Deadline;
end;
{$ENDIF}

procedure Fail(const AMessage: string);
begin
  raise Exception.Create(AMessage);
end;

{**
  Marks the current registered test as inapplicable on this runtime.

  Parameters
  ----------
  AReason
    Concise explanation written beside the explicit SKIP result.

  Returns
  -------
  None

  Raises
  ------
  ETestSkipped
    Always raised so RunTest can account for the skipped case separately.
}
procedure SkipTest(const AReason: string);
begin
  raise ETestSkipped.Create(AReason);
end;

procedure AssertTrue(AValue: Boolean; const AMessage: string);
begin
  if not AValue then
    Fail(AMessage);
end;

procedure AssertEqual(const AExpected, AActual: string; const AMessage: string);
begin
  if AExpected <> AActual then
    Fail(AMessage + Format(' (expected "%s", got "%s")',
      [AExpected, AActual]));
end;

procedure AssertEqual(AExpected, AActual: Int64; const AMessage: string);
begin
  if AExpected <> AActual then
    Fail(AMessage + Format(' (expected %d, got %d)', [AExpected, AActual]));
end;

function Fixture(const AName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(ProjectRoot) + 'tests' +
    DirectorySeparator + 'fixtures' + DirectorySeparator + AName;
end;

{**
  Counts non-overlapping occurrences of one exact source fragment.

  Parameters
  ----------
  AText
    Complete source or resource text to inspect.
  AFragment
    Exact non-empty fragment to count.

  Returns
  -------
  Integer
    Number of non-overlapping matches, or zero for an empty fragment.

  Raises
  ------
  None
}
function CountTextOccurrences(const AText, AFragment: string): Integer;
var
  RemainingText: string;
  MatchAt: SizeInt;
begin
  Result := 0;
  if AFragment = '' then
    Exit;
  RemainingText := AText;
  repeat
    MatchAt := Pos(AFragment, RemainingText);
    if MatchAt = 0 then
      Exit;
    Inc(Result);
    Delete(RemainingText, 1, MatchAt + Length(AFragment) - 1);
  until RemainingText = '';
end;

{**
  Extracts a bounded method or control block from source text.

  Parameters
  ----------
  AText
    Complete source text containing both markers.
  AStartMarker
    Exact first marker retained in the returned section.
  AEndMarker
    Exact later marker excluded from the returned section.

  Returns
  -------
  string
    Text from the first marker up to the later marker, or blank when either
    marker is absent or ordered incorrectly.

  Raises
  ------
  EOutOfMemory
    May propagate while copying the requested source section.
}
function ExtractTextSection(const AText, AStartMarker,
  AEndMarker: string): string;
var
  StartAt, RelativeEndAt: SizeInt;
  TailText: string;
begin
  Result := '';
  StartAt := Pos(AStartMarker, AText);
  if StartAt = 0 then
    Exit;
  TailText := Copy(AText, StartAt, MaxInt);
  RelativeEndAt := Pos(AEndMarker, TailText);
  if RelativeEndAt <= 1 then
    Exit;
  Result := Copy(TailText, 1, RelativeEndAt - 1);
end;

function NewTemporaryDirectory(const AName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(TemporaryRoot) + AName;
  if not ForceDirectories(Result) then
    Fail('Unable to create temporary test directory: ' + Result);
end;

{**
  Independently identifies link-like entries during test cleanup.

  Parameters
  ----------
  APath
    Exact test-owned entry to inspect without following it.

  Returns
  -------
  Boolean
    True for a Unix symbolic link or Windows reparse point.

  Raises
  ------
  None
    Metadata lookup failures are treated as non-links for best-effort cleanup.
}
function CleanupEntryIsLink(const APath: string): Boolean;
{$IFDEF UNIX}
var
  Info: Stat;
{$ENDIF}
{$IFDEF Windows}
var
  Attributes: DWORD;
  WidePath: UnicodeString;
{$ENDIF}
begin
  {$IFDEF UNIX}
  Result := (fpLStat(PChar(APath), Info) = 0) and FPS_ISLNK(Info.st_mode);
  {$ENDIF}
  {$IFDEF Windows}
  WidePath := UTF8Decode(APath);
  Attributes := GetFileAttributesW(PWideChar(WidePath));
  Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
    ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := False;
  {$ENDIF}
  {$ENDIF}
end;

{**
  Best-effort removes a test-owned directory without following symlinks.

  Parameters
  ----------
  ADirectory
    Exact temporary directory tree owned by this test process.

  Returns
  -------
  None

  Raises
  ------
  None
    Cleanup failures are ignored so they cannot hide the actual test result.
}
procedure RemoveTemporaryTree(const ADirectory: string);
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
  EntryPath: string;
begin
  if not DirectoryExists(ADirectory) then
    Exit;
  FindResult := FindFirst(IncludeTrailingPathDelimiter(ADirectory) + '*',
    faAnyFile, SearchRecord);
  if FindResult = 0 then
  begin
    try
      while FindResult = 0 do
      begin
        if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
        begin
          EntryPath := IncludeTrailingPathDelimiter(ADirectory) +
            SearchRecord.Name;
          if ((SearchRecord.Attr and faDirectory) <> 0) and
            not CleanupEntryIsLink(EntryPath) then
            RemoveTemporaryTree(EntryPath)
          else
            SysUtils.DeleteFile(EntryPath);
        end;
        FindResult := FindNext(SearchRecord);
      end;
    finally
      FindClose(SearchRecord);
    end;
  end;
  RemoveDir(ADirectory);
end;

procedure WriteText(const AFileName, AContent: RawByteString);
var
  Stream: TFileStream;
begin
  ForceDirectories(ExtractFileDir(AFileName));
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(AContent) > 0 then
      Stream.WriteBuffer(AContent[1], Length(AContent));
  finally
    Stream.Free;
  end;
end;

{**
  Writes deterministic UTF-16LE text with an explicit byte-order mark.

  Parameters
  ----------
  AFileName
    Test-owned destination file to replace.
  AContent
    Unicode text whose UTF-16 code units are written little-endian.

  Returns
  -------
  None

  Raises
  ------
  EFCreateError, EWriteError
    Propagated when the fixture cannot be created or completely written.
}
procedure WriteUTF16LEText(const AFileName: string;
  const AContent: UnicodeString);
var
  Stream: TFileStream;
  Bytes: array[0..1] of Byte;
  CodeUnit: Word;
  I: Integer;
begin
  ForceDirectories(ExtractFileDir(AFileName));
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    Bytes[0] := $FF;
    Bytes[1] := $FE;
    Stream.WriteBuffer(Bytes[0], Length(Bytes));
    for I := 1 to Length(AContent) do
    begin
      CodeUnit := Ord(AContent[I]);
      Bytes[0] := Byte(CodeUnit);
      Bytes[1] := Byte(CodeUnit shr 8);
      Stream.WriteBuffer(Bytes[0], Length(Bytes));
    end;
  finally
    Stream.Free;
  end;
end;

procedure WriteBytes(const AFileName: string; const ABytes: array of Byte);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(ABytes) > 0 then
      Stream.WriteBuffer(ABytes[0], Length(ABytes));
  finally
    Stream.Free;
  end;
end;

procedure SetUInt16LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: Word);
begin
  ABuffer[AOffset] := Byte(AValue);
  ABuffer[AOffset + 1] := Byte(AValue shr 8);
end;

procedure SetUInt32LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: UInt32);
begin
  ABuffer[AOffset] := Byte(AValue);
  ABuffer[AOffset + 1] := Byte(AValue shr 8);
  ABuffer[AOffset + 2] := Byte(AValue shr 16);
  ABuffer[AOffset + 3] := Byte(AValue shr 24);
end;

procedure SetUInt64LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: QWord);
begin
  SetUInt32LE(ABuffer, AOffset, UInt32(AValue));
  SetUInt32LE(ABuffer, AOffset + 4, UInt32(AValue shr 32));
end;

procedure SetBufferString(var ABuffer: array of Byte; AOffset: Integer;
  const AValue: RawByteString);
var
  I: Integer;
begin
  for I := 1 to Length(AValue) do
    ABuffer[AOffset + I - 1] := Byte(AValue[I]);
  ABuffer[AOffset + Length(AValue)] := 0;
end;

function FindComponent(AComponents: TObjectList; const AName: string):
  uModels.TComponent;
var
  I: Integer;
begin
  for I := 0 to AComponents.Count - 1 do
    if SameText(uModels.TComponent(AComponents[I]).Name, AName) then
      Exit(uModels.TComponent(AComponents[I]));
  Result := nil;
end;

{**
  Appends one deterministic component fixture to a task inventory.

  Parameters
  ----------
  ATask
    Task that receives ownership of the new component.
  AName, AVersion, AEcosystem, AComponentType
    Scalar fallback identity and version fields.
  APackageURL
    Optional strong Package URL identity.
  AScope
    Optional dependency scope copied into comparison rows.

  Returns
  -------
  TComponent
    Borrowed component owned by ATask.

  Raises
  ------
  EArgumentNilException
    Raised when ATask is nil.
  EOutOfMemory
    Propagated while allocating the component.
}
function AddComparisonComponent(ATask: TScanTask; const AName, AVersion,
  AEcosystem, AComponentType, APackageURL, AScope: string):
  uModels.TComponent;
begin
  if ATask = nil then
    raise EArgumentNilException.Create('ATask must not be nil');
  Result := uModels.TComponent.Create;
  try
    Result.Name := AName;
    Result.Version := AVersion;
    Result.Ecosystem := AEcosystem;
    Result.ComponentType := AComponentType;
    Result.PackageURL := APackageURL;
    Result.DependencyScope := AScope;
    Result.SourceArtifact := AName + '.fixture';
    Result.SourceParser := 'regression fixture';
    ATask.Components.Add(Result);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Locates one directional comparison row by kind, name, and versions.

  Parameters
  ----------
  AComparison
    Comparison result whose owned rows are searched.
  AKind
    Required change classification.
  AName
    Required component display name.
  ABeforeVersion, AAfterVersion
    Required directional version values.

  Returns
  -------
  TComponentChange
    Borrowed matching row, or nil when no row matches exactly.

  Raises
  ------
  None
}
function FindComparisonChange(AComparison: TComponentComparison;
  AKind: TComponentChangeKind; const AName, ABeforeVersion,
  AAfterVersion: string): TComponentChange;
var
  I: Integer;
  Change: TComponentChange;
begin
  Result := nil;
  if AComparison = nil then
    Exit;
  for I := 0 to AComparison.Changes.Count - 1 do
  begin
    Change := TComponentChange(AComparison.Changes[I]);
    if (Change.Kind = AKind) and (Change.Name = AName) and
      (Change.BeforeVersion = ABeforeVersion) and
      (Change.AfterVersion = AAfterVersion) then
      Exit(Change);
  end;
end;

{**
  Serializes comparison rows and warnings for deterministic-order assertions.

  Parameters
  ----------
  AComparison
    Comparison result to represent without modifying it.

  Returns
  -------
  string
    Stable scalar signature preserving result and warning order.

  Raises
  ------
  EArgumentNilException
    Raised when AComparison is nil.
  EOutOfMemory
    Propagated while constructing the signature.
}
function ComparisonSignature(AComparison: TComponentComparison): string;
var
  I: Integer;
  Change: TComponentChange;
begin
  if AComparison = nil then
    raise EArgumentNilException.Create('AComparison must not be nil');
  Result := Format('%d/%d/%d/%d', [AComparison.AddedCount,
    AComparison.RemovedCount, AComparison.VersionChangedCount,
    AComparison.UnchangedCount]);
  for I := 0 to AComparison.Changes.Count - 1 do
  begin
    Change := TComponentChange(AComparison.Changes[I]);
    Result := Result + LineEnding + Format('%d|%s|%s|%s|%s|%s|%s|%s',
      [Ord(Change.Kind), Change.RowKey, Change.IdentityKey, Change.Name,
      Change.Ecosystem, Change.ComponentType, Change.BeforeVersion,
      Change.AfterVersion]);
  end;
  for I := 0 to AComparison.Warnings.Count - 1 do
    Result := Result + LineEnding + 'warning|' + AComparison.Warnings[I];
end;

{**
  Creates one task with stable history fields for service regressions.

  Parameters
  ----------
  AID
    Explicit safe task identifier.
  ACreatedUTC
    Sortable UTC creation timestamp.
  AStatus
    Initial lifecycle state.
  ARootName
    Target-folder display name.

  Returns
  -------
  TScanTask
    Newly allocated caller-owned task.

  Raises
  ------
  EOutOfMemory
    Propagated while allocating the task and child collections.
}
function NewHistoryTask(const AID, ACreatedUTC: string;
  AStatus: TTaskStatus; const ARootName: string): TScanTask;
begin
  Result := TScanTask.Create;
  Result.ID := AID;
  Result.CreatedUTC := ACreatedUTC;
  Result.CompletedUTC := '2026-08-20T12:00:00.000Z';
  Result.TargetDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
    ARootName;
  Result.TargetRootName := ARootName;
  Result.Status := AStatus;
  Result.ScannerVersion := '0.5.0';
  Result.ScannerCommit := 'fixture-commit';
end;

{**
  Finds one artifact by its exact root-relative evidence path.

  Parameters
  ----------
  AArtifacts
    Artifact collection produced by the scan engine.
  ARelativePath
    Case-sensitive root-relative path to locate.

  Returns
  -------
  TArtifact
    Matching borrowed artifact, or nil when no exact path exists.

  Raises
  ------
  None
}
function FindArtifact(AArtifacts: TObjectList; const ARelativePath: string):
  TArtifact;
var
  I: Integer;
begin
  for I := 0 to AArtifacts.Count - 1 do
    if TArtifact(AArtifacts[I]).RelativePath = ARelativePath then
      Exit(TArtifact(AArtifacts[I]));
  Result := nil;
end;

{**
  Finds an object in a JSON array by one exact string member.

  Parameters
  ----------
  AArray
    Array whose object elements are searched; nil is accepted.
  AField
    Required string-member name.
  AValue
    Exact case-sensitive member value to match.

  Returns
  -------
  TJSONObject
    Borrowed matching object, or nil when no element matches.

  Raises
  ------
  None
}
function FindJSONObjectByString(AArray: TJSONArray; const AField,
  AValue: string): TJSONObject;
var
  I: Integer;
  Candidate: TJSONObject;
begin
  Result := nil;
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if AArray.Items[I].JSONType = jtObject then
    begin
      Candidate := TJSONObject(AArray.Items[I]);
      if JSONString(Candidate, AField) = AValue then
        Exit(Candidate);
    end;
end;

{**
  Tests whether a JSON array contains one exact string value.

  Parameters
  ----------
  AArray
    Array whose scalar strings are searched; nil is accepted.
  AValue
    Exact case-sensitive value to find.

  Returns
  -------
  Boolean
    True when AValue occurs as a string array element.

  Raises
  ------
  None
}
function JSONArrayContainsString(AArray: TJSONArray; const AValue: string):
  Boolean;
var
  I: Integer;
begin
  Result := False;
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if (AArray.Items[I].JSONType = jtString) and
      (AArray.Items[I].AsString = AValue) then
      Exit(True);
end;

{**
  Looks up one named CycloneDX property on a component object.

  Parameters
  ----------
  AComponent
    Component object containing an optional properties array.
  AName
    Exact property name.
  AValue
    Receives the property value when present.

  Returns
  -------
  Boolean
    True when the requested property exists.

  Raises
  ------
  None
}
function FindCycloneProperty(AComponent: TJSONObject; const AName: string;
  out AValue: string): Boolean;
var
  Item: TJSONObject;
begin
  AValue := '';
  Item := FindJSONObjectByString(JSONArray(AComponent, 'properties'), 'name',
    AName);
  Result := Item <> nil;
  if Result then
    AValue := JSONString(Item, 'value');
end;

{**
  Adds a fully described component to a synthetic scan task.

  Parameters
  ----------
  ATask
    Task that takes ownership of the component.
  AName, AVersion, AEcosystem, APURL
    Component identity and optional Package URL.
  ASourceArtifact, ASourceParser, AScope
    Root-relative provenance and dependency-scope evidence.
  AComponentType
    CycloneDX component type.

  Returns
  -------
  TComponent
    Borrowed component reference for additional test-specific setup.

  Raises
  ------
  EOutOfMemory
    Propagated when the component or evidence list cannot be allocated.
}
function AddFixtureComponent(ATask: TScanTask; const AName, AVersion,
  AEcosystem, APURL, ASourceArtifact, ASourceParser, AScope,
  AComponentType: string): uModels.TComponent;
begin
  Result := uModels.TComponent.Create;
  Result.Name := AName;
  Result.Version := AVersion;
  Result.Ecosystem := AEcosystem;
  Result.PackageURL := APURL;
  Result.SourceArtifact := ASourceArtifact;
  Result.SourceParser := ASourceParser;
  Result.DependencyScope := AScope;
  Result.ComponentType := AComponentType;
  if ASourceArtifact <> '' then
    Result.EvidencePaths.Add(ASourceArtifact);
  ATask.Components.Add(Result);
end;

{**
  Searches a string collection for a case-insensitive diagnostic fragment.

  Parameters
  ----------
  AStrings
    Collection of warnings or errors to search.
  AText
    Required diagnostic fragment.

  Returns
  -------
  Boolean
    True when any entry contains AText, ignoring ASCII letter case.

  Raises
  ------
  None
}
function StringListContainsText(AStrings: TStrings; const AText: string):
  Boolean;
var
  I: Integer;
  SearchText: string;
begin
  Result := False;
  SearchText := LowerCase(AText);
  for I := 0 to AStrings.Count - 1 do
    if Pos(SearchText, LowerCase(AStrings[I])) > 0 then
      Exit(True);
end;

{**
  Parses one named fixture through the production manifest dispatcher.

  Parameters
  ----------
  AName
    Fixture filename relative to the test fixture directory.
  AKind
    Parser kind to exercise.
  AComponents
    Owned list receiving parsed components.
  AArtifact
    Newly allocated artifact record returned to the caller.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated when the artifact cannot be allocated.
}
procedure ParseFixture(const AName: string; AKind: TParserKind;
  AComponents: TObjectList; out AArtifact: TArtifact);
begin
  AArtifact := TArtifact.Create;
  ParseArtifact(Fixture(AName), AName, AKind, AArtifact, AComponents);
end;

procedure TestSHA256;
begin
  AssertEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    SHA256String(''), 'SHA-256 empty vector differs');
  AssertEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    SHA256String('abc'), 'SHA-256 abc vector differs');
end;

{**
  Verifies that the UI exposes the exact embedded product version.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when VERSION, the compiled UI value, Lazarus file/product resource
    metadata, or the operator-only CI generation order diverges.
}
procedure TestDisplayedVersion;
var
  VersionLines, VersionParts, ProjectLines, WorkflowLines: TStringList;
  VersionValue, ProjectText, WorkflowText: string;
  PartIndex, CharacterIndex, PartValue, CheckPosition, WritePosition: Integer;
begin
  VersionLines := TStringList.Create;
  VersionParts := TStringList.Create;
  ProjectLines := TStringList.Create;
  WorkflowLines := TStringList.Create;
  try
    VersionLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'VERSION');
    AssertEqual(1, VersionLines.Count,
      'VERSION should contain exactly one line');
    VersionValue := VersionLines[0];
    AssertEqual(Trim(VersionValue), VersionValue,
      'VERSION should not contain surrounding whitespace');
    AssertEqual(VersionValue, AppVersion,
      'compiled product version differs from VERSION');
    AssertEqual(AppVersion, DisplayVersion,
      'displayed version differs from the embedded product version');

    VersionParts.Delimiter := '.';
    VersionParts.StrictDelimiter := True;
    VersionParts.DelimitedText := VersionValue;
    AssertEqual(3, VersionParts.Count,
      'VERSION should contain three numeric components');
    for PartIndex := 0 to VersionParts.Count - 1 do
    begin
      AssertTrue(VersionParts[PartIndex] <> '',
        'VERSION components should not be empty');
      AssertTrue((Length(VersionParts[PartIndex]) = 1) or
        (VersionParts[PartIndex][1] <> '0'),
        'VERSION components should not contain leading zeros');
      for CharacterIndex := 1 to Length(VersionParts[PartIndex]) do
        AssertTrue(VersionParts[PartIndex][CharacterIndex] in ['0'..'9'],
          'VERSION components should contain decimal digits only');
      AssertTrue(TryStrToInt(VersionParts[PartIndex], PartValue),
        'VERSION component should fit a native integer');
      AssertTrue(PartValue <= 65535,
        'VERSION component exceeds the Windows resource range');
    end;
    ProjectLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpi');
    ProjectText := ProjectLines.Text;
    AssertTrue(Pos('<UseVersionInfo Value="True"/>', ProjectText) > 0,
      'Lazarus version resources should be enabled');
    AssertTrue(Pos('<MajorVersionNr Value="' + VersionParts[0] + '"/>',
      ProjectText) > 0, 'Lazarus major file version differs from VERSION');
    AssertTrue(Pos('<MinorVersionNr Value="' + VersionParts[1] + '"/>',
      ProjectText) > 0, 'Lazarus minor file version differs from VERSION');
    AssertTrue(Pos('<RevisionNr Value="' + VersionParts[2] + '"/>',
      ProjectText) > 0, 'Lazarus revision file version differs from VERSION');
    AssertTrue(Pos('<BuildNr Value="0"/>', ProjectText) > 0,
      'Lazarus file-version build number should be zero');
    AssertTrue(Pos('FileVersion="' + VersionValue + '.0"', ProjectText) > 0,
      'Lazarus string file version differs from VERSION');
    AssertTrue(Pos('ProductVersion="' + VersionValue + '"', ProjectText) > 0,
      'Lazarus product version differs from VERSION');
    WorkflowLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      '.github' + DirectorySeparator + 'workflows' + DirectorySeparator +
      'build-release.yml');
    WorkflowText := WorkflowLines.Text;
    WritePosition := Pos('scripts/write-version.sh', WorkflowText);
    CheckPosition := Pos('scripts/check-version.sh', WorkflowText);
    AssertEqual(0, CheckPosition,
      'CI again requires the optional local fallback checker');
    AssertTrue(WritePosition > 0,
      'CI version generation step is missing');
    AssertTrue(WritePosition < Pos('scripts/run-tests.sh', WorkflowText),
      'CI must generate version metadata before compiling tests');
  finally
    WorkflowLines.Free;
    ProjectLines.Free;
    VersionParts.Free;
    VersionLines.Free;
  end;
end;

{**
  Verifies Sprint 6 command parsing, explicit settings, output containment,
  shared scan/export behavior, and the pre-widgetset application boundary.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when CLI argument policy, safe settings loading, output-path
    validation, shared CycloneDX generation, or early LCL dispatch regresses.
}
procedure TestHeadlessCommandLine;
var
  Arguments: TCommandArgumentArray;
  CommandSourceLines, ProgramLines, WorkerLines: TStringList;
  CommandSource, ProgramText, WorkerText: string;
  Data: TJSONData;
  Digest, ErrorText, ManagedOutputDirectory, ManagedOutputFileName,
    OutputDirectory, OutputFileName, SettingsFileName, TargetDirectory,
    WrappedSettingsFileName: string;
  InvalidRaised: Boolean;
  Options: TCommandLineOptions;
  OutputStream: TFileStream;
  Settings: TScanSettings;
  Task: TScanTask;
  {$IFDEF UNIX}
  LegacyTemporaryLink, VictimFileName: string;
  {$ENDIF}
begin
  SetLength(Arguments, 0);
  AssertTrue(ParseCommandLineArguments(Arguments, Options, ErrorText),
    'empty arguments should select the desktop application');
  AssertTrue(Options.Mode = clmGUI,
    'empty arguments selected a non-GUI mode');
  AssertEqual('', ErrorText,
    'empty arguments returned an unexpected diagnostic');

  AssertTrue(ParseCommandLineArguments(['--help'], Options, ErrorText),
    '--help was rejected');
  AssertTrue(Options.Mode = clmHelp, '--help selected the wrong mode');
  AssertTrue(ParseCommandLineArguments(['-h'], Options, ErrorText),
    '-h was rejected');
  AssertTrue(Options.Mode = clmHelp, '-h selected the wrong mode');
  AssertTrue(ParseCommandLineArguments(['--version'], Options, ErrorText),
    '--version was rejected');
  AssertTrue(Options.Mode = clmVersion,
    '--version selected the wrong mode');

  AssertTrue(ParseCommandLineArguments([
    '--output', 'outside.cdx.json', '--settings', 'settings.json',
    '--scan', 'target'], Options, ErrorText),
    'complete headless arguments were rejected');
  AssertTrue(Options.Mode = clmScan,
    'complete headless arguments selected the wrong mode');
  AssertEqual('target', Options.ScanDirectory,
    'headless target argument differs');
  AssertEqual('outside.cdx.json', Options.OutputFileName,
    'headless output argument differs');
  AssertEqual('settings.json', Options.SettingsFileName,
    'headless settings argument differs');

  AssertTrue(not ParseCommandLineArguments(['--scan', 'target'], Options,
    ErrorText), 'missing --output was accepted');
  AssertTrue(Pos('--output', ErrorText) > 0,
    'missing-output diagnostic is not actionable');
  AssertTrue(not ParseCommandLineArguments(['--help', '--version'], Options,
    ErrorText), 'combined informational modes were accepted');
  AssertTrue(not ParseCommandLineArguments([
    '--scan', 'one', '--scan', 'two', '--output', 'outside.json'], Options,
    ErrorText), 'duplicate --scan was accepted');
  AssertTrue(not ParseCommandLineArguments(['--unknown'], Options,
    ErrorText), 'an unknown CLI option was accepted');

  SettingsFileName := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'cli-direct-settings.json';
  WriteText(SettingsFileName,
    '{"include_absolute_paths":true,"follow_symbolic_links":true,' +
    '"allow_outside_root":true,"calculate_sha256":false,' +
    '"remember_privacy_choices":false,' +
    '"sbom_author_organization":"CLI Fixture",' +
    '"sbom_author_email":"cli@example.invalid",' +
    '"ignore_patterns":["cache","*.tmp"]}');
  Settings := LoadCommandLineSettings(SettingsFileName);
  try
    AssertTrue(Settings.IncludeAbsolutePaths,
      'direct CLI settings lost include-absolute-paths');
    AssertTrue(Settings.FollowSymbolicLinks,
      'direct CLI settings lost follow-links');
    AssertTrue(Settings.AllowOutsideRoot,
      'direct CLI settings lost allow-outside-root');
    AssertTrue(not Settings.CalculateSHA256,
      'direct CLI settings lost calculate-SHA choice');
    AssertEqual('CLI Fixture', Settings.SBOMAuthorOrganization,
      'direct CLI author organization differs');
    AssertEqual('cli@example.invalid', Settings.SBOMAuthorEmail,
      'direct CLI author email differs');
    AssertEqual(2, Settings.IgnorePatterns.Count,
      'direct CLI ignore patterns differ');
  finally
    Settings.Free;
  end;

  WrappedSettingsFileName := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'cli-wrapped-settings.json';
  WriteText(WrappedSettingsFileName,
    '{"format_version":1,"scan_settings":{' +
    '"include_absolute_paths":false,"follow_symbolic_links":false,' +
    '"allow_outside_root":false,"calculate_sha256":true,' +
    '"ignore_patterns":["vendor"]}}');
  Settings := LoadCommandLineSettings(WrappedSettingsFileName);
  try
    AssertTrue(Settings.CalculateSHA256,
      'wrapped CLI settings lost calculate-SHA choice');
    AssertEqual(1, Settings.IgnorePatterns.Count,
      'wrapped CLI ignore patterns differ');
    AssertEqual('vendor', Settings.IgnorePatterns[0],
      'wrapped CLI ignore pattern differs');
  finally
    Settings.Free;
  end;

  WriteText(SettingsFileName, '{"calculate_sha256":"yes"}');
  InvalidRaised := False;
  try
    Settings := LoadCommandLineSettings(SettingsFileName);
    Settings.Free;
  except
    on E: Exception do
      InvalidRaised := True;
  end;
  AssertTrue(InvalidRaised,
    'CLI settings accepted a string in a Boolean field');

  TargetDirectory := NewTemporaryDirectory('headless-target');
  OutputDirectory := NewTemporaryDirectory('headless-output');
  OutputFileName := IncludeTrailingPathDelimiter(OutputDirectory) +
    'fixture.cdx.json';
  WriteText(IncludeTrailingPathDelimiter(TargetDirectory) + 'package.json',
    '{"name":"headless-fixture","version":"1.2.3",' +
    '"dependencies":{"left-pad":"1.3.0"}}');
  AssertEqual(ExpandFileName(OutputFileName),
    ResolveScanOutputFileName(TargetDirectory, OutputFileName),
    'safe headless output resolution differs');

  InvalidRaised := False;
  try
    ResolveScanOutputFileName(TargetDirectory,
      IncludeTrailingPathDelimiter(TargetDirectory) + 'inside.cdx.json');
  except
    on E: Exception do
      InvalidRaised := True;
  end;
  AssertTrue(InvalidRaised,
    'headless output inside the scan target was accepted');

  InvalidRaised := False;
  try
    ResolveScanOutputFileName(TargetDirectory,
      IncludeTrailingPathDelimiter(OutputDirectory) + 'missing' +
      DirectorySeparator + 'result.cdx.json');
  except
    on E: Exception do
      InvalidRaised := True;
  end;
  AssertTrue(InvalidRaised,
    'headless output with a missing parent was accepted');

  WriteText(OutputFileName, 'stale output that must be atomically replaced');
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := TargetDirectory;
    Task.TargetRootName := 'headless-target';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(ExecuteScanToFile(Task, OutputFileName, nil, nil),
      'shared headless scan/export service failed');
    AssertTrue(Task.Status = tsCompleted,
      'shared headless scan did not complete');
    AssertEqual(ExpandFileName(OutputFileName), Task.GeneratedSBOMPath,
      'shared headless output path differs');
    AssertTrue(FileExists(OutputFileName),
      'shared headless output was not created');
    AssertTrue(SHA256File(OutputFileName, Digest, nil, nil),
      'shared headless output could not be hashed');
    AssertEqual(Digest, Task.GeneratedSBOMSHA256,
      'shared headless output digest differs');
    AssertTrue(FindComponent(Task.Components, 'left-pad') <> nil,
      'shared headless scan omitted a manifest component');
    OutputStream := TFileStream.Create(OutputFileName,
      fmOpenRead or fmShareDenyNone);
    try
      Data := GetJSON(OutputStream);
      try
        AssertTrue(Data.JSONType = jtObject,
          'shared headless output is not a JSON object');
        AssertEqual('CycloneDX', JSONString(TJSONObject(Data), 'bomFormat'),
          'shared headless output is not CycloneDX');
      finally
        Data.Free;
      end;
    finally
      OutputStream.Free;
    end;
  finally
    Task.Free;
  end;

  {$IFDEF UNIX}
  LegacyTemporaryLink := OutputFileName + '.tmp';
  VictimFileName := IncludeTrailingPathDelimiter(OutputDirectory) +
    'atomic-symlink-victim.cdx.json';
  AssertTrue(fpSymlink(PChar(VictimFileName),
    PChar(LegacyTemporaryLink)) = 0,
    'unable to create the dangling atomic-output symlink fixture');
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := TargetDirectory;
    Task.TargetRootName := 'headless-target';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(ExecuteScanToFile(Task, OutputFileName, nil, nil),
      'atomic output failed in the presence of an unrelated stale temp link');
    AssertTrue(not FileExists(VictimFileName),
      'atomic output followed a dangling temporary-file symlink');
    AssertTrue(not CleanupEntryIsLink(OutputFileName),
      'atomic output activated a temporary-file symlink as its destination');
    AssertTrue(CleanupEntryIsLink(LegacyTemporaryLink),
      'atomic output unexpectedly consumed the pre-planted stale symlink');
  finally
    Task.Free;
  end;

  {$ENDIF}

  ManagedOutputDirectory := IncludeTrailingPathDelimiter(TargetDirectory) +
    'managed-data' + DirectorySeparator + 'sboms';
  AssertTrue(ForceDirectories(ManagedOutputDirectory),
    'unable to create the managed-output regression directory');
  ManagedOutputFileName := IncludeTrailingPathDelimiter(
    ManagedOutputDirectory) + 'managed.cdx.json';
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := TargetDirectory;
    Task.TargetRootName := 'headless-target';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(ExecuteScanToFile(Task, ManagedOutputFileName, nil, nil,
      sopManagedApplicationData),
      'GUI-managed SBOM output below the selected target was rejected');
    AssertTrue(FileExists(ManagedOutputFileName),
      'GUI-managed SBOM output was not created below the selected target');
  finally
    Task.Free;
  end;

  CommandSourceLines := TStringList.Create;
  ProgramLines := TStringList.Create;
  WorkerLines := TStringList.Create;
  try
    CommandSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uCommandLine.pas');
    ProgramLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpr');
    WorkerLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanWorker.pas');
    CommandSource := CommandSourceLines.Text;
    ProgramText := ProgramLines.Text;
    WorkerText := WorkerLines.Text;
    AssertTrue(Pos('uCommandLine, Interfaces', ProgramText) > 0,
      'the CLI unit no longer initializes before the widgetset');
    AssertTrue(Pos('initialization' + LineEnding +
      '  DispatchEarlyCommandLine;', CommandSource) > 0,
      'CLI dispatch no longer occurs during early unit initialization');
    AssertTrue(Pos('CommandLineToArgvW', CommandSource) > 0,
      'native Windows Unicode argument collection is missing');
    AssertTrue(Pos('Bytes := UTF8String(AText)', CommandSource) > 0,
      'Unix command-line output can again double-encode UTF-8 text');
    AssertTrue(Pos('ExecuteScanToFile(FTask', WorkerText) > 0,
      'the GUI worker no longer shares the headless scan/export service');
    AssertTrue(Pos('sopManagedApplicationData', WorkerText) > 0,
      'the GUI worker regained the CLI output-containment restriction');
    AssertTrue((Pos('GenerateCycloneDX(', WorkerText) = 0) and
      (Pos('WriteAtomicUTF8(', WorkerText) = 0),
      'the GUI worker regained a duplicate SBOM implementation');
  finally
    WorkerLines.Free;
    ProgramLines.Free;
    CommandSourceLines.Free;
  end;
end;

{**
  Verifies that strict CLI output activation cannot follow a rebound parent.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a replacement directory or a symlink back to a moved pinned
    directory receives output after the scan has started, or when Windows
    permits a pinned directory or one of its ancestors to be renamed.
  ETestSkipped
    Raised on hosts other than Unix and Windows.
}
procedure TestStrictOutputParentPinning;
{$IFDEF UNIX}
var
  TargetDirectory: string;

  {**
    Runs one output-parent rebind shape against the shared scan service.

    Parameters
    ----------
    ALabel
      Unique fixture suffix and diagnostic label.
    ALinkBackToPinnedDirectory
      Selects a different replacement directory or a symlink back to the
      original pinned object after that object is moved.

    Returns
    -------
    None

    Raises
    ------
    Exception
      Raised when fixture setup fails or output reaches either path.
  }
  procedure RunRebindAttack(const ALabel: string;
    ALinkBackToPinnedDirectory: Boolean);
  var
    Controller: TOutputParentRebindController;
    MovedDirectory, OutputDirectory, OutputFileName, MovedOutputFileName:
      string;
    Task: TScanTask;
  begin
    OutputDirectory := NewTemporaryDirectory('strict-output-rebind-' + ALabel);
    MovedDirectory := OutputDirectory + '-moved';
    OutputFileName := IncludeTrailingPathDelimiter(OutputDirectory) +
      'must-not-exist.cdx.json';
    MovedOutputFileName := IncludeTrailingPathDelimiter(MovedDirectory) +
      ExtractFileName(OutputFileName);
    Controller := TOutputParentRebindController.Create(OutputDirectory,
      MovedDirectory, ALinkBackToPinnedDirectory);
    Task := TScanTask.Create;
    try
      Task.TargetDirectory := TargetDirectory;
      Task.TargetRootName := 'strict-output-parent-pin';
      Task.Settings.CalculateSHA256 := False;
      AssertTrue(not ExecuteScanToFile(Task, OutputFileName,
        @Controller.Check, nil),
        ALabel + ': strict output accepted a rebound parent during scanning');
      AssertTrue(Controller.Triggered,
        ALabel + ': output-parent rebind fixture was not triggered');
      AssertTrue(Controller.Succeeded,
        ALabel + ': output-parent rebind fixture failed: ' +
        Controller.ErrorText);
      AssertTrue(Task.Status = tsFailed,
        ALabel + ': output-parent rebind did not fail the task');
      AssertTrue(Pos('rebound', Task.Errors.Text) > 0,
        ALabel + ': failure did not explain the rejected directory identity');
      AssertEqual('', Task.GeneratedSBOMPath,
        ALabel + ': failed task retained a generated output path');
      AssertTrue(not FileExists(OutputFileName),
        ALabel + ': output was diverted through the replacement pathname');
      AssertTrue(not FileExists(MovedOutputFileName),
        ALabel + ': failed output remained in the pinned directory');
    finally
      Task.Free;
      Controller.Free;
    end;
  end;
{$ENDIF}
{$IFDEF Windows}
var
  GuardChildDirectory, GuardMovedDirectory, GuardOutputFileName,
    GuardParentDirectory: string;
  DirectoryPin: TPinnedDirectory;
{$ENDIF}
begin
  {$IFDEF UNIX}
  TargetDirectory := NewTemporaryDirectory('strict-output-pin-target');
  WriteText(IncludeTrailingPathDelimiter(TargetDirectory) + 'package.json',
    '{"name":"strict-output-pin","version":"1.0.0"}');
  RunRebindAttack('replacement', False);
  RunRebindAttack('moved-link-back', True);
  {$ELSE}
  {$IFDEF Windows}
  GuardParentDirectory := NewTemporaryDirectory('strict-output-win-guard');
  GuardChildDirectory := IncludeTrailingPathDelimiter(GuardParentDirectory) +
    'child';
  GuardMovedDirectory := GuardParentDirectory + '-moved';
  GuardOutputFileName := IncludeTrailingPathDelimiter(GuardChildDirectory) +
    'guarded-output.cdx.json';
  AssertTrue(ForceDirectories(GuardChildDirectory),
    'unable to create the Windows pin-guard fixture');
  DirectoryPin := PinExistingDirectory(GuardChildDirectory);
  try
    AssertTrue(not RenameFile(GuardParentDirectory, GuardMovedDirectory),
      'Windows allowed a guarded output ancestor to be rebound');
    WriteAtomicUTF8ToPinnedDirectory(DirectoryPin,
      ExtractFileName(GuardOutputFileName), UTF8String('{"guarded":true}'));
    AssertTrue(FileExists(GuardOutputFileName),
      'Windows pin could not activate output in the guarded directory');
  finally
    DirectoryPin.Free;
  end;
  AssertTrue(RenameFile(GuardParentDirectory, GuardMovedDirectory),
    'Windows ancestor guard was not released with the directory pin');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(GuardMovedDirectory) +
    'child' + DirectorySeparator + ExtractFileName(GuardOutputFileName)),
    'Windows guarded output did not remain in the pinned directory object');
  {$ELSE}
  raise ETestSkipped.Create('requires Unix or Windows directory-pin support');
  {$ENDIF}
  {$ENDIF}
end;

{**
  Verifies the Sprint 6 release, launcher, packaging, and onboarding contracts.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when active release assets lose notices, native CLI gates disappear,
    launchers regress to unpinned/unverified downloads, package-manager
    metadata becomes incomplete, or documentation revives an unshipped target.
}
procedure TestSprint6DistributionContracts;
var
  Lines: TStringList;
  WorkflowText, ReadmeText, LinuxLauncherText, WSLLauncherText,
    WindowsLauncherText, LinuxPackageText, WindowsPackageText, ScoopText,
    WingetInstallerText, PackageValidatorText: string;
  InstallPosition, LauncherPosition, DevelopmentPosition: SizeInt;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + '.github' +
      DirectorySeparator + 'workflows' + DirectorySeparator +
      'build-release.yml');
    WorkflowText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'README.md');
    ReadmeText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'start-linux.sh');
    LinuxLauncherText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'start-wsl2.sh');
    WSLLauncherText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'start-windows.ps1');
    WindowsLauncherText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'scripts' +
      DirectorySeparator + 'package-linux.sh');
    LinuxPackageText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'scripts' +
      DirectorySeparator + 'package-windows.ps1');
    WindowsPackageText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'packaging' +
      DirectorySeparator + 'scoop' + DirectorySeparator +
      'purpleray-sbom-analyzer.json.in');
    ScoopText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'packaging' +
      DirectorySeparator + 'winget' + DirectorySeparator +
      'AndreiIonutDamian.PurpleRaySBOMAnalyzer.installer.yaml.in');
    WingetInstallerText := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'scripts' +
      DirectorySeparator + 'validate-package-manifests.py');
    PackageValidatorText := Lines.Text;

    AssertTrue(Pos('cancel-in-progress: ${{ github.event_name == ' +
      '''pull_request'' }}', WorkflowText) > 0,
      'release workflow can again cancel main or manual release runs');
    AssertTrue(Pos('Verify native Linux command line without a display',
      WorkflowText) > 0,
      'release workflow lacks a native displayless Linux CLI gate');
    AssertTrue(Pos('Verify native Windows command line with redirected streams',
      WorkflowText) > 0,
      'release workflow lacks a native redirected Windows CLI gate');
    AssertTrue(Pos('required=("$windows" "$linux" "$debian" "$scoop" ' +
      '"$winget")', WorkflowText) > 0,
      'release workflow does not require the complete active asset set');
    AssertTrue(Pos('expected_windows=(LICENSE NOTICE ' +
      'purpleray-sbom-analyzer.exe)', WorkflowText) > 0,
      'release workflow no longer enforces Windows notices');
    AssertTrue((Pos('$linux_root/LICENSE', WorkflowText) > 0) and
      (Pos('$linux_root/NOTICE', WorkflowText) > 0),
      'release workflow no longer enforces Linux notices');
    AssertTrue(Pos('& $tool update $identifier --urls $installerUrl',
      WorkflowText) > 0,
      'credential-gated WinGet automation does not update the accepted package');
    AssertTrue(Pos('& $tool submit', WorkflowText) = 0,
      'workflow uses WingetCreate submit as though it accepted manifest files');
    AssertTrue((Pos('Validate package manifests against pinned official schemas',
      WorkflowText) > 0) and
      (Pos('scripts/validate-package-manifests.py --self-test', WorkflowText) > 0) and
      (Pos('python3-jsonschema python3-yaml', WorkflowText) > 0),
      'release workflow no longer applies the official package schemas');
    AssertTrue((Pos('SCOOP_COMMIT =', PackageValidatorText) > 0) and
      (Pos('WINGET_COMMIT =', PackageValidatorText) > 0) and
      (Pos('download_verified_schema', PackageValidatorText) > 0),
      'package validator no longer pins and verifies official schemas');

    AssertTrue((Pos('tar.gz', LinuxPackageText) > 0) and
      (Pos('dpkg-deb', LinuxPackageText) > 0),
      'Linux packaging no longer builds both portable and Debian outputs');
    AssertTrue((Pos('readelf --version-info', LinuxPackageText) > 0) and
      (Pos('GLIBC_2.34', LinuxPackageText) > 0),
      'Linux packaging no longer verifies its published GLIBC compatibility floor');
    AssertTrue((Pos('LICENSE', LinuxPackageText) > 0) and
      (Pos('NOTICE', LinuxPackageText) > 0),
      'Linux packaging omitted required notices');
    AssertTrue((Pos('LICENSE', WindowsPackageText) > 0) and
      (Pos('NOTICE', WindowsPackageText) > 0),
      'Windows packaging omitted required notices');
    AssertTrue((Pos('"checkver": "github"', ScoopText) > 0) and
      (Pos('SHA256SUMS.txt', ScoopText) > 0) and
      (Pos('$version', ScoopText) > 0),
      'Scoop metadata lacks GitHub autoupdate or checksum discovery');
    AssertTrue((Pos('NestedInstallerType: portable', WingetInstallerText) > 0)
      and (Pos('PortableCommandAlias: purpleray-sbom-analyzer',
      WingetInstallerText) > 0),
      'WinGet metadata is no longer a portable command package');

    AssertTrue((Pos('--release-version', LinuxLauncherText) > 0) and
      (Pos('PURPLERAY_VERSION', LinuxLauncherText) > 0) and
      (Pos('gh attestation verify', LinuxLauncherText) > 0) and
      (Pos('glibc 2.34', LinuxLauncherText) > 0) and
      (Pos('install_desktop_files', LinuxLauncherText) > 0),
      'native Linux launcher lost pinning, provenance, preflight, or desktop integration');
    AssertTrue((Pos('--release-version', WSLLauncherText) > 0) and
      (Pos('PURPLERAY_VERSION', WSLLauncherText) > 0) and
      (Pos('gh attestation verify', WSLLauncherText) > 0) and
      (Pos('WSLg is unavailable', WSLLauncherText) > 0),
      'WSL2 launcher lost pinning, provenance, or UI preflight');
    AssertTrue((Pos('$ProgressPreference = ''SilentlyContinue''',
      WindowsLauncherText) > 0) and
      (Pos('PURPLERAY_VERSION', WindowsLauncherText) > 0) and
      (Pos('gh attestation verify', WindowsLauncherText) > 0) and
      (Pos('/releases/latest', WindowsLauncherText) > 0) and
      (Pos('api.github.com', WindowsLauncherText) = 0) and
      (Pos('Smart App Control', WindowsLauncherText) > 0),
      'Windows launcher lost lifecycle, provenance, endpoint, or SAC safeguards');

    InstallPosition := Pos('## Install / quick start', ReadmeText);
    LauncherPosition := Pos('### One-line launchers', ReadmeText);
    DevelopmentPosition := Pos('## Development', ReadmeText);
    AssertTrue((InstallPosition > 0) and (LauncherPosition > InstallPosition)
      and (DevelopmentPosition > LauncherPosition),
      'README no longer leads users from manual install to launchers before development');
    AssertTrue(Pos('### First SBOM in 60 seconds', ReadmeText) > 0,
      'README lost the three-step first-SBOM walkthrough');
    AssertTrue(Pos('macOS has no current release, launcher, or support claim',
      ReadmeText) > 0,
      'README revived a shipped macOS support claim');
    AssertTrue(Pos('### Headless command line', ReadmeText) > 0,
      'README does not document the headless CLI');
    AssertTrue(Pos('scoop install .\purpleray-sbom-analyzer.json',
      ReadmeText) > 0,
      'README does not explain how to consume the shipped Scoop manifest');
    AssertTrue((Pos('WINGET_SUBMISSION_ENABLED', ReadmeText) > 0) and
      (Pos('WINGET_CREATE_GITHUB_TOKEN', ReadmeText) > 0),
      'README does not document the credential-gated WinGet setup');
    AssertTrue(FileExists(IncludeTrailingPathDelimiter(ProjectRoot) + 'docs' +
      DirectorySeparator + 'purpleray-sbom-analyzer.png'),
      'privacy-safe main-window screenshot is missing');
  finally
    Lines.Free;
  end;
end;

{**
  Verifies the two-feature shell and shared-history ownership boundary.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when the shell regains scan-domain responsibilities, either feature
    is auto-created, shared history gains a second owner, shortcut routing
    diverges, or an LFM/LPI declaration no longer matches the compiled shell.
}
procedure TestApplicationShellStructure;
var
  ShellSourceLines, ShellResourceLines, AnalyzerSourceLines,
    AnalyzerResourceLines, CompareSourceLines, CompareResourceLines,
    ProjectLines, ProgramLines: TStringList;
  ShellSource, ShellResource, AnalyzerSource, AnalyzerResource, CompareSource,
    CompareResource, ProjectText, ProgramText, InitializeBlock,
    CreateFeaturesBlock,
    HistoryChangedBlock, KeyBlock, DestroyBlock: string;
  LineIndex, PageCount: Integer;
begin
  ShellSourceLines := TStringList.Create;
  ShellResourceLines := TStringList.Create;
  AnalyzerSourceLines := TStringList.Create;
  AnalyzerResourceLines := TStringList.Create;
  CompareSourceLines := TStringList.Create;
  CompareResourceLines := TStringList.Create;
  ProjectLines := TStringList.Create;
  ProgramLines := TStringList.Create;
  try
    ShellSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uMainForm.pas');
    ShellResourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uMainForm.lfm');
    AnalyzerSourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uSBOMAnalyzerFrame.pas');
    AnalyzerResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uSBOMAnalyzerFrame.lfm');
    CompareSourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uCompareScansFrame.pas');
    CompareResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uCompareScansFrame.lfm');
    ProjectLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpi');
    ProgramLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpr');
    ShellSource := ShellSourceLines.Text;
    ShellResource := ShellResourceLines.Text;
    AnalyzerSource := AnalyzerSourceLines.Text;
    AnalyzerResource := AnalyzerResourceLines.Text;
    CompareSource := CompareSourceLines.Text;
    CompareResource := CompareResourceLines.Text;
    ProjectText := ProjectLines.Text;
    ProgramText := ProgramLines.Text;
    InitializeBlock := ExtractTextSection(ShellSource,
      'procedure TMainForm.InitializeShell',
      'destructor TMainForm.Destroy;');
    CreateFeaturesBlock := ExtractTextSection(ShellSource,
      'procedure TMainForm.CreateFeatureFrames;',
      'procedure TMainForm.SelectFeature');
    HistoryChangedBlock := ExtractTextSection(ShellSource,
      'procedure TMainForm.HistoryChanged',
      'function TMainForm.PrimaryShortcut');
    KeyBlock := ExtractTextSection(ShellSource,
      'procedure TMainForm.FormKeyPressed',
      'procedure TMainForm.FeatureSelectionChanged');
    DestroyBlock := ExtractTextSection(ShellSource,
      'destructor TMainForm.Destroy;',
      'procedure TMainForm.CreateFeatureFrames;');

    AssertTrue(Pos('TMainForm = class(TForm)', ShellSource) > 0,
      'the application shell is not the main form');
    AssertTrue(Pos('uSBOMAnalyzerFrame', ShellSource) > 0,
      'the shell does not import the Analyzer feature frame');
    AssertTrue(Pos('uCompareScansFrame', ShellSource) > 0,
      'the shell does not import the Compare Scans feature frame');
    AssertTrue(Pos('uTaskHistory', ShellSource) > 0,
      'the shell does not own shared task history');
    AssertEqual(1, CountTextOccurrences(ShellSource,
      'TTaskHistoryService.Create(ADataDirectory)'),
      'the shell must create exactly one shared task-history service');
    AssertTrue(Pos('FHistoryService.OnChanged := @HistoryChanged',
      ShellSource) > 0, 'the shell does not subscribe to shared history');
    AssertTrue((InitializeBlock <> '') and
      (Pos('SelectFeature(', InitializeBlock) = 0) and
      (Pos('procedure TMainForm.FormShown', ShellSource) <
      Pos('SelectFeature(FeatureSelector.ItemIndex)', ShellSource)),
      'feature activation can move focus before the shell is shown');
    AssertTrue(Pos('TSBOMAnalyzerFrame.CreateWithHistoryService(AnalyzerPage,',
      CreateFeaturesBlock) > 0,
      'the shell does not inject shared history into Analyzer');
    AssertTrue(Pos('TCompareScansFrame.CreateWithHistoryService(ComparePage,',
      CreateFeaturesBlock) > 0,
      'the shell does not inject shared history into Compare Scans');
    AssertTrue(Pos('FAnalyzerFrame.Parent := AnalyzerPage', ShellSource) > 0,
      'the Analyzer frame is not parented to its notebook page');
    AssertTrue(Pos('FCompareFrame.Parent := ComparePage', ShellSource) > 0,
      'the Compare Scans frame is not parented to its notebook page');
    AssertTrue(Pos('uModels', ShellSource) = 0,
      'the shell imports task-model responsibilities');
    AssertTrue(Pos('uSettingsStore', ShellSource) = 0,
      'the shell imports settings-store responsibilities');
    AssertTrue(Pos('uScanWorker', ShellSource) = 0,
      'the shell imports scan-worker responsibilities');
    AssertTrue(Pos('uScanEngine', ShellSource) = 0,
      'the shell imports scan-engine responsibilities');
    AssertTrue(Pos('uExportUtils', ShellSource) = 0,
      'the shell imports export responsibilities');
    AssertTrue((Pos('FAnalyzerFrame.HistoryChanged(', HistoryChangedBlock) > 0)
      and (Pos('FCompareFrame.HistoryChanged(', HistoryChangedBlock) > 0),
      'the shell does not fan shared-history changes to both features');
    AssertTrue((Pos('VK_1', KeyBlock) > 0) and
      (Pos('SelectFeature(0)', KeyBlock) > 0) and
      (Pos('VK_2', KeyBlock) > 0) and
      (Pos('SelectFeature(1)', KeyBlock) > 0),
      'feature keyboard navigation is incomplete');
    AssertTrue((Pos('FActiveFeatureIndex = 0', KeyBlock) > 0) and
      (Pos('FAnalyzerFrame.HandleShortcut', KeyBlock) > 0) and
      (Pos('FActiveFeatureIndex = 1', KeyBlock) > 0) and
      (Pos('FCompareFrame.HandleShortcut', KeyBlock) > 0),
      'active-feature shortcut routing is incomplete');
    AssertTrue((Pos('FreeAndNil(FCompareFrame)', DestroyBlock) > 0) and
      (Pos('FreeAndNil(FAnalyzerFrame)', DestroyBlock) > 0) and
      (Pos('FreeAndNil(FHistoryService)', DestroyBlock) >
      Pos('FreeAndNil(FAnalyzerFrame)', DestroyBlock)),
      'shared history is not destroyed after both borrowing frames');

    AssertTrue(Pos('object MainForm: TMainForm', ShellResource) > 0,
      'the main-form resource root differs');
    AssertTrue(Pos('AllowDropFiles = True', ShellResource) > 0,
      'the shell no longer accepts folder drops');
    AssertTrue(Pos('KeyPreview = True', ShellResource) > 0,
      'the shell no longer receives application shortcuts');
    AssertTrue(Pos('object FeatureSelector: TComboBox', ShellResource) > 0,
      'the feature selector is missing');
    AssertTrue(Pos('Style = csDropDownList', ShellResource) > 0,
      'the feature selector should not accept arbitrary text');
    AssertTrue(Pos('object WorkspaceNotebook: TNotebook', ShellResource) > 0,
      'the tabless workspace notebook is missing');
    AssertTrue(Pos('object AnalyzerPage: TPage', ShellResource) > 0,
      'the Analyzer workspace page is missing');
    AssertTrue(Pos('object ComparePage: TPage', ShellResource) > 0,
      'the Compare Scans workspace page is missing');
    AssertTrue((Pos('''SBOM Analyzer''', ShellResource) > 0) and
      (Pos('''Compare Scans''', ShellResource) > 0),
      'the feature selector does not expose both compiled features');
    PageCount := 0;
    for LineIndex := 0 to ShellResourceLines.Count - 1 do
      if Pos(': TPage', ShellResourceLines[LineIndex]) > 0 then
        Inc(PageCount);
    AssertEqual(2, PageCount,
      'the shell should expose exactly two completed feature pages');

    AssertTrue(Pos('TSBOMAnalyzerFrame = class(TFrame)', AnalyzerSource) > 0,
      'the Analyzer workspace is not an LCL frame');
    AssertTrue(Pos('procedure ShowPendingWarnings;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing startup-warning delivery');
    AssertTrue(Pos('procedure HandleDroppedFiles(', AnalyzerSource) > 0,
      'the Analyzer shell API is missing drop handling');
    AssertTrue(Pos('function HandleShortcut(', AnalyzerSource) > 0,
      'the Analyzer shell API is missing shortcut handling');
    AssertTrue(Pos('function PrepareForClose: Boolean;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing safe shutdown');
    AssertTrue(Pos('procedure Activate;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing feature activation');
    AssertTrue(Pos('procedure Deactivate;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing feature deactivation');
    AssertTrue(Pos('procedure HistoryChanged(AKind:', AnalyzerSource) > 0,
      'the Analyzer shell API is missing shared-history changes');
    AssertTrue(Pos('constructor CreateWithHistoryService(', AnalyzerSource) > 0,
      'the Analyzer shell API lacks history injection');
    AssertTrue(Pos('property ScanActive: Boolean', AnalyzerSource) > 0,
      'the Analyzer shell API is missing activity state');
    AssertTrue(Pos('property OnActivityChanged:', AnalyzerSource) > 0,
      'the Analyzer shell API is missing activity notifications');
    AssertTrue(Pos('uMainForm', AnalyzerSource) = 0,
      'the Analyzer frame depends back on its shell');
    AssertTrue(Pos('FindTask(FWorker.ResultTask.ID)', AnalyzerSource) > 0,
      'shutdown does not recover the worker result independently');
    AssertTrue(Pos('FClosePrepared: Boolean;', AnalyzerSource) > 0,
      'shutdown lacks a separate successful-completion guard');
    AssertTrue(Pos('if FClosePrepared then', AnalyzerSource) > 0,
      'completed shutdown is not idempotent');
    AssertTrue(Pos('FClosePrepared := True;', AnalyzerSource) > 0,
      'shutdown never records successful completion');
    AssertTrue(Pos('FreeAndNil(FWorker)', AnalyzerSource) > 0,
      'shutdown does not remove worker-owned queued events');

    AssertTrue(Pos('object SBOMAnalyzerFrame: TSBOMAnalyzerFrame',
      AnalyzerResource) > 0, 'the Analyzer frame resource root differs');
    AssertTrue(Pos('AllowDropFiles =', AnalyzerResource) = 0,
      'the frame retained a form-only drop property');
    AssertTrue(Pos('OnCloseQuery =', AnalyzerResource) = 0,
      'the frame retained a form-only close event');
    AssertTrue(Pos('OnDropFiles =', AnalyzerResource) = 0,
      'the frame retained a form-only drop event');
    AssertTrue(Pos(LineEnding + '  OnKeyDown =', AnalyzerResource) = 0,
      'the frame retained a form-only key event');
    AssertTrue(Pos('OnShow =', AnalyzerResource) = 0,
      'the frame retained a form-only show event');
    AssertTrue(Pos('Position =', AnalyzerResource) = 0,
      'the frame retained a form-only position property');

    AssertTrue(Pos('TCompareScansFrame = class(TFrame)', CompareSource) > 0,
      'Compare Scans is not an LCL frame');
    AssertTrue(Pos('constructor CreateWithHistoryService(', CompareSource) > 0,
      'Compare Scans lacks shared-history injection');
    AssertTrue(Pos('procedure Activate;', CompareSource) > 0,
      'Compare Scans shell API is missing activation');
    AssertTrue(Pos('procedure Deactivate;', CompareSource) > 0,
      'Compare Scans shell API is missing deactivation');
    AssertTrue(Pos('procedure HistoryChanged(AKind:', CompareSource) > 0,
      'Compare Scans shell API is missing shared-history changes');
    AssertTrue(Pos('function HandleShortcut(var AKey:', CompareSource) > 0,
      'Compare Scans shell API is missing shortcut routing');
    AssertTrue(Pos('function PrepareForClose: Boolean;', CompareSource) > 0,
      'Compare Scans shell API is missing safe shutdown');
    AssertTrue(Pos('object CompareScansFrame: TCompareScansFrame',
      CompareResource) > 0, 'Compare Scans frame resource root differs');
    AssertTrue((Pos('AllowDropFiles =', CompareResource) = 0) and
      (Pos('OnCloseQuery =', CompareResource) = 0) and
      (Pos('OnDropFiles =', CompareResource) = 0) and
      (Pos('Position =', CompareResource) = 0),
      'Compare Scans retained form-only resource properties');

    AssertTrue(Pos('<Units Count="7">', ProjectText) > 0,
      'the Lazarus project unit count does not include both feature frames and CLI units');
    AssertTrue(Pos('<Filename Value="uSBOMAnalyzerFrame.pas"/>',
      ProjectText) > 0, 'the Lazarus project does not list the feature frame');
    AssertTrue(Pos('<ComponentName Value="SBOMAnalyzerFrame"/>',
      ProjectText) > 0, 'the Lazarus frame component name differs');
    AssertTrue(Pos('<Filename Value="uCompareScansFrame.pas"/>',
      ProjectText) > 0,
      'the Lazarus project does not list Compare Scans');
    AssertTrue(Pos('<ComponentName Value="CompareScansFrame"/>',
      ProjectText) > 0,
      'the Lazarus Compare Scans component name differs');
    AssertEqual(2, CountTextOccurrences(ProjectText,
      '<ResourceBaseClass Value="Frame"/>'),
      'the Lazarus project does not register both Frame resources');
    AssertTrue(Pos('Application.CreateForm(TMainForm, MainForm);',
      ProgramText) > 0, 'the application no longer auto-creates its shell');
    AssertTrue(Pos('CreateForm(TSBOMAnalyzerFrame', ProgramText) = 0,
      'the feature frame must be created by the shell, not the program');
    AssertTrue(Pos('CreateForm(TCompareScansFrame', ProgramText) = 0,
      'Compare Scans must be created by the shell, not the program');
  finally
    ProgramLines.Free;
    ProjectLines.Free;
    CompareResourceLines.Free;
    CompareSourceLines.Free;
    AnalyzerResourceLines.Free;
    AnalyzerSourceLines.Free;
    ShellResourceLines.Free;
    ShellSourceLines.Free;
  end;
end;

{**
  Verifies the settings dialog keeps its GTK3 DPI-safe top-label layout.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when the LFM restores top border spacing on the first aligned label
    or removes the fixed spacer that supplies the equivalent visual margin.
}
procedure TestScanSettingsDialogDPIStableLayout;
var
  SourceLines, ResourceLines: TStringList;
  SourceText, ResourceText: string;
  DescriptionIndex, LineIndex: Integer;
begin
  SourceLines := TStringList.Create;
  ResourceLines := TStringList.Create;
  try
    SourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanSettingsDialog.pas');
    ResourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanSettingsDialog.lfm');
    SourceText := SourceLines.Text;
    ResourceText := ResourceLines.Text;

    AssertTrue(Pos('DescriptionTopSpacer: TPanel;', SourceText) > 0,
      'the DPI-safe settings-dialog spacer is not LFM-backed');
    AssertTrue(Pos('object DescriptionTopSpacer: TPanel', ResourceText) > 0,
      'the settings dialog lacks its fixed top spacer');
    AssertTrue(Pos('object DescriptionTopSpacer: TPanel', ResourceText) <
      Pos('object DescriptionLabel: TLabel', ResourceText),
      'the settings-dialog spacer must precede the first aligned label');

    DescriptionIndex := -1;
    for LineIndex := 0 to ResourceLines.Count - 1 do
      if Pos('object DescriptionLabel: TLabel',
        ResourceLines[LineIndex]) > 0 then
      begin
        DescriptionIndex := LineIndex;
        Break;
      end;
    AssertTrue(DescriptionIndex >= 0,
      'the settings-dialog description label is missing');
    for LineIndex := DescriptionIndex + 1 to ResourceLines.Count - 1 do
    begin
      if Trim(ResourceLines[LineIndex]) = 'end' then
        Break;
      AssertTrue(Pos('BorderSpacing.Top', ResourceLines[LineIndex]) = 0,
        'top spacing on the first aligned label reintroduces the GTK3 DPI loop');
      AssertTrue(Pos('BorderSpacing.Around', ResourceLines[LineIndex]) = 0,
        'around spacing on the first aligned label reintroduces the GTK3 DPI loop');
    end;
  finally
    ResourceLines.Free;
    SourceLines.Free;
  end;
end;

{**
  Verifies the non-visual status, timestamp, message, and digest UI policies.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when user-facing trust indicators lose their deterministic meaning.
}
procedure TestPresentationPolicy;
var
  Task: TScanTask;
  Artifact: TArtifact;
  DisplayValue: string;
begin
  Task := TScanTask.Create;
  try
    Task.Status := tsCompleted;
    Task.FilesInspected := 1;
    AssertEqual(#$E2#$9C#$93 + ' completed', TaskStatusDisplayText(Task),
      'completed task status glyph or text differs');
    AssertTrue(not TaskNeedsReview(Task),
      'clean completed task unexpectedly needs review');

    Task.Warnings.Add('review this result');
    AssertTrue(TaskNeedsReview(Task),
      'warning did not mark the completed task for review');
    AssertEqual(#$E2#$9A#$A0 + ' completed with warnings',
      TaskStatusDisplayText(Task), 'warning-aware history status differs');

    Artifact := TArtifact.Create;
    Artifact.MessageText := 'artifact note';
    Task.Artifacts.Add(Artifact);
    Task.Errors.Add('task error');
    AssertEqual(3, TaskMessageCount(Task),
      'Messages-tab count should include warnings, errors, and artifact notes');
    AssertEqual(#$E2#$9C#$93 + ' parsed',
      ArtifactStatusDisplayText(arsParsed),
      'parsed artifact status glyph or text differs');
    AssertEqual(#$E2#$9C#$95 + ' failed',
      ArtifactStatusDisplayText(arsFailed),
      'failed artifact status glyph or text differs');
    AssertEqual(#$E2#$9A#$A0 + ' unsupported',
      StatusDisplayText('detected but unsupported'),
      'unsupported component status glyph or compact text differs');
    AssertEqual('0123456789ab',
      ShortDigest('0123456789abcdef0123456789abcdef'),
      'compact digest display differs');

    DisplayValue := LocalTimestampText('2026-08-20T12:34:56.789Z');
    AssertEqual(19, Length(DisplayValue),
      'local timestamp should use a complete second-resolution display');
    AssertTrue(Pos('T', DisplayValue) = 0,
      'local timestamp retained the ISO separator');
    AssertTrue(Pos('Z', DisplayValue) = 0,
      'local timestamp retained the UTC suffix');
  finally
    Task.Free;
  end;
end;

{**
  Verifies persistence and deep-copy semantics for compliance declarations.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when author/privacy settings or declared component metadata are
    omitted, aliased between clones, or lost through JSON persistence.
}
procedure TestComplianceModelPersistence;
var
  Settings, SettingsClone, LoadedSettings: TScanSettings;
  Component, ComponentClone, LoadedComponent: uModels.TComponent;
  Task, TaskClone, LoadedTask: TScanTask;
  JSONValue: TJSONObject;
begin
  Settings := TScanSettings.Create;
  SettingsClone := nil;
  LoadedSettings := nil;
  Component := uModels.TComponent.Create;
  ComponentClone := nil;
  LoadedComponent := nil;
  Task := nil;
  TaskClone := nil;
  LoadedTask := nil;
  JSONValue := nil;
  try
    Settings.IncludeAbsolutePaths := True;
    Settings.AllowOutsideRoot := True;
    Settings.SBOMAuthorOrganization := 'PurpleRay Research';
    Settings.SBOMAuthorEmail := 'sbom@example.test';
    Settings.RememberPrivacyChoices := True;
    Settings.IgnorePatterns.Add('compliance-cache');

    SettingsClone := Settings.Clone;
    AssertTrue(SettingsClone.IncludeAbsolutePaths and
      SettingsClone.AllowOutsideRoot and SettingsClone.RememberPrivacyChoices,
      'privacy settings were not cloned');
    AssertEqual('PurpleRay Research', SettingsClone.SBOMAuthorOrganization,
      'author organization was not cloned');
    AssertEqual('sbom@example.test', SettingsClone.SBOMAuthorEmail,
      'author email was not cloned');
    SettingsClone.SBOMAuthorOrganization := 'Changed clone';
    SettingsClone.IgnorePatterns.Add('clone-only');
    AssertEqual('PurpleRay Research', Settings.SBOMAuthorOrganization,
      'settings clone aliases the original author value');
    AssertTrue(Settings.IgnorePatterns.IndexOf('clone-only') < 0,
      'settings clone aliases the original ignore list');

    JSONValue := Settings.ToJSON;
    LoadedSettings := TScanSettings.FromJSON(JSONValue);
    FreeAndNil(JSONValue);
    AssertTrue(LoadedSettings.IncludeAbsolutePaths and
      LoadedSettings.AllowOutsideRoot and
      LoadedSettings.RememberPrivacyChoices,
      'privacy settings were not restored from JSON');
    AssertEqual('PurpleRay Research', LoadedSettings.SBOMAuthorOrganization,
      'author organization was not restored from JSON');
    AssertEqual('sbom@example.test', LoadedSettings.SBOMAuthorEmail,
      'author email was not restored from JSON');
    AssertTrue((Pos('PurpleRay Research', Settings.AsSummary) = 0) and
      (Pos('sbom@example.test', Settings.AsSummary) = 0),
      'settings summary exposes author contact details');

    Component.Name := 'declared-metadata';
    Component.Version := '1.0.0';
    Component.Ecosystem := 'npm';
    Component.DeclaredLicenses.Add('MIT');
    Component.DeclaredLicenses.Add('Apache-2.0');
    Component.DeclaredPublishers.Add('Zeta Publisher');
    Component.DeclaredPublishers.Add('Acme Publisher');
    ComponentClone := Component.Clone;
    AssertEqual(2, ComponentClone.DeclaredLicenses.Count,
      'declared licenses were not cloned');
    AssertEqual(2, ComponentClone.DeclaredPublishers.Count,
      'declared publishers were not cloned');
    ComponentClone.DeclaredLicenses.Add('BSD-3-Clause');
    ComponentClone.DeclaredPublishers.Add('Clone Publisher');
    AssertEqual(2, Component.DeclaredLicenses.Count,
      'component clone aliases the original license list');
    AssertEqual(2, Component.DeclaredPublishers.Count,
      'component clone aliases the original publisher list');

    JSONValue := Component.ToJSON;
    LoadedComponent := uModels.TComponent.FromJSON(JSONValue);
    FreeAndNil(JSONValue);
    AssertEqual(2, LoadedComponent.DeclaredLicenses.Count,
      'declared licenses were not restored from JSON');
    AssertEqual('Apache-2.0', LoadedComponent.DeclaredLicenses[0],
      'declared license order is not deterministic');
    AssertEqual('MIT', LoadedComponent.DeclaredLicenses[1],
      'second declared license differs after JSON restoration');
    AssertEqual(2, LoadedComponent.DeclaredPublishers.Count,
      'declared publishers were not restored from JSON');
    AssertEqual('Acme Publisher', LoadedComponent.DeclaredPublishers[0],
      'declared publisher order is not deterministic');

    Task := TScanTask.Create;
    Task.Settings.Assign(Settings);
    Task.Components.Add(Component.Clone);
    TaskClone := Task.Clone;
    AssertEqual('PurpleRay Research',
      TaskClone.Settings.SBOMAuthorOrganization,
      'task clone lost author settings');
    AssertEqual(2,
      uModels.TComponent(TaskClone.Components[0]).DeclaredLicenses.Count,
      'task clone lost declared licenses');
    TaskClone.Settings.SBOMAuthorOrganization := 'Task clone only';
    uModels.TComponent(TaskClone.Components[0]).DeclaredLicenses.Add(
      'BSD-3-Clause');
    AssertEqual('PurpleRay Research', Task.Settings.SBOMAuthorOrganization,
      'task clone aliases original author settings');
    AssertEqual(2,
      uModels.TComponent(Task.Components[0]).DeclaredLicenses.Count,
      'task clone aliases original component declaration lists');
    JSONValue := Task.ToJSON;
    LoadedTask := TScanTask.FromJSON(JSONValue);
    FreeAndNil(JSONValue);
    AssertEqual('PurpleRay Research',
      LoadedTask.Settings.SBOMAuthorOrganization,
      'nested task JSON lost author settings');
    AssertTrue(LoadedTask.Settings.RememberPrivacyChoices,
      'nested task JSON lost the privacy persistence choice');
    AssertEqual(2,
      uModels.TComponent(LoadedTask.Components[0]).DeclaredLicenses.Count,
      'nested task JSON lost declared licenses');
    AssertEqual(2,
      uModels.TComponent(LoadedTask.Components[0]).DeclaredPublishers.Count,
      'nested task JSON lost declared publishers');

    SettingsClone.ResetDefaults;
    AssertTrue((not SettingsClone.IncludeAbsolutePaths) and
      (not SettingsClone.AllowOutsideRoot) and
      (not SettingsClone.RememberPrivacyChoices),
      'restoring settings defaults retained privacy choices');
    AssertEqual('', SettingsClone.SBOMAuthorOrganization,
      'restoring settings defaults retained the author organization');
    AssertEqual('', SettingsClone.SBOMAuthorEmail,
      'restoring settings defaults retained the author email');
  finally
    JSONValue.Free;
    LoadedTask.Free;
    TaskClone.Free;
    Task.Free;
    LoadedComponent.Free;
    ComponentClone.Free;
    Component.Free;
    LoadedSettings.Free;
    SettingsClone.Free;
    Settings.Free;
  end;
end;

{**
  Locks the Analyzer source/resource contracts retained after shell expansion.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when target disclosure, restoration, overwrite protection, local
    time, selection stability, safe deletion, full-hash copy, or asynchronous
    close wiring regresses.
}
procedure TestSprint4UIContracts;
var
  AnalyzerSourceLines, AnalyzerResourceLines, SettingsSourceLines,
    SettingsResourceLines, ShellSourceLines: TStringList;
  AnalyzerSource, AnalyzerResource, SettingsSource, SettingsResource,
    ShellSource, TargetBlock, RequestCloseBlock, PrepareCloseBlock,
    CopyBlock, WorkerCompleteBlock, DeleteBlock: string;
begin
  AnalyzerSourceLines := TStringList.Create;
  AnalyzerResourceLines := TStringList.Create;
  SettingsSourceLines := TStringList.Create;
  SettingsResourceLines := TStringList.Create;
  ShellSourceLines := TStringList.Create;
  try
    AnalyzerSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uSBOMAnalyzerFrame.pas');
    AnalyzerResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uSBOMAnalyzerFrame.lfm');
    SettingsSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanSettingsDialog.pas');
    SettingsResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uScanSettingsDialog.lfm');
    ShellSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uMainForm.pas');
    AnalyzerSource := AnalyzerSourceLines.Text;
    AnalyzerResource := AnalyzerResourceLines.Text;
    SettingsSource := SettingsSourceLines.Text;
    SettingsResource := SettingsResourceLines.Text;
    ShellSource := ShellSourceLines.Text;

    TargetBlock := ExtractTextSection(SettingsResource,
      'object FTargetFolder: TEdit',
      'object FIncludeAbsolutePaths: TCheckBox');
    AssertTrue((TargetBlock <> '') and
      (Pos('ReadOnly = True', TargetBlock) > 0),
      'the settings target-folder field is not read-only');
    AssertTrue(Pos('Dialog.FTargetFolder.Text := ATargetDirectory',
      SettingsSource) > 0, 'the settings target folder is not populated');
    AssertTrue(Pos('Caption = ''Restore defaults''', SettingsResource) > 0,
      'the ignore-pattern restore action is missing');
    AssertTrue(Pos('OnClick = RestoreDefaultsClicked', SettingsResource) > 0,
      'the restore-defaults button is not wired');
    AssertTrue(Pos('FIgnorePatterns.Lines.Assign(Defaults.IgnorePatterns)',
      SettingsSource) > 0,
      'the restore-defaults action does not use model defaults');
    AssertTrue((Pos('object FIncludeAbsolutePaths: TCheckBox',
      SettingsResource) < Pos('object FFollowSymbolicLinks: TCheckBox',
      SettingsResource)) and
      (Pos('object FFollowSymbolicLinks: TCheckBox', SettingsResource) <
      Pos('object FAllowOutsideRoot: TCheckBox', SettingsResource)) and
      (Pos('object FAllowOutsideRoot: TCheckBox', SettingsResource) <
      Pos('object FRememberPrivacyChoices: TCheckBox', SettingsResource)) and
      (Pos('object FRememberPrivacyChoices: TCheckBox', SettingsResource) <
      Pos('object FCalculateSHA256: TCheckBox', SettingsResource)),
      'settings checkbox visual order differs from the privacy workflow');

    AssertEqual(2, CountTextOccurrences(AnalyzerSource,
      'Dialog.Options := Dialog.Options + [ofOverwritePrompt]'),
      'both export dialogs must request overwrite confirmation');
    AssertTrue(Pos('Caption = ''Back up data...''', AnalyzerResource) > 0,
      'the database backup action has an ambiguous caption');
    AssertTrue(Pos('Caption = ''Created (local)''', AnalyzerResource) > 0,
      'history does not identify its local timestamp');
    AssertTrue(Pos('Item.Caption := LocalTimestampText(ATask.CreatedUTC)',
      AnalyzerSource) > 0,
      'history rows do not convert timestamps for local display');
    AssertTrue((Pos('ComponentsPage.Caption := ''Components (''',
      AnalyzerSource) > 0) and
      (Pos('ArtifactsPage.Caption := ''Artifacts (''', AnalyzerSource) > 0) and
      (Pos('MessagesPage.Caption := ''Messages (''', AnalyzerSource) > 0),
      'detail tabs do not expose result counts');

    CopyBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.CopySelectedClicked',
      'procedure TSBOMAnalyzerFrame.OpenExportFolderClicked');
    AssertTrue((CopyBlock <> '') and (Pos('Artifact.SHA256', CopyBlock) > 0),
      'artifact row copy no longer includes the full SHA-256 value');
    AssertTrue(Pos('ShortDigest(Artifact.SHA256)', AnalyzerSource) > 0,
      'artifact table no longer uses the compact digest presentation');

    RequestCloseBlock := ExtractTextSection(AnalyzerSource,
      'function TSBOMAnalyzerFrame.RequestClose',
      'procedure TSBOMAnalyzerFrame.ClosePollTimerTick');
    PrepareCloseBlock := ExtractTextSection(AnalyzerSource,
      'function TSBOMAnalyzerFrame.PrepareForClose',
      'function TSBOMAnalyzerFrame.RequestClose');
    WorkerCompleteBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.WorkerComplete',
      LineEnding + 'end.' + LineEnding);
    DeleteBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.DeleteTaskClicked',
      'procedure TSBOMAnalyzerFrame.TaskListKeyPressed');
    AssertTrue((RequestCloseBlock <> '') and (PrepareCloseBlock <> ''),
      'asynchronous close methods are missing');
    AssertTrue((Pos('WaitFor', RequestCloseBlock) = 0) and
      (Pos('WaitFor', PrepareCloseBlock) = 0),
      'the interactive close path blocks on the scan worker');
    AssertTrue(Pos('ClosePollTimer.Enabled := True', RequestCloseBlock) > 0,
      'close cancellation does not start asynchronous completion polling');
    AssertTrue((Pos('object ClosePollTimer: TTimer', AnalyzerResource) > 0) and
      (Pos('OnTimer = ClosePollTimerTick', AnalyzerResource) > 0),
      'the asynchronous close timer is not resource-backed');
    AssertTrue((Pos('FAnalyzerFrame.RequestClose', ShellSource) > 0) and
      (Pos('FAnalyzerFrame.OnCloseReady', ShellSource) > 0),
      'the shell is not wired to asynchronous Analyzer close completion');

    AssertTrue((Pos('WorkingSettings.IncludeAbsolutePaths := False',
      AnalyzerSource) > 0) and
      (Pos('WorkingSettings.AllowOutsideRoot := False', AnalyzerSource) > 0)
      and (Pos('PersistedSettings.IncludeAbsolutePaths := False',
      AnalyzerSource) > 0) and
      (Pos('PersistedSettings.AllowOutsideRoot := False', AnalyzerSource) > 0),
      'per-scan privacy choices are not reset when they are not remembered');
    AssertTrue((Pos('TTaskHistoryService.Create(ADataDirectory)',
      AnalyzerSource) > 0) and
      (Pos('FHistoryService := AHistoryService', AnalyzerSource) > 0) and
      (Pos('FSettingsStore := TSettingsStore.Create(' +
      'FHistoryService.DataDirectory)', AnalyzerSource) > 0),
      'Analyzer does not honor owned and borrowed history data roots');

    AssertTrue((WorkerCompleteBlock <> '') and
      (Pos('WasSelected := FSelectedTaskID = AResult.ID',
      WorkerCompleteBlock) > 0) and
      (Pos('if WasSelected and', WorkerCompleteBlock) > 0),
      'completed background scans can steal a historical selection');
    AssertTrue((Pos('object FTaskMenu: TPopupMenu', AnalyzerResource) > 0) and
      (Pos('object DeleteTaskMenuItem: TMenuItem', AnalyzerResource) > 0) and
      (Pos('PopupMenu = FTaskMenu', AnalyzerResource) > 0) and
      (Pos('OnKeyDown = TaskListKeyPressed', AnalyzerResource) > 0),
      'task deletion is not exposed through menu and keyboard contracts');
    AssertTrue((DeleteBlock <> '') and
      (Pos('Task.Status in [tsPending, tsRunning]', DeleteBlock) > 0) and
      (Pos('FHistoryService.DeleteTask(TaskID, WarningText)',
      DeleteBlock) > 0) and
      (Pos('FSelectedTaskID := ''''', DeleteBlock) > 0) and
      (Pos('PreferredIndex', DeleteBlock) > 0),
      'safe task deletion or post-delete selection preservation regressed');
  finally
    ShellSourceLines.Free;
    SettingsResourceLines.Free;
    SettingsSourceLines.Free;
    AnalyzerResourceLines.Free;
    AnalyzerSourceLines.Free;
  end;
end;

{**
  Locks the source and LFM contracts for the Compare Scans feature.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when completed-task selection, clone-based comparison, directional
    disclosure, live-history refresh, filtering, sorting, copying, or empty
    states diverge from the Sprint 5 interaction contract.
}
procedure TestSprint5CompareUIContracts;
var
  CompareSourceLines, CompareResourceLines, HistorySourceLines: TStringList;
  CompareSource, CompareResource, HistorySource, RefreshBlock, DefaultsBlock,
    RebuildBlock, SummaryBlock, FilterBlock, PopulateBlock, ShortcutBlock: string;
begin
  CompareSourceLines := TStringList.Create;
  CompareResourceLines := TStringList.Create;
  HistorySourceLines := TStringList.Create;
  try
    CompareSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uCompareScansFrame.pas');
    CompareResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uCompareScansFrame.lfm');
    HistorySourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uTaskHistory.pas');
    CompareSource := CompareSourceLines.Text;
    CompareResource := CompareResourceLines.Text;
    HistorySource := HistorySourceLines.Text;
    RefreshBlock := ExtractTextSection(CompareSource,
      'procedure TCompareScansFrame.RefreshTaskChoices;',
      'procedure TCompareScansFrame.ApplyInitialSelection;');
    DefaultsBlock := ExtractTextSection(CompareSource,
      'procedure TCompareScansFrame.ApplyInitialSelection;',
      'procedure TCompareScansFrame.UpdatePickerHints;');
    RebuildBlock := ExtractTextSection(CompareSource,
      'procedure TCompareScansFrame.RebuildComparison;',
      'procedure TCompareScansFrame.UpdateComparisonSummary');
    SummaryBlock := ExtractTextSection(CompareSource,
      'procedure TCompareScansFrame.UpdateComparisonSummary',
      'function TCompareScansFrame.ChangeMatchesFilters');
    FilterBlock := ExtractTextSection(CompareSource,
      'function TCompareScansFrame.ChangeMatchesFilters',
      'function TCompareScansFrame.CompareChangeRows');
    PopulateBlock := ExtractTextSection(CompareSource,
      'procedure TCompareScansFrame.PopulateRows;',
      'procedure TCompareScansFrame.UpdateControlStates;');
    ShortcutBlock := ExtractTextSection(CompareSource,
      'function TCompareScansFrame.HandleShortcut',
      'function TCompareScansFrame.PrepareForClose');

    AssertTrue(Pos('Task.Status <> tsCompleted', HistorySource) > 0,
      'comparison task summaries are not restricted to completed scans');
    AssertTrue((RefreshBlock <> '') and
      (Pos('FHistory.GetCompletedTaskSummaries(FSummaries)', RefreshBlock) > 0)
      and (Pos('PickerIndexForTask(FBaselinePicker,', RefreshBlock) > 0) and
      (Pos('PickerIndexForTask(FComparisonPicker,', RefreshBlock) > 0),
      'task choice refresh does not preserve stable completed-task IDs');
    AssertTrue((DefaultsBlock <> '') and
      (Pos('Newest := SummaryAt(0)', DefaultsBlock) > 0) and
      (Pos('if Newest = nil then', DefaultsBlock) > 0) and
      (Pos('if Newest = nil then', DefaultsBlock) <
      Pos('FDefaultsApplied := True', DefaultsBlock)) and
      (Pos('FDefaultsApplied := True', DefaultsBlock) <
      Pos('if FSummaries.Count < 2 then', DefaultsBlock)) and
      (Pos('SameTaskTarget(Newest, Candidate)', DefaultsBlock) > 0) and
      (Pos('BaselineIndex := 1', DefaultsBlock) > 0),
      'initial scan pair or empty/one-task default latching differs');
    AssertTrue(Pos('SameFileName(ALeft.TargetRootName, ' +
      'ARight.TargetRootName)', CompareSource) > 0,
      'legacy target-name comparison ignores platform filename semantics');
    AssertTrue((RebuildBlock <> '') and
      (CountTextOccurrences(RebuildBlock, 'CloneTaskByID(') = 2) and
      (Pos('CompareComponentTasks(BaselineTask, ComparisonTask)',
      RebuildBlock) > 0) and
      (Pos('BaselineTask.Free', RebuildBlock) > 0) and
      (Pos('ComparisonTask.Free', RebuildBlock) > 0),
      'comparison does not clone both tasks before model analysis');
    AssertTrue(Pos('FindTaskByID(', CompareSource) = 0,
      'Compare Scans retains borrowed live task pointers');
    AssertTrue((Pos('if FOwnsHistory then', CompareSource) > 0) and
      (Pos('FHistory.OnChanged := @HistoryServiceChanged', CompareSource) > 0)
      and (Pos('FOwnsHistory := False', CompareSource) > 0),
      'owned and borrowed history subscriptions are not separated');

    AssertTrue((SummaryBlock <> '') and
      (Pos('Changes from %s [%s] to %s [%s]', SummaryBlock) > 0) and
      (Pos('Added %d', SummaryBlock) > 0) and
      (Pos('Removed %d', SummaryBlock) > 0) and
      (Pos('Changed %d', SummaryBlock) > 0) and
      (Pos('Unchanged %d', SummaryBlock) > 0),
      'directional comparison summary or counts are incomplete');
    AssertTrue((Pos('different folders', SummaryBlock) > 0) and
      (Pos('completed with diagnostics', SummaryBlock) > 0) and
      (Pos('different analyzer', SummaryBlock) > 0) and
      (Pos('identity warning', SummaryBlock) > 0),
      'comparison cautions do not disclose incompatible or weak evidence');
    AssertTrue((FilterBlock <> '') and
      (Pos('FChangeFilter.ItemIndex', FilterBlock) > 0) and
      (Pos('FSearchEdit.Text', FilterBlock) > 0) and
      (Pos('AChange.IdentityKey', FilterBlock) > 0) and
      (Pos('AChange.BeforePackageURL', FilterBlock) > 0) and
      (Pos('AChange.AfterPackageURL', FilterBlock) > 0),
      'comparison search or change-kind filtering is incomplete');
    AssertTrue((PopulateBlock <> '') and
      (Pos('SortChangePointers', PopulateBlock) > 0) and
      (Pos('SelectedKeys.Add', PopulateBlock) > 0) and
      (Pos('No changes match the current search and filter',
      PopulateBlock) > 0) and
      (Pos('files are not rescanned', PopulateBlock) > 0),
      'comparison rows do not preserve selection, sort, or disclose scope');
    AssertTrue((ShortcutBlock <> '') and
      (Pos('AKey = VK_F5', ShortcutBlock) > 0) and
      (Pos('AKey = VK_F', ShortcutBlock) > 0) and
      (Pos('AKey = VK_C', ShortcutBlock) > 0) and
      (Pos('Escape is deliberately not consumed', ShortcutBlock) > 0),
      'Compare Scans shortcut routing can affect a hidden Analyzer scan');

    AssertTrue(Pos('object CompareScansFrame: TCompareScansFrame',
      CompareResource) > 0, 'Compare Scans LFM root differs');
    AssertTrue((Pos('Height = 626', CompareResource) > 0) and
      (Pos('Width = 1080', CompareResource) > 0),
      'Compare Scans does not fit the compact feature workspace');
    AssertTrue((Pos('object BaselineRowPanel: TPanel', CompareResource) > 0) and
      (Pos('object ComparisonRowPanel: TPanel', CompareResource) > 0) and
      (CountTextOccurrences(CompareResource, '      Height = 38') >= 2),
      'the two scan-picker rows do not use the compact fixed layout');
    AssertTrue((Pos('object FBaselinePicker: TComboBox', CompareResource) > 0)
      and (Pos('object FComparisonPicker: TComboBox', CompareResource) > 0) and
      (Pos('object FSwapButton: TButton', CompareResource) > 0) and
      (Pos('object FRefreshButton: TButton', CompareResource) > 0),
      'baseline, comparison, swap, or refresh controls are missing');
    AssertTrue((Pos('object FSearchEdit: TEdit', CompareResource) > 0) and
      (Pos('object FChangeFilter: TComboBox', CompareResource) > 0) and
      (Pos('''All changes''', CompareResource) > 0) and
      (Pos('''Added''', CompareResource) > 0) and
      (Pos('''Removed''', CompareResource) > 0) and
      (Pos('''Changed''', CompareResource) > 0),
      'comparison search or change filter controls are missing');
    AssertEqual(7, CountTextOccurrences(CompareResource, '        item'),
      'comparison report should expose exactly seven columns');
    AssertTrue((Pos('Caption = ''Change''', CompareResource) > 0) and
      (Pos('Caption = ''Component''', CompareResource) > 0) and
      (Pos('Caption = ''Before''', CompareResource) > 0) and
      (Pos('Caption = ''After''', CompareResource) > 0) and
      (Pos('Caption = ''Ecosystem''', CompareResource) > 0) and
      (Pos('Caption = ''Type''', CompareResource) > 0) and
      (Pos('Caption = ''Identity''', CompareResource) > 0),
      'comparison report columns differ from the directional result model');
    AssertTrue((Pos('OnColumnClick = ResultColumnClicked', CompareResource) > 0)
      and (Pos('MultiSelect = True', CompareResource) > 0) and
      (Pos('PopupMenu = FCopyMenu', CompareResource) > 0) and
      (Pos('Copy selected change(s)', CompareResource) > 0) and
      (Pos('Copy component identity', CompareResource) > 0),
      'sortable multi-row comparison copy controls are incomplete');
    AssertTrue((Pos('object FResultEmptyLabel: TLabel', CompareResource) > 0)
      and (Pos('files are not rescanned', CompareResource) > 0),
      'comparison empty state or saved-inventory disclosure is missing');
  finally
    HistorySourceLines.Free;
    CompareResourceLines.Free;
    CompareSourceLines.Free;
  end;
end;

{**
  Exercises the bounded registry-backed SPDX expression grammar.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when valid registry identifiers/references are rejected or malformed
    expressions are accepted as machine-readable SPDX declarations.
}
procedure TestSPDXExpressions;
begin
  AssertTrue(IsValidSPDXExpression('MIT'),
    'a registered SPDX license identifier was rejected');
  AssertTrue(IsValidSPDXExpression(
    '(MIT OR Apache-2.0) AND BSD-3-Clause'),
    'a parenthesized SPDX expression was rejected');
  AssertTrue(IsValidSPDXExpression(
    'GPL-2.0-only WITH Classpath-exception-2.0'),
    'a registered SPDX exception expression was rejected');
  AssertTrue(IsValidSPDXExpression('GPL-2.0+'),
    'an adjacent SPDX or-later suffix was rejected');
  AssertTrue(IsValidSPDXExpression('LicenseRef-Internal-Evaluation'),
    'a valid SPDX LicenseRef was rejected');
  AssertTrue(IsValidSPDXExpression(
    'DocumentRef-vendor:LicenseRef-Proprietary'),
    'a valid document-scoped LicenseRef was rejected');
  AssertTrue(not IsValidSPDXExpression('mit'),
    'SPDX registry matching became case-insensitive');
  AssertTrue(not IsValidSPDXExpression('MIT or Apache-2.0'),
    'a lowercase SPDX operator was accepted');
  AssertTrue(not IsValidSPDXExpression('MIT AND'),
    'an incomplete SPDX expression was accepted');
  AssertTrue(not IsValidSPDXExpression('(MIT OR Apache-2.0'),
    'an unbalanced SPDX expression was accepted');
  AssertTrue(not IsValidSPDXExpression('MIT WITH Unknown-exception'),
    'an unregistered SPDX exception was accepted');
  AssertTrue(not IsValidSPDXExpression('LicenseRef-'),
    'an empty SPDX LicenseRef suffix was accepted');
  AssertTrue(not IsValidSPDXExpression('LicenseRef-Internal+'),
    'an invalid SPDX LicenseRef character was accepted');
  AssertTrue(not IsValidSPDXExpression('GPL-2.0 +'),
    'whitespace before the SPDX or-later suffix was accepted');
  AssertTrue(not IsValidSPDXExpression(
    'GPL-2.0+WITH Classpath-exception-2.0'),
    'an SPDX WITH operator without leading whitespace was accepted');
  AssertTrue(not IsValidSPDXExpression(
    'GPL-2.0-only WITH' + LineEnding + 'Classpath-exception-2.0'),
    'a multiline SPDX expression was accepted');
  AssertTrue(not IsValidSPDXExpression('MIT' + LineEnding),
    'a trailing line break was trimmed from an SPDX expression');
  AssertTrue(not IsValidSPDXExpression(#9 + 'MIT'),
    'a leading control character was trimmed from an SPDX expression');
  AssertTrue(not IsValidSPDXExpression(
    'GPL-2.0-only WITH(Classpath-exception-2.0)'),
    'an SPDX WITH operator without trailing whitespace was accepted');
  AssertTrue(not IsValidSPDXExpression('MIT AND(Apache-2.0)'),
    'an SPDX binary operator without trailing whitespace was accepted');
  AssertTrue(not IsValidSPDXExpression(StringOfChar('A', 4097)),
    'an over-limit SPDX expression was accepted');
  AssertTrue(not IsValidSPDXExpression('Friendly Internal License'),
    'a free-form license name was accepted as an SPDX expression');
end;

{**
  Verifies declared license and publisher extraction across core manifests.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when package.json, POM, Composer, Cargo, or pyproject declarations
    are omitted, altered, or attached to the wrong project component.
}
procedure TestDeclaredMetadataParsers;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  DirectoryName, FileName: string;
begin
  DirectoryName := NewTemporaryDirectory('declared-metadata-parsers');
  Components := TObjectList.Create(True);
  try
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'package.json';
    WriteText(FileName, '{"name":"metadata-npm","version":"1.0.0",' +
      '"license":"MIT","author":{"name":"NPM Publisher",' +
      '"email":"publisher@example.test"}}');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'package.json', pkPackageJSON, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'package metadata fixture should parse');
      Component := FindComponent(Components, 'metadata-npm');
      AssertTrue(Component <> nil, 'package project component is missing');
      AssertEqual(1, Component.DeclaredLicenses.Count,
        'package license declaration count differs');
      AssertEqual('MIT', Component.DeclaredLicenses[0],
        'package license declaration differs');
      AssertEqual(1, Component.DeclaredPublishers.Count,
        'package publisher declaration count differs');
      AssertEqual('NPM Publisher', Component.DeclaredPublishers[0],
        'package author name was not retained as publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'pom.xml';
    WriteText(FileName, '<?xml version="1.0"?><project>' +
      '<groupId>org.example</groupId><artifactId>metadata-maven</artifactId>' +
      '<version>2.0.0</version>' +
      '<Organization><Name>Invented Case Publisher</Name></Organization>' +
      '<organization><name>Maven Publisher</name></organization>' +
      '<Licenses><License><Name>Invented Case License</Name></License>' +
      '</Licenses><licenses><license><name>Apache-2.0</name></license>' +
      '<license><name>Custom Maven Terms</name></license>' +
      '<license><Name>Invented Case Name</Name></license>' +
      '<license><name>${license.name}</name></license></licenses>' +
      '</project>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
      AssertTrue(Artifact.Status = arsParsed,
        'Maven metadata fixture should parse');
      Component := FindComponent(Components, 'metadata-maven');
      AssertTrue(Component <> nil, 'Maven project component is missing');
      AssertEqual(2, Component.DeclaredLicenses.Count,
        'Maven license declaration count differs');
      AssertTrue((Component.DeclaredLicenses.IndexOf('Apache-2.0') >= 0) and
        (Component.DeclaredLicenses.IndexOf('Custom Maven Terms') >= 0),
        'Maven license declarations differ');
      AssertEqual(1, Component.DeclaredPublishers.Count,
        'Maven publisher declaration count differs');
      AssertEqual('Maven Publisher', Component.DeclaredPublishers[0],
        'Maven organization was not retained as publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'unresolved-pom.xml';
    WriteText(FileName, '<?xml version="1.0"?><project>' +
      '<groupId>org.example</groupId>' +
      '<artifactId>unresolved-maven</artifactId><version>2.0.0</version>' +
      '<organization><name>${project.organization}</name></organization>' +
      '<licenses><license><name>${license.name}</name></license></licenses>' +
      '</project>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
      AssertTrue(Artifact.Status = arsParsed,
        'unresolved Maven declaration fixture should parse');
      AssertEqual(0, Components.Count,
        'unresolved Maven properties became declared project evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'composer.json';
    WriteText(FileName, '{"name":"vendor/metadata-composer",' +
      '"version":"3.0.0","license":["MIT","BSD-3-Clause"],' +
      '"authors":[{"name":"Composer One","email":"one@example.test"},' +
      '{"name":"Composer Two"}]}');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'composer.json', pkComposerJSON, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'Composer metadata fixture should parse');
      Component := FindComponent(Components, 'vendor/metadata-composer');
      AssertTrue(Component <> nil, 'Composer project component is missing');
      AssertTrue((Component.DeclaredLicenses.IndexOf('MIT') >= 0) and
        (Component.DeclaredLicenses.IndexOf('BSD-3-Clause') >= 0),
        'Composer license declarations differ');
      AssertTrue((Component.DeclaredPublishers.IndexOf('Composer One') >= 0)
        and (Component.DeclaredPublishers.IndexOf('Composer Two') >= 0),
        'Composer authors were not retained as publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'Cargo.toml';
    WriteText(FileName, '[package]' + LineEnding +
      'name = "metadata-cargo"' + LineEnding +
      'version = "4.0.0"' + LineEnding +
      'license = "MIT OR Apache-2.0"' + LineEnding +
      'authors = ["Cargo One <one@example.test>", "Cargo Two"]' +
      LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'Cargo.toml', pkCargoTOML, Artifact, Components);
      AssertTrue(Artifact.Status = arsPartiallyParsed,
        'Cargo metadata fixture should report conservative partial parsing');
      Component := FindComponent(Components, 'metadata-cargo');
      AssertTrue(Component <> nil, 'Cargo project component is missing');
      AssertEqual('MIT OR Apache-2.0', Component.DeclaredLicenses[0],
        'Cargo license expression differs');
      AssertTrue((Component.DeclaredPublishers.IndexOf(
        'Cargo One <one@example.test>') >= 0) and
        (Component.DeclaredPublishers.IndexOf('Cargo Two') >= 0),
        'Cargo authors were not retained as publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'pyproject.toml';
    WriteText(FileName, '[project]' + LineEnding +
      'name = "metadata-python"' + LineEnding +
      'version = "5.0.0"' + LineEnding +
      'license = "BSD-3-Clause"' + LineEnding +
      'authors = [{name = "Python One", email = "one@example.test"}, ' +
      '{name = "Python Two"}]' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pyproject.toml', pkPyProjectTOML, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsPartiallyParsed,
        'pyproject metadata fixture should report conservative partial parsing');
      Component := FindComponent(Components, 'metadata-python');
      AssertTrue(Component <> nil, 'pyproject component is missing');
      AssertEqual('BSD-3-Clause', Component.DeclaredLicenses[0],
        'pyproject license declaration differs');
      AssertTrue((Component.DeclaredPublishers.IndexOf('Python One') >= 0) and
        (Component.DeclaredPublishers.IndexOf('Python Two') >= 0),
        'pyproject author names were not retained as publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'invalid-package.json';
    WriteText(FileName, '{"name":"invalid-json-meta","version":"1.0.0",' +
      '"license":["MIT\n",true],"author":{"name":42,' +
      '"email":"fallback@example.test"}}');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'package.json', pkPackageJSON, Artifact,
        Components);
      Component := FindComponent(Components, 'invalid-json-meta');
      AssertTrue(Component <> nil,
        'invalid JSON declaration fixture lost its project component');
      AssertEqual(0, Component.DeclaredLicenses.Count,
        'a non-string JSON license became declared evidence');
      AssertEqual(0, Component.DeclaredPublishers.Count,
        'a non-string JSON author name produced publisher evidence');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'case-sensitive-pyproject.toml';
    WriteText(FileName, '[Project]' + LineEnding +
      'Name = "invented-project"' + LineEnding +
      'Version = "9.9.9"' + LineEnding +
      'License = "MIT"' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pyproject.toml', pkPyProjectTOML, Artifact,
        Components);
      AssertEqual(0, Components.Count,
        'case-distinct TOML table or keys were treated as PEP-621 metadata');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'uncertain-pyproject.toml';
    WriteText(FileName, '[project]' + LineEnding +
      'name = "strict-project"' + LineEnding +
      'version = "1.0.0"' + LineEnding +
      'license = "MIT" trailing-data' + LineEnding +
      'authors = [{name = "Escaped \"Publisher\""}]' + LineEnding +
      'authors = [{note = "name = ''Invented Publisher''"}]' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pyproject.toml', pkPyProjectTOML, Artifact,
        Components);
      Component := FindComponent(Components, 'strict-project');
      AssertTrue(Component <> nil,
        'strict TOML negative fixture lost its valid project identity');
      AssertEqual(0, Component.DeclaredLicenses.Count,
        'a TOML value with trailing syntax became a license declaration');
      AssertEqual(0, Component.DeclaredPublishers.Count,
        'text inside an unrelated TOML author field invented a publisher');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'case-sensitive-cargo.toml';
    WriteText(FileName, '[Package]' + LineEnding +
      'Name = "invented-cargo"' + LineEnding +
      'Version = "1.0.0"' + LineEnding +
      'License = "MIT"' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'Cargo.toml', pkCargoTOML, Artifact,
        Components);
      AssertEqual(0, Components.Count,
        'case-distinct Cargo table or keys produced project declarations');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'control-pyproject.toml';
    WriteText(FileName, '[project]' + LineEnding +
      'name = "bad' + #127 + 'identity"' + LineEnding +
      'version = "1.0.0"' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pyproject.toml', pkPyProjectTOML, Artifact,
        Components);
      AssertEqual(0, Components.Count,
        'a TOML identity containing DEL was accepted');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

procedure TestRequirementsParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('requirements.txt', pkRequirements, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'requirements should parse');
      AssertEqual(3, Components.Count, 'requirements component count differs');
      Component := FindComponent(Components, 'requests');
      AssertTrue(Component <> nil, 'requests component is missing');
      AssertEqual('2.32.3', Component.Version, 'requests version differs');
      AssertEqual('pkg:pypi/requests@2.32.3', Component.PackageURL,
        'requests purl differs');
      Component := FindComponent(Components, 'urllib3');
      AssertEqual('>=2.2', Component.Version, 'constraint should be retained');
      AssertEqual('', Component.PackageURL,
        'constraint must not be converted to an exact purl');
      Component := FindComponent(Components, 'Typing_Extensions');
      AssertTrue(Component <> nil,
        'the display spelling of the Python package is missing');
      AssertEqual('4.12.2', Component.Version,
        'Python exact version differs');
      AssertEqual('pkg:pypi/typing-extensions@4.12.2',
        Component.PackageURL, 'PEP-503 normalized PyPI purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies ecosystem-specific Package URL canonicalization and rejection.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a supported ecosystem produces a noncanonical purl or an
    unresolved version/name is assigned a misleading purl.
}
procedure TestPackageURLNormalization;
begin
  AssertEqual('pkg:pypi/flask@3.0.3',
    BuildPackageURL('PyPI', 'Flask', '3.0.3'),
    'PyPI purl must be lowercase');
  AssertEqual('pkg:pypi/typing-extensions@4.12.2',
    BuildPackageURL('PyPI', 'typing_extensions', '4.12.2'),
    'PyPI separator runs must follow PEP 503');
  AssertEqual('pkg:pypi/friendly-bard@1.0',
    BuildPackageURL('PyPI', 'FrIeNdLy-._.-bArD', '1.0'),
    'PyPI mixed separator normalization differs');
  AssertEqual('pkg:npm/lodash@4.17.21',
    BuildPackageURL('npm', 'LoDash', '4.17.21'),
    'npm purl name must be lowercase');
  AssertEqual('pkg:npm/%40scope/tool@3.4.5',
    BuildPackageURL('npm', '@Scope/Tool', '3.4.5'),
    'scoped npm purl normalization differs');
  AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
    BuildPackageURL('Gradle', 'org.example:demo-core', '2.1.0'),
    'Gradle module must use a Maven purl');
  AssertEqual('pkg:conda/numpy@2.1.0',
    BuildPackageURL('Conda', 'numpy', '2.1.0'),
    'Conda purl differs');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '^4.17.21'),
    'a range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', 'latest'),
    'an npm tag must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '1'),
    'an npm one-segment X-range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '1.2'),
    'an npm two-segment X-range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', 'canary'),
    'an arbitrary npm dist-tag must not produce a purl');
  AssertEqual('pkg:npm/lodash@1.2.3-beta.1%2Bbuild.4',
    BuildPackageURL('npm', 'lodash', '1.2.3-beta.1+build.4'),
    'an exact npm prerelease/build version was rejected');
  AssertEqual('', BuildPackageURL('Gradle', 'org.example:demo-core', '1.+'),
    'a Gradle dynamic selector must not produce a purl');
  AssertTrue(not IsVersionRange('file:/home/alice/private/pkg'),
    'a private local path must not be classified as a requested range');
  AssertEqual('', BuildPackageURL('npm', '@scope/', '1.0.0'),
    'an incomplete npm scope must not produce a purl');
  AssertEqual('', BuildPackageURL('Gradle', 'org.example:', '1.0.0'),
    'an incomplete Gradle coordinate must not produce a purl');
end;

{**
  Verifies that conservative Gradle and Conda parsers assign resolved purls.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when production parser dispatch loses an exact module identity or
    emits an ecosystem-incompatible Package URL.
}
procedure TestGradleAndCondaPURLs;
var
  DirectoryName, FileName: string;
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  DirectoryName := NewTemporaryDirectory('gradle-conda-purls');
  Components := TObjectList.Create(True);
  try
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'gradle.lockfile';
    WriteText(FileName, 'org.example:demo-core:2.1.0=runtimeClasspath' +
      LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'gradle.lockfile', pkGradleLock, Artifact,
        Components);
      Component := FindComponent(Components, 'org.example:demo-core');
      AssertTrue(Component <> nil, 'Gradle component is missing');
      AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
        Component.PackageURL, 'parsed Gradle purl differs');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'environment.yml';
    WriteText(FileName, 'name: fixture' + LineEnding + 'dependencies:' +
      LineEnding + '  - numpy=2.1.0=py312_0' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'environment.yml', pkEnvironmentYAML, Artifact,
        Components);
      Component := FindComponent(Components, 'numpy');
      AssertTrue(Component <> nil, 'Conda component is missing');
      AssertEqual('pkg:conda/numpy@2.1.0', Component.PackageURL,
        'parsed Conda purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies production manifest parsing and honest CycloneDX version/scope use.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when Cargo requirements, npm paths/tags/partials, or Maven scopes
    are represented as resolved versions or mapped to an incorrect spec scope.
}
procedure TestDeclaredVersionAndScopeSemantics;
var
  DirectoryName, FileName, PropertyValue: string;
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  Task: TScanTask;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, Metadata, PrimaryComponent, ComponentJSON: TJSONObject;
  ComponentArray: TJSONArray;
  I: Integer;
begin
  DirectoryName := NewTemporaryDirectory('declared-version-scope');
  Components := TObjectList.Create(True);
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := DirectoryName;
    Task.TargetRootName := 'declared-version-scope';
    Task.ScannerVersion := AppVersion;

    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'Cargo.toml';
    WriteText(FileName, '[package]' + LineEnding +
      'name = "declared-cargo-project"' + LineEnding +
      'version = "4.0.0"' + LineEnding +
      '[dependencies]' + LineEnding +
      'serde = "1.0.0"' + LineEnding + '[dev-dependencies]' + LineEnding +
      'insta = "1.2"' + LineEnding + '[build-dependencies]' + LineEnding +
      'cc = "1.0.99"' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'Cargo.toml', pkCargoTOML, Artifact, Components);
      AssertTrue(Artifact.Status in [arsParsed, arsPartiallyParsed],
        'Cargo.toml should parse conservatively');
    finally
      Artifact.Free;
    end;
    Component := FindComponent(Components, 'serde');
    AssertTrue(Component <> nil, 'Cargo runtime dependency is missing');
    AssertEqual('runtime', Component.DependencyScope,
      'Cargo runtime scope differs');
    AssertEqual('', Component.PackageURL,
      'Cargo manifest requirement must not produce a resolved purl');
    AssertEqual('development', FindComponent(Components,
      'insta').DependencyScope, 'Cargo dev scope differs');
    AssertEqual('build', FindComponent(Components, 'cc').DependencyScope,
      'Cargo build scope differs');
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      PrimaryComponent := JSONObject(Metadata, 'component');
      AssertEqual('4.0.0', JSONString(PrimaryComponent, 'version'),
        'Cargo project version was treated as a dependency requirement');
      AssertEqual('pkg:cargo/declared-cargo-project@4.0.0',
        JSONString(PrimaryComponent, 'purl'),
        'Cargo project purl is missing or differs');
      AssertTrue(not FindCycloneProperty(PrimaryComponent,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'Cargo project version was exported as a requested range');
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'serde');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil),
        'Cargo manifest requirement became a resolved identity');
      AssertTrue(FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'Cargo shorthand requested range is missing');
      AssertEqual('1.0.0', PropertyValue,
        'Cargo shorthand requested range differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'insta');
      AssertEqual('excluded', JSONString(ComponentJSON, 'scope'),
        'Cargo development dependency must be excluded');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'cc');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Cargo build dependency must retain the required default');
    finally
      Data.Free;
    end;

    Components.Clear;
    Task.Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'package.json';
    WriteText(FileName, '{"dependencies":{' +
      '"local-secret":"file:/home/alice/private/pkg",' +
      '"partial":"1.2","tagged":"canary","exact":"1.2.3"}}');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'package.json', pkPackageJSON, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed, 'package.json should parse');
    finally
      Artifact.Free;
    end;
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    AssertTrue(Pos('/home/alice/private/pkg', string(SBOM)) = 0,
      'default SBOM leaked a local dependency path');
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'partial');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil),
        'npm partial X-range became a resolved identity');
      AssertTrue(FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'npm partial requested range is missing');
      AssertEqual('1.2', PropertyValue, 'npm partial range differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'tagged');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil) and
        not FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'npm dist-tag was mislabeled as a resolved version or range');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'exact');
      AssertEqual('1.2.3', JSONString(ComponentJSON, 'version'),
        'exact npm version was lost');
      AssertEqual('pkg:npm/exact@1.2.3', JSONString(ComponentJSON, 'purl'),
        'exact npm purl differs');
    finally
      Data.Free;
    end;

    Components.Clear;
    Task.Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'pom.xml';
    WriteText(FileName, '<?xml version="1.0"?><project><dependencies>' +
      '<dependency><groupId>org.example</groupId><artifactId>compile-dep' +
      '</artifactId><version>1.0.0</version></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>test-dep' +
      '</artifactId><version>1.0.0</version><scope>test</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>provided-dep' +
      '</artifactId><version>1.0.0</version><scope>provided</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>system-dep' +
      '</artifactId><version>1.0.0</version><scope>system</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>optional-dep' +
      '</artifactId><version>1.0.0</version><optional>true</optional></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>imported-bom' +
      '</artifactId><version>1.0.0</version><scope>import</scope></dependency>' +
      '</dependencies></project>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
      AssertTrue(Artifact.Status = arsParsed, 'scope POM should parse');
    finally
      Artifact.Free;
    end;
    AssertEqual('runtime', FindComponent(Components,
      'compile-dep').DependencyScope, 'Maven compile scope differs');
    AssertEqual('development', FindComponent(Components,
      'test-dep').DependencyScope, 'Maven test scope differs');
    AssertEqual('provided', FindComponent(Components,
      'provided-dep').DependencyScope, 'Maven provided scope was not retained');
    AssertEqual('system', FindComponent(Components,
      'system-dep').DependencyScope, 'Maven system scope was not retained');
    AssertEqual('optional', FindComponent(Components,
      'optional-dep').DependencyScope, 'Maven optional flag differs');
    AssertTrue(FindComponent(Components, 'imported-bom') = nil,
      'Maven dependency-management import became a runtime component');
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'test-dep');
      AssertEqual('excluded', JSONString(ComponentJSON, 'scope'),
        'Maven test dependency must be excluded');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'optional-dep');
      AssertEqual('optional', JSONString(ComponentJSON, 'scope'),
        'Maven optional dependency scope differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'provided-dep');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Maven provided dependency must remain required');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'system-dep');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Maven system dependency must remain required');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
    Components.Free;
  end;
end;

procedure TestPackageJSONParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('package.json', pkPackageJSON, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'package.json should parse');
      AssertEqual(3, Components.Count, 'package.json component count differs');
      Component := FindComponent(Components, 'fixture-app');
      AssertTrue(Component <> nil, 'package root component is missing');
      AssertEqual('application', Component.ComponentType,
        'package root type differs');
      Component := FindComponent(Components, 'lodash');
      AssertEqual('pkg:npm/lodash@4.17.21', Component.PackageURL,
        'npm dependency purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

procedure TestPackageLockParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('package-lock.json', pkPackageLockJSON, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'package lock should parse');
      AssertEqual(3, Components.Count, 'package lock component count differs');
      Component := FindComponent(Components, '@scope/tool');
      AssertTrue(Component <> nil, 'scoped npm package is missing');
      AssertEqual('pkg:npm/%40scope/tool@3.4.5', Component.PackageURL,
        'scoped npm purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

procedure TestXMLParsers;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('pom.xml', pkMavenPOM, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'pom.xml should parse');
      Component := FindComponent(Components, 'demo-core');
      AssertTrue(Component <> nil, 'Maven dependency is missing');
      AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
        Component.PackageURL, 'Maven purl differs');
    finally
      Artifact.Free;
    end;
    Components.Clear;
    ParseFixture('project.csproj', pkMSBuildProject, Components, Artifact);
    try
      Component := FindComponent(Components, 'Example.Core');
      AssertTrue(Component <> nil, 'MSBuild PackageReference is missing');
      AssertEqual('5.4.3', Component.Version, 'MSBuild version differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies current and legacy-compatible Lazarus package-name extraction.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when a current-format `.lpi` requirement is
    not represented as build-scope Free Pascal component evidence.
}
procedure TestLazarusProjectParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  DirectoryName, FileName: string;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('lazarus-current.lpi', pkLazarusXML, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed,
        'current Lazarus project should parse');
      AssertEqual(1, Artifact.ComponentCount,
        'current Lazarus artifact component count differs');
      AssertEqual(1, Components.Count,
        'current Lazarus requirement count differs');
      Component := FindComponent(Components, 'LCL');
      AssertTrue(Component <> nil, 'LCL requirement is missing');
      AssertEqual('', Component.Version,
        'Lazarus requirement should not invent a version');
      AssertEqual('FreePascal', Component.Ecosystem,
        'Lazarus requirement ecosystem differs');
      AssertEqual('library', Component.ComponentType,
        'Lazarus requirement component type differs');
      AssertEqual('lazarus-current.lpi', Component.SourceArtifact,
        'Lazarus requirement source artifact differs');
      AssertEqual('lazarus-project-xml', Component.SourceParser,
        'Lazarus requirement parser evidence differs');
      AssertEqual('build', Component.DependencyScope,
        'Lazarus requirement scope differs');
      AssertEqual('', Component.PackageURL,
        'Lazarus requirement should not invent a package URL');
      AssertEqual(1, Component.EvidencePaths.Count,
        'Lazarus requirement evidence count differs');
      AssertEqual('lazarus-current.lpi', Component.EvidencePaths[0],
        'Lazarus requirement evidence path differs');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    DirectoryName := NewTemporaryDirectory('lazarus-parser-compatibility');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'legacy.lpk';
    WriteText(FileName, '<?xml version="1.0"?><CONFIG><RequiredPackages>' +
      '<Item1><Name Value="LegacyAttr"/></Item1>' +
      '<Item2><Name>LegacyText</Name></Item2>' +
      '</RequiredPackages></CONFIG>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'legacy.lpk', pkLazarusXML, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'legacy Lazarus package should parse');
      AssertEqual(2, Artifact.ComponentCount,
        'legacy Lazarus package-name variants differ');
      AssertTrue(FindComponent(Components, 'LegacyAttr') <> nil,
        'legacy Lazarus Name Value requirement is missing');
      AssertTrue(FindComponent(Components, 'LegacyText') <> nil,
        'legacy Lazarus Name text requirement is missing');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'empty.lpi';
    WriteText(FileName, '<?xml version="1.0"?><CONFIG><ProjectOptions>' +
      '<RequiredPackages Count="0"/></ProjectOptions></CONFIG>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'empty.lpi', pkLazarusXML, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'empty valid Lazarus project should still parse');
      AssertEqual(0, Artifact.ComponentCount,
        'empty Lazarus project should have no components');
      AssertTrue(Pos('No dependency components were identified.',
        Artifact.MessageText) > 0,
        'zero-component Lazarus parse should be visibly annotated');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies deterministic parser-kind size policies and an oversized rejection.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a parser is unbounded or an over-limit manifest is opened,
    parsed, hashed, or omitted instead of becoming a failed artifact.
}
procedure TestManifestSizeLimits;
var
  ParserKind: TParserKind;
  RootName, FileName, ExpectedMessage: string;
  Stream: TFileStream;
  Task: TScanTask;
  Engine: TScanEngine;
  Artifact: TArtifact;
  LimitValue: Int64;
begin
  AssertEqual(0, ManifestSizeLimit(pkNone),
    'unsupported artifacts should not receive a parser size limit');
  for ParserKind := Low(TParserKind) to High(TParserKind) do
    if ParserKind <> pkNone then
      AssertTrue(ManifestSizeLimit(ParserKind) > 0,
        'recognized parser kind has no bounded size policy');
  AssertEqual(8 * 1024 * 1024, ManifestSizeLimit(pkPackageJSON),
    'ordinary manifest size limit differs');
  AssertEqual(32 * 1024 * 1024, ManifestSizeLimit(pkPackageLockJSON),
    'JSON lockfile size limit differs');
  AssertEqual(64 * 1024 * 1024, ManifestSizeLimit(pkCargoLock),
    'line-oriented lockfile size limit differs');

  RootName := NewTemporaryDirectory('manifest-size-limit');
  FileName := IncludeTrailingPathDelimiter(RootName) + 'package.json';
  LimitValue := ManifestSizeLimit(pkPackageJSON);
  Stream := TFileStream.Create(FileName, fmCreate);
  try
    Stream.Size := LimitValue + 1;
  finally
    Stream.Free;
  end;
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'manifest-size-limit';
    Task.Settings.CalculateSHA256 := True;
    AssertTrue(Engine.Scan(Task),
      'over-limit manifest should not fail the containing scan');
    AssertEqual(1, Task.Artifacts.Count,
      'over-limit manifest artifact is missing');
    Artifact := TArtifact(Task.Artifacts[0]);
    ExpectedMessage := 'Manifest exceeds the size limit for package-json: ' +
      IntToStr(LimitValue + 1) + ' bytes (maximum ' + IntToStr(LimitValue) +
      ' bytes).';
    AssertTrue(Artifact.Status = arsFailed,
      'over-limit manifest should be a failed artifact');
    AssertEqual(ExpectedMessage, Artifact.MessageText,
      'over-limit manifest diagnostic differs');
    AssertEqual(0, Artifact.ComponentCount,
      'over-limit manifest should produce no components');
    AssertEqual(1, Task.FailedArtifacts,
      'over-limit manifest failed-artifact count differs');
    AssertEqual(0, Task.ArtifactsParsed,
      'over-limit manifest should not be counted as parsed');
    AssertEqual(0, Task.ComponentsIdentified,
      'over-limit manifest should not identify components');
    AssertEqual('', Artifact.SHA256,
      'over-limit manifest should be rejected before hashing');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

{**
  Verifies parser-level DOCTYPE rejection across XML encodings.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when ASCII or UTF-16LE external-entity declarations reach parsing,
    produce components, lose the stable diagnostic, or valid UTF-8 XML fails.
}
procedure TestXMLDocumentTypeRejection;
var
  DirectoryName, FileName: string;
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  DirectoryName := NewTemporaryDirectory('xml-doctype');
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'pom.xml';
  WriteText(FileName, '<!DOCTYPE project [<!ENTITY local SYSTEM ' +
    '"file:///etc/passwd">]><project><dependencies><dependency>' +
    '<artifactId>&local;</artifactId></dependency></dependencies></project>');
  Components := TObjectList.Create(True);
  Artifact := TArtifact.Create;
  try
    ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
    AssertTrue(Artifact.Status = arsFailed,
      'XML with a document type must be rejected');
    AssertEqual(0, Components.Count,
      'rejected XML must not produce components');
    AssertTrue(Pos('document type declarations are not allowed',
      LowerCase(Artifact.MessageText)) > 0,
      'ASCII XML rejection message is unclear');

    Components.Clear;
    FreeAndNil(Artifact);
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'utf16-pom.xml';
    WriteUTF16LEText(FileName,
      '<?xml version="1.0" encoding="UTF-16"?>' +
      '<!DOCTYPE project [<!ENTITY remote SYSTEM ' +
      '"https://example.invalid/external-entity">]>' +
      '<project><dependencies><dependency><artifactId>&remote;</artifactId>' +
      '</dependency></dependencies></project>');
    Artifact := TArtifact.Create;
    ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
    AssertTrue(Artifact.Status = arsFailed,
      'UTF-16LE XML with a document type must be rejected');
    AssertEqual(0, Components.Count,
      'rejected UTF-16LE XML must not produce components');
    AssertTrue(Pos('document type declarations are not allowed',
      LowerCase(Artifact.MessageText)) > 0,
      'UTF-16LE XML rejection message differs');

    Components.Clear;
    FreeAndNil(Artifact);
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'valid-pom.xml';
    WriteText(FileName, '<?xml version="1.0" encoding="UTF-8"?>' +
      '<project><dependencies><dependency><groupId>org.example</groupId>' +
      '<artifactId>valid-utf8</artifactId><version>1.2.3</version>' +
      '</dependency></dependencies></project>');
    Artifact := TArtifact.Create;
    ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
    AssertTrue(Artifact.Status = arsParsed,
      'valid UTF-8 XML should still parse');
    Component := FindComponent(Components, 'valid-utf8');
    AssertTrue(Component <> nil,
      'valid UTF-8 XML dependency is missing');
    AssertEqual('pkg:maven/org.example/valid-utf8@1.2.3',
      Component.PackageURL, 'valid UTF-8 XML dependency purl differs');
  finally
    Artifact.Free;
    Components.Free;
  end;
end;

{**
  Exercises conservative, deterministic scan-to-scan component comparison.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when identity matching, version reconciliation, diagnostics,
    directionality, determinism, or result ownership regresses.
}
procedure TestComponentComparison;
var
  Baseline, Current: TScanTask;
  Comparison, ReverseComparison, PermutedComparison: TComponentComparison;
  Change: TComponentChange;
  Component: uModels.TComponent;
  StableSignature, FirstBaselineName, FirstCurrentName: string;
  RaisedForNil: Boolean;
begin
  Baseline := TScanTask.Create;
  Current := TScanTask.Create;
  Comparison := nil;
  ReverseComparison := nil;
  PermutedComparison := nil;
  try
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(0, Comparison.Changes.Count,
      'empty scans produced comparison rows');
    AssertEqual(0, Comparison.AddedCount,
      'empty scans produced additions');
    AssertEqual(0, Comparison.RemovedCount,
      'empty scans produced removals');
    AssertEqual(0, Comparison.VersionChangedCount,
      'empty scans produced version changes');
    AssertEqual(0, Comparison.UnchangedCount,
      'empty scans produced unchanged components');
    FreeAndNil(Comparison);

    Component := AddComparisonComponent(Baseline, 'kept', '1.0.0', 'npm',
      'library', 'pkg:npm/kept@1.0.0', 'runtime');
    Component.DeclaredLicenses.Add('MIT');
    Component.DeclaredPublishers.Add('Baseline Publisher');
    Component.SourceParser := 'baseline-parser';
    Component.SHA256 := StringOfChar('a', 64);
    Component := AddComparisonComponent(Current, 'kept', '1.0.0', 'npm',
      'library', 'pkg:npm/kept@1.0.0', 'development');
    Component.EvidencePaths.Add('different/evidence.json');
    Component.DeclaredLicenses.Add('Apache-2.0');
    Component.DeclaredPublishers.Add('Current Publisher');
    Component.SourceParser := 'current-parser';
    Component.SHA256 := StringOfChar('b', 64);
    AddComparisonComponent(Baseline, 'removed', '3.0.0', 'cargo', 'library',
      'pkg:cargo/removed@3.0.0', 'runtime');
    AddComparisonComponent(Current, 'added', '4.0.0', 'pypi', 'library',
      'pkg:pypi/added@4.0.0', 'runtime');
    AddComparisonComponent(Baseline, 'changed', '1.0.0', 'maven', 'library',
      'pkg:maven/org.example/changed@1.0.0', 'runtime');
    AddComparisonComponent(Current, 'changed', '2.0.0', 'maven', 'library',
      'pkg:maven/org.example/changed@2.0.0', 'optional');
    FirstBaselineName := uModels.TComponent(
      Baseline.Components[0]).Name;
    FirstCurrentName := uModels.TComponent(Current.Components[0]).Name;
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.AddedCount,
      'one-sided current component was not added');
    AssertEqual(1, Comparison.RemovedCount,
      'one-sided baseline component was not removed');
    AssertEqual(1, Comparison.VersionChangedCount,
      'unique strong identity was not version-changed');
    AssertEqual(1, Comparison.UnchangedCount,
      'non-version metadata-only changes affected comparison equality');
    AssertEqual(3, Comparison.Changes.Count,
      'basic directional comparison row count differs');
    Change := FindComparisonChange(Comparison, ccVersionChanged, 'changed',
      '1.0.0', '2.0.0');
    AssertTrue(Change <> nil, 'version-change row is missing');
    AssertTrue((Change.IdentityKey <> '') and (Change.RowKey <> ''),
      'version-change row lacks stable keys');
    AssertEqual('pkg:maven/org.example/changed@1.0.0',
      Change.BeforePackageURL, 'baseline Package URL was not copied');
    AssertEqual('pkg:maven/org.example/changed@2.0.0',
      Change.AfterPackageURL, 'current Package URL was not copied');
    AssertEqual('runtime', Change.BeforeScope,
      'baseline scope was not copied');
    AssertEqual('optional', Change.AfterScope,
      'current scope was not copied');
    AssertEqual(FirstBaselineName,
      uModels.TComponent(Baseline.Components[0]).Name,
      'comparison modified baseline component order or fields');
    AssertEqual(FirstCurrentName,
      uModels.TComponent(Current.Components[0]).Name,
      'comparison modified current component order or fields');
    StableSignature := ComparisonSignature(Comparison);

    ReverseComparison := CompareComponentTasks(Current, Baseline);
    AssertEqual(1, ReverseComparison.AddedCount,
      'reverse comparison addition count differs');
    AssertEqual(1, ReverseComparison.RemovedCount,
      'reverse comparison removal count differs');
    AssertEqual(1, ReverseComparison.VersionChangedCount,
      'reverse comparison version-change count differs');
    AssertTrue(FindComparisonChange(ReverseComparison, ccVersionChanged,
      'changed', '2.0.0', '1.0.0') <> nil,
      'reverse comparison did not exchange before and after versions');
    AssertTrue(FindComparisonChange(ReverseComparison, ccRemoved, 'added',
      '4.0.0', '') <> nil,
      'reverse comparison did not turn an addition into a removal');
    FreeAndNil(ReverseComparison);

    Baseline.Components.Exchange(0, Baseline.Components.Count - 1);
    Current.Components.Exchange(0, Current.Components.Count - 1);
    PermutedComparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(StableSignature, ComparisonSignature(PermutedComparison),
      'component input order changed deterministic comparison output');
    FreeAndNil(PermutedComparison);
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'blank-version', '', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Current, 'blank-version', '', 'generic',
      'library', '', 'optional');
    AddComparisonComponent(Baseline, 'range-version', '^1.0', 'npm',
      'library', '', 'runtime');
    AddComparisonComponent(Current, 'range-version', '^2.0', 'npm',
      'library', '', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.UnchangedCount,
      'matching blank versions should remain unchanged');
    AssertEqual(1, Comparison.VersionChangedCount,
      'distinct declared version ranges should be reported as changed');
    AssertTrue(FindComparisonChange(Comparison, ccVersionChanged,
      'range-version', '^1.0', '^2.0') <> nil,
      'version-range change row is missing');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'fallback', '1', 'npm', 'library',
      'pkg:npm/fallback@1', 'runtime');
    AddComparisonComponent(Current, 'fallback', '2', 'npm', 'library', '',
      'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.VersionChangedCount,
      'unambiguous missing-purl fallback did not match strong identity');
    AssertTrue(StringListContainsText(Comparison.Warnings,
      'unambiguous field fallback'),
      'unambiguous Package URL fallback was not disclosed');
    Change := FindComparisonChange(Comparison, ccVersionChanged, 'fallback',
      '1', '2');
    AssertTrue((Change <> nil) and (Change.BeforePackageURL <> '') and
      (Change.AfterPackageURL = ''),
      'fallback comparison row did not preserve directional Package URLs');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'ambiguous', '1', 'npm', 'library',
      'pkg:npm/namespace-one/ambiguous@1', 'runtime');
    AddComparisonComponent(Baseline, 'ambiguous', '1', 'npm', 'library',
      'pkg:npm/namespace-two/ambiguous@1', 'runtime');
    AddComparisonComponent(Current, 'ambiguous', '1', 'npm', 'library', '',
      'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.AddedCount,
      'ambiguous weak record should remain a separate addition');
    AssertEqual(2, Comparison.RemovedCount,
      'ambiguous strong coordinates should remain separate removals');
    AssertEqual(0, Comparison.VersionChangedCount,
      'ambiguous namespace records were paired speculatively');
    AssertTrue(StringListContainsText(Comparison.Warnings,
      'multiple Package URL coordinates'),
      'ambiguous Package URL fallback was not disclosed');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'coordinate', '1', 'npm', 'library',
      'pkg:npm/left/coordinate@1', 'runtime');
    AddComparisonComponent(Current, 'coordinate', '2', 'npm', 'library',
      'pkg:npm/right/coordinate@2', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.AddedCount,
      'different strong coordinate did not remain an addition');
    AssertEqual(1, Comparison.RemovedCount,
      'different strong coordinate did not remain a removal');
    AssertEqual(0, Comparison.VersionChangedCount,
      'different strong coordinates were paired as a version change');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'cross-ecosystem', '1', 'npm',
      'library', '', 'runtime');
    AddComparisonComponent(Current, 'cross-ecosystem', '2', 'maven',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'cross-type', '1', 'generic',
      'application', '', 'runtime');
    AddComparisonComponent(Current, 'cross-type', '2', 'generic',
      'library', '', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(2, Comparison.AddedCount,
      'ecosystem/type boundaries did not preserve additions');
    AssertEqual(2, Comparison.RemovedCount,
      'ecosystem/type boundaries did not preserve removals');
    AssertEqual(0, Comparison.VersionChangedCount,
      'cross-ecosystem or cross-type records were paired');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'CaseSensitive', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Current, 'casesensitive', '2', 'generic',
      'library', '', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.AddedCount,
      'case-distinct weak component name did not remain an addition');
    AssertEqual(1, Comparison.RemovedCount,
      'case-distinct weak component name did not remain a removal');
    AssertEqual(0, Comparison.VersionChangedCount,
      'case-distinct weak component names were paired speculatively');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'multi', '1', 'npm', 'library',
      'pkg:npm/multi@1', 'runtime');
    AddComparisonComponent(Baseline, 'multi', '2', 'npm', 'library',
      'pkg:npm/multi@2', 'runtime');
    AddComparisonComponent(Current, 'multi', '2', 'npm', 'library',
      'pkg:npm/multi@2', 'runtime');
    AddComparisonComponent(Current, 'multi', '3', 'npm', 'library',
      'pkg:npm/multi@3', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.UnchangedCount,
      'multi-version exact match did not cancel');
    AssertEqual(1, Comparison.AddedCount,
      'multi-version residual current version is missing');
    AssertEqual(1, Comparison.RemovedCount,
      'multi-version residual baseline version is missing');
    AssertEqual(0, Comparison.VersionChangedCount,
      'multi-version residuals were paired speculatively');
    AssertTrue(FindComparisonChange(Comparison, ccRemoved, 'multi', '1', '') <>
      nil, 'multi-version removed row differs');
    AssertTrue(FindComparisonChange(Comparison, ccAdded, 'multi', '', '3') <>
      nil, 'multi-version added row differs');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'duplicate', '1', 'cargo', 'library',
      'pkg:cargo/duplicate@1', 'runtime');
    AddComparisonComponent(Baseline, 'duplicate', '1', 'cargo', 'library',
      'pkg:cargo/duplicate@1', 'optional');
    AddComparisonComponent(Current, 'duplicate', '1', 'cargo', 'library',
      'pkg:cargo/duplicate@1', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.UnchangedCount,
      'duplicate records did not collapse to one unchanged version');
    AssertEqual(0, Comparison.Changes.Count,
      'duplicate records produced a spurious change');
    AssertTrue(StringListContainsText(Comparison.Warnings,
      'duplicate records were collapsed'),
      'duplicate collapse was not disclosed');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'canonical-purl', '1.0.0', 'npm',
      'library', 'PKG://NPM//%40scope/%63anonical-purl/@1.0.0?' +
      'b=two&a=%31#/src/%6Cib/', 'runtime');
    AddComparisonComponent(Current, 'canonical-purl', '2.0.0', 'npm',
      'library', 'pkg:npm/%40scope/canonical-purl@2.0.0?' +
      'a=1&b=two#src/lib', 'runtime');
    AddComparisonComponent(Baseline, 'slash-name', '1', 'generic', 'library',
      'pkg:generic/foo%2fbar@1', 'runtime');
    AddComparisonComponent(Current, 'slash-name', '2', 'generic', 'library',
      'pkg:generic/foo%2Fbar@2', 'runtime');
    AddComparisonComponent(Baseline, 'qualifier', '1', 'npm', 'library',
      'pkg:npm/qualifier@1?arch=x86#src', 'runtime');
    AddComparisonComponent(Current, 'qualifier', '2', 'npm', 'library',
      'pkg:npm/qualifier@2?arch=arm64#src', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(2, Comparison.VersionChangedCount,
      'canonical versionless Package URL identity did not match');
    AssertTrue(FindComparisonChange(Comparison, ccVersionChanged,
      'canonical-purl', '1.0.0', '2.0.0') <> nil,
      'canonical Package URL change row is missing');
    Change := FindComparisonChange(Comparison, ccVersionChanged,
      'canonical-purl', '1.0.0', '2.0.0');
    AssertEqual('purl:pkg:npm/%40scope/canonical-purl?' +
      'a=1&b=two#src/lib', Change.IdentityKey,
      'equivalent Package URL spelling did not canonicalize');
    Change := FindComparisonChange(Comparison, ccVersionChanged,
      'slash-name', '1', '2');
    AssertTrue(Change <> nil,
      'percent-encoded slash in a package name did not match');
    AssertEqual('purl:pkg:generic/foo%2Fbar', Change.IdentityKey,
      'package-name slash escape was not canonicalized');
    AssertEqual(1, Comparison.AddedCount,
      'identity-bearing qualifier difference lost its addition');
    AssertEqual(1, Comparison.RemovedCount,
      'identity-bearing qualifier difference lost its removal');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'bad-version-escape', '1', 'generic',
      'library', 'pkg:generic/bad-version-escape@%ZZ', 'runtime');
    AddComparisonComponent(Current, 'bad-version-escape', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'bad-qualifier', '1', 'generic',
      'library', 'pkg:generic/bad-qualifier@1?arch', 'runtime');
    AddComparisonComponent(Current, 'bad-qualifier', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'bad-subpath', '1', 'generic',
      'library', 'pkg:generic/bad-subpath@1#../x', 'runtime');
    AddComparisonComponent(Current, 'bad-subpath', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'bad-subpath-gap', '1', 'generic',
      'library', 'pkg:generic/bad-subpath-gap@1#src//x', 'runtime');
    AddComparisonComponent(Current, 'bad-subpath-gap', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'bad-type', '1', 'generic',
      'library', 'pkg:gen+eric/bad-type@1', 'runtime');
    AddComparisonComponent(Current, 'bad-type', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'raw-unicode', '1', 'generic',
      'library', 'pkg:generic/raw-' + #$C3 + #$A9 + '@1', 'runtime');
    AddComparisonComponent(Current, 'raw-unicode', '1', 'generic',
      'library', '', 'runtime');
    AddComparisonComponent(Baseline, 'bad-utf8', '1', 'generic',
      'library', 'pkg:generic/bad-utf8@%FF', 'runtime');
    AddComparisonComponent(Current, 'bad-utf8', '1', 'generic',
      'library', '', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(7, Comparison.UnchangedCount,
      'malformed Package URLs did not fall back conservatively');
    AssertEqual(0, Comparison.Changes.Count,
      'malformed Package URLs produced confident strong-identity changes');
    AssertTrue((Comparison.Warnings.Count >= 6) and
      StringListContainsText(Comparison.Warnings, '%ZZ') and
      StringListContainsText(Comparison.Warnings, '?arch') and
      StringListContainsText(Comparison.Warnings, '#../x') and
      StringListContainsText(Comparison.Warnings, '#src//x') and
      StringListContainsText(Comparison.Warnings, 'gen+eric') and
      StringListContainsText(Comparison.Warnings, '%FF'),
      'malformed Package URL diagnostics are incomplete');
    FreeAndNil(Comparison);

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'malformed', '1', 'generic', 'library',
      'not a purl', 'runtime');
    AddComparisonComponent(Current, 'malformed', '1', 'generic', 'library',
      '', 'runtime');
    Component := AddComparisonComponent(Baseline, '', '1', 'generic',
      'library', '', 'runtime');
    Component.SourceArtifact := 'baseline-empty.bin';
    Component := AddComparisonComponent(Current, '', '1', 'generic',
      'library', '', 'runtime');
    Component.SourceArtifact := 'current-empty.bin';
    AddComparisonComponent(Baseline, 'project-boundary', '1', 'generic',
      'application', '', 'runtime');
    AddComparisonComponent(Current, 'project-boundary', '1', 'generic',
      'library', '', 'runtime');
    Comparison := CompareComponentTasks(Baseline, Current);
    AssertEqual(1, Comparison.UnchangedCount,
      'malformed purl did not use conservative matching fields');
    AssertEqual(2, Comparison.AddedCount,
      'empty-name source or project boundary addition count differs');
    AssertEqual(2, Comparison.RemovedCount,
      'empty-name source or project boundary removal count differs');
    AssertTrue(StringListContainsText(Comparison.Warnings, 'is malformed'),
      'malformed Package URL was not disclosed');
    AssertTrue(StringListContainsText(Comparison.Warnings,
      'component without a name'),
      'empty component name was not disclosed');
    FreeAndNil(Comparison);

    RaisedForNil := False;
    try
      Comparison := CompareComponentTasks(nil, Current);
    except
      on EArgumentNilException do
        RaisedForNil := True;
    end;
    AssertTrue(RaisedForNil, 'nil baseline did not raise an argument error');

    Baseline.Components.Clear;
    Current.Components.Clear;
    AddComparisonComponent(Baseline, 'owned-result', '1', 'pypi', 'library',
      'pkg:pypi/owned-result@1', 'runtime');
    AddComparisonComponent(Current, 'owned-result', '2', 'pypi', 'library',
      'pkg:pypi/owned-result@2', 'optional');
    Comparison := CompareComponentTasks(Baseline, Current);
    FreeAndNil(Baseline);
    FreeAndNil(Current);
    Change := FindComparisonChange(Comparison, ccVersionChanged,
      'owned-result', '1', '2');
    AssertTrue(Change <> nil,
      'comparison rows borrowed component lifetime from input tasks');
    AssertEqual('optional', Change.AfterScope,
      'comparison-owned row lost copied scalar state');
  finally
    PermutedComparison.Free;
    ReverseComparison.Free;
    Comparison.Free;
    Current.Free;
    Baseline.Free;
  end;
end;

procedure TestHistoryRoundTrip;
var
  DirectoryName, RelocatedSBOM: string;
  Store: TTaskHistoryStore;
  Tasks, Loaded: TObjectList;
  Task: TScanTask;
  WarningText: string;
begin
  DirectoryName := NewTemporaryDirectory('history-roundtrip');
  Store := TTaskHistoryStore.Create(DirectoryName);
  Tasks := TObjectList.Create(True);
  Loaded := TObjectList.Create(True);
  try
    Task := TScanTask.Create;
    Task.TargetDirectory := '/tmp/example';
    Task.TargetRootName := 'example';
    Task.Status := tsCompleted;
    Task.FilesInspected := 42;
    Task.Warnings.Add('fixture warning');
    Task.InspectionTools.Add('readelf');
    Task.GeneratedSBOMPath := '/old/location/' + Task.ID + '.cdx.json';
    RelocatedSBOM := IncludeTrailingPathDelimiter(DirectoryName) + 'sboms' +
      DirectorySeparator + Task.ID + '.cdx.json';
    WriteText(RelocatedSBOM, '{}');
    Tasks.Add(Task);
    Store.Save(Tasks);
    AssertTrue(Store.Load(Loaded, WarningText), 'history should load');
    AssertEqual('', WarningText, 'valid history produced a warning');
    AssertEqual(1, Loaded.Count, 'loaded task count differs');
    AssertEqual(42, TScanTask(Loaded[0]).FilesInspected,
      'loaded file count differs');
    AssertEqual('fixture warning', TScanTask(Loaded[0]).Warnings[0],
      'loaded warning differs');
    AssertEqual('readelf', TScanTask(Loaded[0]).InspectionTools[0],
      'inspection tool was not persisted');
    AssertEqual(RelocatedSBOM, TScanTask(Loaded[0]).GeneratedSBOMPath,
      'SBOM path was not relocated with the application data');
  finally
    Loaded.Free;
    Tasks.Free;
    Store.Free;
  end;
end;

{**
  Verifies shared task-history ownership, revisions, summaries, and deletion.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when service ownership, persistence, event ordering, terminal-state
    protection, canonical SBOM cleanup, or transactional rollback regresses.
}
procedure TestTaskHistoryService;
var
  DirectoryName, RollbackDirectory, RootDirectory, CanonicalSBOM,
    ExternalExport, WarningText, BlockingPersistencePath: string;
  Service, RollbackService, RootService: TTaskHistoryService;
  Observer: THistoryChangeObserver;
  Summaries, NonOwningSummaries: TObjectList;
  NewTask, BorrowedTask, Clone: TScanTask;
  Summary: TTaskHistorySummary;
  RevisionBefore: QWord;
  EventCountBefore: Integer;
  RaisedForNonOwningList, RaisedForUnsafeID: Boolean;
begin
  DirectoryName := NewTemporaryDirectory('shared-history-service');
  Service := TTaskHistoryService.Create(DirectoryName);
  Observer := THistoryChangeObserver.Create;
  Summaries := TObjectList.Create(True);
  NonOwningSummaries := TObjectList.Create(False);
  Clone := nil;
  NewTask := nil;
  try
    AssertTrue(not Service.UsesDefaultDataDirectory,
      'explicit history service reports the operator profile directory');
    AssertTrue(SameFileName(ExpandFileName(DirectoryName),
      Service.DataDirectory), 'explicit history data directory differs');
    AssertEqual(0, Service.TaskCount,
      'new explicit history service is not empty');
    AssertEqual(0, Int64(Service.Revision),
      'new history service revision is not zero');
    AssertEqual('', Service.StartupWarning,
      'empty explicit history produced a startup warning');
    Service.OnChanged := @Observer.Changed;

    RaisedForUnsafeID := False;
    NewTask := NewHistoryTask('UPPER-ID',
      '2026-08-20T09:00:00.000Z', tsCompleted, 'unsafe-id-target');
    try
      Service.AddTask(NewTask);
      NewTask := nil;
    except
      on EArgumentException do
        RaisedForUnsafeID := True;
    end;
    AssertTrue(RaisedForUnsafeID,
      'service accepted a non-lowercase filename-colliding task ID');
    NewTask.Free;
    NewTask := nil;
    AssertEqual(0, Service.TaskCount,
      'refused unsafe task ID changed service ownership');
    AssertEqual(0, Observer.Count,
      'refused unsafe task ID emitted a history event');

    NewTask := NewHistoryTask('completed-new',
      '2026-08-20T10:00:00.000Z', tsCompleted, 'new-target');
    NewTask.Warnings.Add('review this scan');
    AddComparisonComponent(NewTask, 'one', '1', 'npm', 'library',
      'pkg:npm/one@1', 'runtime');
    AddComparisonComponent(NewTask, 'two', '2', 'npm', 'library',
      'pkg:npm/two@2', 'runtime');
    Service.AddTask(NewTask);
    NewTask := nil;
    AssertTrue((Observer.LastKind = thcAdded) and
      (Observer.LastTaskID = 'completed-new') and
      (Observer.LastRevision = Service.Revision),
      'addition event identity or revision differs');

    NewTask := NewHistoryTask('completed-b',
      '2025-01-01T00:00:00.000Z', tsCompleted, 'tie-b');
    Service.AddTask(NewTask);
    NewTask := nil;
    NewTask := NewHistoryTask('completed-a',
      '2025-01-01T00:00:00.000Z', tsCompleted, 'tie-a');
    Service.AddTask(NewTask);
    NewTask := nil;
    NewTask := NewHistoryTask('running-task',
      '2026-08-20T11:00:00.000Z', tsRunning, 'running-target');
    Service.AddTask(NewTask);
    NewTask := nil;
    NewTask := NewHistoryTask('cancelled-task',
      '2026-08-20T11:10:00.000Z', tsCancelled, 'cancelled-target');
    Service.AddTask(NewTask);
    NewTask := nil;
    NewTask := NewHistoryTask('pending-task',
      '2026-08-20T11:20:00.000Z', tsPending, 'pending-target');
    Service.AddTask(NewTask);
    NewTask := nil;

    AssertEqual(6, Service.TaskCount,
      'service did not retain sole ownership of every added task');
    AssertEqual(6, Observer.Count,
      'history addition event count differs');
    AssertEqual(6, Int64(Service.Revision),
      'history revision did not advance once per addition');
    AssertTrue(not FileExists(IncludeTrailingPathDelimiter(DirectoryName) +
      'history.json'), 'AddTask persisted history implicitly');

    Service.GetCompletedTaskSummaries(Summaries);
    AssertEqual(3, Summaries.Count,
      'completed summaries included active or non-completed tasks');
    Summary := TTaskHistorySummary(Summaries[0]);
    AssertEqual('completed-new', Summary.ID,
      'completed summaries are not ordered newest first');
    AssertEqual(2, Summary.ComponentCount,
      'completed summary component count differs');
    AssertEqual(1, Summary.WarningCount,
      'completed summary warning count differs');
    AssertEqual('0.5.0', Summary.ScannerVersion,
      'completed summary scanner version differs');
    AssertEqual('completed-a',
      TTaskHistorySummary(Summaries[1]).ID,
      'equal-timestamp summaries are not ordered by ordinal identifier');
    AssertEqual('completed-b',
      TTaskHistorySummary(Summaries[2]).ID,
      'equal-timestamp summary tie-break differs');

    RaisedForNonOwningList := False;
    try
      Service.GetCompletedTaskSummaries(NonOwningSummaries);
    except
      on EArgumentException do
        RaisedForNonOwningList := True;
    end;
    AssertTrue(RaisedForNonOwningList,
      'summary service accepted a non-owning destination list');

    RevisionBefore := Service.Revision;
    AssertTrue(not Service.DeleteTask('running-task', WarningText),
      'running task deletion was accepted');
    AssertTrue(Pos('cannot be deleted', WarningText) > 0,
      'running task deletion refusal is unclear');
    AssertTrue(not Service.DeleteTask('pending-task', WarningText),
      'pending task deletion was accepted');
    AssertEqual(Int64(RevisionBefore), Int64(Service.Revision),
      'refused active-task deletion changed the revision');
    AssertEqual(6, Observer.Count,
      'refused active-task deletion emitted a mutation');

    Service.Save;
    AssertTrue(FileExists(IncludeTrailingPathDelimiter(DirectoryName) +
      'history.json'), 'explicit history save produced no file');
    Clone := Service.CloneTaskByID('completed-new');
    AssertTrue(Clone <> nil, 'completed task clone is missing');
    AssertEqual(2, Clone.Components.Count,
      'task clone did not deep-copy components');
    BorrowedTask := Service.FindTaskByID('completed-new');
    AssertTrue(BorrowedTask <> nil, 'borrowed task lookup failed');
    BorrowedTask.TargetRootName := 'persisted-new-target';
    uModels.TComponent(BorrowedTask.Components[0]).Name :=
      'persisted-component';
    AssertEqual('new-target', Clone.TargetRootName,
      'task clone borrowed task scalar state');
    AssertEqual('one', uModels.TComponent(Clone.Components[0]).Name,
      'task clone borrowed component state');
    RevisionBefore := Service.Revision;
    Service.NotifyTaskUpdated('completed-new', True);
    AssertEqual(Int64(RevisionBefore + 1), Int64(Service.Revision),
      'persisted task update did not advance the revision once');
    AssertTrue((Observer.LastKind = thcUpdated) and
      (Observer.LastTaskID = 'completed-new'),
      'task update event identity differs');

    RevisionBefore := Service.Revision;
    AssertTrue(Service.Reload(WarningText),
      'valid shared task history did not reload');
    AssertEqual('', WarningText, 'valid shared history reload warned');
    AssertEqual(Int64(RevisionBefore + 1), Int64(Service.Revision),
      'history reset did not advance the revision once');
    AssertTrue((Observer.LastKind = thcReset) and
      (Observer.LastTaskID = ''),
      'history reload did not publish a reset');
    BorrowedTask := Service.FindTaskByID('completed-new');
    AssertTrue(BorrowedTask <> nil, 'persisted task disappeared after reload');
    AssertEqual('persisted-new-target', BorrowedTask.TargetRootName,
      'NotifyTaskUpdated did not persist changed task state');
    AssertEqual('persisted-component',
      uModels.TComponent(BorrowedTask.Components[0]).Name,
      'NotifyTaskUpdated did not persist changed component state');
    AssertEqual('new-target', Clone.TargetRootName,
      'caller-owned clone changed when live history reloaded');
    AssertEqual('one', uModels.TComponent(Clone.Components[0]).Name,
      'clone component changed when live history reloaded');
    Service.GetCompletedTaskSummaries(Summaries);
    AssertEqual(3, Summaries.Count,
      'reload exposed interrupted tasks as completed summaries');

    CanonicalSBOM := IncludeTrailingPathDelimiter(DirectoryName) + 'sboms' +
      DirectorySeparator + 'completed-new.cdx.json';
    ExternalExport := IncludeTrailingPathDelimiter(TemporaryRoot) +
      'external-completed-new.cdx.json';
    WriteText(CanonicalSBOM, '{"owned":true}');
    WriteText(ExternalExport, '{"exported":true}');
    BorrowedTask := Service.FindTaskByID('completed-new');
    BorrowedTask.GeneratedSBOMPath := ExternalExport;
    Service.NotifyTaskUpdated(BorrowedTask.ID, True);
    RevisionBefore := Service.Revision;
    AssertTrue(Service.DeleteTask('completed-new', WarningText),
      'completed task could not be deleted');
    AssertEqual('', WarningText,
      'safe completed-task deletion produced a warning');
    AssertTrue(Service.FindTaskByID('completed-new') = nil,
      'deleted task remains in live history');
    AssertTrue(not FileExists(CanonicalSBOM),
      'canonical application-owned SBOM was retained');
    AssertTrue(FileExists(ExternalExport),
      'arbitrary exported SBOM was deleted with task history');
    AssertEqual(Int64(RevisionBefore + 1), Int64(Service.Revision),
      'committed task deletion did not advance the revision once');
    AssertTrue((Observer.LastKind = thcRemoved) and
      (Observer.LastTaskID = 'completed-new'),
      'task removal event identity differs');
    AssertEqual('new-target', Clone.TargetRootName,
      'caller-owned clone changed after service-owned task deletion');

    RevisionBefore := Service.Revision;
    AssertTrue(Service.Reload(WarningText),
      'history did not reload after committed deletion');
    AssertTrue(Service.FindTaskByID('completed-new') = nil,
      'deleted task returned after persistence reload');
    AssertEqual(Int64(RevisionBefore + 1), Int64(Service.Revision),
      'post-deletion reload revision differs');
    RevisionBefore := Service.Revision;
    AssertTrue(not Service.DeleteTask('missing-task', WarningText),
      'unknown task deletion was accepted');
    AssertTrue(Pos('not found', WarningText) > 0,
      'unknown task deletion refusal is unclear');
    AssertEqual(Int64(RevisionBefore), Int64(Service.Revision),
      'unknown task deletion changed the revision');

    { A failed disk refresh must leave the valid in-memory repository and its
      observable revision untouched. }
    Service.Save;
    Service.Save;
    WriteText(IncludeTrailingPathDelimiter(DirectoryName) + 'history.json',
      '{invalid primary');
    WriteText(IncludeTrailingPathDelimiter(DirectoryName) +
      'history.json.bak', '{invalid backup');
    RevisionBefore := Service.Revision;
    EventCountBefore := Observer.Count;
    AssertTrue(not Service.Reload(WarningText),
      'invalid primary and backup history unexpectedly reloaded');
    AssertTrue(WarningText <> '',
      'failed shared-history reload produced no diagnostic');
    AssertTrue(Service.FindTaskByID('completed-a') <> nil,
      'failed shared-history reload discarded the live task list');
    AssertEqual(Int64(RevisionBefore), Int64(Service.Revision),
      'failed shared-history reload changed the revision');
    AssertEqual(EventCountBefore, Observer.Count,
      'failed shared-history reload emitted a reset event');
  finally
    Service.OnChanged := nil;
    NewTask.Free;
    Clone.Free;
    NonOwningSummaries.Free;
    Summaries.Free;
    Observer.Free;
    Service.Free;
  end;

  RollbackDirectory := NewTemporaryDirectory('history-delete-rollback');
  RollbackService := TTaskHistoryService.Create(RollbackDirectory);
  NewTask := nil;
  try
    NewTask := NewHistoryTask('rollback-task',
      '2026-08-20T12:00:00.000Z', tsCompleted, 'rollback-target');
    RollbackService.AddTask(NewTask);
    NewTask := nil;
    RollbackService.Save;
    CanonicalSBOM := IncludeTrailingPathDelimiter(RollbackDirectory) +
      'sboms' + DirectorySeparator + 'rollback-task.cdx.json';
    WriteText(CanonicalSBOM, '{"owned":true}');
    BlockingPersistencePath := IncludeTrailingPathDelimiter(RollbackDirectory) +
      'history.json.bak';
    AssertTrue(ForceDirectories(BlockingPersistencePath),
      'could not create rollback failure fixture');
    RevisionBefore := RollbackService.Revision;
    AssertTrue(not RollbackService.DeleteTask('rollback-task', WarningText),
      'task deletion committed despite persistence failure');
    AssertTrue(Pos('rolled back', WarningText) > 0,
      'persistence failure did not disclose deletion rollback');
    AssertTrue(RollbackService.FindTaskByID('rollback-task') <> nil,
      'failed deletion did not restore the live task');
    AssertTrue(FileExists(CanonicalSBOM),
      'failed deletion removed the application-owned SBOM');
    AssertEqual(Int64(RevisionBefore), Int64(RollbackService.Revision),
      'rolled-back deletion changed the history revision');
    RemoveDir(BlockingPersistencePath);
  finally
    NewTask.Free;
    RollbackService.Free;
  end;

  {$IFDEF Windows}
  RootDirectory := ExtractFileDrive(ExpandFileName(TemporaryRoot)) +
    DirectorySeparator;
  {$ELSE}
  RootDirectory := DirectorySeparator;
  {$ENDIF}
  RootService := TTaskHistoryService.Create(RootDirectory);
  try
    AssertTrue(RootService.DataDirectory <> '',
      'explicit filesystem root collapsed to an empty data directory');
    AssertTrue(SameFileName(RootDirectory, RootService.DataDirectory),
      'explicit filesystem root was not preserved');
    AssertTrue(SameFileName(RootDirectory, CanonicalPath(RootDirectory)),
      'canonical filesystem root collapsed to an empty path');
    AssertTrue(PathIsWithin(IncludeTrailingPathDelimiter(RootDirectory) +
      'synthetic-child', RootDirectory),
      'filesystem-root containment rejected a direct child');
  finally
    RootService.Free;
  end;
end;

procedure TestApplicationDataMigration;
var
  SourceDirectory, DestinationDirectory, WarningText: string;
begin
  SourceDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
    '.sbom-analyzer';
  DestinationDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
    '.purpleray' + DirectorySeparator + 'sbom-analyzer';
  ForceDirectories(SourceDirectory);
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'history.json',
    '{"format_version":1,"tasks":[]}');
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'sboms' +
    DirectorySeparator + 'fixture.cdx.json', '{}');
  AssertTrue(MigrateApplicationDataDirectory(SourceDirectory,
    DestinationDirectory, WarningText), 'application data migration failed');
  AssertEqual('', WarningText, 'successful migration produced a warning');
  AssertTrue(not DirectoryExists(SourceDirectory),
    '~/.sbom-analyzer was retained after successful migration');
  AssertTrue(DirectoryExists(DestinationDirectory),
    '~/.purpleray/sbom-analyzer was not created');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(DestinationDirectory) +
    'history.json'), 'history was not migrated');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(DestinationDirectory) +
    'sboms' + DirectorySeparator + 'fixture.cdx.json'),
    'saved SBOM was not migrated');

  { A later partial migration must preserve the legacy directory when a file
    would overwrite data already present at the destination. }
  ForceDirectories(SourceDirectory);
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'history.json',
    '{"format_version":1,"tasks":[{"legacy":true}]}');
  AssertTrue(not MigrateApplicationDataDirectory(SourceDirectory,
    DestinationDirectory, WarningText),
    'colliding application data migration unexpectedly succeeded');
  AssertTrue(WarningText <> '',
    'colliding application data migration produced no warning');
  AssertTrue(DirectoryExists(SourceDirectory),
    'legacy directory was removed after a partial migration');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(SourceDirectory) +
    'history.json'), 'unmigrated legacy data was deleted');
end;

procedure TestExportNaming;
var
  Task: TScanTask;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.TargetRootName := 'Demo: Folder';
    AssertEqual('20250102_030405_Demo_Folder_' + Task.ID + '.cdx.json',
      TaskSBOMExportFileName(Task), 'SBOM export filename differs');
  finally
    Task.Free;
  end;
end;

function ArchiveContains(AEntries: TFullZipFileEntries;
  const AName: string): Boolean;
var
  I: Integer;
begin
  for I := 0 to AEntries.Count - 1 do
    if AEntries[I].ArchiveFileName = AName then
      Exit(True);
  Result := False;
end;

procedure TestDatabaseArchive;
var
  DataDirectory, ArchiveName: string;
  UnZipper: TUnZipper;
begin
  DataDirectory := NewTemporaryDirectory('database-archive');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'history.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'settings.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'sboms' +
    DirectorySeparator + 'fixture.cdx.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'ignored.tmp',
    'temporary');
  ArchiveName := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'database-export.zip';
  ExportDatabaseArchive(DataDirectory, ArchiveName);
  AssertTrue(FileExists(ArchiveName), 'database archive was not created');
  UnZipper := TUnZipper.Create;
  try
    UnZipper.FileName := ArchiveName;
    UnZipper.Examine;
    AssertEqual(3, UnZipper.Entries.Count,
      'database archive entry count differs');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/history.json'), 'database archive omits history');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/settings.json'), 'database archive omits settings');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/sboms/fixture.cdx.json'),
      'database archive omits saved SBOMs');
  finally
    UnZipper.Free;
  end;
end;

procedure TestReadElfParsing;
var
  Inspection: TSystemInspection;
begin
  Inspection := TSystemInspection.Create;
  try
    AssertTrue(ParseReadElfOutput(
      ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' + LineEnding +
      ' 0x0000000000000001 (NEEDED) Shared library: [libz.so.1]' + LineEnding +
      ' 0x000000000000000e (SONAME) Library soname: [libdemo.so.4.2]' + LineEnding +
      ' Build ID: 0123456789abcdef', Inspection),
      'readelf evidence was not recognized');
    AssertEqual(2, Inspection.Dependencies.Count,
      'readelf dependency count differs');
    AssertEqual('libc.so.6', Inspection.Dependencies[0],
      'first readelf dependency differs');
    AssertEqual('libz.so.1', Inspection.Dependencies[1],
      'second readelf dependency differs');
    AssertEqual('4.2', Inspection.ComponentVersion,
      'readelf SONAME version differs');
    AssertEqual('build ID: 0123456789abcdef', Inspection.Details[0],
      'readelf build ID differs');
  finally
    Inspection.Free;
  end;
end;

procedure TestNativeDependencyVersions;
begin
  AssertEqual('', NativeDependencyVersion('libc.so.6'),
    'ELF SONAME ABI major must not become a product version');
  AssertEqual('', NativeDependencyVersion('libgtk-3.so.0'),
    'a bare ELF ABI suffix must not become a product version');
  AssertEqual('1.2.3', NativeDependencyVersion('/opt/lib/libdemo.so.1.2.3'),
    'ELF SONAME dotted version differs');
  AssertEqual('3', NativeDependencyVersion('/usr/lib/libcrypto.3.dylib'),
    'Mach-O install-name version differs');
  AssertEqual('', NativeDependencyVersion('kernel32.dll'),
    'unversioned PE import must not invent a version');
  AssertEqual('', NativeDependencyVersion('api-ms-win-core-file-l1-1-0.dll'),
    'Windows API-set tokens must not become a version');
  AssertEqual('', NativeDependencyVersion('libSystem.B.dylib'),
    'non-numeric Mach-O suffix must not become a version');
end;

procedure TestNativeVersionScanAndSBOM;
var
  DirectoryName, FileName: string;
  Buffer: array[0..63] of Byte;
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
  SBOM: UTF8String;
begin
  DirectoryName := NewTemporaryDirectory('native-version-scan');
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'libdemo.so.4.2';
  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
  Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
  SetUInt16LE(Buffer, 16, 3);
  SetUInt16LE(Buffer, 18, 62);
  WriteBytes(FileName, Buffer);
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'libc.so.6';
  WriteBytes(FileName, Buffer);

  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := DirectoryName;
    Task.TargetRootName := 'native-version-scan';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'native version fixture scan failed');
    Component := FindComponent(Task.Components, 'libdemo.so.4.2');
    AssertTrue(Component <> nil, 'versioned native component is missing');
    AssertEqual('4.2', Component.Version,
      'versioned native component lost filename evidence');
    Component := FindComponent(Task.Components, 'libc.so.6');
    AssertTrue(Component <> nil, 'bare-ABI native component is missing');
    AssertEqual('', Component.Version,
      'bare ELF ABI suffix leaked into the component version');
    SBOM := GenerateCycloneDX(Task);
    AssertTrue(Pos('"version" : "4.2"', string(SBOM)) > 0,
      'native version evidence is missing from CycloneDX output');
    AssertTrue(Pos('purpleray-sbom-analyzer:soname-abi-version',
      string(SBOM)) > 0,
      'bare ELF ABI evidence is missing from CycloneDX properties');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure TestNativeDependencyTables;
var
  DirectoryName, FileName: string;
  Buffer: array[0..511] of Byte;
  Dependencies: TStringList;
begin
  DirectoryName := NewTemporaryDirectory('native-dependencies');
  Dependencies := TStringList.Create;
  try
    Dependencies.Sorted := True;
    Dependencies.Duplicates := dupIgnore;

    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
    Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
    SetUInt64LE(Buffer, 32, 64);
    SetUInt16LE(Buffer, 54, 56);
    SetUInt16LE(Buffer, 56, 2);
    SetUInt32LE(Buffer, 64, 1);
    SetUInt64LE(Buffer, 72, 0);
    SetUInt64LE(Buffer, 80, $400000);
    SetUInt64LE(Buffer, 96, SizeOf(Buffer));
    SetUInt32LE(Buffer, 120, 2);
    SetUInt64LE(Buffer, 128, 256);
    SetUInt64LE(Buffer, 136, $400100);
    SetUInt64LE(Buffer, 152, 64);
    SetUInt64LE(Buffer, 256, 5);
    SetUInt64LE(Buffer, 264, $400180);
    SetUInt64LE(Buffer, 272, 10);
    SetUInt64LE(Buffer, 280, 32);
    SetUInt64LE(Buffer, 288, 1);
    SetBufferString(Buffer, 384, 'libfixture.so');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.elf';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'ELF', Dependencies),
      'ELF dependency table was not parsed');
    AssertEqual(1, Dependencies.Count, 'ELF dependency count differs');
    AssertEqual('libfixture.so', Dependencies[0],
      'ELF dependency name differs');

    Dependencies.Clear;
    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := Ord('M'); Buffer[1] := Ord('Z');
    SetUInt32LE(Buffer, $3C, 64);
    Buffer[64] := Ord('P'); Buffer[65] := Ord('E');
    SetUInt16LE(Buffer, 70, 1);
    SetUInt16LE(Buffer, 84, 224);
    SetUInt16LE(Buffer, 88, $010B);
    SetUInt32LE(Buffer, 116, $400000);
    SetUInt32LE(Buffer, 148, 400);
    SetUInt32LE(Buffer, 180, 16);
    SetUInt32LE(Buffer, 192, $1000);
    SetUInt32LE(Buffer, 196, 40);
    SetUInt32LE(Buffer, 320, $100);
    SetUInt32LE(Buffer, 324, $1000);
    SetUInt32LE(Buffer, 328, $70);
    SetUInt32LE(Buffer, 332, 400);
    SetUInt32LE(Buffer, 400, $1060);
    SetUInt32LE(Buffer, 412, $1050);
    SetBufferString(Buffer, 480, 'KERNEL32.dll');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.exe';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'PE', Dependencies),
      'PE import table was not parsed');
    AssertEqual(1, Dependencies.Count, 'PE dependency count differs');
    AssertEqual('KERNEL32.dll', Dependencies[0],
      'PE dependency name differs');

    Dependencies.Clear;
    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := $CF; Buffer[1] := $FA; Buffer[2] := $ED; Buffer[3] := $FE;
    SetUInt32LE(Buffer, 4, $01000007);
    SetUInt32LE(Buffer, 12, 2);
    SetUInt32LE(Buffer, 16, 1);
    SetUInt32LE(Buffer, 20, 64);
    SetUInt32LE(Buffer, 32, $0C);
    SetUInt32LE(Buffer, 36, 64);
    SetUInt32LE(Buffer, 40, 24);
    SetBufferString(Buffer, 56, '@rpath/libFixture.dylib');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.macho';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'Mach-O', Dependencies),
      'Mach-O load commands were not parsed');
    AssertEqual(1, Dependencies.Count, 'Mach-O dependency count differs');
    AssertEqual('@rpath/libFixture.dylib', Dependencies[0],
      'Mach-O dependency name differs');
  finally
    Dependencies.Free;
  end;
end;

procedure TestAtomicHistoryRecovery;
var
  DirectoryName, InvalidDirectory: string;
  Store, InvalidStore: TTaskHistoryStore;
  Tasks, Loaded: TObjectList;
  FirstTask, SecondTask, SentinelTask: TScanTask;
  WarningText: string;
  SearchRecord: TSearchRec;
begin
  DirectoryName := NewTemporaryDirectory('history-recovery');
  Store := TTaskHistoryStore.Create(DirectoryName);
  Tasks := TObjectList.Create(True);
  Loaded := TObjectList.Create(True);
  try
    FirstTask := TScanTask.Create;
    FirstTask.TargetRootName := 'first';
    FirstTask.Status := tsCompleted;
    Tasks.Add(FirstTask);
    Store.Save(Tasks);
    SecondTask := TScanTask.Create;
    SecondTask.TargetRootName := 'second';
    SecondTask.Status := tsCompleted;
    Tasks.Add(SecondTask);
    Store.Save(Tasks);
    WriteText(Store.HistoryFileName, '{invalid json');
    AssertTrue(Store.Load(Loaded, WarningText), 'backup history should recover');
    AssertEqual(1, Loaded.Count, 'backup should contain prior task set');
    AssertEqual('first', TScanTask(Loaded[0]).TargetRootName,
      'wrong task recovered from backup');
    AssertTrue(Pos('backup was loaded', WarningText) > 0,
      'recovery warning is unclear');
    AssertTrue(FindFirst(IncludeTrailingPathDelimiter(DirectoryName) +
      'history.corrupt-*.json', faAnyFile, SearchRecord) = 0,
      'malformed history was not preserved');
    FindClose(SearchRecord);

    { Recover the backup when a process crash leaves the atomic-write window
      after the active file moved aside but before the new file activated. }
    AssertTrue(DeleteFile(Store.HistoryFileName),
      'could not remove the active history recovery fixture');
    Loaded.Clear;
    AssertTrue(Store.Load(Loaded, WarningText),
      'missing active history did not recover its valid backup');
    AssertEqual(1, Loaded.Count,
      'missing-primary recovery loaded the wrong task set');
    AssertEqual('first', TScanTask(Loaded[0]).TargetRootName,
      'missing-primary recovery loaded the wrong backup task');
    AssertTrue((Pos('missing', LowerCase(WarningText)) > 0) and
      (Pos('backup', LowerCase(WarningText)) > 0),
      'missing-primary recovery warning is unclear');
  finally
    Loaded.Free;
    Tasks.Free;
    Store.Free;
  end;

  InvalidDirectory := NewTemporaryDirectory('history-identity-validation');
  InvalidStore := TTaskHistoryStore.Create(InvalidDirectory);
  Loaded := TObjectList.Create(True);
  try
    SentinelTask := TScanTask.Create;
    SentinelTask.ID := 'sentinel-task';
    Loaded.Add(SentinelTask);
    WriteText(InvalidStore.HistoryFileName,
      '{"format_version":1,"tasks":[{}]}');
    AssertTrue(not InvalidStore.Load(Loaded, WarningText),
      'history task without an identifier was accepted');
    AssertTrue((Loaded.Count = 1) and
      (TScanTask(Loaded[0]).ID = 'sentinel-task'),
      'failed missing-ID load replaced the destination list');

    WriteText(InvalidStore.HistoryFileName,
      '{"format_version":1,"tasks":[{"id":"duplicate-task"},' +
      '{"id":"duplicate-task"}]}');
    AssertTrue(not InvalidStore.Load(Loaded, WarningText),
      'history with duplicate task identifiers was accepted');
    AssertTrue(Pos('duplicate', LowerCase(WarningText)) > 0,
      'duplicate task identifier diagnostic is unclear');

    WriteText(InvalidStore.HistoryFileName,
      '{"format_version":1,"tasks":[{"id":"../escape",' +
      '"generated_sbom_path":"/missing/export.cdx.json"}]}');
    AssertTrue(not InvalidStore.Load(Loaded, WarningText),
      'unsafe history task identifier was accepted');
    AssertTrue(Pos('unsafe identifier', LowerCase(WarningText)) > 0,
      'unsafe task identifier diagnostic is unclear');
    AssertTrue((Loaded.Count = 1) and
      (TScanTask(Loaded[0]).ID = 'sentinel-task'),
      'failed identifier validation replaced the destination list');
  finally
    Loaded.Free;
    InvalidStore.Free;
  end;
end;

procedure TestBinaryInspection;
var
  DirectoryName, FileName: string;
  Buffer: array[0..127] of Byte;
  Info: TBinaryInfo;
begin
  DirectoryName := NewTemporaryDirectory('binary-headers');
  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := Ord('M'); Buffer[1] := Ord('Z'); Buffer[$3C] := $40;
  Buffer[$40] := Ord('P'); Buffer[$41] := Ord('E');
  Buffer[$44] := $64; Buffer[$45] := $86;
  Buffer[$56] := $00; Buffer[$57] := $20;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample.dll';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'PE header was not detected');
  AssertEqual('PE', Info.FormatName, 'PE format differs');
  AssertEqual('x86_64', Info.Architecture, 'PE architecture differs');
  AssertEqual('library', Info.Classification, 'PE classification differs');

  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
  Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
  Buffer[16] := 2; Buffer[18] := 62;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample-elf';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'ELF header was not detected');
  AssertEqual('x86_64', Info.Architecture, 'ELF architecture differs');

  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $CF; Buffer[1] := $FA; Buffer[2] := $ED; Buffer[3] := $FE;
  Buffer[4] := $07; Buffer[7] := $01;
  Buffer[12] := 2;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample-macho';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'Mach-O header was not detected');
  AssertEqual('Mach-O', Info.FormatName, 'Mach-O format differs');
  AssertEqual('x86_64', Info.Architecture, 'Mach-O architecture differs');
end;

{**
  Verifies deterministic merging of duplicate component evidence and scopes.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when normalization loses evidence or cannot
    merge two non-empty dependency scopes.
}
procedure TestComponentDeduplication;
var
  Input, Output: TObjectList;
  First, Second, Merged: uModels.TComponent;
begin
  Input := TObjectList.Create(True);
  Output := TObjectList.Create(True);
  try
    First := uModels.TComponent.Create;
    First.Name := 'demo'; First.Version := '1.0.0'; First.Ecosystem := 'npm';
    First.PackageURL := 'pkg:npm/demo@1.0.0';
    First.SourceArtifact := 'a/package.json';
    First.DependencyScope := ' runtime, development ';
    First.EvidencePaths.Add('a/package.json');
    First.DeclaredLicenses.Add('MIT');
    First.DeclaredPublishers.Add('Zeta Publisher');
    Input.Add(First);
    Second := uModels.TComponent.Create;
    Second.Name := 'demo'; Second.Version := '1.0.0'; Second.Ecosystem := 'npm';
    Second.PackageURL := 'pkg:npm/demo@1.0.0';
    Second.SourceArtifact := 'b/package-lock.json';
    Second.DependencyScope := 'optional, runtime';
    Second.EvidencePaths.Add('b/package-lock.json');
    Second.DeclaredLicenses.Add('Apache-2.0');
    Second.DeclaredPublishers.Add('Acme Publisher');
    Input.Add(Second);
    NormalizeComponents(Input, Output);
    AssertEqual(1, Output.Count, 'duplicate components were not merged');
    Merged := uModels.TComponent(Output[0]);
    AssertEqual(2, Merged.EvidencePaths.Count,
      'duplicate evidence paths were not merged');
    AssertEqual('development, optional, runtime', Merged.DependencyScope,
      'duplicate dependency scopes were not merged deterministically');
    AssertEqual(2, Merged.DeclaredLicenses.Count,
      'duplicate declared licenses were not merged');
    AssertEqual('Apache-2.0', Merged.DeclaredLicenses[0],
      'merged license declarations are not deterministic');
    AssertEqual('MIT', Merged.DeclaredLicenses[1],
      'second merged license declaration differs');
    AssertEqual(2, Merged.DeclaredPublishers.Count,
      'duplicate declared publishers were not merged');
    AssertEqual('Acme Publisher', Merged.DeclaredPublishers[0],
      'merged publisher declarations are not deterministic');
    AssertEqual('Zeta Publisher', Merged.DeclaredPublishers[1],
      'second merged publisher declaration differs');
  finally
    Output.Free;
    Input.Free;
  end;
end;

{**
  Verifies that an escaped scan exception still completes exactly once.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when worker containment, diagnostics, timing,
    or queued completion delivery regresses.
}
procedure TestWorkerExceptionContainment;
var
  SourceTask: TScanTask;
  Worker: TFailingScanWorker;
  Observer: TCompletionObserver;
  Deadline: QWord;
begin
  SourceTask := TScanTask.Create;
  SourceTask.StartedUTC := SourceTask.CreatedUTC;
  Observer := TCompletionObserver.Create;
  Worker := TFailingScanWorker.Create(SourceTask, TemporaryRoot);
  try
    Worker.OnComplete := @Observer.Complete;
    Worker.Start;
    Deadline := GetTickCount64 + 5000;
    repeat
      CheckSynchronize(10);
      Sleep(1);
    until (Observer.Count > 0) or (GetTickCount64 >= Deadline);
    Worker.WaitFor;
    CheckSynchronize(10);
    AssertEqual(1, Observer.Count,
      'failed worker completion was not delivered exactly once');
    AssertTrue(Observer.Status = tsFailed,
      'escaped worker exception did not fail the task');
    AssertTrue(Pos('intentional worker regression failure',
      Observer.ErrorText) > 0,
      'escaped worker diagnostic was not retained');
    AssertTrue(Observer.CompletedUTC <> '',
      'failed worker task has no completion timestamp');
  finally
    Worker.Free;
    Observer.Free;
    SourceTask.Free;
  end;
end;

{**
  Scans manifest, lockfile, and Lazarus fixtures through the production engine.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when scoped evidence does not merge or production artifact
    identification/serialization omits the parsed project or current-format
    Lazarus requirement.
}
procedure TestManifestLockScan;
var
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
  Artifact: TArtifact;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, ComponentJSON, RootDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  RootReference, ComponentReferenceValue: string;
begin
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := Fixture('');
    Task.TargetRootName := 'fixtures';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task),
      'manifest-plus-lockfile directory scan failed');
    Component := FindComponent(Task.Components, 'lodash');
    AssertTrue(Component <> nil,
      'manifest-plus-lockfile scan omitted lodash');
    AssertEqual('resolved, runtime', Component.DependencyScope,
      'manifest and lockfile scopes were not merged');

    Component := FindComponent(Task.Components, 'LCL');
    AssertTrue(Component <> nil,
      'production scan omitted the current-format Lazarus requirement');
    AssertEqual('lazarus-current.lpi', Component.SourceArtifact,
      'production Lazarus component evidence path differs');
    Artifact := FindArtifact(Task.Artifacts, 'lazarus-current.lpi');
    AssertTrue(Artifact <> nil,
      'production artifact identification omitted lazarus-current.lpi');
    AssertTrue(Artifact.Status = arsParsed,
      'production Lazarus artifact should parse');
    AssertEqual('lazarus-project-xml', Artifact.ParserName,
      'production Lazarus parser identification differs');
    AssertEqual(1, Artifact.ComponentCount,
      'production Lazarus artifact component count differs');

    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('fixtures', JSONString(Primary, 'name'),
        'production root folder name differs');
      AssertEqual('pkg:npm/fixture-app@1.2.3', JSONString(Primary, 'purl'),
        'parsed project component was not promoted');
      RootReference := JSONString(Primary, 'bom-ref');
      Components := JSONArray(Root, 'components');
      AssertTrue(FindJSONObjectByString(Components, 'name',
        'fixture-app') = nil, 'parsed project remains duplicated');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'lodash');
      AssertTrue(ComponentJSON <> nil,
        'production CycloneDX components omitted lodash');
      ComponentReferenceValue := JSONString(ComponentJSON, 'bom-ref');
      Dependencies := JSONArray(Root, 'dependencies');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        RootReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertTrue(JSONArrayContainsString(DependsOn,
        ComponentReferenceValue),
        'production manifest edge to lodash is missing');
    finally
      Data.Free;
    end;
  finally
    Engine.Free;
    Task.Free;
  end;
end;

{**
  Verifies stable synthetic roots and conservative multi-project handling.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when task IDs affect root identity, filesystem roots leak as names,
    or ambiguous projects are promoted instead of remaining explicit.
}
procedure TestCycloneDXSyntheticRoot;
var
  Task: TScanTask;
  Content: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, RootDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  FirstReference, SecondReference: string;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '11111111-2222-3333-4444-555555555555';
    Task.TargetDirectory := '/first/location/repeated-name';
    Task.ScannerVersion := AppVersion;
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      FirstReference := JSONString(Primary, 'bom-ref');
      AssertTrue(FirstReference <> '', 'synthetic root reference is missing');
    finally
      Data.Free;
    end;

    Task.ID := 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      SecondReference := JSONString(Primary, 'bom-ref');
      AssertEqual(FirstReference, SecondReference,
        'synthetic root reference changed with the task ID');
    finally
      Data.Free;
    end;

    AddFixtureComponent(Task, 'project-one', '1.0.0', 'npm',
      'pkg:npm/project-one@1.0.0', 'one/package.json', 'package-json',
      'project', 'application');
    AddFixtureComponent(Task, 'project-two', '2.0.0', 'npm',
      'pkg:npm/project-two@2.0.0', 'two/package.json', 'package-json',
      'project', 'application');
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual(FirstReference, JSONString(Primary, 'bom-ref'),
        'ambiguous projects replaced the synthetic root');
      Components := JSONArray(Root, 'components');
      AssertEqual(2, Components.Count,
        'ambiguous project components should remain explicit');
      Dependencies := JSONArray(Root, 'dependencies');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        FirstReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertEqual(2, DependsOn.Count,
        'ambiguous projects should remain root dependencies');
    finally
      Data.Free;
    end;

    Task.TargetDirectory := '/';
    Task.TargetRootName := '/';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('scanned-project', JSONString(Primary, 'name'),
        'Unix filesystem root leaked as the primary component name');
    finally
      Data.Free;
    end;

    Task.TargetDirectory := 'C:\';
    Task.TargetRootName := 'C:\';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('scanned-project', JSONString(Primary, 'name'),
        'Windows filesystem root leaked as the primary component name');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
  end;
end;

{**
  Verifies CycloneDX subject promotion, honest fields, scopes, and graph edges.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when either supported schema version loses subject identity,
    component semantics, retained evidence, or a directly observed graph edge.
  EFCreateError, EWriteError
    Propagated when the optional CI schema fixtures cannot be written.
}
procedure TestCycloneDXStructure;
var
  Task: TScanTask;
  ProjectComponent, SharedComponent: uModels.TComponent;
  Artifact: TArtifact;
  SBOM16, SBOM17: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, ComponentJSON, RuntimeJSON, RangeJSON,
    OptionalJSON, PeerJSON, ResolvedJSON, MergedJSON, BuildJSON, BinaryJSON,
    SecondBinaryJSON, LibcJSON, DottedJSON, SharedJSON, RootDependency, BinaryDependency,
    SecondBinaryDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  RootReference, RuntimeReference, RangeReference, OptionalReference,
    PeerReference, ResolvedReference, MergedReference, BinaryReference,
    SecondBinaryReference, LibcReference,
    DottedReference, SharedReference, SystemReference, PropertyValue,
    FixtureDirectory: string;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := '/private/acme/fixture-root/';
    Task.TargetRootName := 'stale-root-name';
    Task.ScannerVersion := AppVersion;

    ProjectComponent := AddFixtureComponent(Task, 'fixture-app', '1.2.3',
      'npm', 'pkg:npm/fixture-app@1.2.3', 'package.json', 'package-json',
      'project', 'application');
    ProjectComponent.SHA256 := SHA256String('fixture-project');
    AddFixtureComponent(Task, 'lodash', '4.17.21', 'npm',
      'pkg:npm/lodash@4.17.21', 'package.json', 'package-json', 'runtime',
      'library');
    AddFixtureComponent(Task, 'vitest', '^2.0.0', 'npm', '', 'package.json',
      'package-json', 'development', 'library');
    AddFixtureComponent(Task, 'optional-tool', '1.1.0', 'npm',
      'pkg:npm/optional-tool@1.1.0', 'package.json', 'package-json',
      'optional', 'library');
    AddFixtureComponent(Task, 'peer-tool', '1.0.0', 'npm',
      'pkg:npm/peer-tool@1.0.0', 'package.json', 'package-json', 'peer',
      'library');
    AddFixtureComponent(Task, 'locked-tool', '3.0.0', 'npm',
      'pkg:npm/locked-tool@3.0.0', 'package-lock.json',
      'package-lock-json', 'resolved', 'library');
    AddFixtureComponent(Task, 'merged-tool', '2.0.0', 'npm',
      'pkg:npm/merged-tool@2.0.0', 'package.json', 'package-json',
      'development, runtime', 'library');

    AddFixtureComponent(Task, 'demo-tool', '', 'native', '', 'bin/demo-tool',
      'binary-header', '', 'application');
    AddFixtureComponent(Task, 'libc.so.6', '6', 'native', '', 'bin/demo-tool',
      'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(Task, 'libdemo.so.1.2.3', '1.2.3', 'native', '',
      'bin/demo-tool', 'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(Task, 'libsystem.so.2', '', 'native', '',
      'bin/demo-tool', 'readelf', 'runtime', 'library');
    AddFixtureComponent(Task, 'libbuild.so.1', '', 'native', '',
      'bin/demo-tool', 'binary-dependency-table', 'build', 'library');
    AddFixtureComponent(Task, 'libother.so.1', '', 'native', '',
      'bin/other-tool', 'binary-dependency-table', 'runtime', 'library');
    SharedComponent := AddFixtureComponent(Task, 'libshared.so.7', '',
      'native', '', 'bin/demo-tool', 'binary-dependency-table', 'runtime',
      'library');
    SharedComponent.EvidencePaths.Add('bin/demo-copy');
    AddFixtureComponent(Task, 'demo-copy', '', 'native', '', 'bin/demo-copy',
      'binary-header', '', 'application');

    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'bin/demo-tool';
    Artifact.ArtifactType := 'ELF executable';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);

    SBOM16 := GenerateCycloneDX(Task, cdxSpec16);
    SBOM17 := GenerateCycloneDX(Task);
    FixtureDirectory := GetEnvironmentVariable(
      'PURPLERAY_CYCLONEDX_FIXTURE_DIR');
    if FixtureDirectory <> '' then
    begin
      if not ForceDirectories(FixtureDirectory) then
        Fail('Unable to create CycloneDX schema-fixture directory: ' +
          FixtureDirectory);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'structure-1.6.cdx.json', SBOM16);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'structure-1.7.cdx.json', SBOM17);
    end;

    Data := GetJSON(string(SBOM16));
    try
      AssertTrue(Data.JSONType = jtObject,
        'CycloneDX 1.6 output root is not an object');
      Root := TJSONObject(Data);
      AssertEqual('1.6', JSONString(Root, 'specVersion'),
        'explicit CycloneDX compatibility version differs');
      AssertEqual('https://cyclonedx.org/schema/bom-1.6.schema.json',
        JSONString(Root, '$schema'), 'CycloneDX 1.6 schema URL differs');
    finally
      Data.Free;
    end;

    Data := GetJSON(string(SBOM17));
    try
      AssertTrue(Data.JSONType = jtObject,
        'CycloneDX 1.7 output root is not an object');
      Root := TJSONObject(Data);
      AssertEqual('1.7', JSONString(Root, 'specVersion'),
        'default CycloneDX version differs');
      AssertEqual('https://cyclonedx.org/schema/bom-1.7.schema.json',
        JSONString(Root, '$schema'), 'CycloneDX 1.7 schema URL differs');

      Metadata := JSONObject(Root, 'metadata');
      AssertTrue(Metadata <> nil, 'CycloneDX metadata is missing');
      Primary := JSONObject(Metadata, 'component');
      AssertTrue(Primary <> nil, 'metadata.component is missing');
      AssertEqual('application', JSONString(Primary, 'type'),
        'primary component type differs');
      AssertEqual('fixture-root', JSONString(Primary, 'name'),
        'primary component must use the target-folder basename');
      AssertEqual('1.2.3', JSONString(Primary, 'version'),
        'project version was not promoted');
      AssertEqual('pkg:npm/fixture-app@1.2.3', JSONString(Primary, 'purl'),
        'project purl was not promoted');
      RootReference := JSONString(Primary, 'bom-ref');
      AssertEqual('pkg:npm/fixture-app@1.2.3', RootReference,
        'promoted project reference differs');
      AssertTrue(Primary.Find('scope') = nil,
        'project scope must use the required default');

      Components := JSONArray(Root, 'components');
      AssertTrue(Components <> nil, 'CycloneDX components are missing');
      AssertEqual(14, Components.Count,
        'promoted project component was not removed exactly once');
      AssertTrue(FindJSONObjectByString(Components, 'name', 'fixture-app') = nil,
        'promoted project remains duplicated in components');

      RuntimeJSON := FindJSONObjectByString(Components, 'name', 'lodash');
      RangeJSON := FindJSONObjectByString(Components, 'name', 'vitest');
      OptionalJSON := FindJSONObjectByString(Components, 'name',
        'optional-tool');
      PeerJSON := FindJSONObjectByString(Components, 'name', 'peer-tool');
      ResolvedJSON := FindJSONObjectByString(Components, 'name',
        'locked-tool');
      MergedJSON := FindJSONObjectByString(Components, 'name', 'merged-tool');
      BuildJSON := FindJSONObjectByString(Components, 'name', 'libbuild.so.1');
      BinaryJSON := FindJSONObjectByString(Components, 'name', 'demo-tool');
      SecondBinaryJSON := FindJSONObjectByString(Components, 'name',
        'demo-copy');
      LibcJSON := FindJSONObjectByString(Components, 'name', 'libc.so.6');
      DottedJSON := FindJSONObjectByString(Components, 'name',
        'libdemo.so.1.2.3');
      SharedJSON := FindJSONObjectByString(Components, 'name',
        'libshared.so.7');
      ComponentJSON := FindJSONObjectByString(Components, 'name',
        'libsystem.so.2');
      AssertTrue((RuntimeJSON <> nil) and (RangeJSON <> nil) and
        (OptionalJSON <> nil) and (PeerJSON <> nil) and
        (ResolvedJSON <> nil) and (MergedJSON <> nil) and
        (BuildJSON <> nil) and (BinaryJSON <> nil) and
        (SecondBinaryJSON <> nil) and (LibcJSON <> nil) and
        (DottedJSON <> nil) and (SharedJSON <> nil) and
        (ComponentJSON <> nil), 'CycloneDX fixture components are incomplete');

      AssertTrue(RangeJSON.Find('version') = nil,
        'requested range leaked into the CycloneDX version field');
      AssertEqual('excluded', JSONString(RangeJSON, 'scope'),
        'development dependency scope differs');
      AssertTrue(FindCycloneProperty(RangeJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'requested-range property is missing');
      AssertEqual('^2.0.0', PropertyValue,
        'requested-range property value differs');
      AssertTrue(FindCycloneProperty(RangeJSON,
        'purpleray-sbom-analyzer:dependency-scope', PropertyValue),
        'custom dependency-scope property was lost');
      AssertEqual('development', PropertyValue,
        'custom development scope differs');
      AssertEqual('optional', JSONString(OptionalJSON, 'scope'),
        'optional dependency scope differs');
      AssertEqual('optional', JSONString(PeerJSON, 'scope'),
        'peer dependency must map to optional');
      AssertTrue(ResolvedJSON.Find('scope') = nil,
        'resolved dependency must use the required default');
      AssertTrue(MergedJSON.Find('scope') = nil,
        'runtime plus development must remain required');
      AssertTrue(RuntimeJSON.Find('scope') = nil,
        'runtime must use the required default');
      AssertTrue(BuildJSON.Find('scope') = nil,
        'build dependency must use the required default');

      AssertTrue(LibcJSON.Find('version') = nil,
        'bare SONAME ABI leaked into version');
      AssertTrue(FindCycloneProperty(LibcJSON,
        'purpleray-sbom-analyzer:soname-abi-version', PropertyValue),
        'SONAME ABI property is missing');
      AssertEqual('6', PropertyValue, 'SONAME ABI property differs');
      AssertTrue(not FindCycloneProperty(LibcJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'persisted SONAME ABI was mislabeled as a requested range');
      AssertEqual('1.2.3', JSONString(DottedJSON, 'version'),
        'dotted native product version was lost');

      RuntimeReference := JSONString(RuntimeJSON, 'bom-ref');
      RangeReference := JSONString(RangeJSON, 'bom-ref');
      OptionalReference := JSONString(OptionalJSON, 'bom-ref');
      PeerReference := JSONString(PeerJSON, 'bom-ref');
      ResolvedReference := JSONString(ResolvedJSON, 'bom-ref');
      MergedReference := JSONString(MergedJSON, 'bom-ref');
      BinaryReference := JSONString(BinaryJSON, 'bom-ref');
      SecondBinaryReference := JSONString(SecondBinaryJSON, 'bom-ref');
      LibcReference := JSONString(LibcJSON, 'bom-ref');
      DottedReference := JSONString(DottedJSON, 'bom-ref');
      SharedReference := JSONString(SharedJSON, 'bom-ref');
      SystemReference := JSONString(ComponentJSON, 'bom-ref');

      Dependencies := JSONArray(Root, 'dependencies');
      AssertTrue(Dependencies <> nil, 'CycloneDX dependency graph is missing');
      AssertEqual(3, Dependencies.Count,
        'dependency graph must contain root and two binary owners');
      AssertEqual(RootReference,
        JSONString(TJSONObject(Dependencies.Items[0]), 'ref'),
        'metadata root must be the first dependency entry');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        RootReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertEqual(6, DependsOn.Count,
        'root direct-manifest dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, RuntimeReference) and
        JSONArrayContainsString(DependsOn, RangeReference) and
        JSONArrayContainsString(DependsOn, OptionalReference) and
        JSONArrayContainsString(DependsOn, PeerReference) and
        JSONArrayContainsString(DependsOn, ResolvedReference) and
        JSONArrayContainsString(DependsOn, MergedReference),
        'root manifest dependency edges are incomplete');
      AssertTrue(not JSONArrayContainsString(DependsOn, BinaryReference) and
        not JSONArrayContainsString(DependsOn, LibcReference),
        'root graph inferred unsupported native edges');

      BinaryDependency := FindJSONObjectByString(Dependencies, 'ref',
        BinaryReference);
      DependsOn := JSONArray(BinaryDependency, 'dependsOn');
      AssertEqual(4, DependsOn.Count,
        'first binary direct-dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, LibcReference) and
        JSONArrayContainsString(DependsOn, DottedReference) and
        JSONArrayContainsString(DependsOn, SharedReference) and
        JSONArrayContainsString(DependsOn, SystemReference),
        'first binary dependency-table edges are incomplete');
      SecondBinaryDependency := FindJSONObjectByString(Dependencies, 'ref',
        SecondBinaryReference);
      DependsOn := JSONArray(SecondBinaryDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'second binary must have only the merged shared dependency');
      AssertTrue(JSONArrayContainsString(DependsOn, SharedReference),
        'merged cross-artifact evidence lost the second binary edge');
      AssertTrue(FindJSONObjectByString(Dependencies, 'ref', LibcReference) = nil,
        'leaf dependency received an inferred transitive graph entry');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
  end;
end;

{**
  Verifies one generated compliance document independent of schema version.

  Parameters
  ----------
  ASBOM
    CycloneDX JSON document to parse and inspect.
  ASpecVersion
    Exact expected CycloneDX specification version.

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when author, lifecycle, completeness, license, or publisher fields
    are absent or represented with incorrect CycloneDX choice semantics.
}
procedure AssertCycloneDXComplianceDocument(const ASBOM: UTF8String;
  const ASpecVersion: string);
var
  Data: TJSONData;
  Root, Metadata, AuthorValue, LifecycleValue, Primary, LicenseChoice,
    DependencyValue, NamedLicense, CompositionValue: TJSONObject;
  Authors, Lifecycles, Licenses, Components, Compositions: TJSONArray;
begin
  Data := GetJSON(string(ASBOM));
  try
    Root := TJSONObject(Data);
    AssertEqual(ASpecVersion, JSONString(Root, 'specVersion'),
      'compliance document specification version differs');
    Metadata := JSONObject(Root, 'metadata');
    AssertTrue(Metadata <> nil, 'compliance metadata is missing');

    Authors := JSONArray(Metadata, 'authors');
    AssertTrue((Authors <> nil) and (Authors.Count = 1),
      'SBOM author metadata count differs');
    AuthorValue := TJSONObject(Authors.Items[0]);
    AssertEqual('PurpleRay Research', JSONString(AuthorValue, 'name'),
      'SBOM author organization differs');
    AssertEqual('sbom@example.test', JSONString(AuthorValue, 'email'),
      'SBOM author email differs');

    Lifecycles := JSONArray(Metadata, 'lifecycles');
    AssertTrue((Lifecycles <> nil) and (Lifecycles.Count = 1),
      'SBOM lifecycle metadata count differs');
    LifecycleValue := TJSONObject(Lifecycles.Items[0]);
    AssertEqual('post-build', JSONString(LifecycleValue, 'phase'),
      'SBOM lifecycle phase differs');

    Primary := JSONObject(Metadata, 'component');
    AssertTrue(Primary <> nil, 'compliance primary component is missing');
    AssertEqual('Project Publisher', JSONString(Primary, 'publisher'),
      'promoted project publisher differs');
    Licenses := JSONArray(Primary, 'licenses');
    AssertTrue((Licenses <> nil) and (Licenses.Count = 1),
      'promoted project license choice count differs');
    LicenseChoice := TJSONObject(Licenses.Items[0]);
    AssertEqual('MIT', JSONString(LicenseChoice, 'expression'),
      'valid SPDX declaration was not emitted as an expression');
    AssertEqual('declared', JSONString(LicenseChoice, 'acknowledgement'),
      'SPDX expression acknowledgement differs');

    Components := JSONArray(Root, 'components');
    DependencyValue := FindJSONObjectByString(Components, 'name',
      'compliance-dependency');
    AssertTrue(DependencyValue <> nil,
      'compliance dependency component is missing');
    AssertEqual('Alpha Publisher; Zeta Publisher',
      JSONString(DependencyValue, 'publisher'),
      'dependency publisher differs');
    Licenses := JSONArray(DependencyValue, 'licenses');
    AssertTrue((Licenses <> nil) and (Licenses.Count = 1),
      'dependency license choice count differs');
    LicenseChoice := TJSONObject(Licenses.Items[0]);
    AssertTrue(LicenseChoice.Find('expression') = nil,
      'free-form license name was mislabeled as an SPDX expression');
    NamedLicense := JSONObject(LicenseChoice, 'license');
    AssertTrue(NamedLicense <> nil,
      'free-form license did not use the named-license choice');
    AssertEqual('Internal Evaluation License',
      JSONString(NamedLicense, 'name'), 'named license text differs');
    AssertEqual('declared', JSONString(NamedLicense, 'acknowledgement'),
      'named license acknowledgement differs');

    Compositions := JSONArray(Root, 'compositions');
    AssertTrue((Compositions <> nil) and (Compositions.Count = 1),
      'machine-readable completeness declaration count differs');
    CompositionValue := TJSONObject(Compositions.Items[0]);
    AssertEqual('incomplete', JSONString(CompositionValue, 'aggregate'),
      'machine-readable completeness aggregate differs');
  finally
    Data.Free;
  end;
end;

{**
  Verifies Sprint 4 compliance metadata in CycloneDX 1.6 and 1.7 output.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when either compatibility mode loses authors, publishers, declared
    licenses, lifecycle context, or the incomplete-composition declaration.
}
procedure TestCycloneDXComplianceMetadata;
var
  Task: TScanTask;
  ProjectComponent, DependencyComponent: uModels.TComponent;
  SBOM16, SBOM17: UTF8String;
  FixtureDirectory: string;
begin
  Task := TScanTask.Create;
  try
    Task.ID := 'fedcba98-7654-3210-fedc-ba9876543210';
    Task.CreatedUTC := '2026-08-20T12:34:56.000Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := '/private/compliance-fixture';
    Task.TargetRootName := 'compliance-fixture';
    Task.ScannerVersion := AppVersion;
    Task.Settings.SBOMAuthorOrganization := 'PurpleRay Research';
    Task.Settings.SBOMAuthorEmail := 'sbom@example.test';

    ProjectComponent := AddFixtureComponent(Task, 'compliance-project',
      '1.0.0', 'npm', 'pkg:npm/compliance-project@1.0.0', 'package.json',
      'package-json', 'project', 'application');
    ProjectComponent.DeclaredLicenses.Add('MIT');
    ProjectComponent.DeclaredPublishers.Add('Project Publisher');
    DependencyComponent := AddFixtureComponent(Task, 'compliance-dependency',
      '2.0.0', 'npm', 'pkg:npm/compliance-dependency@2.0.0', 'package.json',
      'package-json', 'runtime', 'library');
    DependencyComponent.DeclaredLicenses.Add('Internal Evaluation License');
    DependencyComponent.DeclaredPublishers.Add('Zeta Publisher');
    DependencyComponent.DeclaredPublishers.Add('Alpha Publisher');

    SBOM16 := GenerateCycloneDX(Task, cdxSpec16);
    SBOM17 := GenerateCycloneDX(Task, cdxSpec17);
    AssertCycloneDXComplianceDocument(SBOM16, '1.6');
    AssertCycloneDXComplianceDocument(SBOM17, '1.7');

    FixtureDirectory := GetEnvironmentVariable(
      'PURPLERAY_CYCLONEDX_FIXTURE_DIR');
    if FixtureDirectory <> '' then
    begin
      if not ForceDirectories(FixtureDirectory) then
        Fail('Unable to create CycloneDX compliance-fixture directory: ' +
          FixtureDirectory);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'compliance-1.6.cdx.json', SBOM16);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'compliance-1.7.cdx.json', SBOM17);
    end;
  finally
    Task.Free;
  end;
end;

{**
  Verifies binary graph edges survive production component normalization.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a scanned library header merged with another binary's direct
    dependency evidence loses its owner edge or creates a transitive edge.
}
procedure TestCycloneDXNormalizedBinaryGraph;
var
  RawTask, Task: TScanTask;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, ComponentJSON, AppDependency, LibraryDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  AppReference, LibraryReference, LibcReference: string;
begin
  RawTask := TScanTask.Create;
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := '/private/normalized-binary-graph';
    Task.TargetRootName := 'normalized-binary-graph';
    Task.ScannerVersion := AppVersion;

    AddFixtureComponent(RawTask, 'app', '', 'native', '', 'bin/app',
      'binary-header', '', 'application');
    AddFixtureComponent(RawTask, 'libfoo.so.1.2.3', '1.2.3', 'native', '',
      'bin/app', 'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(RawTask, 'libfoo.so.1.2.3', '1.2.3', 'native', '',
      'lib/libfoo.so.1.2.3', 'binary-header', '', 'library');
    AddFixtureComponent(RawTask, 'libc.so.6', '', 'native', '',
      'lib/libfoo.so.1.2.3', 'binary-dependency-table', 'runtime', 'library');
    NormalizeComponents(RawTask.Components, Task.Components);
    AssertEqual(3, Task.Components.Count,
      'binary normalization fixture did not merge exactly one identity');
    Component := FindComponent(Task.Components, 'libfoo.so.1.2.3');
    AssertTrue(Component <> nil, 'normalized library component is missing');
    AssertEqual('binary-dependency-table', Component.SourceParser,
      'regression fixture did not collapse the binary-header parser pair');
    AssertEqual(2, Component.EvidencePaths.Count,
      'normalized library did not retain both binary evidence paths');

    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'bin/app';
    Artifact.ArtifactType := 'ELF executable';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);
    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'lib/libfoo.so.1.2.3';
    Artifact.ArtifactType := 'ELF library';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);

    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Components := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'app');
      AssertTrue(ComponentJSON <> nil, 'binary application node is missing');
      AppReference := JSONString(ComponentJSON, 'bom-ref');
      ComponentJSON := FindJSONObjectByString(Components, 'name',
        'libfoo.so.1.2.3');
      AssertTrue(ComponentJSON <> nil, 'binary library owner node is missing');
      LibraryReference := JSONString(ComponentJSON, 'bom-ref');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'libc.so.6');
      AssertTrue(ComponentJSON <> nil, 'normalized leaf library is missing');
      LibcReference := JSONString(ComponentJSON, 'bom-ref');

      Dependencies := JSONArray(Root, 'dependencies');
      AssertEqual(3, Dependencies.Count,
        'normalized graph must contain root and two binary owners');
      AppDependency := FindJSONObjectByString(Dependencies, 'ref',
        AppReference);
      AssertTrue(AppDependency <> nil,
        'application dependency entry is missing');
      DependsOn := JSONArray(AppDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'application received a lost or inferred dependency edge');
      AssertTrue(JSONArrayContainsString(DependsOn, LibraryReference),
        'application-to-library direct edge was lost during normalization');
      AssertTrue(not JSONArrayContainsString(DependsOn, LibcReference),
        'application received an inferred transitive libc edge');

      LibraryDependency := FindJSONObjectByString(Dependencies, 'ref',
        LibraryReference);
      AssertTrue(LibraryDependency <> nil,
        'scanned library dependency entry is missing after normalization');
      DependsOn := JSONArray(LibraryDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'scanned library direct-dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, LibcReference),
        'library-to-libc direct edge was lost during normalization');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
    RawTask.Free;
  end;
end;

procedure TestDeterministicCycloneDX;
var
  Task: TScanTask;
  Component: uModels.TComponent;
  First, Second: UTF8String;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := '/secret/work';
    Task.ScannerVersion := '1.2.3';
    Component := uModels.TComponent.Create;
    Component.Name := 'demo'; Component.Version := '1.0.0';
    Component.Ecosystem := 'npm'; Component.PackageURL := 'pkg:npm/demo@1.0.0';
    Component.SourceArtifact := 'src/package.json';
    Component.SourceParser := 'package-json';
    Component.EvidencePaths.Add('src/package.json');
    Task.Components.Add(Component);
    First := GenerateCycloneDX(Task);
    Second := GenerateCycloneDX(Task);
    AssertEqual(string(First), string(Second),
      'CycloneDX generation is not deterministic');
    AssertTrue(Pos('/secret/work', string(First)) = 0,
      'default CycloneDX output leaked the absolute target path');
    AssertTrue(Pos('"specVersion" : "1.7"', string(First)) > 0,
      'CycloneDX version is missing');
    AssertTrue(Pos('"name" : "PurpleRay SBOM Analyzer"', string(First)) > 0,
      'renamed scanner identity is missing from CycloneDX output');
    AssertTrue(Pos('purpleray-sbom-analyzer:inspection-method',
      string(First)) > 0,
      'renamed scanner property namespace is missing from CycloneDX output');
    AssertTrue(Pos('"version" : "1.0.0"', string(First)) > 0,
      'known component version is missing from CycloneDX output');
  finally
    Task.Free;
  end;
end;

procedure TestIgnoreMatching;
var
  Settings: TScanSettings;
begin
  Settings := TScanSettings.Create;
  try
    AssertTrue(ShouldIgnorePath('src/node_modules', True,
      Settings.IgnorePatterns), 'node_modules default ignore is missing');
    AssertTrue(ShouldIgnorePath('deep/.git/config', False,
      Settings.IgnorePatterns), '.git contents should be ignored');
    AssertTrue(not ShouldIgnorePath('dist/output', True,
      Settings.IgnorePatterns), 'dist must not be ignored by default');
    Settings.IgnorePatterns.Add('generated/*/cache');
    AssertTrue(ShouldIgnorePath('generated/x/cache', True,
      Settings.IgnorePatterns), 'relative wildcard did not match');
    AssertTrue(WildcardMatches('requirements*.txt', 'requirements-dev.txt'),
      'simple wildcard did not match');
  finally
    Settings.Free;
  end;
end;

{**
  Verifies that a named pipe is warned about and never opened by the scanner.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when FIFO creation fails or scanner counters/warnings show that the
    special entry reached file processing.
}
procedure TestSpecialFileSkip;
{$IFDEF UNIX}
var
  RootName, FifoName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Writer: TFIFOWriter;
begin
  RootName := NewTemporaryDirectory('special-file-skip');
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'ordinary.txt', 'safe');
  FifoName := IncludeTrailingPathDelimiter(RootName) + 'events.pipe';
  if fpMkFifo(PChar(FifoName), 384) <> 0 then
    Fail('Unable to create FIFO fixture: ' + SysErrorMessage(fpGetErrNo));
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  Writer := TFIFOWriter.Create(FifoName);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'special-file-skip';
    Task.Settings.CalculateSHA256 := False;
    Writer.Start;
    AssertTrue(Engine.Scan(Task), 'scan containing a FIFO should finish');
    AssertEqual(1, Task.FilesInspected,
      'FIFO should not be counted as an inspected file');
    AssertTrue(StringListContainsText(Task.Warnings, 'events.pipe') and
      StringListContainsText(Task.Warnings, 'non-regular'),
      'FIFO skip warning should name the non-regular entry');
  finally
    Writer.Terminate;
    Writer.WaitFor;
    Writer.Free;
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix named-pipe support');
end;
{$ENDIF}

{**
  Verifies Windows device and offline attributes are rejected before opening.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when captured Windows attributes are classified as regular inputs.
}
procedure TestWindowsSpecialAttributeClassification;
{$IFDEF Windows}
var
  Reason: string;
begin
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_DEVICE, 0, Reason) =
    fsekUnsupported, 'Windows device attribute should be unsupported');
  AssertEqual('device', Reason,
    'Windows device classification reason differs');
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_OFFLINE, 0, Reason) =
    fsekUnsupported, 'Windows offline attribute should be unsupported');
  AssertEqual('offline file', Reason,
    'Windows offline classification reason differs');
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_DIRECTORY, 0, Reason) =
    fsekDirectory, 'Windows directory attribute classification differs');
  AssertTrue(ClassifyFileSystemEntry(0, 0, Reason) = fsekRegularFile,
    'ordinary Windows file classification differs');
end;
{$ELSE}
begin
  SkipTest('requires Windows file-attribute constants');
end;
{$ENDIF}

{**
  Verifies platform-specific end-of-directory and enumeration-error handling.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when normal enumeration exhaustion is reported as a failure or a
    real continuation error is silently accepted.
}
procedure TestDirectoryEnumerationErrors;
var
  Reason: string;
{$IFDEF Windows}
  RootName, MissingName: string;
{$ENDIF}
begin
  ResetDirectoryEnumerationError;
  {$IFDEF UNIX}
  AssertTrue(not DirectoryEnumerationContinuationFailed(-1, Reason),
    'Unix end-of-directory sentinel should not be an enumeration failure');
  AssertEqual('', Reason,
    'Unix normal end-of-directory should have no diagnostic');
  try
    fpSetErrNo(ESysEIO);
    AssertTrue(DirectoryEnumerationContinuationFailed(-1, Reason),
      'Unix FindNext I/O error should be reported');
    AssertTrue(Reason <> '',
      'Unix FindNext I/O error should retain a diagnostic');
  finally
    ResetDirectoryEnumerationError;
  end;
  {$ENDIF}
  {$IFDEF Windows}
  AssertTrue(not DirectoryEnumerationContinuationFailed(
    ERROR_NO_MORE_FILES, Reason),
    'Windows end-of-directory code should not be an enumeration failure');
  AssertEqual('', Reason,
    'Windows normal end-of-directory should have no diagnostic');
  AssertTrue(DirectoryEnumerationContinuationFailed(
    ERROR_ACCESS_DENIED, Reason),
    'Windows FindNext access denial should be reported');
  AssertTrue(Reason <> '',
    'Windows FindNext access denial should retain a diagnostic');

  RootName := NewTemporaryDirectory('windows-directory-errors');
  AssertTrue(not DirectoryEnumerationFailed(RootName,
    ERROR_FILE_NOT_FOUND, Reason),
    'Windows empty existing directory should not be an enumeration failure');
  AssertEqual('', Reason,
    'Windows empty existing directory should have no diagnostic');
  MissingName := IncludeTrailingPathDelimiter(RootName) + 'missing';
  AssertTrue(DirectoryEnumerationFailed(MissingName,
    ERROR_PATH_NOT_FOUND, Reason),
    'Windows missing directory should be an enumeration failure');
  AssertTrue(Reason <> '',
    'Windows missing directory should retain a diagnostic');
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  SkipTest('requires Unix or Windows enumeration semantics');
  {$ENDIF}
  {$ENDIF}
end;

{**
  Verifies case-preserving Linux enumeration and ordinal artifact ordering.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when either case-variant is dropped, receives incorrect metadata,
    or is emitted outside ordinal path order.
}
procedure TestCasePreservingEnumeration;
{$IFDEF LINUX}
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Artifact: TArtifact;
  UpperContent, LowerContent: RawByteString;
begin
  RootName := NewTemporaryDirectory('case-preserving-enumeration');
  LowerContent := 'lower-package==2.0.0' + LineEnding;
  UpperContent := 'upper-package==1.0.0' + LineEnding;
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirements.txt',
    LowerContent);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'Requirements.txt',
    UpperContent);
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'case-preserving-enumeration';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'case-variant scan should finish');
    AssertEqual(2, Task.FilesInspected,
      'case-variant filename was silently dropped');
    AssertEqual(Length(UpperContent) + Length(LowerContent),
      Task.BytesInspected,
      'case-variant file sizes were not retained');
    AssertEqual(2, Task.Artifacts.Count,
      'case-variant requirements artifacts were not both retained');
    Artifact := FindArtifact(Task.Artifacts, 'Requirements.txt');
    AssertTrue(Artifact <> nil,
      'uppercase requirements artifact is missing');
    AssertEqual(Length(UpperContent), Artifact.FileSize,
      'uppercase requirements artifact size differs');
    Artifact := FindArtifact(Task.Artifacts, 'requirements.txt');
    AssertTrue(Artifact <> nil,
      'lowercase requirements artifact is missing');
    AssertEqual(Length(LowerContent), Artifact.FileSize,
      'lowercase requirements artifact size differs');
    AssertEqual('Requirements.txt',
      TArtifact(Task.Artifacts[0]).RelativePath,
      'case-variant artifacts are not in ordinal order');
    AssertEqual('requirements.txt',
      TArtifact(Task.Artifacts[1]).RelativePath,
      'case-variant artifact ordinal order differs');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires a case-sensitive Linux filesystem');
end;
{$ENDIF}

{**
  Verifies literal wildcard characters cannot redirect artifact metadata.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a literal question-mark artifact is lost, assigned another
    entry's size, or emitted outside ordinal path order.
}
procedure TestGlobMetacharacterEnumeration;
{$IFDEF UNIX}
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  LiteralArtifact, AlternateArtifact: TArtifact;
  LiteralContent, AlternateContent: RawByteString;
begin
  RootName := NewTemporaryDirectory('glob-metachar-enumeration');
  AlternateContent := 'alternate-package==22.0.0' + LineEnding;
  LiteralContent := 'literal-package==1.0.0' + LineEnding;
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirementsA.txt',
    AlternateContent);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirements?.txt',
    LiteralContent);
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'glob-metachar-enumeration';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'glob-metacharacter scan should finish');
    AssertEqual(2, Task.FilesInspected,
      'glob-metacharacter filename was not independently processed');
    AssertEqual(2, Task.Artifacts.Count,
      'glob-metacharacter requirements artifacts were not both retained');
    LiteralArtifact := FindArtifact(Task.Artifacts, 'requirements?.txt');
    AlternateArtifact := FindArtifact(Task.Artifacts, 'requirementsA.txt');
    AssertTrue(LiteralArtifact <> nil,
      'literal question-mark artifact is missing');
    AssertTrue(AlternateArtifact <> nil,
      'alternate wildcard-match artifact is missing');
    AssertEqual(Length(LiteralContent), LiteralArtifact.FileSize,
      'literal question-mark artifact received another entry''s size');
    AssertEqual(Length(AlternateContent), AlternateArtifact.FileSize,
      'alternate wildcard-match artifact size differs');
    AssertEqual('requirements?.txt',
      TArtifact(Task.Artifacts[0]).RelativePath,
      'glob-metacharacter artifacts are not in ordinal order');
    AssertEqual('requirementsA.txt',
      TArtifact(Task.Artifacts[1]).RelativePath,
      'glob-metacharacter artifact ordinal order differs');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix support for a literal question mark in a filename');
end;
{$ENDIF}

{**
  Verifies unreadable directories are reported instead of silently omitted.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a permission-denied subtree or target root produces no warning.
}
procedure TestUnreadableDirectoryWarning;
{$IFDEF UNIX}
var
  RootName, RestrictedName: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  if fpGetUID = 0 then
    SkipTest('chmod 000 is not an effective denial fixture for UID 0');
  RootName := NewTemporaryDirectory('unreadable-directory');
  RestrictedName := IncludeTrailingPathDelimiter(RootName) + 'restricted';
  ForceDirectories(RestrictedName);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'visible.txt', 'v');
  WriteText(IncludeTrailingPathDelimiter(RestrictedName) + 'hidden.txt', 'x');
  if fpChmod(PChar(RestrictedName), 0) <> 0 then
    Fail('Unable to restrict directory fixture: ' +
      SysErrorMessage(fpGetErrNo));
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'unreadable-directory';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task),
      'scan with an unreadable subtree should retain partial results');
    AssertEqual(1, Task.FilesInspected,
      'unreadable subtree contents should not be reported as inspected');
    AssertTrue(StringListContainsText(Task.Warnings, 'restricted') and
      StringListContainsText(Task.Warnings, 'unable to enumerate'),
      'unreadable subtree warning should name the omitted directory');

    Task.TargetDirectory := RestrictedName;
    Task.TargetRootName := 'restricted';
    AssertTrue(Engine.Scan(Task),
      'unreadable target root should complete with an explicit warning');
    AssertEqual(0, Task.FilesInspected,
      'unreadable target root should not report inspected files');
    AssertTrue(StringListContainsText(Task.Warnings, 'unable to enumerate'),
      'unreadable target root was presented as a clean empty scan');
  finally
    fpChmod(PChar(RestrictedName), 448);
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix permission semantics');
end;
{$ENDIF}

procedure TestSymlinkLoopPrevention;
{$IFDEF UNIX}
var
  RootName, PackageName, LinkName: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  RootName := NewTemporaryDirectory('symlink-loop');
  ForceDirectories(IncludeTrailingPathDelimiter(RootName) + 'a');
  PackageName := IncludeTrailingPathDelimiter(RootName) + 'a/package.json';
  WriteText(PackageName, '{"name":"loop-fixture","version":"1.0.0"}');
  LinkName := IncludeTrailingPathDelimiter(RootName) + 'a/loop';
  if fpSymlink(PChar(IncludeTrailingPathDelimiter(RootName) + 'a'),
    PChar(LinkName)) <> 0 then
    Fail('Unable to create symlink-loop fixture');
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'symlink-loop';
    Task.Settings.FollowSymbolicLinks := True;
    AssertTrue(Engine.Scan(Task), 'scan with symlink loop should finish');
    AssertEqual(1, Task.FilesInspected,
      'symlink loop caused a file to be scanned repeatedly');
    AssertTrue(Task.Warnings.Count > 0, 'symlink loop should produce a warning');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix symbolic-link support');
end;
{$ENDIF}

{**
  Verifies that a LICENSE file is evidence only and never a license guess.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when license evidence creates a component declaration, is hashed as
    package metadata, or adds a license choice to the synthetic root.
}
procedure TestLicenseEvidenceDoesNotInferLicense;
var
  RootName, LicenseName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Artifact: TArtifact;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary: TJSONObject;
  Components: TJSONArray;
begin
  RootName := NewTemporaryDirectory('license-evidence-only');
  LicenseName := IncludeTrailingPathDelimiter(RootName) + 'LICENSE';
  WriteText(LicenseName, 'MIT License' + LineEnding +
    'Copyright fixture text only; this is not a package declaration.');
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'license-evidence-only';
    AssertTrue(Engine.Scan(Task), 'license-evidence scan should complete');
    AssertEqual(1, Task.FilesInspected,
      'license-evidence scan inspected an unexpected file count');
    AssertEqual(0, Task.Components.Count,
      'LICENSE-file presence inferred a component license');
    Artifact := FindArtifact(Task.Artifacts, 'LICENSE');
    AssertTrue(Artifact <> nil, 'LICENSE evidence artifact is missing');
    AssertEqual('license evidence', Artifact.ArtifactType,
      'LICENSE evidence artifact type differs');
    AssertTrue(Artifact.Status = arsUnsupported,
      'LICENSE evidence should remain explicitly unsupported');
    AssertTrue(Pos('no package license is inferred',
      LowerCase(Artifact.MessageText)) > 0,
      'LICENSE evidence does not disclose the no-inference boundary');
    AssertEqual('', Artifact.SHA256,
      'LICENSE evidence was hashed as if it were package metadata');

    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertTrue(Primary.Find('licenses') = nil,
        'LICENSE-file presence added a license to the synthetic root');
      Components := JSONArray(Root, 'components');
      AssertTrue((Components = nil) or (Components.Count = 0),
        'LICENSE-file presence emitted a licensed component');
    finally
      Data.Free;
    end;
  finally
    Engine.Free;
    Task.Free;
  end;
end;

{**
  Verifies that a readable empty directory completes with an explicit warning.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a zero-file scan silently appears complete and trustworthy.
}
procedure TestEmptyDirectoryWarning;
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  RootName := NewTemporaryDirectory('empty-directory-warning');
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'empty-directory-warning';
    AssertTrue(Engine.Scan(Task), 'empty-directory scan should complete');
    AssertTrue(Task.Status = tsCompleted,
      'empty-directory scan should retain completed status');
    AssertEqual(0, Task.FilesInspected,
      'empty-directory scan inspected an unexpected file');
    AssertEqual(0, Task.Components.Count,
      'empty-directory scan created an unexpected component');
    AssertTrue(StringListContainsText(Task.Warnings,
      'without inspecting any regular files'),
      'empty-directory scan omitted its completeness warning');
    AssertEqual(0, Task.Errors.Count,
      'empty-directory scan incorrectly reported an error');
    AssertTrue(TaskNeedsReview(Task),
      'empty completed scan is not marked for review');
    AssertEqual(#$E2#$9A#$A0 + ' completed with warnings',
      TaskStatusDisplayText(Task),
      'empty completed scan lacks the warning-aware history status');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure TestScanCancellation;
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Controller: TCancelController;
  I: Integer;
begin
  RootName := NewTemporaryDirectory('cancellation');
  for I := 1 to 30 do
    WriteText(IncludeTrailingPathDelimiter(RootName) + Format('file-%.2d.txt', [I]),
      'ordinary content');
  Task := TScanTask.Create;
  Controller := TCancelController.Create(8);
  Engine := TScanEngine.Create(@Controller.Check, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'cancellation';
    AssertTrue(not Engine.Scan(Task), 'cancelled scan reported success');
    AssertTrue(Task.Status = tsCancelled, 'cancelled scan status differs');
    AssertTrue(Task.FilesInspected < 30,
      'cancellation did not stop directory traversal');
  finally
    Engine.Free;
    Controller.Free;
    Task.Free;
  end;
end;

{**
  Executes one test case and records a pass or failure without aborting the run.

  Parameters
  ----------
  AName
    Human-readable test name written to the console.
  AMethod
    Test procedure to invoke.

  Returns
  -------
  None

  Raises
  ------
  None
    Test exceptions are counted as failures; ETestSkipped is counted and
    reported separately.
}
procedure RunTest(const AName: string; AMethod: TTestMethod);
begin
  Inc(TestCount);
  try
    AMethod();
    Inc(PassCount);
    WriteLn('[PASS] ', AName);
  except
    on E: ETestSkipped do
    begin
      Inc(SkipCount);
      WriteLn('[SKIP] ', AName, ': ', E.Message);
    end;
    on E: Exception do
    begin
      Inc(FailureCount);
      WriteLn(StdErr, '[FAIL] ', AName, ': ', E.Message);
    end;
  end;
end;

begin
  ProjectRoot := ExpandFileName(ExtractFilePath(ParamStr(0)) + '..' +
    DirectorySeparator + '..');
  TemporaryRoot := IncludeTrailingPathDelimiter(GetTempDir(False)) +
    'purpleray-sbom-analyzer-tests-' + NewTaskID;
  ForceDirectories(TemporaryRoot);
  RunTest('SHA-256 vectors', @TestSHA256);
  RunTest('displayed product version', @TestDisplayedVersion);
  RunTest('headless command line', @TestHeadlessCommandLine);
  RunTest('strict output-parent pinning', @TestStrictOutputParentPinning);
  RunTest('Sprint 6 distribution contracts',
    @TestSprint6DistributionContracts);
  RunTest('application shell structure', @TestApplicationShellStructure);
  RunTest('settings dialog DPI-stable layout',
    @TestScanSettingsDialogDPIStableLayout);
  RunTest('presentation policy', @TestPresentationPolicy);
  RunTest('compliance model persistence', @TestComplianceModelPersistence);
  RunTest('Sprint 4 UI contracts', @TestSprint4UIContracts);
  RunTest('Sprint 5 Compare UI contracts', @TestSprint5CompareUIContracts);
  RunTest('component scan comparison', @TestComponentComparison);
  RunTest('SPDX expressions', @TestSPDXExpressions);
  RunTest('declared manifest metadata', @TestDeclaredMetadataParsers);
  RunTest('requirements parser', @TestRequirementsParser);
  RunTest('Package URL normalization', @TestPackageURLNormalization);
  RunTest('Gradle and Conda purls', @TestGradleAndCondaPURLs);
  RunTest('declared version and scope semantics',
    @TestDeclaredVersionAndScopeSemantics);
  RunTest('package.json parser', @TestPackageJSONParser);
  RunTest('package-lock.json parser', @TestPackageLockParser);
  RunTest('XML dependency parsers', @TestXMLParsers);
  RunTest('Lazarus project parser', @TestLazarusProjectParser);
  RunTest('manifest size limits', @TestManifestSizeLimits);
  RunTest('XML document type rejection', @TestXMLDocumentTypeRejection);
  RunTest('task-history round trip', @TestHistoryRoundTrip);
  RunTest('shared task-history service', @TestTaskHistoryService);
  RunTest('atomic-history recovery', @TestAtomicHistoryRecovery);
  RunTest('application-data migration', @TestApplicationDataMigration);
  RunTest('SBOM export naming', @TestExportNaming);
  RunTest('database archive export', @TestDatabaseArchive);
  RunTest('readelf output parsing', @TestReadElfParsing);
  RunTest('native dependency versions', @TestNativeDependencyVersions);
  RunTest('native version scan and SBOM', @TestNativeVersionScanAndSBOM);
  RunTest('native dependency tables', @TestNativeDependencyTables);
  RunTest('PE/ELF/Mach-O inspection', @TestBinaryInspection);
  RunTest('component deduplication', @TestComponentDeduplication);
  RunTest('worker exception containment', @TestWorkerExceptionContainment);
  RunTest('manifest and lockfile scan', @TestManifestLockScan);
  RunTest('CycloneDX synthetic root', @TestCycloneDXSyntheticRoot);
  RunTest('CycloneDX structure and semantics', @TestCycloneDXStructure);
  RunTest('CycloneDX compliance metadata',
    @TestCycloneDXComplianceMetadata);
  RunTest('CycloneDX normalized binary graph',
    @TestCycloneDXNormalizedBinaryGraph);
  RunTest('deterministic CycloneDX', @TestDeterministicCycloneDX);
  RunTest('ignore and wildcard matching', @TestIgnoreMatching);
  RunTest('special-file skip', @TestSpecialFileSkip);
  RunTest('Windows special attributes',
    @TestWindowsSpecialAttributeClassification);
  RunTest('filesystem enumeration errors',
    @TestDirectoryEnumerationErrors);
  RunTest('case-preserving enumeration', @TestCasePreservingEnumeration);
  RunTest('glob-metacharacter enumeration', @TestGlobMetacharacterEnumeration);
  RunTest('unreadable-directory warnings', @TestUnreadableDirectoryWarning);
  RunTest('symbolic-link loop prevention', @TestSymlinkLoopPrevention);
  RunTest('LICENSE evidence does not infer a license',
    @TestLicenseEvidenceDoesNotInferLicense);
  RunTest('empty-directory warning', @TestEmptyDirectoryWarning);
  RunTest('scan cancellation', @TestScanCancellation);
  WriteLn(Format('%d tests: %d passed, %d failed, %d skipped',
    [TestCount, PassCount, FailureCount, SkipCount]));
  RemoveTemporaryTree(TemporaryRoot);
  if FailureCount <> 0 then
    Halt(1);
end.
