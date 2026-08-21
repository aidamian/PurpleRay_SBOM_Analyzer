(**
  PurpleRay SBOM Analyzer task-history persistence unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Owns and publishes shared scan history through an LCL-free service. Persists
  scan tasks atomically, repairs migrated SBOM paths, recovers from a valid
  backup, and preserves malformed history for diagnosis.

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
unit uTaskHistory;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels;

type
  { Kinds of observable task-history mutations. }
  TTaskHistoryChangeKind = (thcReset, thcAdded, thcUpdated, thcRemoved);

  {**
    Receives a committed task-history mutation.

    Parameters
    ----------
    Sender
      TTaskHistoryService that emitted the notification.
    Kind
      Kind of mutation that completed.
    TaskID
      Stable task identifier, or an empty string for a complete reset.
    Revision
      Monotonically increasing in-process history revision.

    Returns
    -------
    None

    Raises
    ------
    Exception
      Subscriber exceptions propagate to the service caller after the
      mutation has completed.
  }
  TTaskHistoryChangedEvent = procedure(Sender: TObject;
    Kind: TTaskHistoryChangeKind; const TaskID: string;
    Revision: QWord) of object;

  {**
    Caller-owned scalar snapshot of one completed scan task.

    Notes
    -----
    The snapshot never borrows strings, collections, or model objects from the
    history service. Instances returned by GetCompletedTaskSummaries belong to
    the supplied owning destination list.
  }
  TTaskHistorySummary = class
  public
    ID: string;
    CreatedUTC: string;
    CompletedUTC: string;
    TargetDirectory: string;
    TargetRootName: string;
    Status: TTaskStatus;
    WarningCount: Integer;
    ErrorCount: Integer;
    ComponentCount: Integer;
    ScannerVersion: string;
    ScannerCommit: string;
  end;

  TTaskHistoryStore = class
  private
    FDataDirectory: string;
    function GetHistoryFileName: string;

    {**
      Validates and reconstructs tasks from one candidate history file.

      Parameters
      ----------
      AFileName
        Active or backup history filename.
      ATasks
        Temporary owned destination list.
      AError
        Receives a concise parse, schema, or reconstruction diagnostic.

      Returns
      -------
      Boolean
        True only when the complete file was valid and loaded.

      Raises
      ------
      EOutOfMemory
        May propagate while allocating reconstructed tasks.
    }
    function TryLoadFile(const AFileName: string; ATasks: TObjectList;
      out AError: string): Boolean;

    {**
      Copies malformed active history to a timestamped diagnostic filename.

      Parameters
      ----------
      AFileName
        Malformed file to preserve.

      Returns
      -------
      string
        Preserved filename, or an empty string when preservation failed.

      Raises
      ------
      EFOpenError, EFCreateError, EReadError, EWriteError
        Propagated when the malformed file cannot be copied. Load contains
        these failures and reports them in its recovery warning.
    }
    function PreserveMalformedFile(const AFileName: string): string;
  public
    {**
      Creates a history store rooted at an explicit or default data directory.

      Parameters
      ----------
      ADataDirectory
        Override directory; an empty value selects ApplicationDataDirectory.

      Returns
      -------
      TTaskHistoryStore
        Newly configured store.

      Raises
      ------
      None
    }
    constructor Create(const ADataDirectory: string = '');

    {**
      Atomically persists the complete owned task list as versioned JSON.

      Parameters
      ----------
      ATasks
        List containing TScanTask instances to serialize.

      Returns
      -------
      None

      Raises
      ------
      EAccessViolation
        Raised when ATasks is nil or contains incompatible objects.
      EJSON, EOutOfMemory
        Propagated if deterministic UTF-8 serialization cannot complete.
      EFCreateError, EWriteError, EInOutError
        Propagated by atomic persistence.
    }
    procedure Save(ATasks: TObjectList);

    {**
      Loads history with backup recovery and interrupted-task repair.

      Parameters
      ----------
      ATasks
        Owned destination list cleared and populated only after valid loading.
      AWarning
        Receives backup-recovery, malformed-file, or path-repair information.

      Returns
      -------
      Boolean
        True when active or backup history was loaded; False when no valid
        history could be recovered.

      Raises
      ------
      EAccessViolation
        Raised when ATasks is nil.
      EOutOfMemory
        May propagate while reconstructing task objects.
    }
    function Load(ATasks: TObjectList; out AWarning: string): Boolean;
    property DataDirectory: string read FDataDirectory;
    property HistoryFileName: string read GetHistoryFileName;
  end;

  {**
    Owns the application's sole live task list and persistence store.

    Notes
    -----
    TaskAt and FindTaskByID return borrowed objects that remain valid only
    until the next reset, removal, or service destruction. AddTask transfers
    ownership on success. CloneTaskByID and summary instances are owned by the
    caller.
  }
  TTaskHistoryService = class
  private
    FStore: TTaskHistoryStore;
    FTasks: TObjectList;
    FRevision: QWord;
    FStartupWarning: string;
    FUsesDefaultDataDirectory: Boolean;
    FOnChanged: TTaskHistoryChangedEvent;

    {**
      Returns the normalized root owned by the persistence store.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Active task-history data directory.

      Raises
      ------
      None
    }
    function GetDataDirectory: string;

    {**
      Returns the number of service-owned tasks.

      Parameters
      ----------
      None

      Returns
      -------
      Integer
        Current task count.

      Raises
      ------
      None
    }
    function GetTaskCount: Integer;

    {**
      Increments the revision and publishes one completed mutation.

      Parameters
      ----------
      AKind
        Mutation kind.
      ATaskID
        Affected task identifier, or an empty string for a reset.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Subscriber exceptions propagate after the revision increments.
    }
    procedure EmitChange(AKind: TTaskHistoryChangeKind;
      const ATaskID: string);

    {**
      Locates a task's zero-based position by ordinal identifier equality.

      Parameters
      ----------
      ATaskID
        Identifier to locate.

      Returns
      -------
      Integer
        Matching index, or -1 when absent.

      Raises
      ------
      None
    }
    function FindTaskIndexByID(const ATaskID: string): Integer;

    {**
      Derives and validates the sole application-owned SBOM deletion target.

      Parameters
      ----------
      ATaskID
        Candidate safe filename stem.
      AFileName
        Receives DataDirectory/sboms/<task-id>.cdx.json when safe.
      AReason
        Receives the refusal reason when unsafe.

      Returns
      -------
      Boolean
        True only when the identifier, directory, canonical containment, and
        symbolic-link checks permit a deletion attempt.

      Raises
      ------
      Exception
        Filesystem canonicalization errors may propagate to DeleteOwnedSBOM.
    }
    function GetOwnedSBOMFileName(const ATaskID: string;
      out AFileName, AReason: string): Boolean;

    {**
      Best-effort deletes only the validated application-owned SBOM file.

      Parameters
      ----------
      ATaskID
        Identifier from the task whose history removal already committed.
      AWarning
        Receives unsafe-path or deletion-failure details.

      Returns
      -------
      None

      Raises
      ------
      None
        Filesystem exceptions are converted into AWarning.
    }
    procedure DeleteOwnedSBOM(const ATaskID: string; out AWarning: string);
  public
    {**
      Creates the shared task-history service and loads its initial history.

      Parameters
      ----------
      ADataDirectory
        Explicit history directory. An empty value selects the application
        data directory and permits legacy-data migration.

      Returns
      -------
      TTaskHistoryService
        Newly allocated service owned by the caller.

      Raises
      ------
      EOutOfMemory
        May propagate while creating or loading task objects.
      Exception
        Unexpected filesystem errors outside recoverable history parsing may
        propagate. Explicit directories never trigger default-data migration.
    }
    constructor Create(const ADataDirectory: string = '');

    {**
      Releases the owned task list and persistence store.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    }
    destructor Destroy; override;

    {**
      Replaces the live list from persistent history and emits a reset.

      Parameters
      ----------
      AWarning
        Receives recovery or malformed-history diagnostics.

      Returns
      -------
      Boolean
        True when the active file, its backup, or an empty history loaded;
        False when no valid persisted history could be recovered.

      Raises
      ------
      EOutOfMemory
        May propagate before the live list is replaced.
      Exception
        An OnChanged subscriber exception may propagate after replacement.
    }
    function Reload(out AWarning: string): Boolean;

    {**
      Persists the complete live history without changing its revision.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EFCreateError, EWriteError, EInOutError
        Propagated when atomic persistence fails.
    }
    procedure Save;

    {**
      Finds a live task by its case-sensitive stable identifier.

      Parameters
      ----------
      ATaskID
        Identifier to locate.

      Returns
      -------
      TScanTask
        Borrowed task, or nil when no task matches.

      Raises
      ------
      None
    }
    function FindTaskByID(const ATaskID: string): TScanTask;

    {**
      Clones a task for use outside the service ownership boundary.

      Parameters
      ----------
      ATaskID
        Identifier to locate.

      Returns
      -------
      TScanTask
        Caller-owned deep clone, or nil when no task matches.

      Raises
      ------
      EOutOfMemory
        May propagate while cloning the task and its child collections.
    }
    function CloneTaskByID(const ATaskID: string): TScanTask;

    {**
      Populates an owning list with snapshots of completed tasks.

      Parameters
      ----------
      ADestination
        Caller-owned TObjectList whose OwnsObjects property must be True. It
        is cleared and filled with TTaskHistorySummary instances.

      Returns
      -------
      None

      Raises
      ------
      EArgumentNilException
        Raised when ADestination is nil.
      EArgumentException
        Raised when ADestination does not own its objects.
      EOutOfMemory
        May propagate while allocating summary instances.
    }
    procedure GetCompletedTaskSummaries(ADestination: TObjectList);

    {**
      Transfers one task into the service without implicit persistence.

      Parameters
      ----------
      ATask
        Task whose ownership transfers to the service on success.
      AIndex
        Insertion position from zero through TaskCount; defaults to newest.

      Returns
      -------
      None

      Raises
      ------
      EArgumentNilException
        Raised when ATask is nil.
      EArgumentException
        Raised for a blank, unsafe, non-lowercase, or duplicate task
        identifier.
      EArgumentOutOfRangeException
        Raised when AIndex is outside the valid insertion range.
      Exception
        An OnChanged subscriber exception may propagate after insertion.
    }
    procedure AddTask(ATask: TScanTask; AIndex: Integer = 0);

    {**
      Publishes an in-place task update, optionally persisting it first.

      Parameters
      ----------
      ATaskID
        Identifier of the already-owned task that changed.
      APersist
        When True, atomically saves history before publishing the change.

      Returns
      -------
      None

      Raises
      ------
      EArgumentException
        Raised when ATaskID does not identify a live task.
      EFCreateError, EWriteError, EInOutError
        Propagated on persistence failure; no revision is published.
      Exception
        An OnChanged subscriber exception may propagate after publication.
    }
    procedure NotifyTaskUpdated(const ATaskID: string;
      APersist: Boolean = True);

    {**
      Removes a terminal task transactionally and deletes only its safe,
      canonical application-owned SBOM file.

      Parameters
      ----------
      ATaskID
        Identifier of the task to remove.
      AWarning
        Receives refusal, persistence, unsafe-path, or file-deletion details.

      Returns
      -------
      Boolean
        True after history removal commits, even when best-effort deletion of
        its application-owned SBOM file produces AWarning; otherwise False.

      Raises
      ------
      EOutOfMemory
        May propagate if rollback or notification allocation fails.
      Exception
        An OnChanged subscriber exception may propagate after committed
        removal.
    }
    function DeleteTask(const ATaskID: string; out AWarning: string): Boolean;

    {**
      Returns a borrowed task at a zero-based history position.

      Parameters
      ----------
      AIndex
        Zero-based history position.

      Returns
      -------
      TScanTask
        Borrowed live task.

      Raises
      ------
      EListError
        Raised when AIndex is outside the live list.
    }
    function TaskAt(AIndex: Integer): TScanTask;

    property DataDirectory: string read GetDataDirectory;
    property Revision: QWord read FRevision;
    property StartupWarning: string read FStartupWarning;
    property TaskCount: Integer read GetTaskCount;
    property UsesDefaultDataDirectory: Boolean
      read FUsesDefaultDataDirectory;
    property OnChanged: TTaskHistoryChangedEvent read FOnChanged
      write FOnChanged;
  end;

implementation

uses
  fpjson, uJSONUtils, uAtomicFiles, uPlatform, uTimeUtils;

{**
  Appends one non-empty diagnostic to a warning accumulator.

  Parameters
  ----------
  ATarget
    Warning text updated in place.
  AValue
    Diagnostic to append.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    May propagate while extending the warning string.
}
procedure AppendHistoryWarning(var ATarget: string; const AValue: string);
begin
  if AValue = '' then
    Exit;
  if ATarget <> '' then
    ATarget := ATarget + LineEnding;
  ATarget := ATarget + AValue;
end;

{**
  Compares two strings by their unsigned byte sequence.

  Parameters
  ----------
  ALeft, ARight
    Strings to compare without locale-dependent collation.

  Returns
  -------
  Integer
    Negative, zero, or positive when ALeft is respectively before, equal to,
    or after ARight in ordinal order.

  Raises
  ------
  None
}
function CompareOrdinalStrings(const ALeft, ARight: string): Integer;
var
  I, CommonLength: Integer;
begin
  CommonLength := Length(ALeft);
  if Length(ARight) < CommonLength then
    CommonLength := Length(ARight);
  for I := 1 to CommonLength do
  begin
    if Byte(ALeft[I]) < Byte(ARight[I]) then
      Exit(-1);
    if Byte(ALeft[I]) > Byte(ARight[I]) then
      Exit(1);
  end;
  if Length(ALeft) < Length(ARight) then
    Result := -1
  else if Length(ALeft) > Length(ARight) then
    Result := 1
  else
    Result := 0;
end;

{**
  Normalizes an explicit persistence directory without collapsing a root.

  Parameters
  ----------
  ADirectory
    Operator- or probe-supplied persistence directory.

  Returns
  -------
  string
    Expanded directory with redundant trailing delimiters removed, while Unix,
    drive, and UNC roots retain their required delimiter.

  Raises
  ------
  None
}
function NormalizedHistoryDirectory(const ADirectory: string): string;
var
  RootValue: string;
begin
  Result := ExpandFileName(ADirectory);
  RootValue := IncludeTrailingPathDelimiter(ExtractFileDrive(Result));
  if (RootValue = '') or not SameFileName(Result, RootValue) then
    Result := ExcludeTrailingPathDelimiter(Result);
end;

{**
  Orders completed-task summaries for the comparison task pickers.

  Parameters
  ----------
  ALeft, ARight
    Pointers to TTaskHistorySummary instances.

  Returns
  -------
  Integer
    Sort comparison ordering CreatedUTC descending, then ID ascending in
    ordinal order.

  Raises
  ------
  EAccessViolation
    Raised if either pointer is nil or not a TTaskHistorySummary instance.
}
function CompareTaskHistorySummaries(ALeft, ARight: Pointer): Integer;
var
  LeftSummary, RightSummary: TTaskHistorySummary;
begin
  LeftSummary := TTaskHistorySummary(ALeft);
  RightSummary := TTaskHistorySummary(ARight);
  Result := CompareOrdinalStrings(RightSummary.CreatedUTC,
    LeftSummary.CreatedUTC);
  if Result = 0 then
    Result := CompareOrdinalStrings(LeftSummary.ID, RightSummary.ID);
end;

{**
  Checks whether a task identifier is safe for a derived leaf filename.

  Parameters
  ----------
  ATaskID
    Identifier to validate.

  Returns
  -------
  Boolean
    True only for a non-empty, bounded sequence of lowercase ASCII letters,
    digits, hyphens, or underscores. Generated task IDs are lowercase, which
    also prevents filename collisions on case-insensitive filesystems.

  Raises
  ------
  None
}
function IsSafeTaskID(const ATaskID: string): Boolean;
var
  I: Integer;
begin
  Result := (Length(ATaskID) > 0) and (Length(ATaskID) <= 128);
  if not Result then
    Exit;
  for I := 1 to Length(ATaskID) do
    if not (ATaskID[I] in ['a'..'z', '0'..'9', '-', '_']) then
      Exit(False);
end;

constructor TTaskHistoryService.Create(const ADataDirectory: string);
var
  LoadWarning: string;
begin
  inherited Create;
  FUsesDefaultDataDirectory := ADataDirectory = '';
  FTasks := TObjectList.Create(True);
  FStore := TTaskHistoryStore.Create(ADataDirectory);
  if FUsesDefaultDataDirectory then
    AppendHistoryWarning(FStartupWarning,
      ApplicationDataMigrationWarning);
  FStore.Load(FTasks, LoadWarning);
  AppendHistoryWarning(FStartupWarning, LoadWarning);
end;

destructor TTaskHistoryService.Destroy;
begin
  FTasks.Free;
  FStore.Free;
  inherited Destroy;
end;

function TTaskHistoryService.GetDataDirectory: string;
begin
  Result := FStore.DataDirectory;
end;

function TTaskHistoryService.GetTaskCount: Integer;
begin
  Result := FTasks.Count;
end;

procedure TTaskHistoryService.EmitChange(AKind: TTaskHistoryChangeKind;
  const ATaskID: string);
begin
  Inc(FRevision);
  if Assigned(FOnChanged) then
    FOnChanged(Self, AKind, ATaskID, FRevision);
end;

function TTaskHistoryService.FindTaskIndexByID(
  const ATaskID: string): Integer;
var
  I: Integer;
begin
  for I := 0 to FTasks.Count - 1 do
    if TScanTask(FTasks[I]).ID = ATaskID then
      Exit(I);
  Result := -1;
end;

function TTaskHistoryService.GetOwnedSBOMFileName(const ATaskID: string;
  out AFileName, AReason: string): Boolean;
var
  DataRoot, SBOMRoot, CanonicalDataRoot, CanonicalSBOMRoot,
    Candidate, CanonicalCandidate: string;
begin
  Result := False;
  AFileName := '';
  AReason := '';
  if not IsSafeTaskID(ATaskID) then
  begin
    AReason := 'the task identifier is not safe for an owned SBOM filename';
    Exit;
  end;

  DataRoot := FStore.DataDirectory;
  SBOMRoot := IncludeTrailingPathDelimiter(DataRoot) + 'sboms';
  Candidate := IncludeTrailingPathDelimiter(SBOMRoot) + ATaskID +
    '.cdx.json';
  CanonicalDataRoot := CanonicalPath(DataRoot);
  CanonicalSBOMRoot := CanonicalPath(SBOMRoot);
  CanonicalCandidate := CanonicalPath(Candidate);

  if IsSymbolicLink(SBOMRoot) then
  begin
    AReason := 'the application SBOM directory is a symbolic link';
    Exit;
  end;
  if IsSymbolicLink(Candidate) then
  begin
    AReason := 'the derived application SBOM file is a symbolic link';
    Exit;
  end;
  if not PathIsWithin(CanonicalSBOMRoot, CanonicalDataRoot) then
  begin
    AReason := 'the application SBOM directory is outside the data directory';
    Exit;
  end;
  if not PathIsWithin(CanonicalCandidate, CanonicalSBOMRoot) then
  begin
    AReason := 'the derived application SBOM file is outside its directory';
    Exit;
  end;
  AFileName := Candidate;
  Result := True;
end;

procedure TTaskHistoryService.DeleteOwnedSBOM(const ATaskID: string;
  out AWarning: string);
var
  FileName, Reason: string;
begin
  AWarning := '';
  try
    if not GetOwnedSBOMFileName(ATaskID, FileName, Reason) then
    begin
      AWarning := 'Task history was removed, but its application SBOM was ' +
        'not deleted because ' + Reason + '.';
      Exit;
    end;
    if not FileExists(FileName) then
      Exit;
    if not DeleteFile(FileName) then
      AWarning := 'Task history was removed, but the application SBOM could ' +
        'not be deleted: ' + FileName;
  except
    on E: Exception do
      AWarning := 'Task history was removed, but the application SBOM could ' +
        'not be deleted: ' + E.Message;
  end;
end;

function TTaskHistoryService.Reload(out AWarning: string): Boolean;
var
  Loaded, Previous: TObjectList;
begin
  Loaded := TObjectList.Create(True);
  try
    Result := FStore.Load(Loaded, AWarning);
    if not Result then
      Exit;
    Previous := FTasks;
    FTasks := Loaded;
    Loaded := Previous;
    EmitChange(thcReset, '');
  finally
    Loaded.Free;
  end;
end;

procedure TTaskHistoryService.Save;
begin
  FStore.Save(FTasks);
end;

function TTaskHistoryService.FindTaskByID(const ATaskID: string): TScanTask;
var
  Index: Integer;
begin
  Index := FindTaskIndexByID(ATaskID);
  if Index >= 0 then
    Result := TScanTask(FTasks[Index])
  else
    Result := nil;
end;

function TTaskHistoryService.CloneTaskByID(const ATaskID: string): TScanTask;
var
  Task: TScanTask;
begin
  Task := FindTaskByID(ATaskID);
  if Task <> nil then
    Result := Task.Clone
  else
    Result := nil;
end;

procedure TTaskHistoryService.GetCompletedTaskSummaries(
  ADestination: TObjectList);
var
  Summaries: TObjectList;
  Summary: TTaskHistorySummary;
  Task: TScanTask;
  I: Integer;
begin
  if ADestination = nil then
    raise EArgumentNilException.Create('ADestination must not be nil');
  if not ADestination.OwnsObjects then
    raise EArgumentException.Create(
      'ADestination must own its summary objects');

  Summaries := TObjectList.Create(True);
  try
    for I := 0 to FTasks.Count - 1 do
    begin
      Task := TScanTask(FTasks[I]);
      if Task.Status <> tsCompleted then
        Continue;
      Summary := TTaskHistorySummary.Create;
      try
        Summary.ID := Task.ID;
        Summary.CreatedUTC := Task.CreatedUTC;
        Summary.CompletedUTC := Task.CompletedUTC;
        Summary.TargetDirectory := Task.TargetDirectory;
        Summary.TargetRootName := Task.TargetRootName;
        Summary.Status := Task.Status;
        Summary.WarningCount := Task.Warnings.Count;
        Summary.ErrorCount := Task.Errors.Count;
        Summary.ComponentCount := Task.Components.Count;
        Summary.ScannerVersion := Task.ScannerVersion;
        Summary.ScannerCommit := Task.ScannerCommit;
        Summaries.Add(Summary);
        Summary := nil;
      finally
        Summary.Free;
      end;
    end;
    Summaries.Sort(@CompareTaskHistorySummaries);
    ADestination.Clear;
    while Summaries.Count > 0 do
    begin
      Summary := TTaskHistorySummary(Summaries.Extract(Summaries[0]));
      try
        ADestination.Add(Summary);
        Summary := nil;
      finally
        Summary.Free;
      end;
    end;
  finally
    Summaries.Free;
  end;
end;

procedure TTaskHistoryService.AddTask(ATask: TScanTask; AIndex: Integer);
begin
  if ATask = nil then
    raise EArgumentNilException.Create('ATask must not be nil');
  if ATask.ID = '' then
    raise EArgumentException.Create('ATask must have an identifier');
  if not IsSafeTaskID(ATask.ID) then
    raise EArgumentException.Create(
      'ATask identifier must be lowercase and filename-safe');
  if FindTaskIndexByID(ATask.ID) >= 0 then
    raise EArgumentException.CreateFmt('Task identifier already exists: %s',
      [ATask.ID]);
  if (AIndex < 0) or (AIndex > FTasks.Count) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'AIndex %d is outside 0..%d', [AIndex, FTasks.Count]);
  FTasks.Insert(AIndex, ATask);
  EmitChange(thcAdded, ATask.ID);
end;

procedure TTaskHistoryService.NotifyTaskUpdated(const ATaskID: string;
  APersist: Boolean);
begin
  if FindTaskIndexByID(ATaskID) < 0 then
    raise EArgumentException.CreateFmt('Task identifier was not found: %s',
      [ATaskID]);
  if APersist then
    Save;
  EmitChange(thcUpdated, ATaskID);
end;

function TTaskHistoryService.DeleteTask(const ATaskID: string;
  out AWarning: string): Boolean;
var
  Index: Integer;
  Task: TScanTask;
  StableID: string;
begin
  Result := False;
  AWarning := '';
  Index := FindTaskIndexByID(ATaskID);
  if Index < 0 then
  begin
    AWarning := 'Task identifier was not found: ' + ATaskID;
    Exit;
  end;
  Task := TScanTask(FTasks[Index]);
  if Task.Status in [tsPending, tsRunning] then
  begin
    AWarning := 'Pending or running tasks cannot be deleted.';
    Exit;
  end;

  StableID := Task.ID;
  Task := TScanTask(FTasks.Extract(Task));
  try
    try
      Save;
    except
      on E: Exception do
      begin
        FTasks.Insert(Index, Task);
        Task := nil;
        AWarning := 'Task history could not be saved; deletion was rolled ' +
          'back: ' + E.Message;
        Exit;
      end;
    end;

    DeleteOwnedSBOM(StableID, AWarning);
    FreeAndNil(Task);
    Result := True;
    EmitChange(thcRemoved, StableID);
  finally
    Task.Free;
  end;
end;

function TTaskHistoryService.TaskAt(AIndex: Integer): TScanTask;
begin
  Result := TScanTask(FTasks[AIndex]);
end;

constructor TTaskHistoryStore.Create(const ADataDirectory: string);
begin
  inherited Create;
  if ADataDirectory <> '' then
    FDataDirectory := NormalizedHistoryDirectory(ADataDirectory)
  else
    FDataDirectory := ApplicationDataDirectory;
end;

function TTaskHistoryStore.GetHistoryFileName: string;
begin
  Result := IncludeTrailingPathDelimiter(FDataDirectory) + 'history.json';
end;

procedure TTaskHistoryStore.Save(ATasks: TObjectList);
var
  Root: TJSONObject;
  TasksArray: TJSONArray;
  I: Integer;
  Content: UTF8String;
begin
  Root := TJSONObject.Create;
  try
    Root.Add('format_version', 1);
    TasksArray := TJSONArray.Create;
    for I := 0 to ATasks.Count - 1 do
      TasksArray.Add(TScanTask(ATasks[I]).ToJSON);
    Root.Add('tasks', TasksArray);
    Content := SerializeJSONUTF8(Root, [], 2, True);
    WriteAtomicUTF8(HistoryFileName, Content, True);
  finally
    Root.Free;
  end;
end;

function TTaskHistoryStore.TryLoadFile(const AFileName: string;
  ATasks: TObjectList; out AError: string): Boolean;
var
  Data: TJSONData;
  Root: TJSONObject;
  TasksArray: TJSONArray;
  Loaded: TObjectList;
  SeenIDs: TStringList;
  TaskObject: TJSONObject;
  Task: TScanTask;
  PersistedID, RelocatedSBOM: string;
  I: Integer;
begin
  Result := False;
  AError := '';
  Loaded := TObjectList.Create(True);
  SeenIDs := TStringList.Create;
  try
    SeenIDs.Sorted := True;
    SeenIDs.CaseSensitive := True;
    SeenIDs.UseLocale := False;
    SeenIDs.Duplicates := dupError;
    try
      Data := ReadJSONFile(AFileName);
      try
        if Data.JSONType <> jtObject then
          raise Exception.Create('history root is not a JSON object');
        Root := TJSONObject(Data);
        if JSONInt64(Root, 'format_version', 0) <> 1 then
          raise Exception.Create('history format version is unsupported');
        TasksArray := JSONArray(Root, 'tasks');
        if TasksArray = nil then
          raise Exception.Create('history does not contain a task array');
        for I := 0 to TasksArray.Count - 1 do
        begin
          if TasksArray.Items[I].JSONType <> jtObject then
            raise Exception.CreateFmt('task %d is not a JSON object', [I]);
          TaskObject := TJSONObject(TasksArray.Items[I]);
          if (TaskObject.Find('id') = nil) or
            (TaskObject.Find('id').JSONType <> jtString) then
            raise Exception.CreateFmt('task %d has no string identifier', [I]);
          PersistedID := Trim(TaskObject.Find('id').AsString);
          if not IsSafeTaskID(PersistedID) then
            raise Exception.CreateFmt('task %d has an unsafe identifier', [I]);
          if SeenIDs.IndexOf(PersistedID) >= 0 then
            raise Exception.CreateFmt('task %d duplicates identifier %s',
              [I, PersistedID]);
          SeenIDs.Add(PersistedID);
          Task := TScanTask.FromJSON(TaskObject);
          try
            Task.ID := PersistedID;
            if (Task.GeneratedSBOMPath <> '') and
              not FileExists(Task.GeneratedSBOMPath) then
            begin
              RelocatedSBOM := IncludeTrailingPathDelimiter(FDataDirectory) +
                'sboms' + DirectorySeparator + Task.ID + '.cdx.json';
              if FileExists(RelocatedSBOM) then
                Task.GeneratedSBOMPath := RelocatedSBOM;
            end;
            if Task.Status in [tsPending, tsRunning] then
            begin
              Task.Status := tsFailed;
              Task.CompletedUTC := UTCNowISO8601;
              Task.Errors.Add(
                'The application exited before this scan finished.');
            end;
            Loaded.Add(Task);
            Task := nil;
          finally
            Task.Free;
          end;
        end;
      finally
        Data.Free;
      end;
      ATasks.Clear;
      while Loaded.Count > 0 do
      begin
        Task := TScanTask(Loaded.Extract(Loaded[0]));
        try
          ATasks.Add(Task);
          Task := nil;
        finally
          Task.Free;
        end;
      end;
      Result := True;
    except
      on E: Exception do
        AError := E.Message;
    end;
  finally
    SeenIDs.Free;
    Loaded.Free;
  end;
end;

function TTaskHistoryStore.PreserveMalformedFile(const AFileName: string): string;
var
  Suffix: string;
begin
  Result := '';
  if not FileExists(AFileName) then
    Exit;
  Suffix := FormatDateTime('yyyymmdd-hhnnss-zzz', Now);
  Result := IncludeTrailingPathDelimiter(FDataDirectory) +
    'history.corrupt-' + Suffix + '.json';
  CopyFileContents(AFileName, Result);
end;

function TTaskHistoryStore.Load(ATasks: TObjectList; out AWarning: string): Boolean;
var
  ErrorText, BackupError, BackupName, PreservedName: string;
begin
  AWarning := '';
  BackupName := HistoryFileName + '.bak';
  if not FileExists(HistoryFileName) then
  begin
    if not FileExists(BackupName) then
    begin
      ATasks.Clear;
      Exit(True);
    end;
    if TryLoadFile(BackupName, ATasks, BackupError) then
    begin
      AWarning := 'The active task-history file was missing. Its valid ' +
        'backup was loaded.';
      Exit(True);
    end;
    AWarning := 'The active task-history file was missing and its backup ' +
      'could not be loaded: ' + BackupError;
    Exit(False);
  end;
  if TryLoadFile(HistoryFileName, ATasks, ErrorText) then
    Exit(True);

  try
    PreservedName := PreserveMalformedFile(HistoryFileName);
  except
    on E: Exception do
      PreservedName := '(preservation failed: ' + E.Message + ')';
  end;
  if FileExists(BackupName) and
    TryLoadFile(BackupName, ATasks, BackupError) then
  begin
    AWarning := 'Task history was malformed (' + ErrorText + '). The backup '+
      'was loaded. The malformed file was preserved as ' + PreservedName + '.';
    Exit(True);
  end;
  AWarning := 'Task history and its backup could not be loaded. Primary error: '+
    ErrorText;
  if BackupError <> '' then
    AWarning := AWarning + '; backup error: ' + BackupError;
  AWarning := AWarning + '. The malformed file was preserved as ' +
    PreservedName + '.';
  Result := False;
end;

end.
