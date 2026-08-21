(**
  PurpleRay SBOM Analyzer scan-worker unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Runs the scanner away from the LCL thread, queues coalesced progress safely,
  generates the SBOM, and delivers an owned result to the main window.

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
unit uScanWorker;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uModels, uOSVCore, uScanEngine;

type
  TWorkerProgressEvent = procedure(Sender: TObject;
    const AProgress: TScanProgress) of object;
  TWorkerCompleteEvent = procedure(Sender: TObject; AResult: TScanTask) of object;

  TScanWorker = class(TThread)
  private
    FTask: TScanTask;
    FDataDirectory: string;
    FCheckKnownIssues: Boolean;
    FOSVTransport: IOSVTransport;
    FLatestProgress: TScanProgress;
    FProgressQueued: LongInt;
    FProgressLock: TRTLCriticalSection;
    FProgressLockInitialized: Boolean;
    FStarted: Boolean;
    FThreadInitialized: Boolean;
    FOnProgress: TWorkerProgressEvent;
    FOnComplete: TWorkerCompleteEvent;
    {**
      Records an unexpected worker failure without discarding partial results.

      Parameters
      ----------
      AMessage
        Diagnostic text to append to the task error collection.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if the diagnostic cannot be stored; task status is changed
        before the allocation is attempted.
    }
    procedure MarkTaskFailed(const AMessage: string);

    {**
      Reports whether TThread termination has been requested.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True after Cancel or thread termination.

      Raises
      ------
      None
    }
    function CancellationRequested: Boolean;

    {**
      Captures scanner progress under a lock and queues one UI delivery.

      Parameters
      ----------
      AProgress
        Latest scanner counters and current relative path.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure EngineProgress(const AProgress: TScanProgress);

    {**
      Delivers the most recent coalesced progress snapshot on the UI thread.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      Exception
        Exceptions raised by the assigned OnProgress handler may propagate.
    }
    procedure DeliverProgress;

    {**
      Delivers the completed task to the assigned UI-thread callback.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      Exception
        Exceptions raised by the assigned OnComplete handler may propagate.
    }
    procedure DeliverCompletion;

  protected
    {**
      Runs the shared scanner-to-SBOM service for the worker's private task.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      Exception
        Scanner construction, execution, generation, or teardown failures
        propagate to Execute's last-resort containment boundary.
    }
    procedure PerformScan; virtual;

    {**
      Owns the complete background scan/SBOM lifecycle and queues completion.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Internal exceptions are converted into failed task state and messages.
    }
    procedure Execute; override;
  public
    {**
      Creates a suspended worker with a private clone of the requested task.

      Parameters
      ----------
      ATask
        Task definition to clone before the caller starts the thread.
      ADataDirectory
        Directory in which generated SBOM files are persisted.
      ACheckKnownIssues
        Explicit transient opt-in for one post-inventory OSV.dev check.

      Returns
      -------
      TScanWorker
        Suspended worker owned by the caller.

      Raises
      ------
      EArgumentNilException
        Raised when ATask is nil.
      EOutOfMemory
        Propagated if the thread, task clone, or lock cannot be initialized.
    }
    constructor Create(ATask: TScanTask; const ADataDirectory: string;
      ACheckKnownIssues: Boolean = False);
    destructor Destroy; override;

    {**
      Starts the suspended worker and records that teardown must join it.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    **}
    procedure Start; reintroduce;

    {**
      Requests cooperative cancellation without blocking the caller.

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
    procedure Cancel;
    property OnProgress: TWorkerProgressEvent read FOnProgress write FOnProgress;
    property OnComplete: TWorkerCompleteEvent read FOnComplete write FOnComplete;
    property ResultTask: TScanTask read FTask;
  end;

implementation

uses
  uOSVTransportFactory, uScanService, uTimeUtils;

procedure TScanWorker.MarkTaskFailed(const AMessage: string);
var
  MessageValue: string;
begin
  FTask.Status := tsFailed;
  MessageValue := Trim(AMessage);
  if MessageValue = '' then
    MessageValue := 'Unexpected scan failure';
  if FTask.Errors.IndexOf(MessageValue) < 0 then
    FTask.Errors.Add(MessageValue);
end;

constructor TScanWorker.Create(ATask: TScanTask; const ADataDirectory: string;
  ACheckKnownIssues: Boolean);
begin
  inherited Create(True);
  FThreadInitialized := True;
  FProgressLockInitialized := False;
  FStarted := False;
  FreeOnTerminate := False;
  InitCriticalSection(FProgressLock);
  FProgressLockInitialized := True;
  if ATask = nil then
    raise EArgumentNilException.Create('Scan worker task must not be nil');
  FTask := ATask.Clone;
  FDataDirectory := ExcludeTrailingPathDelimiter(ADataDirectory);
  FCheckKnownIssues := ACheckKnownIssues;
end;

destructor TScanWorker.Destroy;
begin
  FOnProgress := nil;
  FOnComplete := nil;
  if FThreadInitialized and not Finished then
  begin
    if FStarted then
      Cancel
    else
    begin
      { Wake the suspended base thread only after marking it terminated.  It
        then exits without entering Execute, so partially built fields remain
        untouched while TThread completes its own teardown. }
      Terminate;
      inherited Start;
    end;
    WaitFor;
  end;
  TThread.RemoveQueuedEvents(Self);
  if FProgressLockInitialized then
  begin
    FProgressLockInitialized := False;
    DoneCriticalSection(FProgressLock);
  end;
  FTask.Free;
  inherited Destroy;
end;

procedure TScanWorker.Start;
begin
  inherited Start;
  FStarted := True;
end;

procedure TScanWorker.Cancel;
var
  Transport: IOSVTransport;
begin
  Terminate;
  Transport := nil;
  EnterCriticalSection(FProgressLock);
  try
    Transport := FOSVTransport;
  finally
    LeaveCriticalSection(FProgressLock);
  end;
  if Transport <> nil then
    Transport.Cancel;
end;

function TScanWorker.CancellationRequested: Boolean;
begin
  Result := Terminated;
end;

procedure TScanWorker.EngineProgress(const AProgress: TScanProgress);
begin
  EnterCriticalSection(FProgressLock);
  try
    FLatestProgress := AProgress;
  finally
    LeaveCriticalSection(FProgressLock);
  end;
  if InterlockedCompareExchange(FProgressQueued, 1, 0) = 0 then
    TThread.Queue(Self, @DeliverProgress);
end;

procedure TScanWorker.DeliverProgress;
var
  ProgressValue: TScanProgress;
begin
  EnterCriticalSection(FProgressLock);
  try
    ProgressValue := FLatestProgress;
    InterlockedExchange(FProgressQueued, 0);
  finally
    LeaveCriticalSection(FProgressLock);
  end;
  if Assigned(FOnProgress) then
    FOnProgress(Self, ProgressValue);
end;

procedure TScanWorker.DeliverCompletion;
begin
  if Assigned(FOnComplete) then
    FOnComplete(Self, FTask);
end;

procedure TScanWorker.PerformScan;
var
  DirectoryName, FileName: string;
  Transport: IOSVTransport;
begin
  DirectoryName := IncludeTrailingPathDelimiter(FDataDirectory) + 'sboms';
  if not ForceDirectories(DirectoryName) then
    raise EInOutError.CreateFmt('Unable to create SBOM directory: %s',
      [DirectoryName]);
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + FTask.ID +
    '.cdx.json';
  Transport := nil;
  if FCheckKnownIssues then
    try
      Transport := CreateProductionOSVTransport;
    except
      { Native transport setup is optional enrichment. Even allocation failure
        here must not prevent the inventory transaction from running. }
      on EOutOfMemory do
        Transport := nil;
      on EOSVProductionTransportUnavailable do
        Transport := nil;
    end;
  EnterCriticalSection(FProgressLock);
  try
    FOSVTransport := Transport;
  finally
    LeaveCriticalSection(FProgressLock);
  end;
  try
    ExecuteScanToFile(FTask, FileName, @CancellationRequested,
      @EngineProgress, sopManagedApplicationData, FDataDirectory,
      FCheckKnownIssues, Transport);
  finally
    EnterCriticalSection(FProgressLock);
    try
      FOSVTransport := nil;
    finally
      LeaveCriticalSection(FProgressLock);
    end;
  end;
end;

procedure TScanWorker.Execute;

  function InventoryWasCommitted: Boolean;
  begin
    Result := (FTask.Status = tsCompleted) and
      (Trim(FTask.GeneratedSBOMPath) <> '') and
      (Trim(FTask.GeneratedSBOMSHA256) <> '');
  end;

  procedure PreserveCommittedInventory;
  const
    WarningText = 'A post-inventory operation did not complete.';
  begin
    try
      if FTask.Warnings.IndexOf(WarningText) < 0 then
        FTask.Warnings.Add(WarningText);
    except
      { The committed inventory remains authoritative if allocation fails. }
    end;
  end;

begin
  try
    try
      PerformScan;
    except
      on E: Exception do
        if InventoryWasCommitted then
          PreserveCommittedInventory
        else
          MarkTaskFailed('Unexpected scan failure (' + E.ClassName + '): ' +
            E.Message);
      else
        if InventoryWasCommitted then
          PreserveCommittedInventory
        else
          MarkTaskFailed('Unexpected non-standard scan failure');
    end;
    try
      FTask.CompletedUTC := UTCNowISO8601;
      FTask.DurationMS := DurationMilliseconds(FTask.StartedUTC,
        FTask.CompletedUTC);
    except
      on E: Exception do
        if InventoryWasCommitted then
          PreserveCommittedInventory
        else
          MarkTaskFailed('Unable to finalize scan timing (' + E.ClassName +
            '): ' + E.Message);
      else
        if InventoryWasCommitted then
          PreserveCommittedInventory
        else
          MarkTaskFailed('Unable to finalize scan timing');
    end;
  finally
    TThread.Queue(Self, @DeliverCompletion);
  end;
end;

end.
