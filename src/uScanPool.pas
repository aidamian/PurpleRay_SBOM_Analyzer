(**
  PurpleRay SBOM Analyzer bounded scan-analysis pool.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Runs verified per-file analysis on a persistent pool of one to four workers,
  bounds outstanding inputs, and exposes completed transactions for strictly
  ordinal coordinator consumption.

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
unit uScanPool;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, SyncObjs, uScanAnalysis;

const
  MinimumScanWorkerCount = 1;
  MaximumScanWorkerCount = 4;

type
  TScanAnalysisPool = class;

  TScanAnalysisWorker = class(TThread)
  private
    FOwner: TScanAnalysisPool;
  protected
    {**
      Consumes jobs until the pool stops and contains worker exceptions.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Analysis exceptions are converted into pool failure state.
    *}
    procedure Execute; override;
  public
    {**
      Creates one suspended persistent worker bound to a pool.

      Parameters
      ----------
      AOwner
        Borrowed pool that must outlive the worker.

      Returns
      -------
      TScanAnalysisWorker
        Suspended caller-owned worker.

      Raises
      ------
      EThread
        Propagated when the runtime cannot create the thread object.
      EOutOfMemory
        Propagated when worker allocation fails.
    *}
    constructor Create(AOwner: TScanAnalysisPool);
  end;

  {**
    Persistent bounded pool for path-independent scan analysis.

    Submit and result-consumption methods are coordinator-only. Workers access
    queues under the private lock. At most twice the worker count jobs may be
    queued, active, or awaiting ordered publication at any time.
  *}
  TScanAnalysisPool = class
  private
    FLock: TRTLCriticalSection;
    FLockInitialized: Boolean;
    FJobEvent: TEvent;
    FResultEvent: TEvent;
    FWorkers: TObjectList;
    FJobs: TObjectList;
    FResults: TObjectList;
    FOutstandingPaths: TStringList;
    FWorkerCount: Integer;
    FStartedWorkerCount: Integer;
    FMaximumInFlight: Integer;
    FPeakInFlight: Integer;
    FHasSubmittedOrdinal: Boolean;
    FNextSubmittedOrdinal: QWord;
    FNextTakenOrdinal: QWord;
    FCancelled: Boolean;
    FStopping: Boolean;
    FJoined: Boolean;
    FWorkerFailure: string;

    {**
      Removes the next queued job for one worker.

      Parameters
      ----------
      None

      Returns
      -------
      TScanAnalysisJob
        Worker-owned job, or nil while stopped, cancelled, or empty.

      Raises
      ------
      None
    *}
    function TakeJob: TScanAnalysisJob;

    {**
      Publishes one completed transaction under the pool lock.

      Parameters
      ----------
      AResult
        Worker-owned result transferred to the pool after successful enqueue.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated when the completed-result queue cannot grow.
    *}
    procedure StoreResult(AResult: TScanAnalysisResult);

    {**
      Retains the first worker failure and cancels queued work.

      Parameters
      ----------
      AMessage
        Deterministic failure text reported by a worker.

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    procedure StoreWorkerFailure(const AMessage: string);

    {**
      Reads the cancellation or stopping state under the pool lock.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True when workers must stop current analysis.

      Raises
      ------
      None
    *}
    function WorkerCancellationRequested: Boolean;

    {**
      Marks the pool as stopping and optionally cancels queued jobs.

      Parameters
      ----------
      ACancel
        Also records cancellation and destroys queued jobs when True.

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    procedure SetStopping(ACancel: Boolean);

    {**
      Terminates and joins every worker exactly once.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EThread
        Propagated when the runtime cannot wait for a started worker.
    *}
    procedure JoinWorkers;
  public
    {**
      Creates and starts a bounded persistent worker pool.

      Parameters
      ----------
      AWorkerCount
        Worker count from MinimumScanWorkerCount through MaximumScanWorkerCount.

      Returns
      -------
      TScanAnalysisPool
        Caller-owned running pool with a two-per-worker in-flight bound.

      Raises
      ------
      EArgumentOutOfRangeException
        Raised when AWorkerCount is outside the supported range.
      EThread
        Propagated when a worker cannot be created or started.
      EOutOfMemory
        Propagated if pool queues or workers cannot be allocated.
    *}
    constructor Create(AWorkerCount: Integer);

    {**
      Stops, joins, and frees all workers, jobs, results, and synchronization.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    destructor Destroy; override;

    {**
      Queues the next consecutive job without exceeding the in-flight bound.

      Parameters
      ----------
      AJob
        Caller-owned job transferred to the pool only when True is returned.

      Returns
      -------
      Boolean
        True when queued; False for nil, stopped, cancelled, or full input.

      Raises
      ------
      EArgumentException
        Raised when the ordinal is not the next consecutive value.
      EOutOfMemory
        Propagated when queue or outstanding-path storage cannot grow.
    *}
    function Submit(AJob: TScanAnalysisJob): Boolean;

    {**
      Transfers the exact next ordered result when it is ready.

      Parameters
      ----------
      AOrdinal
        Required next publication ordinal.
      AResult
        Receives the caller-owned result on success, otherwise nil.

      Returns
      -------
      Boolean
        True when the exact next result was removed from the pool.

      Raises
      ------
      EStringListError
        Raised if internal result and path accounting diverges.
    *}
    function TryTakeResult(AOrdinal: QWord;
      out AResult: TScanAnalysisResult): Boolean;

    {**
      Tests whether a completed result with one ordinal is buffered.

      Parameters
      ----------
      AOrdinal
        Result ordinal to query.

      Returns
      -------
      Boolean
        True when the result is present, regardless of publication order.

      Raises
      ------
      None
    *}
    function IsResultReady(AOrdinal: QWord): Boolean;

    {**
      Waits for a completion notification without consuming pool state.

      Parameters
      ----------
      ATimeoutMilliseconds
        Maximum wait duration passed to the result event.

      Returns
      -------
      TWaitResult
        Event wait outcome; callers must recheck results and failure state.

      Raises
      ------
      ESyncObjectException
        Propagated when the synchronization primitive cannot be waited on.
    *}
    function WaitForResult(ATimeoutMilliseconds: Cardinal): TWaitResult;

    {**
      Requests cooperative cancellation and destroys jobs not yet taken.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    procedure RequestCancel;

    {**
      Cancels queued work, terminates workers, and waits for their exit.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EThread
        Propagated when the runtime cannot join a worker.
    *}
    procedure CancelAndJoin;

    {**
      Stops new work and joins workers without marking results cancelled.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EThread
        Propagated when the runtime cannot join a worker.
    *}
    procedure StopAndJoin;

    {**
      Retrieves the first contained worker failure.

      Parameters
      ----------
      AMessage
        Receives failure text, or an empty string when no worker failed.

      Returns
      -------
      Boolean
        True when AMessage contains a failure.

      Raises
      ------
      None
    *}
    function HasWorkerFailure(out AMessage: string): Boolean;

    {**
      Counts jobs queued, active, or awaiting ordered publication.

      Parameters
      ----------
      None

      Returns
      -------
      Integer
        Current outstanding-path count.

      Raises
      ------
      None
    *}
    function InFlight: Integer;

    {**
      Returns the path of the oldest job not yet published.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Root-relative path, or an empty string when no work is outstanding.

      Raises
      ------
      None
    *}
    function OldestUncommittedPath: string;

    property WorkerCount: Integer read FWorkerCount;
    property MaximumInFlight: Integer read FMaximumInFlight;
    property PeakInFlight: Integer read FPeakInFlight;
  end;

implementation

constructor TScanAnalysisWorker.Create(AOwner: TScanAnalysisPool);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FOwner := AOwner;
end;

procedure TScanAnalysisWorker.Execute;
const
  WorkerWakeIntervalMilliseconds = 50;
var
  Job: TScanAnalysisJob;
  AnalysisResult: TScanAnalysisResult;
begin
  try
    while not Terminated do
    begin
      Job := FOwner.TakeJob;
      if Job = nil then
      begin
        if FOwner.WorkerCancellationRequested then
          Break;
        FOwner.FJobEvent.WaitFor(WorkerWakeIntervalMilliseconds);
        Continue;
      end;

      AnalysisResult := nil;
      try
        try
          AnalysisResult := ExecuteScanAnalysis(Job,
            @FOwner.WorkerCancellationRequested);
          if FOwner.WorkerCancellationRequested then
            AnalysisResult.Cancelled := True;
          FOwner.StoreResult(AnalysisResult);
          AnalysisResult := nil;
        except
          on E: Exception do
            FOwner.StoreWorkerFailure('Scan analysis worker failed (' +
              E.ClassName + '): ' + E.Message);
        else
          FOwner.StoreWorkerFailure(
            'Scan analysis worker failed with a non-standard exception');
        end;
      finally
        AnalysisResult.Free;
        Job.Free;
      end;
    end;
  except
    on E: Exception do
      FOwner.StoreWorkerFailure('Scan analysis worker terminated (' +
        E.ClassName + '): ' + E.Message);
  else
    FOwner.StoreWorkerFailure(
      'Scan analysis worker terminated with a non-standard exception');
  end;
end;

constructor TScanAnalysisPool.Create(AWorkerCount: Integer);
var
  I: Integer;
  Worker: TScanAnalysisWorker;
begin
  inherited Create;
  if (AWorkerCount < MinimumScanWorkerCount) or
    (AWorkerCount > MaximumScanWorkerCount) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'Scan worker count must be between %d and %d',
      [MinimumScanWorkerCount, MaximumScanWorkerCount]);
  FWorkerCount := AWorkerCount;
  FMaximumInFlight := AWorkerCount * 2;
  InitCriticalSection(FLock);
  FLockInitialized := True;
  FJobEvent := TEvent.Create(nil, False, False, '');
  FResultEvent := TEvent.Create(nil, False, False, '');
  FWorkers := TObjectList.Create(True);
  FJobs := TObjectList.Create(True);
  FResults := TObjectList.Create(True);
  FOutstandingPaths := TStringList.Create;
  try
    FWorkers.Capacity := FWorkerCount;
    for I := 1 to FWorkerCount do
    begin
      Worker := TScanAnalysisWorker.Create(Self);
      try
        Worker.Start;
        FWorkers.Add(Worker);
        Worker := nil;
        Inc(FStartedWorkerCount);
      except
        Worker.Free;
        raise;
      end;
    end;
  except
    SetStopping(True);
    JoinWorkers;
    raise;
  end;
end;

destructor TScanAnalysisPool.Destroy;
begin
  SetStopping(True);
  JoinWorkers;
  FOutstandingPaths.Free;
  FResults.Free;
  FJobs.Free;
  FWorkers.Free;
  FResultEvent.Free;
  FJobEvent.Free;
  if FLockInitialized then
    DoneCriticalSection(FLock);
  inherited Destroy;
end;

function TScanAnalysisPool.TakeJob: TScanAnalysisJob;
begin
  Result := nil;
  EnterCriticalSection(FLock);
  try
    if FStopping or FCancelled or (FJobs.Count = 0) then
      Exit;
    Result := TScanAnalysisJob(FJobs.Extract(FJobs[0]));
    { An auto-reset event can coalesce signals. Relay one while queued work
      remains so every persistent worker can become active. }
    if FJobs.Count > 0 then
      FJobEvent.SetEvent;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TScanAnalysisPool.StoreResult(AResult: TScanAnalysisResult);
begin
  if AResult = nil then
    Exit;
  EnterCriticalSection(FLock);
  try
    { Cancellation and result publication share this lock. This closes the
      completion race between a worker's last cooperative poll and enqueue. }
    if FCancelled or FStopping then
      AResult.Cancelled := True;
    FResults.Add(AResult);
  finally
    LeaveCriticalSection(FLock);
  end;
  FResultEvent.SetEvent;
end;

procedure TScanAnalysisPool.StoreWorkerFailure(const AMessage: string);
begin
  EnterCriticalSection(FLock);
  try
    if FWorkerFailure = '' then
      FWorkerFailure := AMessage;
    FCancelled := True;
    FJobs.Clear;
  finally
    LeaveCriticalSection(FLock);
  end;
  FResultEvent.SetEvent;
  FJobEvent.SetEvent;
end;

function TScanAnalysisPool.WorkerCancellationRequested: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FCancelled or FStopping;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TScanAnalysisPool.SetStopping(ACancel: Boolean);
begin
  if not FLockInitialized then
    Exit;
  EnterCriticalSection(FLock);
  try
    if ACancel then
    begin
      FCancelled := True;
      if FJobs <> nil then
        FJobs.Clear;
    end;
    FStopping := True;
  finally
    LeaveCriticalSection(FLock);
  end;
  if FJobEvent <> nil then
    FJobEvent.SetEvent;
  if FResultEvent <> nil then
    FResultEvent.SetEvent;
end;

procedure TScanAnalysisPool.JoinWorkers;
var
  I: Integer;
begin
  if FJoined or (FWorkers = nil) then
    Exit;
  for I := 0 to FStartedWorkerCount - 1 do
    TScanAnalysisWorker(FWorkers[I]).Terminate;
  if FJobEvent <> nil then
    FJobEvent.SetEvent;
  for I := 0 to FStartedWorkerCount - 1 do
    TScanAnalysisWorker(FWorkers[I]).WaitFor;
  FJoined := True;
end;

function TScanAnalysisPool.Submit(AJob: TScanAnalysisJob): Boolean;
begin
  Result := False;
  if AJob = nil then
    Exit;
  EnterCriticalSection(FLock);
  try
    if FStopping or FCancelled or
      (FOutstandingPaths.Count >= FMaximumInFlight) then
      Exit;
    if not FHasSubmittedOrdinal then
    begin
      FHasSubmittedOrdinal := True;
      FNextSubmittedOrdinal := AJob.Ordinal;
      FNextTakenOrdinal := AJob.Ordinal;
    end;
    if AJob.Ordinal <> FNextSubmittedOrdinal then
      raise EArgumentException.CreateFmt(
        'Analysis jobs must be submitted in consecutive ordinal order ' +
        '(expected %d, received %d)',
        [FNextSubmittedOrdinal, AJob.Ordinal]);
    FOutstandingPaths.Add(AJob.RelativePath);
    try
      FJobs.Add(AJob);
    except
      FOutstandingPaths.Delete(FOutstandingPaths.Count - 1);
      raise;
    end;
    Inc(FNextSubmittedOrdinal);
    if FOutstandingPaths.Count > FPeakInFlight then
      FPeakInFlight := FOutstandingPaths.Count;
    Result := True;
  finally
    LeaveCriticalSection(FLock);
  end;
  if Result then
    FJobEvent.SetEvent;
end;

function TScanAnalysisPool.TryTakeResult(AOrdinal: QWord;
  out AResult: TScanAnalysisResult): Boolean;
var
  I: Integer;
begin
  AResult := nil;
  EnterCriticalSection(FLock);
  try
    if not FHasSubmittedOrdinal or (AOrdinal <> FNextTakenOrdinal) then
      Exit(False);
    for I := 0 to FResults.Count - 1 do
      if TScanAnalysisResult(FResults[I]).Ordinal = AOrdinal then
      begin
        if FOutstandingPaths.Count = 0 then
          raise EStringListError.Create(
            'Analysis pool lost its outstanding-path invariant');
        AResult := TScanAnalysisResult(FResults.Extract(FResults[I]));
        FOutstandingPaths.Delete(0);
        Inc(FNextTakenOrdinal);
        Exit(True);
      end;
    Result := False;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TScanAnalysisPool.IsResultReady(AOrdinal: QWord): Boolean;
var
  I: Integer;
begin
  EnterCriticalSection(FLock);
  try
    for I := 0 to FResults.Count - 1 do
      if TScanAnalysisResult(FResults[I]).Ordinal = AOrdinal then
        Exit(True);
    Result := False;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TScanAnalysisPool.WaitForResult(
  ATimeoutMilliseconds: Cardinal): TWaitResult;
begin
  Result := FResultEvent.WaitFor(ATimeoutMilliseconds);
end;

procedure TScanAnalysisPool.RequestCancel;
begin
  EnterCriticalSection(FLock);
  try
    FCancelled := True;
    FJobs.Clear;
  finally
    LeaveCriticalSection(FLock);
  end;
  FJobEvent.SetEvent;
  FResultEvent.SetEvent;
end;

procedure TScanAnalysisPool.CancelAndJoin;
begin
  SetStopping(True);
  JoinWorkers;
end;

procedure TScanAnalysisPool.StopAndJoin;
begin
  SetStopping(False);
  JoinWorkers;
end;

function TScanAnalysisPool.HasWorkerFailure(out AMessage: string): Boolean;
begin
  EnterCriticalSection(FLock);
  try
    AMessage := FWorkerFailure;
    Result := AMessage <> '';
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TScanAnalysisPool.InFlight: Integer;
begin
  EnterCriticalSection(FLock);
  try
    Result := FOutstandingPaths.Count;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TScanAnalysisPool.OldestUncommittedPath: string;
begin
  EnterCriticalSection(FLock);
  try
    if FOutstandingPaths.Count > 0 then
      Result := FOutstandingPaths[0]
    else
      Result := '';
  finally
    LeaveCriticalSection(FLock);
  end;
end;

end.
