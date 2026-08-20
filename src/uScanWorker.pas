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
  Classes, SysUtils, uModels, uScanEngine;

type
  TWorkerProgressEvent = procedure(Sender: TObject;
    const AProgress: TScanProgress) of object;
  TWorkerCompleteEvent = procedure(Sender: TObject; AResult: TScanTask) of object;

  TScanWorker = class(TThread)
  private
    FTask: TScanTask;
    FDataDirectory: string;
    FLatestProgress: TScanProgress;
    FProgressQueued: LongInt;
    FProgressLock: TRTLCriticalSection;
    FOnProgress: TWorkerProgressEvent;
    FOnComplete: TWorkerCompleteEvent;
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

    {**
      Generates, hashes, and atomically persists CycloneDX for FTask.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EFCreateError, EWriteError, EInOutError
        Propagated when SBOM generation or atomic persistence fails.
    }
    procedure GenerateSBOM;
  protected
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

      Returns
      -------
      TScanWorker
        Suspended worker owned by the caller.

      Raises
      ------
      EAccessViolation
        Raised when ATask is nil.
      EOutOfMemory
        Propagated if the thread, task clone, or lock cannot be initialized.
    }
    constructor Create(ATask: TScanTask; const ADataDirectory: string);
    destructor Destroy; override;

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
  uCycloneDX, uAtomicFiles, uSHA256, uTimeUtils;

constructor TScanWorker.Create(ATask: TScanTask; const ADataDirectory: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FTask := ATask.Clone;
  FDataDirectory := ExcludeTrailingPathDelimiter(ADataDirectory);
  InitCriticalSection(FProgressLock);
end;

destructor TScanWorker.Destroy;
begin
  FOnProgress := nil;
  FOnComplete := nil;
  if not Finished then
  begin
    Terminate;
    WaitFor;
  end;
  TThread.RemoveQueuedEvents(Self);
  DoneCriticalSection(FProgressLock);
  FTask.Free;
  inherited Destroy;
end;

procedure TScanWorker.Cancel;
begin
  Terminate;
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

procedure TScanWorker.GenerateSBOM;
var
  DirectoryName, FileName, Digest: string;
  Content: UTF8String;
begin
  DirectoryName := IncludeTrailingPathDelimiter(FDataDirectory) + 'sboms';
  if not ForceDirectories(DirectoryName) then
    raise EInOutError.CreateFmt('Unable to create SBOM directory: %s',
      [DirectoryName]);
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + FTask.ID +
    '.cdx.json';
  Content := GenerateCycloneDX(FTask);
  WriteAtomicUTF8(FileName, Content, False);
  if not SHA256File(FileName, Digest, @CancellationRequested, nil) then
    raise EAbort.Create('SBOM generation was cancelled');
  FTask.GeneratedSBOMPath := FileName;
  FTask.GeneratedSBOMSHA256 := Digest;
end;

procedure TScanWorker.Execute;
var
  Engine: TScanEngine;
begin
  Engine := TScanEngine.Create(@CancellationRequested, @EngineProgress);
  try
    Engine.Scan(FTask);
    if (FTask.Status = tsCompleted) and not Terminated then
    begin
      try
        GenerateSBOM;
      except
        on E: EAbort do
          FTask.Status := tsCancelled;
        on E: Exception do
        begin
          FTask.Status := tsFailed;
          FTask.Errors.Add('Unable to generate the CycloneDX file: ' + E.Message);
        end;
      end;
    end;
    FTask.CompletedUTC := UTCNowISO8601;
    FTask.DurationMS := DurationMilliseconds(FTask.StartedUTC,
      FTask.CompletedUTC);
  finally
    Engine.Free;
  end;
  TThread.Queue(Self, @DeliverCompletion);
end;

end.
