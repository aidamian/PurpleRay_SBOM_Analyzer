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
    function CancellationRequested: Boolean;
    procedure EngineProgress(const AProgress: TScanProgress);
    procedure DeliverProgress;
    procedure DeliverCompletion;
    procedure GenerateSBOM;
  protected
    procedure Execute; override;
  public
    constructor Create(ATask: TScanTask; const ADataDirectory: string);
    destructor Destroy; override;
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
