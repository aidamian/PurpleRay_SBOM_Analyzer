{ Sprint 9 manual OSV.dev refresh regressions. This file is included after
  RunTest is declared. Every refresh test injects an in-memory transport; no
  test opens a network endpoint or rescans a target. }

type
  TS9TransportMode = (
    s9tmSucceeded,
    s9tmFailed,
    s9tmWaitForCancellation
  );

  TS9FakeOSVTransport = class(TInterfacedObject, IOSVTransport)
  private
    FCancelled: LongInt;
    FEntered: LongInt;
    FMode: TS9TransportMode;
  public
    Requests: TStringList;
    constructor Create(AMode: TS9TransportMode);
    destructor Destroy; override;
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    procedure Cancel;
    function Entered: Boolean;
  end;

  { Supplies the fake transport through the worker's protected refresh seam.
    Raising before the service call also verifies the completion/adoption gate
    for an unexpected worker-local failure. }
  TS9RefreshWorker = class(TScanWorker)
  private
    FFakeTransport: IOSVTransport;
    FRaiseBeforeRefresh: Boolean;
    function RefreshCancellationRequested: Boolean;
  protected
    procedure PerformKnownIssueRefresh; override;
  public
    constructor CreateForTest(ATask: TScanTask;
      const ATransport: IOSVTransport; ARaiseBeforeRefresh: Boolean = False);
  end;

constructor TS9FakeOSVTransport.Create(AMode: TS9TransportMode);
begin
  inherited Create;
  FMode := AMode;
  Requests := TStringList.Create;
end;

destructor TS9FakeOSVTransport.Destroy;
begin
  Requests.Free;
  inherited Destroy;
end;

function TS9FakeOSVTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
var
  Deadline: QWord;
begin
  Requests.Add(string(ARequestBody));
  InterlockedExchange(FEntered, 1);
  AHTTPStatus := 0;
  AResponseBody := '';
  case FMode of
    s9tmSucceeded:
      begin
        AHTTPStatus := 200;
        AResponseBody := '{"results":[{"vulns":[{' +
          '"id":"GHSA-sprint-nine-new","modified":' +
          '"2026-08-23T12:00:00Z"}]}]}';
        if Length(AResponseBody) > AMaximumResponseBytes then
          Exit(otoResponseTooLarge);
        Result := otoSucceeded;
      end;
    s9tmFailed:
      Result := otoFailed;
    s9tmWaitForCancellation:
      begin
        Deadline := GetTickCount64 + 5000;
        repeat
          if (InterlockedCompareExchange(FCancelled, 0, 0) <> 0) or
            (Assigned(ACancelCheck) and ACancelCheck()) then
            Exit(otoCancelled);
          Sleep(1);
        until GetTickCount64 >= Deadline;
        Result := otoFailed;
      end;
  else
    Result := otoFailed;
  end;
end;

procedure TS9FakeOSVTransport.Cancel;
begin
  InterlockedExchange(FCancelled, 1);
end;

function TS9FakeOSVTransport.Entered: Boolean;
begin
  Result := InterlockedCompareExchange(FEntered, 0, 0) <> 0;
end;

constructor TS9RefreshWorker.CreateForTest(ATask: TScanTask;
  const ATransport: IOSVTransport; ARaiseBeforeRefresh: Boolean);
begin
  inherited CreateKnownIssueRefresh(ATask);
  FFakeTransport := ATransport;
  FRaiseBeforeRefresh := ARaiseBeforeRefresh;
end;

function TS9RefreshWorker.RefreshCancellationRequested: Boolean;
begin
  Result := Terminated;
end;

procedure TS9RefreshWorker.PerformKnownIssueRefresh;
begin
  if FRaiseBeforeRefresh then
    raise Exception.Create('intentional Sprint 9 refresh failure');
  ExecuteKnownIssueCheck(ResultTask, FFakeTransport,
    @RefreshCancellationRequested);
end;

function S9NewMatch(const APackageURL, AAdvisoryID,
  AModified: string): TKnownIssueMatch;
begin
  Result := TKnownIssueMatch.Create;
  Result.PackageURL := APackageURL;
  Result.AdvisoryID := AAdvisoryID;
  Result.Modified := AModified;
end;

procedure S9InitializeCheck(ACheck: TKnownIssueCheck;
  const AOutcomeCode, ACheckedUTC: string);
begin
  ACheck.Clear;
  ACheck.Requested := True;
  ACheck.CheckedUTC := ACheckedUTC;
  ACheck.OutcomeCode := AOutcomeCode;
  if AOutcomeCode = OSVOutcomeCode(osoSucceeded) then
    ACheck.HTTPStatus := 200;
end;

function S9TaskJSON(ATask: TScanTask): string;
var
  Value: TJSONObject;
begin
  Value := ATask.ToJSON;
  try
    Result := Value.AsJSON;
  finally
    Value.Free;
  end;
end;

function S9CompletedTask: TScanTask;
begin
  Result := TScanTask.Create;
  Result.ID := '90112233-4455-6677-8899-aabbccddeeff';
  Result.TargetDirectory := '/private/sprint-nine-target-path';
  Result.TargetRootName := 'sprint-nine-target';
  Result.Status := tsCompleted;
  Result.CreatedUTC := '2026-08-23T10:00:00Z';
  Result.StartedUTC := '2026-08-23T10:00:01Z';
  Result.CompletedUTC := '2026-08-23T10:00:02Z';
  Result.DurationMS := 1000;
  Result.FilesInspected := 7;
  Result.BytesInspected := 12345;
  Result.ArtifactsDetected := 2;
  Result.ArtifactsParsed := 2;
  Result.ComponentsIdentified := 2;
  Result.GeneratedSBOMPath :=
    '/private/managed/sboms/90112233-4455-6677-8899-aabbccddeeff.cdx.json';
  Result.GeneratedSBOMSHA256 :=
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  Result.ScannerVersion := '0.8.4';
  Result.ScannerCommit := 'ffdb850';
  Result.Settings.SBOMAuthorOrganization := 'Private Sprint Nine Author';
  Result.Settings.SBOMAuthorEmail := 'private-s9@example.invalid';
  AddComparisonComponent(Result, 'sprint-nine', '1.2.3', 'npm',
    'library', 'pkg:npm/sprint-nine@1.2.3', 'runtime');
  AddComparisonComponent(Result, 'private-rejected-coordinate', '9.9.9',
    'npm', 'library',
    'pkg:npm/private-rejected-coordinate@9.9.9?secret-token=never-send',
    'runtime');
  S9InitializeCheck(Result.KnownIssueCheck,
    OSVOutcomeCode(osoSucceeded), '2026-08-22T12:00:00Z');
  AssertTrue(Result.KnownIssueCheck.AddMatch(S9NewMatch(
    'pkg:npm/sprint-nine@1.2.3', 'GHSA-sprint-nine-old',
    '2026-08-22T12:00:00Z')),
    'unable to initialize the Sprint 9 prior known-issue snapshot');
end;

procedure S9WaitForTransport(AFake: TS9FakeOSVTransport);
var
  Deadline: QWord;
begin
  Deadline := GetTickCount64 + 2000;
  while not AFake.Entered and (GetTickCount64 < Deadline) do
    Sleep(1);
  AssertTrue(AFake.Entered,
    'Sprint 9 fake transport was not entered before the deadline');
end;

procedure TestSprint9KnownIssueReplacementPolicy;
var
  Candidate: TKnownIssueCheck;
  Outcome: TOSVOutcome;
begin
  Candidate := TKnownIssueCheck.Create;
  try
    AssertTrue(not KnownIssueCheckCanReplace(nil),
      'nil known-issue result was replaceable');
    AssertTrue(not KnownIssueCheckCanReplace(Candidate),
      'unrequested known-issue result was replaceable');
    Candidate.Requested := True;
    for Outcome := Low(TOSVOutcome) to High(TOSVOutcome) do
    begin
      Candidate.OutcomeCode := OSVOutcomeCode(Outcome);
      AssertTrue(KnownIssueCheckCanReplace(Candidate) =
        (Outcome in [osoSucceeded, osoNoEligibleCandidates]),
        'known-issue replacement eligibility differs for ' +
        OSVOutcomeCode(Outcome));
    end;
    Candidate.OutcomeCode := 'transport-unavailable';
    AssertTrue(not KnownIssueCheckCanReplace(Candidate),
      'transport-unavailable result was replaceable');
    Candidate.OutcomeCode := 'lookup-failed';
    AssertTrue(not KnownIssueCheckCanReplace(Candidate),
      'lookup-failed result was replaceable');
  finally
    Candidate.Free;
  end;
end;

procedure TestSprint9RefreshWorkerIsolationAndPrivacy;
const
  ExpectedRequest = '{"queries":[{"package":{"purl":' +
    '"pkg:npm/sprint-nine@1.2.3"}}]}';
var
  ComparableResult, SourceTask: TScanTask;
  Fake: TS9FakeOSVTransport;
  SourceJSON, RequestText: string;
  Transport: IOSVTransport;
  Worker: TS9RefreshWorker;
begin
  SourceTask := S9CompletedTask;
  ComparableResult := nil;
  Worker := nil;
  Fake := TS9FakeOSVTransport.Create(s9tmSucceeded);
  Transport := Fake;
  try
    SourceJSON := S9TaskJSON(SourceTask);
    Worker := TS9RefreshWorker.CreateForTest(SourceTask, Transport);
    AssertTrue(Worker.WorkerMode = swmKnownIssueRefresh,
      'manual refresh worker selected scan mode');
    Worker.Start;
    Worker.WaitFor;
    AssertTrue(Worker.RefreshAttemptCompleted,
      'successful manual refresh did not complete its worker attempt');
    AssertTrue(KnownIssueCheckCanReplace(Worker.ResultTask.KnownIssueCheck),
      'successful manual refresh did not yield a replaceable result');
    AssertEqual(1, Worker.ResultTask.KnownIssueCheck.MatchCount,
      'successful manual refresh match count differs');
    AssertEqual('GHSA-sprint-nine-new',
      Worker.ResultTask.KnownIssueCheck.Matches[0].AdvisoryID,
      'successful manual refresh retained the old advisory');
    AssertEqual(1, Fake.Requests.Count,
      'manual refresh sent an unexpected request count');
    RequestText := Fake.Requests[0];
    AssertEqual(ExpectedRequest, RequestText,
      'manual refresh request contains fields beyond the eligible Package URL');
    AssertTrue(Pos(SourceTask.TargetDirectory, RequestText) = 0,
      'manual refresh request leaked the target path');
    AssertTrue(Pos(SourceTask.GeneratedSBOMPath, RequestText) = 0,
      'manual refresh request leaked the managed SBOM path');
    AssertTrue(Pos(SourceTask.GeneratedSBOMSHA256, RequestText) = 0,
      'manual refresh request leaked the managed SBOM hash');
    AssertTrue(Pos(SourceTask.Settings.SBOMAuthorOrganization,
      RequestText) = 0,
      'manual refresh request leaked the SBOM author');
    AssertTrue(Pos('secret-token', RequestText) = 0,
      'manual refresh request leaked a rejected Package URL');

    { Normalize only the refreshed field, then compare the complete persisted
      task representation. This proves the worker changed no scan inventory,
      status, timing, settings, output metadata, components, or diagnostics. }
    ComparableResult := Worker.ResultTask.Clone;
    ComparableResult.KnownIssueCheck.Assign(SourceTask.KnownIssueCheck);
    AssertEqual(SourceJSON, S9TaskJSON(ComparableResult),
      'manual refresh changed persisted task state outside KnownIssueCheck');
    AssertEqual('GHSA-sprint-nine-old',
      SourceTask.KnownIssueCheck.Matches[0].AdvisoryID,
      'manual refresh mutated the caller-owned source task');
  finally
    Worker.Free;
    Transport := nil;
    ComparableResult.Free;
    SourceTask.Free;
  end;
end;

procedure TestSprint9RefreshFailureAndCancellation;
var
  Fake: TS9FakeOSVTransport;
  SourceTask: TScanTask;
  Transport: IOSVTransport;
  Worker: TS9RefreshWorker;

  procedure AssertNotAdoptable(const ALabel: string);
  begin
    AssertTrue(not (Worker.RefreshAttemptCompleted and
      KnownIssueCheckCanReplace(Worker.ResultTask.KnownIssueCheck)),
      ALabel + ' produced an adoptable refresh result');
    AssertTrue(Worker.ResultTask.Status = tsCompleted,
      ALabel + ' relabelled the completed inventory');
    AssertEqual(SourceTask.CreatedUTC, Worker.ResultTask.CreatedUTC,
      ALabel + ' changed the inventory creation time');
    AssertEqual(SourceTask.StartedUTC, Worker.ResultTask.StartedUTC,
      ALabel + ' changed the inventory start time');
    AssertEqual(SourceTask.CompletedUTC, Worker.ResultTask.CompletedUTC,
      ALabel + ' changed the inventory completion time');
    AssertEqual(SourceTask.DurationMS, Worker.ResultTask.DurationMS,
      ALabel + ' changed the inventory duration');
    AssertEqual(SourceTask.GeneratedSBOMPath,
      Worker.ResultTask.GeneratedSBOMPath,
      ALabel + ' changed the managed SBOM path');
    AssertEqual(SourceTask.GeneratedSBOMSHA256,
      Worker.ResultTask.GeneratedSBOMSHA256,
      ALabel + ' changed the managed SBOM digest');
  end;

begin
  SourceTask := S9CompletedTask;
  Worker := nil;
  Transport := nil;
  try
    Fake := TS9FakeOSVTransport.Create(s9tmFailed);
    Transport := Fake;
    Worker := TS9RefreshWorker.CreateForTest(SourceTask, Transport);
    Worker.Start;
    Worker.WaitFor;
    AssertTrue(Worker.RefreshAttemptCompleted,
      'transport-failed refresh did not finish its bounded attempt');
    AssertEqual(OSVOutcomeCode(osoTransportFailed),
      Worker.ResultTask.KnownIssueCheck.OutcomeCode,
      'transport-failed refresh outcome differs');
    AssertNotAdoptable('transport-failed refresh');
    FreeAndNil(Worker);
    Transport := nil;

    Fake := TS9FakeOSVTransport.Create(s9tmWaitForCancellation);
    Transport := Fake;
    Worker := TS9RefreshWorker.CreateForTest(SourceTask, Transport);
    Worker.Start;
    S9WaitForTransport(Fake);
    Worker.Cancel;
    Worker.WaitFor;
    AssertTrue(Worker.RefreshAttemptCompleted,
      'cancelled refresh did not finish its bounded attempt');
    AssertEqual(OSVOutcomeCode(osoCancelled),
      Worker.ResultTask.KnownIssueCheck.OutcomeCode,
      'cancelled refresh outcome differs');
    AssertNotAdoptable('cancelled refresh');
    FreeAndNil(Worker);
    Transport := nil;

    Worker := TS9RefreshWorker.CreateForTest(SourceTask, nil, True);
    Worker.Start;
    Worker.WaitFor;
    AssertTrue(not Worker.RefreshAttemptCompleted,
      'unexpected refresh exception was marked completed');
    AssertNotAdoptable('exceptional refresh');
    AssertEqual('GHSA-sprint-nine-old',
      SourceTask.KnownIssueCheck.Matches[0].AdvisoryID,
      'failed refresh mutated the caller-owned previous result');
  finally
    Worker.Free;
    Transport := nil;
    SourceTask.Free;
  end;
end;

procedure TestSprint9RefreshUIAndCLIContract;
var
  ActiveFooterBlock, AnalyzerResource, AnalyzerSource, CancellationBlock,
    CommandSource, CompletionBlock, ConsentBlock, FinalizeBlock,
    SuccessFooterBlock: string;
  ApplyAt, BranchAt, CancelAt, ClearAt, ConfirmAt, ElseAt, EndIfAt, FreeAt,
    GTKAt, MarqueeAt, NormalAt, StateGuardAt, WorkerGuardAt: SizeInt;
  Lines: TStringList;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uSBOMAnalyzerFrame.lfm');
    AnalyzerResource := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uSBOMAnalyzerFrame.pas');
    AnalyzerSource := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uCommandLine.pas');
    CommandSource := Lines.Text;

    AssertTrue((Pos('object FRefreshIntelligenceButton: TButton',
      AnalyzerResource) > 0) and
      (Pos('Caption = ''Refresh intelligence...''', AnalyzerResource) > 0) and
      (Pos('OnClick = RefreshIntelligenceClicked', AnalyzerResource) > 0),
      'manual intelligence refresh action is missing or not wired');
    ConsentBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.RefreshIntelligenceClicked',
      'procedure TSBOMAnalyzerFrame.RefreshClicked');
    AssertTrue(ConsentBlock <> '',
      'manual intelligence refresh handler is missing');
    AssertTrue(Pos('Only eligible canonical versioned Package URLs are ' +
      'sent to OSV.dev.', ConsentBlock) > 0,
      'manual refresh consent does not disclose the sent identifiers');
    AssertTrue(Pos('No files, paths, hashes, authors, or SBOM content are ' +
      'sent.', ConsentBlock) > 0,
      'manual refresh consent omits prohibited-data disclosure');
    AssertTrue(Pos('The target is not rescanned and the managed SBOM will ' +
      'not change.', ConsentBlock) > 0,
      'manual refresh consent omits immutable-inventory disclosure');
    AssertTrue(Pos('This consent applies only to this refresh.',
      ConsentBlock) > 0,
      'manual refresh consent can be mistaken for a remembered choice');
    AssertTrue(Pos('StartIntelligenceRefresh(Task)', ConsentBlock) > 0,
      'accepted manual refresh does not start the dedicated worker');

    CompletionBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.CompleteIntelligenceRefresh',
      'procedure TSBOMAnalyzerFrame.ShowError');
    SuccessFooterBlock := ExtractTextSection(CompletionBlock,
      '    SetCompactFooter(Format(', '  except');
    AssertTrue((Pos('OSV.dev intelligence refreshed at %s: %d matches.',
      SuccessFooterBlock) > 0) and
      (Pos('[Task.KnownIssueCheck.CheckedUTC,', SuccessFooterBlock) > 0) and
      (Pos('Task.KnownIssueCheck.MatchCount]))', SuccessFooterBlock) > 0),
      'successful refresh footer does not report only check time and matches');

    FinalizeBlock := ExtractTextSection(AnalyzerSource,
      'function TSBOMAnalyzerFrame.FinalizeFinishedWorker',
      'procedure TSBOMAnalyzerFrame.ForceShutdown');
    BranchAt := Pos('else if FActiveTaskID <> '''' then', FinalizeBlock);
    ApplyAt := Pos('CompleteIntelligenceRefresh(FWorker.ResultTask);',
      FinalizeBlock);
    ClearAt := Pos('SetActiveTaskID('''');', FinalizeBlock);
    FreeAt := Pos('FreeAndNil(FWorker);', FinalizeBlock);
    AssertTrue((BranchAt > 0) and (ApplyAt > BranchAt) and
      (ClearAt > ApplyAt) and (FreeAt > ClearAt),
      'finished refresh result is not applied before active-state cleanup');

    CancellationBlock := ExtractTextSection(AnalyzerSource,
      'function TSBOMAnalyzerFrame.RequestActiveCancellation',
      'procedure TSBOMAnalyzerFrame.AdoptWorkerResult');
    ConfirmAt := Pos('if AConfirm then', CancellationBlock);
    WorkerGuardAt := Pos('(FWorker = nil) or (FWorker <> Worker) or',
      CancellationBlock);
    StateGuardAt := Pos('(FActiveTaskID <> ActiveTaskID) or ' +
      'FWorker.Finished then', CancellationBlock);
    CancelAt := Pos('FCancelRequested := True;', CancellationBlock);
    AssertTrue((ConfirmAt > 0) and (WorkerGuardAt > ConfirmAt) and
      (StateGuardAt >= WorkerGuardAt) and (CancelAt > StateGuardAt),
      'modal cancellation does not revalidate worker state before mutation');

    ActiveFooterBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.SetActiveFooter',
      'procedure TSBOMAnalyzerFrame.SetCompactFooter');
    GTKAt := Pos('{$IFDEF LCLGTK2}', ActiveFooterBlock);
    NormalAt := Pos('FProgressBar.Style := pbstNormal;', ActiveFooterBlock);
    ElseAt := Pos('{$ELSE}', ActiveFooterBlock);
    MarqueeAt := Pos('FProgressBar.Style := pbstMarquee;',
      ActiveFooterBlock);
    EndIfAt := Pos('{$ENDIF}', ActiveFooterBlock);
    AssertTrue((GTKAt > 0) and (NormalAt > GTKAt) and (ElseAt > NormalAt) and
      (MarqueeAt > ElseAt) and (EndIfAt > MarqueeAt),
      'GTK2 progress style is not isolated from marquee mode');

    AssertTrue((Pos('--refresh-intelligence', CommandSource) = 0) and
      (Pos('--refresh-known-issues', CommandSource) = 0) and
      (Pos('--online', CommandSource) = 0) and
      (Pos('--osv', CommandSource) = 0),
      'headless command line exposes an online intelligence option');
  finally
    Lines.Free;
  end;
end;

procedure RunSprint9RegressionTests;
begin
  RunTest('Sprint 9 known-issue replacement policy',
    @TestSprint9KnownIssueReplacementPolicy);
  RunTest('Sprint 9 refresh worker isolation and request privacy',
    @TestSprint9RefreshWorkerIsolationAndPrivacy);
  RunTest('Sprint 9 refresh failure and cancellation policy',
    @TestSprint9RefreshFailureAndCancellation);
  RunTest('Sprint 9 refresh UI and CLI contract',
    @TestSprint9RefreshUIAndCLIContract);
end;
