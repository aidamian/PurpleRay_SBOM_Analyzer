{ Sprint 12 regressions: the LCL-free scan-details report, the rail /
  splash / red-row source contracts, and the cmd.exe launcher invariants.
  Tests are deterministic, offline, and LCL-free. }

function S12Match(const APackageURL, AAdvisoryID,
  AModified: string): TKnownIssueMatch;
begin
  Result := TKnownIssueMatch.Create;
  Result.PackageURL := APackageURL;
  Result.AdvisoryID := AAdvisoryID;
  Result.Modified := AModified;
end;

procedure S12AddComponent(ATask: TScanTask; const AName, AVersion,
  APackageURL: string);
var
  Component: uModels.TComponent;
begin
  Component := uModels.TComponent.Create;
  Component.Name := AName;
  Component.Version := AVersion;
  Component.Ecosystem := 'pypi';
  Component.PackageURL := APackageURL;
  ATask.Components.Add(Component);
end;

function S12Task(AStatus: TTaskStatus; ARequested: Boolean;
  const AOutcomeCode: string): TScanTask;
begin
  Result := TScanTask.Create;
  Result.Status := AStatus;
  Result.TargetDirectory := '/home/alice/clients/acme-bank/backend';
  Result.TargetRootName := 'backend';
  Result.CreatedUTC := '2026-08-25T08:00:00Z';
  Result.StartedUTC := '2026-08-25T08:00:01Z';
  if AStatus in [tsCompleted, tsCancelled, tsFailed] then
    Result.CompletedUTC := '2026-08-25T08:00:09Z';
  Result.DurationMS := 8000;
  Result.ComponentsIdentified := 3;
  S12AddComponent(Result, 'flask', '3.0.3', 'pkg:pypi/flask@3.0.3');
  S12AddComponent(Result, 'requests', '2.31.0', 'pkg:pypi/requests@2.31.0');
  S12AddComponent(Result, 'libcrypto', '', '');
  Result.KnownIssueCheck.Requested := ARequested;
  if ARequested then
  begin
    Result.KnownIssueCheck.CheckedUTC := '2026-08-25T08:00:08Z';
    Result.KnownIssueCheck.OutcomeCode := AOutcomeCode;
    Result.KnownIssueCheck.EligibleCandidateCount := 2;
    Result.KnownIssueCheck.RejectedCandidateCount := 0;
  end;
end;

function S12Report(ATask: TScanTask; APending: Boolean = False): string;
begin
  Result := BuildScanDetailsReport(ATask, APending);
end;

procedure TestDetailsReportOutcomeSentences;
var
  Task: TScanTask;
  Outcome: TOSVOutcome;
  Report: string;
begin
  Task := S12Task(tsCompleted, True, '');
  try
    for Outcome := Low(TOSVOutcome) to High(TOSVOutcome) do
    begin
      Task.KnownIssueCheck.OutcomeCode := OSVOutcomeCode(Outcome);
      Report := S12Report(Task);
      AssertTrue((Pos('Outcome code:', Report) = 0) and
        (Pos('cannot describe', Report) = 0),
        'outcome ' + OSVOutcomeCode(Outcome) + ' is not translated');
    end;
    Task.KnownIssueCheck.OutcomeCode := KnownIssueOutcomeTransportUnavailable;
    Report := S12Report(Task);
    AssertTrue((Pos('secure (TLS) connection', Report) > 0) and
      (Pos('eligible for lookup', Report) = 0),
      'transport-unavailable is not explained or still prints counts');
    Task.KnownIssueCheck.OutcomeCode := KnownIssueOutcomeLookupFailed;
    Report := S12Report(Task);
    AssertTrue(Pos('internal error in this application', Report) > 0,
      'lookup-failed is not explained');
    Task.KnownIssueCheck.OutcomeCode := 'future-code';
    Report := S12Report(Task);
    AssertTrue(Pos('cannot describe (code: future-code)', Report) > 0,
      'an unknown code must be described as such');
    AssertTrue((Pos('Outcome code:', Report) = 0),
      'the bare Outcome code fallback must be gone');
  finally
    Task.Free;
  end;
end;

procedure TestDetailsReportCountsAndCap;
var
  Task: TScanTask;
  Report: string;
  I: Integer;
begin
  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoSucceeded));
  try
    Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-TEST-0001', '2026-08-10T00:00:00Z'));
    Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-TEST-0002', '2024-06-10T20:40:14.641907Z'));
    Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/requests@2.31.0',
      'GHSA-TEST-0003', '20260823'));
    Report := S12Report(Task);
    AssertTrue(Pos('3 advisories affecting 2 packages', Report) > 0,
      'advisory and distinct package counts are wrong');
    AssertTrue((Pos('(advisory last updated 2026-08-10)', Report) > 0) and
      (Pos('(advisory last updated 2024-06-10)', Report) > 0) and
      (Pos('(advisory last updated 20260823)', Report) > 0),
      'advisory dates are not reduced to calendar dates');
    AssertTrue(Pos('shown in red in the Components tab', Report) > 0,
      'the report does not cross-reference the red rows');
    AssertTrue(Pos('* flask 3.0.3 (pypi)', Report) > 0,
      'affected packages are not labelled by component');
  finally
    Task.Free;
  end;

  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoSucceeded));
  try
    Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-ONLY-0001', '2026-08-10T00:00:00Z'));
    Report := S12Report(Task);
    AssertTrue(Pos('1 advisory affecting 1 package.', Report) > 0,
      'singular counts are wrong');
  finally
    Task.Free;
  end;

  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoSucceeded));
  try
    for I := 1 to MaximumDisplayedKnownIssueMatches do
      AssertTrue(Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
        Format('GHSA-CAP-%.4d', [I]), '2026-01-01T00:00:00Z')),
        'fixture match was rejected');
    Report := S12Report(Task);
    AssertEqual(MaximumDisplayedKnownIssueMatches,
      CountTextOccurrences(Report, 'https://osv.dev/vulnerability/'),
      'exactly the cap must be listed');
    AssertTrue(Pos('additional match', Report) = 0,
      'no omission notice at exactly the cap');
    AssertTrue(Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-CAP-EXTRA-1', '2026-01-01T00:00:00Z')), 'extra match rejected');
    Report := S12Report(Task);
    AssertEqual(MaximumDisplayedKnownIssueMatches,
      CountTextOccurrences(Report, 'https://osv.dev/vulnerability/'),
      'the cap must hold at cap + 1');
    AssertTrue(Pos('1 additional match is kept', Report) > 0,
      'singular omission notice is wrong');
    AssertTrue(Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-CAP-EXTRA-2', '2026-01-01T00:00:00Z')), 'extra match rejected');
    Report := S12Report(Task);
    AssertTrue(Pos('2 additional matches are kept', Report) > 0,
      'plural omission notice is wrong');
  finally
    Task.Free;
  end;
end;

procedure TestDetailsReportIncompleteConsequences;
var
  Task: TScanTask;
  Report: string;
begin
  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoTransportFailed));
  try
    Task.KnownIssueCheck.AddMatch(S12Match('pkg:pypi/flask@3.0.3',
      'GHSA-PART-0001', '2026-08-10T00:00:00Z'));
    Report := S12Report(Task);
    AssertTrue(Task.KnownIssueCheck.IsPartial, 'fixture is not partial');
    AssertTrue((Pos('could not be reached', Report) > 0) and
      (Pos('are incomplete', Report) > 0) and
      (Pos('No findings were recorded', Report) = 0) and
      (Pos('No results were recorded', Report) = 0) and
      (Pos('incomplete' + LineEnding, Report) > 0),
      'a failed check with retained findings must be reported as incomplete');
  finally
    Task.Free;
  end;
  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoTransportFailed));
  try
    Report := S12Report(Task);
    AssertTrue((Pos('No findings were retained', Report) > 0) and
      (Pos('did not cover every package', Report) > 0) and
      (Pos('No findings were recorded', Report) = 0),
      'a failed check without findings must say coverage is incomplete');
  finally
    Task.Free;
  end;
  Task := S12Task(tsCompleted, True,
    OSVOutcomeCode(osoCandidateLimitExceeded));
  try
    Report := S12Report(Task);
    AssertTrue((Pos('did not start', Report) > 0) and
      (Pos('No findings were recorded', Report) > 0) and
      (Pos('listed below', Report) = 0) and
      (Pos('are partial', Report) = 0) and (Pos('incomplete', Report) = 0),
      'a check that never started must not claim partial results below');
  finally
    Task.Free;
  end;
end;

procedure TestDetailsReportPendingAndNotRequested;
var
  Task: TScanTask;
  Report: string;
begin
  Task := S12Task(tsRunning, False, '');
  try
    Report := S12Report(Task, True);
    AssertTrue((Pos('You asked for the OSV.dev online check', Report) > 0) and
      (Pos('Not requested', Report) = 0),
      'a requested check must not be reported as not requested while pending');
    Report := S12Report(Task, False);
    AssertTrue(Pos('Not requested for this scan', Report) > 0,
      'a scan without the check must say so');
  finally
    Task.Free;
  end;
  Task := S12Task(tsCancelled, False, '');
  try
    Report := S12Report(Task);
    AssertTrue((Pos('No online check was recorded', Report) > 0) and
      (Pos('Refresh intelligence', Report) = 0),
      'a cancelled scan without a check must stay neutral about intent');
  finally
    Task.Free;
  end;
  Task := S12Task(tsRunning, True, '');
  try
    Report := S12Report(Task);
    AssertTrue(Pos('has not finished yet', Report) > 0,
      'an empty code on a running task must read as unfinished');
    Task.Status := tsCompleted;
    Report := S12Report(Task);
    AssertTrue(Pos('No outcome was recorded', Report) > 0,
      'an empty code on a completed task must read as missing');
  finally
    Task.Free;
  end;
end;

procedure TestDetailsReportPrivacyAndSettings;
var
  Task: TScanTask;
  Artifact: TArtifact;
  Report: string;
begin
  Task := S12Task(tsCompleted, False, '');
  try
    Task.Settings.SBOMAuthorOrganization := 'Private Org Ltd';
    Task.Settings.SBOMAuthorEmail := 'alice@example.invalid';
    Task.Settings.IncludeAbsolutePaths := False;
    Task.Warnings.Add('Skipped symbolic link loop at ' +
      Task.TargetDirectory + '/vendor/loop');
    Task.Errors.Add('Cannot read ' + Task.TargetDirectory + '/locked');
    Task.Warnings.Add('Alternate spelling ' + StringReplace(
      Task.TargetDirectory, '/', '\', [rfReplaceAll]) + '\x');
    Task.KnownIssueCheck.Requested := True;
    Task.KnownIssueCheck.OutcomeCode := OSVOutcomeCode(osoTransportFailed);
    Task.KnownIssueCheck.Diagnostic := 'probe ' + Task.TargetDirectory;
    Artifact := TArtifact.Create;
    Artifact.RelativePath := Task.TargetDirectory + '/requirements.txt';
    Artifact.MessageText := 'read from ' + Task.TargetDirectory;
    Task.Artifacts.Add(Artifact);
    Report := S12Report(Task);
    AssertTrue(Pos(Task.TargetDirectory, Report) = 0,
      'the absolute scan folder leaked without the opt-in');
    AssertTrue((Pos('[scanned folder]/vendor/loop', Report) > 0) and
      (Pos('[scanned folder]\x', Report) > 0) and
      (Pos('probe [scanned folder]', Report) > 0) and
      (Pos('[scanned folder]/requirements.txt', Report) > 0) and
      (Pos('read from [scanned folder]', Report) > 0),
      'embedded paths must be redacted in every free-text field');
    Task.TargetRootName := 'bad' + #10 + 'name';
    Report := S12Report(Task);
    AssertTrue(Pos('Folder: scanned folder (folder name only', Report) > 0,
      'an invalid root name must not be replaced by a derived basename');
    Task.TargetRootName := 'backend' + #9;
    Report := S12Report(Task);
    AssertTrue(Pos('Folder: scanned folder (folder name only', Report) > 0,
      'a trailing control character must not be trimmed away');
    Task.TargetRootName := 'back' + #127 + 'end';
    Report := S12Report(Task);
    AssertTrue(Pos('Folder: scanned folder (folder name only', Report) > 0,
      'DEL must be rejected in a folder name');
    Task.TargetDirectory := 'C:\';
    Task.TargetRootName := 'C:\';
    Task.Warnings.Add('drive-root warning C:\Users\alice');
    Report := S12Report(Task);
    AssertTrue((Pos('Folder: scanned folder', Report) > 0) and
      (Pos('C:\Users\alice', Report) > 0),
      'a drive root must be skipped by redaction and not shown as a name');
    Task.TargetDirectory := '\\server\share\';
    Task.TargetRootName := 'share';
    Task.Warnings.Add('unc-root warning \\server\share\x');
    Report := S12Report(Task);
    AssertTrue((Pos('Folder: share (folder name only', Report) > 0) and
      (Pos('\\server\share\x', Report) > 0),
      'a UNC share root must be skipped by redaction');
    Task.TargetDirectory := '/home/alice/clients/acme-bank/backend';
    Task.TargetRootName := 'backend';
    Report := S12Report(Task);
    AssertTrue(Pos('Folder: backend (folder name only', Report) > 0,
      'the folder name line is missing');
    AssertTrue((Pos('Private Org Ltd', Report) = 0) and
      (Pos('alice@example.invalid', Report) = 0),
      'author details must never appear in the report');
    AssertTrue((Pos(': True', Report) = 0) and (Pos(': False', Report) = 0),
      'settings must be sentences, not Pascal literals');
    AssertTrue((Pos('Absolute paths permitted in the exported SBOM',
      Report) > 0) and (Pos('leave the selected folder', Report) = 0),
      'settings sentences are wrong when links are not followed');
    Task.Settings.FollowSymbolicLinks := True;
    Task.Settings.IncludeAbsolutePaths := True;
    Report := S12Report(Task);
    AssertTrue((Pos('Folder: ' + Task.TargetDirectory, Report) > 0) and
      (Pos(Task.TargetDirectory + '/vendor/loop', Report) > 0),
      'the opt-in must print the absolute folder and leave messages intact');
    Task.Settings.IncludeAbsolutePaths := False;
    Task.TargetDirectory := '/';
    Task.TargetRootName := '/';
    Report := S12Report(Task);
    AssertTrue((Pos('Folder: scanned folder (folder name only', Report) > 0),
      'a filesystem root must not be printed as a folder name');
    AssertTrue(Pos('leave the selected folder', Report) > 0,
      'the outside-root sentence must follow the link setting');
  finally
    Task.Free;
  end;
end;

procedure TestDetailsReportStructureAndTimestamps;
var
  Task: TScanTask;
  Report: string;
  SummaryAt, KnownAt, CaveatAt, SettingsAt: SizeInt;
begin
  AssertEqual('2026-08-10', AdvisoryDateText('2026-08-10T00:00:00Z'),
    'ISO timestamp not reduced');
  AssertEqual('2024-06-10', AdvisoryDateText('2024-06-10T20:40:14.641907Z'),
    'fractional ISO timestamp not reduced');
  AssertEqual('20260823', AdvisoryDateText('20260823'),
    'opaque value must pass through');
  AssertEqual('2026-13-01x', AdvisoryDateText('2026-13-01x'),
    'invalid date must pass through');
  AssertEqual('2026-08-10Trash', AdvisoryDateText('2026-08-10Trash'),
    'a corrupted ISO tail must pass through');
  AssertEqual('2026-08-10T', AdvisoryDateText('2026-08-10T'),
    'a dangling designator must pass through');
  Task := S12Task(tsCompleted, True, OSVOutcomeCode(osoSucceeded));
  try
    Report := S12Report(Task);
    AssertTrue(Pos(AppName + ' ' + DisplayVersion, Report) = 1,
      'the report must start with the product identity');
    SummaryAt := Pos('Scan summary', Report);
    KnownAt := Pos('Known issues (OSV.dev online check)', Report);
    CaveatAt := Pos('What this scan can and cannot tell you', Report);
    SettingsAt := Pos('Scan settings', Report);
    AssertTrue((SummaryAt > 0) and (KnownAt > SummaryAt) and
      (CaveatAt > KnownAt) and (SettingsAt > CaveatAt),
      'section order must put findings before the standing caveats');
    AssertTrue((Pos('described above', Report) > 0) and
      (Pos('described below', Report) = 0),
      'the caveat must point back at the findings');
    AssertTrue((Pos('A lookup with no finding is not a clean bill', Report)
      > 0) and (Pos('No finding is not', Report) = 0),
      'the double negative must be gone');
    AssertTrue((Pos('Started: ', Report) > 0) and
      (Pos(', after ', Report) > 0), 'start and duration lines missing');
    AssertTrue(Pos('Unique canonical package URLs eligible for lookup: 2.',
      Report) > 0, 'lookup breakdown is missing');
    AssertTrue(Pos('never looked up: 1.', Report) > 0,
      'components without a package URL are not counted');
    Task.StartedUTC := '';
    Report := S12Report(Task);
    AssertTrue((Pos('Started: ', Report) = 0) and
      (Pos('start time was not recorded', Report) > 0) and
      (Pos(', after ', Report) = 0),
      'a missing start time must not print an empty or zero duration');
    AssertEqual('', BuildScanDetailsReport(nil, False),
      'nil task must yield an empty report');
  finally
    Task.Free;
  end;
end;

function S12ReadProjectFile(const ARelativePath: string): string;
var
  Lines: TStringList;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      StringReplace(ARelativePath, '/', DirectorySeparator, [rfReplaceAll]));
    Result := Lines.Text;
  finally
    Lines.Free;
  end;
end;

procedure TestScanStartRollbackContract;
var
  ActiveSetterBlock, AnalyzerSource, RefreshBlock, RollbackBlock,
    StartBlock: string;
  ActiveAt, AddAt, CreateAt, ExceptAt, PendingAt, SaveAt, SelectAt, StartAt,
    SuccessPersistAt, TryAt: SizeInt;
begin
  AnalyzerSource := S12ReadProjectFile('src/uSBOMAnalyzerFrame.pas');
  StartBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.StartScan(',
    'procedure TSBOMAnalyzerFrame.ConfigureAndStartScan(');
  ActiveAt := Pos('SetActiveTaskID(Task.ID);', StartBlock);
  AddAt := Pos('FHistoryService.AddTask(Task, 0);', StartBlock);
  CreateAt := Pos('FWorker := TScanWorker.Create(', StartBlock);
  PendingAt := Pos('FPendingScanTaskID := Task.ID;', StartBlock);
  SaveAt := Pos('SaveHistory;', StartBlock);
  SelectAt := Pos('SelectTask(Task);', StartBlock);
  StartAt := Pos('FWorker.Start;', StartBlock);
  TryAt := Pos('  try' + LineEnding + '    { The Details report', StartBlock);
  ExceptAt := Pos('  except' + LineEnding + '    on E: Exception do',
    StartBlock);
  AssertTrue((StartBlock <> '') and (AddAt > 0) and (TryAt > AddAt) and
    (PendingAt > TryAt) and (SelectAt > PendingAt) and (SaveAt > SelectAt) and
    (ActiveAt > SaveAt) and (CreateAt > ActiveAt) and (StartAt > CreateAt) and
    (ExceptAt > StartAt),
    'all adopted-task UI state and worker startup must share one guard');
  RollbackBlock := Copy(StartBlock, ExceptAt, MaxInt);
  AssertTrue(Pos('FreeAndNil(FWorker);', RollbackBlock) > 0,
    'a failed scan start must release the partial worker');
  AssertTrue((Pos('Task.Status := tsFailed;', RollbackBlock) > 0) and
    (Pos('Task.CompletedUTC := UTCNowISO8601;', RollbackBlock) > 0) and
    (Pos('Task.Errors.Add(''The scan worker could not be started.'');',
      RollbackBlock) > 0) and
    (Pos('try' + LineEnding + '        SaveHistory;', RollbackBlock) > 0) and
    (Pos('NotifyTaskUpdated(Task.ID, False)', RollbackBlock) > 0),
    'failed startup must retain a path-free error and contain persistence failures');
  AssertTrue((Pos('FCancelRequested := False;', RollbackBlock) > 0) and
    (Pos('SetActiveTaskID('''');', RollbackBlock) > 0) and
    (Pos('SetCompactFooter(', RollbackBlock) > 0) and
    (Pos('UpdateButtons;', RollbackBlock) > 0),
    'a failed scan start must unlock active state and restore compact UI');
  SuccessPersistAt := Pos('  try' + LineEnding + '    SaveHistory;' +
    LineEnding + '    FHistoryService.NotifyTaskUpdated(Task.ID, False);',
    StartBlock);
  AssertTrue(SuccessPersistAt > ExceptAt,
    'post-start history persistence and publication must share a guard');
  ActiveSetterBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.SetActiveTaskID(',
    'procedure TSBOMAnalyzerFrame.SetActiveFooter;');
  AssertTrue((Pos('FPendingScanTaskID := '''';', ActiveSetterBlock) > 0) and
    (Pos('FPendingScanChecksKnownIssues := False;', ActiveSetterBlock) > 0) and
    (Pos('try' + LineEnding + '      FOnActivityChanged(Self, IsActive);',
    ActiveSetterBlock) > 0),
    'clearing active state and its cosmetic callback must be exception-safe');
  RefreshBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.StartIntelligenceRefresh(',
    'procedure TSBOMAnalyzerFrame.CompleteIntelligenceRefresh(');
  TryAt := Pos('  try' + LineEnding + '    FCancelRequested := False;',
    RefreshBlock);
  ActiveAt := Pos('SetActiveTaskID(ATask.ID);', RefreshBlock);
  CreateAt := Pos('FWorker := TScanWorker.CreateKnownIssueRefresh(',
    RefreshBlock);
  StartAt := Pos('FWorker.Start;', RefreshBlock);
  ExceptAt := Pos('  except' + LineEnding + '    on E: Exception do',
    RefreshBlock);
  AssertTrue((TryAt > 0) and (ActiveAt > TryAt) and (CreateAt > ActiveAt) and
    (StartAt > CreateAt) and (ExceptAt > StartAt) and
    (Pos('SetActiveTaskID('''');', Copy(RefreshBlock, ExceptAt, MaxInt)) > 0),
    'intelligence-refresh UI activation and worker startup must share a guard');
end;

procedure TestScanDirectoryWarningPrivacyContract;
var
  EngineSource, EnterBlock, RootCheckBlock, ScanBlock: string;
begin
  EngineSource := S12ReadProjectFile('src/uScanEngine.pas');
  EnterBlock := ExtractTextSection(EngineSource,
    'function TScanEngine.EnterDirectory(',
    'function TScanEngine.ScanDirectory(');
  ScanBlock := ExtractTextSection(EngineSource,
    'function TScanEngine.ScanDirectory(',
    'procedure TScanEngine.CountArtifactStatus(');
  RootCheckBlock := ExtractTextSection(EngineSource,
    'procedure TScanEngine.VerifyScanRoot;',
    'procedure TScanEngine.ReportCacheDiagnostic;');
  AssertTrue((EnterBlock <> '') and
    (Pos('WarningPath := NormalizeRelativePath(ARelativeDirectory)',
      EnterBlock) > 0) and
    (Pos('[outside selected folder]', EnterBlock) = 0),
    'directory warnings must retain only the safe root-relative link path');
  AssertEqual(2, CountTextOccurrences(EnterBlock, 'WarningPath);'),
    'both EnterDirectory warning emissions must use the selected safe path');
  AssertTrue((Pos('+ ADirectory', EnterBlock) = 0) and
    (Pos('if EnterDirectory(AbsolutePath, RelativePath) then', ScanBlock) > 0),
    'EnterDirectory must receive the relative path and never emit its absolute path');
  AssertTrue((Pos('ScanRootVerificationFailure', RootCheckBlock) > 0) and
    (Pos('Unable to enumerate directory .: '' + E.Message', EngineSource) = 0),
    'root identity failures must map to the fixed path-free diagnostic');
  AssertTrue((Pos('raise EScanRootVerificationError.Create(', RootCheckBlock) > 0) and
    (Pos('on E: EScanRootVerificationError do' + LineEnding +
      '        raise;', ScanBlock) > 0),
    'root identity failures must bypass the generic enumeration warning path');
end;

procedure TestWindowsBuildPreflightContract;
var
  BuildAt, CompilerAt, LinkerAt, LazbuildAt, RTLAt: SizeInt;
  LowerText, Text: string;
begin
  Text := S12ReadProjectFile('scripts/build-windows.sh');
  LowerText := LowerCase(Text);
  LazbuildAt := Pos('if ! command -v lazbuild', Text);
  CompilerAt := Pos('if ! command -v ppcrossx64', Text);
  LinkerAt := Pos('if ! command -v x86_64-w64-mingw32-ld', Text);
  RTLAt := Pos('if ! ppcrossx64 -Twin64 -Px86_64 -Cn', Text);
  BuildAt := Pos('lazbuild -B', Text);
  AssertTrue((LazbuildAt > 0) and (CompilerAt > LazbuildAt) and
    (LinkerAt > CompilerAt) and (RTLAt > LinkerAt) and (BuildAt > RTLAt),
    'Windows cross-build preflight checks are missing or out of order');
  AssertTrue((Pos('set -euo pipefail', Text) > 0) and
    (Pos('cross_probe_directory=$(mktemp -d', Text) > 0) and
    (Pos('trap ''rm -rf -- "$cross_probe_directory"'' EXIT', Text) > 0),
    'the guarded target probes or temporary RTL probe cleanup are missing');
  AssertEqual(4, CountTextOccurrences(Text,
    'Windows cross-build cannot start:'),
    'Windows preflight must expose exactly four bounded failure messages');
  AssertTrue((Pos('lazbuild was not found in PATH', Text) > 0) and
    (Pos('ppcrossx64 was not found in PATH', Text) > 0) and
    (Pos('x86_64-w64-mingw32-ld was not found in PATH', Text) > 0) and
    (Pos('Win64 RTL units are unavailable to ppcrossx64', Text) > 0) and
    (Pos('ppcrossx64 -iTO', Text) = 0) and
    (Pos('ppcrossx64 -iTP', Text) = 0),
    'Windows preflight diagnostics or portable capability checks changed');
  AssertTrue((Pos('internal migration notes', LowerText) = 0) and
    (Pos('distro fpc tree', LowerText) = 0) and
    (Pos('internal-purpleray', LowerText) = 0),
    'the public build helper contains a private reference or distro-tree assumption');
end;

procedure TestRailCollapseContract;
var
  ShellSource, ShellResource, ToggleSection, LayoutBlock, ToggleBlock,
    KeyBlock, SelectBlock, GlyphBlock, ActivityBlock: string;
begin
  ShellSource := S12ReadProjectFile('src/uMainForm.pas');
  ShellResource := S12ReadProjectFile('src/uMainForm.lfm');
  ToggleSection := ExtractTextSection(ShellResource,
    'object RailToggleButton: TSpeedButton', 'object VersionLabel: TLabel');
  AssertTrue((ToggleSection <> '') and
    (Pos('Align = alBottom', ToggleSection) > 0) and
    (Pos('OnClick = RailToggleClicked', ToggleSection) > 0),
    'the rail toggle button is missing or not wired');
  AssertTrue((Pos('RailExpandedWidth = 168', ShellSource) > 0) and
    (Pos('RailCollapsedWidth = 56', ShellSource) > 0),
    'rail width constants changed');
  LayoutBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.ApplyRailLayout;',
    'procedure TMainForm.RailToggleClicked');
  AssertTrue((LayoutBlock <> '') and
    (Pos('if FRailCollapsed then', LayoutBlock) > 0) and
    (Pos('ShowCaption := False', LayoutBlock) > 0) and
    (Pos('ShowCaption := True', LayoutBlock) > 0) and
    (Pos('Margin := -1', LayoutBlock) > 0) and
    (Pos('ShowHint := True', LayoutBlock) > 0) and
    (Pos('VersionLabel.Top :=', LayoutBlock) > 0) and
    (Pos('RailToggleButton.Top :=', LayoutBlock) > 0) and
    (Pos('SetBounds(0, 0,', LayoutBlock) > 0) and
    (Pos('(Ctrl+B)', LayoutBlock) > 0),
    'collapsed/expanded rail layout lost a required step');
  ToggleBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.RailToggleClicked',
    'procedure TMainForm.AutoAdjustLayout');
  AssertTrue(Pos('FRailCollapsed := not FRailCollapsed', ToggleBlock) > 0,
    'the toggle no longer flips the collapsed state');
  KeyBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.FormKeyPressed', 'procedure TMainForm.DashboardNavClicked');
  AssertTrue((Pos('VK_B', KeyBlock) > 0) and
    (Pos('RailToggleClicked(nil)', KeyBlock) > 0),
    'Ctrl+B no longer toggles the rail');
  SelectBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.SelectFeature', 'procedure TMainForm.WarmUpFeaturePages');
  AssertTrue(Pos('SetBounds(0, 0,', SelectBlock) > 0,
    'feature selection no longer re-fits the page after a rail toggle');
  GlyphBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.AssignAnalyzerGlyph', 'procedure TMainForm.CreateFeatureFrames;');
  AssertTrue((GlyphBlock <> '') and (Pos('if AScanActive then', GlyphBlock) > 0)
    and (Pos('clRed', GlyphBlock) > 0),
    'the Analyzer glyph lost its activity dot');
  ActivityBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.AnalyzerActivityChanged',
    'procedure TMainForm.AnalyzerCloseReady');
  AssertTrue(Pos('AssignAnalyzerGlyph(AScanActive)', ActivityBlock) > 0,
    'scan activity no longer redraws the Analyzer glyph');
  AssertTrue((Pos('Left = 168', ExtractTextSection(ShellResource,
    'object WorkspaceNotebook: TNotebook', 'Align = alClient')) > 0),
    'stale designer bounds on the workspace notebook');
end;

procedure TestStartupSplashContract;
var
  SplashSource, ProgramText, StatusBlock, WarmBlock, LowerSplash: string;
  InitializeAt, CreateSplashAt, ShowAt, PumpAt, CreateFormAt, WarmAt,
    ReleaseAt, RunAt: SizeInt;
begin
  SplashSource := S12ReadProjectFile('src/uSplashForm.pas');
  ProgramText := S12ReadProjectFile('src/purpleray_sbom_analyzer.lpr');
  AssertTrue((Pos('TSplashForm = class(TForm)', SplashSource) > 0) and
    (Pos('FormStyle := fsSplash', SplashSource) > 0) and
    (Pos('ShowInTaskBar := stNever', SplashSource) > 0) and
    (Pos('BorderStyle := bsNone', SplashSource) > 0) and
    (Pos('pbstMarquee', SplashSource) = 0) and
    (Pos('FProgressBar.Max := SplashStepCount', SplashSource) > 0),
    'the splash lost its window style or uses a marquee bar');
  StatusBlock := ExtractTextSection(SplashSource,
    'procedure TSplashForm.SetStatus', 'end.');
  AssertTrue((StatusBlock <> '') and (Pos('ProcessMessages', StatusBlock) = 0)
    and (Pos('FProgressBar.Position + 1', StatusBlock) > 0),
    'SetStatus must step the bar and must not pump the message queue');
  LowerSplash := LowerCase(SplashSource);
  AssertTrue((Pos('uosv', LowerSplash) = 0) and
    (Pos('uknownissue', LowerSplash) = 0) and
    (Pos('fphttpclient', LowerSplash) = 0) and
    (Pos('winhttp', LowerSplash) = 0) and (Pos('sockets', LowerSplash) = 0),
    'the splash must not import network-capable units');
  InitializeAt := Pos('Application.Initialize;', ProgramText);
  CreateSplashAt := Pos('TSplashForm.CreateSplash(', ProgramText);
  ShowAt := Pos('Splash.Show;', ProgramText);
  PumpAt := Pos('Splash.WaitForFirstPaint;', ProgramText);
  CreateFormAt := Pos('Application.CreateForm(TMainForm, MainForm);',
    ProgramText);
  WarmAt := Pos('MainForm.WarmUpFeaturePages(Splash);', ProgramText);
  ReleaseAt := Pos('Splash.Release;', ProgramText);
  RunAt := Pos('Application.Run;', ProgramText);
  AssertTrue((InitializeAt > 0) and (CreateSplashAt > InitializeAt) and
    (ShowAt > CreateSplashAt) and (PumpAt > ShowAt) and
    (CreateFormAt > PumpAt) and (WarmAt > CreateFormAt) and
    (ReleaseAt > WarmAt) and (RunAt > ReleaseAt),
    'startup order: initialize, splash, first paint, shell, warm-up, ' +
    'release, run');
  AssertTrue(Pos('Application.ProcessMessages', ProgramText) = 0,
    'the program must pump only through the bounded splash helper');
  AssertTrue(Pos('Splash.Free', ExtractTextSection(ProgramText,
    'except', 'Splash.Release')) > 0,
    'a failed startup must free the splash before re-raising');
  WarmBlock := ExtractTextSection(S12ReadProjectFile('src/uMainForm.pas'),
    'procedure TMainForm.WarmUpFeaturePages', 'procedure TMainForm.FormKeyPressed');
  AssertTrue((WarmBlock <> '') and (Pos('HandleNeeded', WarmBlock) > 0) and
    (Pos('ASplash.SetStatus(', WarmBlock) > 0) and
    (Pos('ProcessMessages', WarmBlock) = 0),
    'the warm-up must realize handles, report status, and never pump');
end;

procedure TestRedRowAndCopyContract;
var
  AnalyzerSource, WiringBlock, ItemBlock, SubItemBlock, CopyBlock: string;
begin
  AnalyzerSource := S12ReadProjectFile('src/uSBOMAnalyzerFrame.pas');
  WiringBlock := ExtractTextSection(AnalyzerSource,
    'FComponentList.OnCustomDrawItem := @ComponentListCustomDrawItem;',
    'FComponentList.ShowHint := True;');
  AssertTrue((WiringBlock <> '') and
    (Pos('{$IFDEF LCLGTK2}', WiringBlock) > 0) and
    (Pos('OnCustomDrawSubItem := @ComponentListCustomDrawSubItem', WiringBlock)
    > 0) and (Pos('{$ENDIF}', WiringBlock) > 0),
    'the sub-item painter must stay wired under the GTK2 guard only');
  AssertEqual(1, CountTextOccurrences(AnalyzerSource,
    'OnCustomDrawSubItem :='), 'sub-item painter wired more than once');
  AssertTrue((Pos('OnShowHint := @ComponentListShowHint', AnalyzerSource) > 0)
    and (Pos('OnDblClick := @ComponentListDoubleClicked', AnalyzerSource) > 0),
    'red rows lost their hint or double-click route to Details');
  ItemBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.ComponentListCustomDrawItem(',
    'procedure TSBOMAnalyzerFrame.ComponentListCustomDrawSubItem(');
  SubItemBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.ComponentListCustomDrawSubItem(',
    'procedure TSBOMAnalyzerFrame.ComponentListShowHint(');
  AssertTrue((Pos('DefaultDraw := True;', ItemBlock) > 0) and
    (Pos('DefaultDraw := True;', ItemBlock) < Pos('try', ItemBlock)) and
    (Pos('except', ItemBlock) > 0) and
    (Pos('cdsSelected in State', ItemBlock) > 0) and
    (Pos('DefaultDraw := True;', SubItemBlock) > 0) and
    (Pos('except', SubItemBlock) > 0) and
    (Pos('cdsSelected in State', SubItemBlock) > 0),
    'custom-draw handlers must default-draw, contain exceptions, and ' +
    'leave selected rows to the native painter');
  AssertTrue(Pos('FlaggedTextColor', AnalyzerSource) = 0,
    'the selected-row tint helper must not return');
  CopyBlock := ExtractTextSection(AnalyzerSource,
    'procedure TSBOMAnalyzerFrame.CopyDetailsClicked(',
    'procedure TSBOMAnalyzerFrame.CopiedResetTimerTick(');
  AssertTrue((CopyBlock <> '') and (Pos('SetCompactFooter', CopyBlock) = 0)
    and (Pos('''Copied''', CopyBlock) > 0) and
    (Pos('Clipboard.AsText', CopyBlock) > 0) and
    (Pos('except', CopyBlock) > 0),
    'copying the report must confirm at the button and never touch the ' +
    'progress footer');
  AssertTrue(Pos('BuildScanDetailsReport(ATask, OnlineCheckPending)',
    AnalyzerSource) > 0,
    'the Details tab must delegate to the LCL-free report builder');
end;

procedure TestBatchLauncherInvariants;
var
  Lines: TStringList;
  Raw, Text, Line, Lower, Attributes: string;
  I, PipeCount, CRLFCount, LFCount, CRCount: Integer;
  InHelpers: Boolean;
begin
  with TFileStream.Create(IncludeTrailingPathDelimiter(ProjectRoot) +
    'start-win.bat', fmOpenRead or fmShareDenyNone) do
  try
    SetLength(Raw, Size);
    if Size > 0 then
      ReadBuffer(Raw[1], Size);
  finally
    Free;
  end;
  CRLFCount := CountTextOccurrences(Raw, #13#10);
  LFCount := CountTextOccurrences(Raw, #10);
  CRCount := CountTextOccurrences(Raw, #13);
  AssertTrue((Raw <> '') and (CRLFCount = LFCount) and (CRLFCount = CRCount)
    and (Copy(Raw, Length(Raw) - 1, 2) = #13#10),
    'start-win.bat must be strictly CRLF-terminated on every line');
  Attributes := S12ReadProjectFile('.gitattributes');
  AssertTrue(Pos('start-win.bat -text', Attributes) > 0,
    '.gitattributes must protect the batch launcher from normalization');
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'start-win.bat');
    Text := Lines.Text;
    AssertTrue((Pos('System32\curl.exe', Text) > 0) and
      (Pos('System32\certutil.exe', Text) > 0) and
      (Pos('System32\tar.exe', Text) > 0) and
      (Pos('System32\findstr.exe', Text) > 0) and
      (Pos('System32\find.exe', Text) > 0),
      'every tool must be pinned to System32');
    AssertTrue((Pos('SCRIPT_DIRECTORY=%~dp0', Text) > 0) and
      (Pos('"!FIND!" /V "" <', Text) > 0) and
      (Pos('if not "!MATCH_COUNT!"=="1"', Text) > 0) and
      (Pos('call :check_hex64 EXPECTED_CHECKSUM', Text) > 0) and
      (Pos('/C:" link to "', Text) > 0) and
      (Pos('goto :launch', Text) > 0) and (Pos(#10':launch', Text) > 0) and
      (Pos('rmdir /S /Q "!WORK_DIRECTORY!"', Text) > 0) and
      (Pos('PURPLERAY_NO_PAUSE', Text) > 0) and
      (Pos('--connect-timeout', Text) > 0) and
      (Pos('--proto =https --proto-redir =https', Text) > 0),
      'batch launcher lost a hardening step');
    AssertTrue((Pos('%*', Text) = 0) and
      (Pos('pwsh', LowerCase(Text)) = 0) and
      (Pos('bitsadmin', LowerCase(Text)) = 0) and
      (Pos('mshta', LowerCase(Text)) = 0) and
      (Pos('cscript', LowerCase(Text)) = 0) and
      (Pos('wscript', LowerCase(Text)) = 0),
      'batch launcher forwards arguments or invokes a scripting host');
    InHelpers := False;
    for I := 0 to Lines.Count - 1 do
    begin
      Line := Lines[I];
      Lower := LowerCase(Trim(Line));
      if (Lower = '') or (Pos('rem ', Lower) = 1) or (Lower = 'rem') then
        Continue;
      if Lower = ':check_version' then
        InHelpers := True;
      PipeCount := CountTextOccurrences(Line, '|') -
        2 * CountTextOccurrences(Line, '||');
      AssertEqual(0, PipeCount, Format('line %d uses a pipe', [I + 1]));
      if Pos('for /f', Lower) > 0 then
        AssertTrue(Pos('usebackq', Lower) > 0,
          Format('line %d: for /f must read a file with usebackq', [I + 1]));
      if Pos('"!findstr!"', Lower) > 0 then
        AssertTrue(Pos('^', Line) = 0,
          Format('line %d: findstr patterns must use /B, never ^', [I + 1]));
      if Pos('"!curl!"', Lower) = 1 then
        AssertTrue(Pos('"!CURL!" -q ', Line) = 1,
          Format('line %d: curl must disable curlrc first', [I + 1]));
      if not InHelpers then
        AssertTrue((Pos('%1', Line) = 0) and (Pos('%~1', Line) = 0),
          Format('line %d: positional arguments outside helpers', [I + 1]));
    end;
    AssertTrue(InHelpers, 'the helper section is missing');
  finally
    Lines.Free;
  end;
end;

procedure TestLauncherChecksumGates;
var
  Text: string;
begin
  Text := S12ReadProjectFile('start-linux.sh');
  AssertTrue((Pos('release checksum verification failed', Text) > 0) and
    (CountTextOccurrences(Text, 'gh attestation verify') = 1) and
    (Pos('Optional provenance check', Text) > 0),
    'Linux launcher: checksum gate or optional provenance hint changed');
  Text := S12ReadProjectFile('start-wsl2.sh');
  AssertTrue((Pos('release checksum verification failed', Text) > 0) and
    (CountTextOccurrences(Text, 'gh attestation verify') = 1),
    'WSL2 launcher: checksum gate or optional provenance hint changed');
  Text := S12ReadProjectFile('start-windows.ps1');
  AssertTrue((Pos('release checksum verification failed', Text) > 0) and
    (CountTextOccurrences(Text, 'gh attestation verify') = 1) and
    (Pos('already matches the verified package', Text) > 0),
    'PowerShell launcher: checksum gate, provenance hint, or ' +
    'already-installed skip changed');
  Text := S12ReadProjectFile('start-win.bat');
  AssertTrue((Pos('release checksum verification failed', Text) > 0) and
    (Pos('gh attestation verify', Text) > 0) and
    (Pos('already matches the verified package', Text) > 0),
    'batch launcher: checksum gate, provenance hint, or already-installed ' +
    'skip changed');
end;

procedure RunSprint12RegressionTests;
begin
  RunTest('details report outcome sentences', @TestDetailsReportOutcomeSentences);
  RunTest('details report counts and cap', @TestDetailsReportCountsAndCap);
  RunTest('details report incomplete consequences',
    @TestDetailsReportIncompleteConsequences);
  RunTest('details report pending and not-requested states',
    @TestDetailsReportPendingAndNotRequested);
  RunTest('details report privacy and settings sentences',
    @TestDetailsReportPrivacyAndSettings);
  RunTest('details report structure and timestamps',
    @TestDetailsReportStructureAndTimestamps);
  RunTest('scan-start rollback contract', @TestScanStartRollbackContract);
  RunTest('scan-directory warning privacy contract',
    @TestScanDirectoryWarningPrivacyContract);
  RunTest('Windows build preflight contract',
    @TestWindowsBuildPreflightContract);
  RunTest('rail collapse contract', @TestRailCollapseContract);
  RunTest('startup splash contract', @TestStartupSplashContract);
  RunTest('red-row and copy contract', @TestRedRowAndCopyContract);
  RunTest('batch launcher invariants', @TestBatchLauncherInvariants);
  RunTest('launcher checksum gates', @TestLauncherChecksumGates);
end;
