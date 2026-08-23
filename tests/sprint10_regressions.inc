{ Sprint 10 deterministic security-findings export regressions. Tests use
  retained in-memory snapshots and never open a network endpoint. }

function S10NewMatch(const APackageURL, AAdvisoryID,
  AModified: string): TKnownIssueMatch;
begin
  Result := TKnownIssueMatch.Create;
  Result.PackageURL := APackageURL;
  Result.AdvisoryID := AAdvisoryID;
  Result.Modified := AModified;
end;

function S10CompletedTask(AWithMatches: Boolean = True): TScanTask;
var
  PrivateUnicode: string;
begin
  Result := TScanTask.Create;
  PrivateUnicode := #$E7#$A7#$98#$E5#$AF#$86;
  Result.ID := 'ABCDEF01-2345-6789-ABCD-EF0123456789';
  Result.Status := tsCompleted;
  Result.TargetDirectory := '/private/' + PrivateUnicode + '/target';
  Result.TargetRootName := 'private-' + PrivateUnicode;
  Result.GeneratedSBOMPath := '/private/managed/inventory.cdx.json';
  Result.GeneratedSBOMSHA256 := StringOfChar('A', 64);
  Result.Settings.SBOMAuthorOrganization := 'private-' + PrivateUnicode;
  Result.Warnings.Add('private-' + PrivateUnicode + '-warning');
  Result.KnownIssueCheck.Requested := True;
  Result.KnownIssueCheck.CheckedUTC := '2026-08-23T12:34:56Z';
  Result.KnownIssueCheck.OutcomeCode :=
    OSVOutcomeCode(osoNoEligibleCandidates);
  Result.KnownIssueCheck.Diagnostic := 'private-response-diagnostic';
  if not AWithMatches then
    Exit;
  Result.KnownIssueCheck.OutcomeCode := OSVOutcomeCode(osoSucceeded);
  Result.KnownIssueCheck.HTTPStatus := 200;
  Result.KnownIssueCheck.RequestCount := 1;
  Result.KnownIssueCheck.AggregateResponseBytes := 321;
  Result.KnownIssueCheck.EligibleCandidateCount := 3;
  AssertTrue(Result.KnownIssueCheck.AddMatch(S10NewMatch(
    'pkg:npm/zeta@2.0.0', 'OSV-ZETA', '2026-08-20T00:00:00Z')),
    'Sprint 10 zeta match fixture was rejected');
  AssertTrue(Result.KnownIssueCheck.AddMatch(S10NewMatch(
    'pkg:cargo/alpha@1.0.0', 'GHSA-ALPHA', '2026-08-19T00:00:00Z')),
    'Sprint 10 alpha match fixture was rejected');
end;

function S10TaskJSON(ATask: TScanTask): string;
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

function S10HasExactKeys(AObject: TJSONObject;
  const AExpected: array of string): Boolean;
var
  I: Integer;
begin
  Result := (AObject <> nil) and (AObject.Count = Length(AExpected));
  if not Result then
    Exit;
  for I := Low(AExpected) to High(AExpected) do
    if AObject.Names[I] <> AExpected[I] then
      Exit(False);
end;

procedure S10AssertExactKeys(AObject: TJSONObject;
  const AExpected: array of string; const AMessage: string);
begin
  AssertTrue(S10HasExactKeys(AObject, AExpected), AMessage);
end;

procedure S10AssertStringArray(AArray: TJSONArray;
  const AExpected: array of string; const AMessage: string);
var
  I: Integer;
begin
  AssertTrue(AArray <> nil, AMessage + ' is missing');
  AssertEqual(Length(AExpected), AArray.Count,
    AMessage + ' count differs');
  for I := Low(AExpected) to High(AExpected) do
    AssertEqual(AExpected[I], AArray.Items[I].AsString,
      AMessage + ' differs at index ' + IntToStr(I));
end;

procedure S10AssertError(ATask: TScanTask; const AExpectedCode: string;
  AEligibilityMustFail: Boolean = True);
var
  Generated: UTF8String;
begin
  if AEligibilityMustFail then
    AssertTrue(not CanGenerateSecurityFindings(ATask),
      AExpectedCode + ' input remained eligible');
  try
    Generated := GenerateSecurityFindings(ATask);
    Fail(AExpectedCode + ' input generated ' + IntToStr(Length(Generated)) +
      ' bytes');
  except
    on E: ESecurityFindingsError do
      AssertEqual(AExpectedCode, E.Code,
        'security-findings error code differs');
  end;
end;

procedure TestSprint10DeterministicBindingAndPrivacy;
const
  ExpectedReportSHA256 =
    'a9cca952a593658ffa38b6d921e798b7781009f3765b66987563c9951fad0dab';
var
  Task: TScanTask;
  BeforeTask, First, Second: string;
  Data, SnapshotData: TJSONData;
  Root, SourceValue, SummaryValue, ClaimValue, PrivacyValue,
    FirstMatch, SecondMatch: TJSONObject;
  Matches, Limitations: TJSONArray;
  SnapshotBytes: UTF8String;
begin
  Task := S10CompletedTask;
  Data := nil;
  SnapshotData := nil;
  try
    AssertTrue(CanGenerateSecurityFindings(Task),
      'valid completed snapshot is not exportable');
    BeforeTask := S10TaskJSON(Task);
    First := string(GenerateSecurityFindings(Task));
    Second := string(GenerateSecurityFindings(Task));
    AssertEqual(First, Second,
      'identical snapshot state did not produce identical report bytes');
    AssertEqual(ExpectedReportSHA256, SHA256String(RawByteString(First)),
      'security-findings golden byte digest differs');
    AssertTrue((First <> '') and (First[Length(First)] = #10) and
      ((Length(First) = 1) or (First[Length(First) - 1] <> #10)),
      'security-findings report lacks exactly one final line feed');
    AssertTrue(IsValidUTF8Bytes(RawByteString(First)),
      'security-findings report is not valid UTF-8');
    AssertEqual(BeforeTask, S10TaskJSON(Task),
      'security-findings generation mutated its task or retained snapshot');
    AssertTrue((Pos('/private/', First) = 0) and
      (Pos('private-response-diagnostic', First) = 0) and
      (Pos(#$E7#$A7#$98#$E5#$AF#$86, First) = 0),
      'security-findings report leaked a path, diagnostic, or Unicode contact');

    Data := ParseStrictUTF8JSON(RawByteString(First));
    AssertTrue(Data.JSONType = jtObject,
      'security-findings root is not an object');
    Root := TJSONObject(Data);
    S10AssertExactKeys(Root, ['format', 'formatVersion', 'source', 'summary',
      'claim', 'privacy', 'matches', 'limitations'],
      'security-findings root is not closed or ordered');
    AssertEqual(SecurityFindingsFormat, JSONString(Root, 'format'),
      'security-findings format differs');
    AssertEqual(SecurityFindingsFormatVersion,
      JSONInt64(Root, 'formatVersion', -1),
      'security-findings format version differs');

    SourceValue := JSONObject(Root, 'source');
    S10AssertExactKeys(SourceValue, ['taskId', 'managedSbomSha256',
      'knownIssueSnapshotSha256', 'provider', 'checkedUtc', 'outcome'],
      'security-findings source is not closed or ordered');
    AssertEqual(LowerCase(Task.ID), JSONString(SourceValue, 'taskId'),
      'source task binding differs');
    AssertEqual(LowerCase(Task.GeneratedSBOMSHA256),
      JSONString(SourceValue, 'managedSbomSha256'),
      'managed-SBOM binding differs');
    SnapshotData := Task.KnownIssueCheck.ToJSON;
    SnapshotBytes := SerializeJSONUTF8(SnapshotData, AsCompressedJSON, 0,
      False);
    AssertEqual(SHA256String(RawByteString(SnapshotBytes)),
      JSONString(SourceValue, 'knownIssueSnapshotSha256'),
      'retained-snapshot binding differs');
    AssertEqual(KnownIssueSource, JSONString(SourceValue, 'provider'),
      'security-findings provider differs');
    AssertEqual(Task.KnownIssueCheck.CheckedUTC,
      JSONString(SourceValue, 'checkedUtc'), 'snapshot check time differs');
    AssertEqual(Task.KnownIssueCheck.OutcomeCode,
      JSONString(SourceValue, 'outcome'), 'snapshot outcome differs');

    SummaryValue := JSONObject(Root, 'summary');
    S10AssertExactKeys(SummaryValue, ['eligibleCandidateCount',
      'advisoryCount', 'matchCount'],
      'security-findings summary is not closed or ordered');
    AssertEqual(3, JSONInt64(SummaryValue, 'eligibleCandidateCount', -1),
      'eligible candidate count differs');
    AssertEqual(2, JSONInt64(SummaryValue, 'advisoryCount', -1),
      'advisory count differs');
    AssertEqual(2, JSONInt64(SummaryValue, 'matchCount', -1),
      'match count differs');

    ClaimValue := JSONObject(Root, 'claim');
    AssertTrue(not JSONBoolean(ClaimValue, 'confirmedVulnerabilities', True),
      'advisory matches were presented as confirmed vulnerabilities');
    PrivacyValue := JSONObject(Root, 'privacy');
    AssertTrue(not JSONBoolean(PrivacyValue, 'pathsIncluded', True) and
      not JSONBoolean(PrivacyValue, 'contactsIncluded', True) and
      not JSONBoolean(PrivacyValue, 'diagnosticsIncluded', True),
      'security-findings privacy declarations differ');

    Matches := JSONArray(Root, 'matches');
    AssertEqual(2, Matches.Count, 'security-findings match count differs');
    FirstMatch := TJSONObject(Matches.Items[0]);
    SecondMatch := TJSONObject(Matches.Items[1]);
    S10AssertExactKeys(FirstMatch, ['packageUrl', 'advisoryId',
      'recordModified'], 'first advisory match is not closed or ordered');
    AssertEqual('pkg:cargo/alpha@1.0.0',
      JSONString(FirstMatch, 'packageUrl'),
      'advisory matches are not in canonical Package URL order');
    AssertEqual('pkg:npm/zeta@2.0.0',
      JSONString(SecondMatch, 'packageUrl'),
      'second advisory match order differs');
    Limitations := JSONArray(Root, 'limitations');
    AssertEqual(2, Limitations.Count,
      'security-findings limitation count differs');
    AssertTrue((Pos('reachability or exploitability',
      Limitations.Items[0].AsString) > 0) and
      (Pos('not a clean bill of health', Limitations.Items[1].AsString) > 0),
      'security-findings limitations lost their bounded claims');
  finally
    SnapshotData.Free;
    Data.Free;
    Task.Free;
  end;
end;

procedure TestSprint10StrictInputsAndOutcomes;
var
  Task: TScanTask;
  ReportData: TJSONData;
  Root: TJSONObject;
  BorrowedMatch: TKnownIssueMatch;
begin
  S10AssertError(nil, 'PRSF-E001-TASK-MISSING');

  Task := S10CompletedTask;
  try
    Task.Status := tsRunning;
    S10AssertError(Task, 'PRSF-E002-TASK-NOT-COMPLETED');
    Task.Status := tsCompleted;
    Task.ID := 'not-a-task-id';
    S10AssertError(Task, 'PRSF-E003-TASK-ID-INVALID');
    Task.ID := 'abcdef01-2345-6789-abcd-ef0123456789';
    Task.GeneratedSBOMSHA256 := 'not-a-sha256';
    S10AssertError(Task, 'PRSF-E004-SBOM-HASH-INVALID');
    Task.GeneratedSBOMSHA256 := StringOfChar('a', 64);
    Task.KnownIssueCheck.OutcomeCode := OSVOutcomeCode(osoCancelled);
    S10AssertError(Task, 'PRSF-E005-SNAPSHOT-INCOMPLETE');
    Task.KnownIssueCheck.OutcomeCode := OSVOutcomeCode(osoSucceeded);
    Task.KnownIssueCheck.HTTPStatus := 201;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.HTTPStatus := 200;
    Task.KnownIssueCheck.RequestCount := 0;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.RequestCount := 1;
    Task.KnownIssueCheck.CheckedUTC := '2026-02-30T12:34:56Z';
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.CheckedUTC := '2026-08-23T12:34:56Z';

    BorrowedMatch := Task.KnownIssueCheck.Matches[0];
    BorrowedMatch.Modified := '2026-02-30T00:00:00Z';
    AssertTrue(CanGenerateSecurityFindings(Task),
      'cheap eligibility unexpectedly walked retained match entries');
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID', False);
    AssertTrue(Task.KnownIssueCheck.Matches[0] = BorrowedMatch,
      'failed strict generation released or replaced its borrowed match');
    AssertEqual('2026-02-30T00:00:00Z', BorrowedMatch.Modified,
      'failed strict generation mutated its caller-owned match');
    BorrowedMatch.Modified := '20260823';
    AssertTrue(CanGenerateSecurityFindings(Task),
      'cheap eligibility unexpectedly walked compact match timestamps');
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID', False);
  finally
    Task.Free;
  end;

  Task := S10CompletedTask(False);
  ReportData := nil;
  try
    AssertTrue(CanGenerateSecurityFindings(Task),
      'complete no-eligible-candidates outcome is not exportable');
    ReportData := ParseStrictUTF8JSON(RawByteString(
      GenerateSecurityFindings(Task)));
    Root := TJSONObject(ReportData);
    AssertEqual(OSVOutcomeCode(osoNoEligibleCandidates),
      JSONString(JSONObject(Root, 'source'), 'outcome'),
      'no-eligible-candidates outcome differs');
    AssertEqual(0, JSONArray(Root, 'matches').Count,
      'no-eligible-candidates report contains matches');
    AssertTrue(Pos('not a clean bill of health',
      JSONArray(Root, 'limitations').Items[1].AsString) > 0,
      'empty report lost its coverage limitation');
    ReportData.Free;
    ReportData := nil;
    Task.KnownIssueCheck.EligibleCandidateCount := 1;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.EligibleCandidateCount := 0;
    Task.KnownIssueCheck.HTTPStatus := 200;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.HTTPStatus := 0;
    Task.KnownIssueCheck.RequestCount := 1;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
    Task.KnownIssueCheck.RequestCount := 0;
    Task.KnownIssueCheck.AggregateResponseBytes := 1;
    S10AssertError(Task, 'PRSF-E006-SNAPSHOT-INVALID');
  finally
    ReportData.Free;
    Task.Free;
  end;
end;

procedure TestSprint10ClosedSchemaAndNegativeControls;
var
  Task: TScanTask;
  SchemaData, ReportData: TJSONData;
  SchemaRoot, Properties, Definitions, SourceSchema, SummarySchema,
    ClaimSchema, PrivacySchema, MatchesSchema, MatchSchema, MatchProperties,
    RecordModifiedSchema, OSVTimestampSchema, LimitationsSchema, ReportRoot,
    FirstMatch: TJSONObject;
begin
  Task := S10CompletedTask;
  SchemaData := nil;
  ReportData := nil;
  try
    SchemaData := ParseStrictUTF8JSON(S8ReadFileBytes(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'schemas' +
      DirectorySeparator + 'purpleray-security-findings-v1.schema.json'));
    SchemaRoot := TJSONObject(SchemaData);
    AssertEqual('urn:purpleray:schema:security-findings:v1',
      JSONString(SchemaRoot, '$id'), 'security-findings schema ID differs');
    AssertTrue(not JSONBoolean(SchemaRoot, 'additionalProperties', True),
      'security-findings root schema is open');
    S10AssertStringArray(JSONArray(SchemaRoot, 'required'),
      ['format', 'formatVersion', 'source', 'summary', 'claim', 'privacy',
      'matches', 'limitations'], 'security-findings root requirements');
    Properties := JSONObject(SchemaRoot, 'properties');
    S10AssertExactKeys(Properties, ['format', 'formatVersion', 'source',
      'summary', 'claim', 'privacy', 'matches', 'limitations'],
      'security-findings schema properties differ from producer shape');
    SourceSchema := JSONObject(Properties, 'source');
    SummarySchema := JSONObject(Properties, 'summary');
    ClaimSchema := JSONObject(Properties, 'claim');
    PrivacySchema := JSONObject(Properties, 'privacy');
    MatchesSchema := JSONObject(Properties, 'matches');
    MatchSchema := JSONObject(MatchesSchema, 'items');
    MatchProperties := JSONObject(MatchSchema, 'properties');
    RecordModifiedSchema := JSONObject(MatchProperties, 'recordModified');
    Definitions := JSONObject(SchemaRoot, '$defs');
    OSVTimestampSchema := JSONObject(Definitions, 'osvTimestamp');
    LimitationsSchema := JSONObject(Properties, 'limitations');
    AssertTrue(not JSONBoolean(SourceSchema, 'additionalProperties', True) and
      not JSONBoolean(SummarySchema, 'additionalProperties', True) and
      not JSONBoolean(ClaimSchema, 'additionalProperties', True) and
      not JSONBoolean(PrivacySchema, 'additionalProperties', True) and
      not JSONBoolean(MatchSchema, 'additionalProperties', True),
      'a security-findings object schema is open');
    S10AssertStringArray(JSONArray(SourceSchema, 'required'),
      ['taskId', 'managedSbomSha256', 'knownIssueSnapshotSha256', 'provider',
      'checkedUtc', 'outcome'], 'security-findings source requirements');
    S10AssertStringArray(JSONArray(SummarySchema, 'required'),
      ['eligibleCandidateCount', 'advisoryCount', 'matchCount'],
      'security-findings summary requirements');
    S10AssertStringArray(JSONArray(ClaimSchema, 'required'),
      ['kind', 'confirmedVulnerabilities', 'text'],
      'security-findings claim requirements');
    S10AssertStringArray(JSONArray(PrivacySchema, 'required'),
      ['pathsIncluded', 'contactsIncluded', 'diagnosticsIncluded'],
      'security-findings privacy requirements');
    S10AssertStringArray(JSONArray(MatchSchema, 'required'),
      ['packageUrl', 'advisoryId', 'recordModified'],
      'security-findings match requirements');
    AssertEqual('#/$defs/osvTimestamp',
      JSONString(RecordModifiedSchema, '$ref'),
      'recordModified is not bound to the OSV timestamp schema');
    AssertEqual(
      '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' +
      '(\.[0-9]{1,9})?Z$', JSONString(OSVTimestampSchema, 'pattern'),
      'OSV timestamp schema no longer rejects compact arbitrary values');
    AssertTrue(not JSONBoolean(LimitationsSchema, 'items', True) and
      (JSONArray(LimitationsSchema, 'prefixItems').Count = 2),
      'security-findings limitations schema is not closed');

    ReportData := ParseStrictUTF8JSON(RawByteString(
      GenerateSecurityFindings(Task)));
    ReportRoot := TJSONObject(ReportData);
    AssertTrue(S10HasExactKeys(ReportRoot, ['format', 'formatVersion',
      'source', 'summary', 'claim', 'privacy', 'matches', 'limitations']),
      'valid report failed the closed-shape control');
    ReportRoot.Add('unexpected', True);
    AssertTrue(not S10HasExactKeys(ReportRoot, ['format', 'formatVersion',
      'source', 'summary', 'claim', 'privacy', 'matches', 'limitations']),
      'unexpected top-level member passed the negative control');
    ReportRoot.Delete('unexpected');
    FirstMatch := TJSONObject(JSONArray(ReportRoot, 'matches').Items[0]);
    FirstMatch.Add('severity', 'critical');
    AssertTrue(not S10HasExactKeys(FirstMatch,
      ['packageUrl', 'advisoryId', 'recordModified']),
      'invented severity passed the closed-match negative control');
    FirstMatch.Delete('severity');
    FirstMatch.Delete('recordModified');
    AssertTrue(not S10HasExactKeys(FirstMatch,
      ['packageUrl', 'advisoryId', 'recordModified']),
      'missing required match member passed the negative control');
  finally
    ReportData.Free;
    SchemaData.Free;
    Task.Free;
  end;
end;

procedure TestSprint10UIAndCLIContract;
var
  Lines: TStringList;
  AnalyzerSource, AnalyzerForm, CommandSource, UpdateBlock, ExportBlock: string;
begin
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uSBOMAnalyzerFrame.pas');
    AnalyzerSource := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uSBOMAnalyzerFrame.lfm');
    AnalyzerForm := Lines.Text;
    Lines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) + 'src' +
      DirectorySeparator + 'uCommandLine.pas');
    CommandSource := Lines.Text;

    AssertTrue((Pos('object ExportSecurityFindingsMenuItem: TMenuItem',
      AnalyzerForm) > 0) and
      (Pos('Caption = ''Security findings report...''', AnalyzerForm) > 0) and
      (Pos('OnClick = ExportSecurityFindingsClicked', AnalyzerForm) > 0),
      'desktop Export menu lost the security-findings action');
    UpdateBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.UpdateButtons',
      'procedure TSBOMAnalyzerFrame.FreeFinishedWorker');
    AssertTrue((Pos('ExportSecurityFindingsMenuItem.Enabled :=',
      UpdateBlock) > 0) and
      (Pos('CanGenerateSecurityFindings(Task)', UpdateBlock) > 0),
      'security-findings action is not gated by core eligibility');
    ExportBlock := ExtractTextSection(AnalyzerSource,
      'procedure TSBOMAnalyzerFrame.ExportSecurityFindingsClicked',
      'procedure TSBOMAnalyzerFrame.ExportBSIReadinessClicked');
    AssertTrue((Pos('GenerateSecurityFindings(Task)', ExportBlock) > 0) and
      (Pos('SecurityFindingsSuggestedExtension', ExportBlock) > 0) and
      (Pos('TPurpleRaySaveDialog', ExportBlock) > 0) and
      (Pos('[ofOverwritePrompt]', ExportBlock) > 0),
      'security-findings handler lost generation, naming, or save consent');
    AssertTrue((Pos('SameFileName(ExpandFileName(Dialog.FileName)',
      ExportBlock) > 0) and
      (Pos('ExpandFileName(Task.GeneratedSBOMPath)', ExportBlock) > 0) and
      (Pos('cannot replace the managed SBOM', ExportBlock) > 0),
      'security-findings handler can target the managed SBOM');
    AssertTrue((Pos('WriteAtomicUTF8(Dialog.FileName, Report, False)',
      ExportBlock) > 0) and (Pos('WriteUTF8File(', ExportBlock) = 0) and
      (Pos('ExportedMatchCount := Task.KnownIssueCheck.MatchCount',
        ExportBlock) > 0) and (Pos('IntToStr(ExportedMatchCount)',
        ExportBlock) > 0) and
      (Pos('advisory matches', ExportBlock) > 0),
      'security-findings handler lost atomic output, stable feedback, or ' +
      'neutral terminology');
    AssertTrue((Pos('--security-findings', CommandSource) = 0) and
      (Pos('--export-security', CommandSource) = 0) and
      (Pos('uSecurityFindings', CommandSource) = 0),
      'headless command line exposes the desktop security-findings export');
  finally
    Lines.Free;
  end;
end;

procedure RunSprint10RegressionTests;
begin
  RunTest('Sprint 10 deterministic binding, order, and privacy',
    @TestSprint10DeterministicBindingAndPrivacy);
  RunTest('Sprint 10 strict inputs and complete outcomes',
    @TestSprint10StrictInputsAndOutcomes);
  RunTest('Sprint 10 closed schema and negative controls',
    @TestSprint10ClosedSchemaAndNegativeControls);
  RunTest('Sprint 10 desktop export and offline CLI contract',
    @TestSprint10UIAndCLIContract);
end;
