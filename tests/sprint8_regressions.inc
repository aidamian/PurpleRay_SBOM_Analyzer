{ Sprint 8 declared-lockfile-hash, CycloneDX occurrence-evidence, and
  opt-in OSV core regressions. This file is included after RunTest is declared.
  Every OSV test injects an in-memory transport; no test opens a network
  endpoint. }

type
  { Reports an impossible caller-owned cardinality. The OSV core must inspect
    Count, fail closed, and never index or mutate this object. }
  TS8HugeCandidateStrings = class(TStrings)
  protected
    function Get(Index: Integer): string; override;
    function GetCount: Integer; override;
  public
    procedure Clear; override;
    procedure Delete(Index: Integer); override;
    procedure Insert(Index: Integer; const S: string); override;
  end;

  TS8FakeOSVTransport = class(TInterfacedObject, IOSVTransport)
  private
    FResponseIndex: Integer;
  public
    Requests: TStringList;
    Responses: TStringList;
    Cancelled: Boolean;
    constructor Create;
    destructor Destroy; override;
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    procedure Cancel;
  end;

  TS8GeneratedOSVMode = (
    s8gmEmpty,
    s8gmPagingForever,
    s8gmOversize,
    s8gmTransportOversize,
    s8gmAggregatePadding,
    s8gmAdvisoryOverflow,
    s8gmMatchOverflow,
    s8gmRawEntryLimit,
    s8gmRawEntryOverflow,
    s8gmJSONNodeOverflow,
    s8gmCancelDuringPost,
    s8gmTransportFailure,
    s8gmTransportException,
    s8gmEnrichmentException,
    s8gmHTTPFailure
  );

  TS8GeneratedOSVTransport = class(TInterfacedObject, IOSVTransport)
  private
    FCallCount: Integer;
    FMode: TS8GeneratedOSVMode;
    function QueryCount(const ARequestBody: RawByteString): Integer;
    function EmptyResponse(AQueryCount: Integer): RawByteString;
    function AdvisoryOverflowResponse: RawByteString;
    function MatchOverflowResponse: RawByteString;
    function RawDuplicateResponse(AQueryCount, AEntryCount: Integer):
      RawByteString;
    function JSONNodeOverflowResponse: RawByteString;
  public
    Cancelled: Boolean;
    MaximumQueriesSeen: Integer;
    Requests: TStringList;
    constructor Create(AMode: TS8GeneratedOSVMode);
    destructor Destroy; override;
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    procedure Cancel;
  end;

  TS8CancelProbe = class
  private
    FChecks: Integer;
  public
    CancelAt: Integer;
    function Check: Boolean;
  end;

  { Pins the generated timestamp only at completed-task cancellation polls,
    allowing two otherwise identical scans to prove online/offline byte
    identity without racing the analysis workers. }
  TS8TimestampPin = class
  public
    Task: TScanTask;
    function Check: Boolean;
  end;

  { Fails only at the post-output enrichment progress boundary. Scanner
    progress remains observable, so the fixture proves that the committed
    inventory survives a callback exception after activation. }
  TS8FailingEnrichmentProgress = class
  public
    EnrichmentCalls: Integer;
    procedure Update(const AProgress: TScanProgress);
  end;

  { Exercises the worker's last-resort boundary after a managed inventory has
    already been committed. There is intentionally no production transport-
    factory injection seam, so the protected test seam models its OOM path
    without constructing a production transport or opening the network. }
  TS8CommittedEnrichmentFailureWorker = class(TScanWorker)
  public
    OutputBytes: RawByteString;
    OutputFileName: string;
  protected
    procedure PerformScan; override;
  end;

  { Observes the scan-service transaction from the injected lookup boundary.
    It returns an empty, cardinality-correct querybatch response and never
    opens a network endpoint. }
  TS8SequencingOSVTransport = class(TInterfacedObject, IOSVTransport)
  private
    function QueryCount(const ARequestBody: RawByteString): Integer;
    function EmptyResponse(AQueryCount: Integer): RawByteString;
  public
    Task: TScanTask;
    ExpectedOutputFileName: string;
    ExpectedCacheFileName: string;
    Requests: TStringList;
    OutputBytesAtLookup: RawByteString;
    SawActivatedOutput: Boolean;
    SawCommittedCache: Boolean;
    SawMatchingStoredDigest: Boolean;
    Cancelled: Boolean;
    constructor Create;
    destructor Destroy; override;
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    procedure Cancel;
  end;

function S8NewDeclaredHash(const AAlgorithm, ADigest, ASubject,
  ASourceArtifact, ASourceParser: string): TDeclaredHash;
begin
  Result := TDeclaredHash.Create;
  Result.Algorithm := AAlgorithm;
  Result.Digest := ADigest;
  Result.Subject := ASubject;
  Result.SourceArtifact := ASourceArtifact;
  Result.SourceParser := ASourceParser;
end;

function S8NewKnownIssueMatch(const APackageURL, AAdvisoryID,
  AModified: string): TKnownIssueMatch;
begin
  Result := TKnownIssueMatch.Create;
  Result.PackageURL := APackageURL;
  Result.AdvisoryID := AAdvisoryID;
  Result.Modified := AModified;
end;

function S8ReadFileBytes(const AFileName: string): RawByteString;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    if Stream.Size > High(Integer) then
      Fail('Sprint 8 test file exceeds the in-memory fixture limit');
    SetLength(Result, Stream.Size);
    if Stream.Size > 0 then
      Stream.ReadBuffer(Result[1], Stream.Size);
  finally
    Stream.Free;
  end;
end;

function S8CountHistoryTemporaryFiles(const ADirectory: string): Integer;
var
  SearchRecord: TSearchRec;
begin
  Result := 0;
  if FindFirst(IncludeTrailingPathDelimiter(ADirectory) +
    'history.json.tmp-*', faAnyFile, SearchRecord) <> 0 then
    Exit;
  try
    repeat
      Inc(Result);
    until FindNext(SearchRecord) <> 0;
  finally
    FindClose(SearchRecord);
  end;
end;

function S8BaseKnownIssueJSON: TJSONObject;
var
  Matches: TJSONArray;
begin
  Result := TJSONObject.Create;
  Result.Add('requested', True);
  Result.Add('source', KnownIssueSource);
  Result.Add('checked_utc', '2026-08-21T12:00:00Z');
  Result.Add('outcome', 'ok');
  Result.Add('http_status', 200);
  Result.Add('request_count', 1);
  Result.Add('aggregate_response_bytes', 64);
  Result.Add('eligible_candidate_count', 1);
  Result.Add('rejected_candidate_count', 0);
  Result.Add('duplicate_candidate_count', 0);
  Matches := TJSONArray.Create;
  Result.Add('matches', Matches);
end;

function S8KnownIssueMatchJSON(const APackageURL, AAdvisoryID,
  AModified: string): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.Add('package_url', APackageURL);
  Result.Add('advisory_id', AAdvisoryID);
  Result.Add('modified', AModified);
end;

function S8ParseManifestText(const AText, ARelativePath: string;
  AKind: TParserKind): TObjectList;
var
  Input: TStringStream;
  Artifact: TArtifact;
begin
  Result := TObjectList.Create(True);
  Input := TStringStream.Create(AText);
  Artifact := TArtifact.Create;
  try
    ParseArtifact(Input, ARelativePath, AKind, Artifact, Result);
    AssertTrue(Artifact.Status <> arsFailed,
      'Sprint 8 parser failed: ' + Artifact.MessageText);
  finally
    Artifact.Free;
    Input.Free;
  end;
end;

function S8FindModelComponent(AComponents: TObjectList;
  const AName: string): TComponent;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to AComponents.Count - 1 do
    if TComponent(AComponents[I]).Name = AName then
      Exit(TComponent(AComponents[I]));
end;

function S8ParseJSONObject(const AText: UTF8String): TJSONObject;
var
  Data: TJSONData;
begin
  Data := GetJSON(AText);
  if Data.JSONType <> jtObject then
  begin
    Data.Free;
    Fail('Sprint 8 fixture did not produce a JSON object');
  end;
  Result := TJSONObject(Data);
end;

function S8FindJSONComponent(AComponents: TJSONArray;
  const AName: string): TJSONObject;
var
  I: Integer;
begin
  Result := nil;
  if AComponents = nil then
    Exit;
  for I := 0 to AComponents.Count - 1 do
    if (AComponents.Items[I].JSONType = jtObject) and
      (JSONString(TJSONObject(AComponents.Items[I]), 'name') = AName) then
      Exit(TJSONObject(AComponents.Items[I]));
end;

function S8CountProperties(AComponent: TJSONObject; const AName: string;
  out AFirstValue: string): Integer;
var
  I: Integer;
  Item: TJSONObject;
  Properties: TJSONArray;
begin
  Result := 0;
  AFirstValue := '';
  Properties := JSONArray(AComponent, 'properties');
  if Properties = nil then
    Exit;
  for I := 0 to Properties.Count - 1 do
  begin
    if Properties.Items[I].JSONType <> jtObject then
      Continue;
    Item := TJSONObject(Properties.Items[I]);
    if JSONString(Item, 'name') <> AName then
      Continue;
    Inc(Result);
    if Result = 1 then
      AFirstValue := JSONString(Item, 'value');
  end;
end;

procedure S8AssertJSONObjectKeys(AObject: TJSONObject;
  const AExpected: array of string; const AMessage: string);
var
  I: Integer;
begin
  AssertTrue(AObject <> nil, AMessage + ' is not an object');
  AssertEqual(Length(AExpected), AObject.Count,
    AMessage + ' member count differs');
  for I := Low(AExpected) to High(AExpected) do
    AssertEqual(AExpected[I], AObject.Names[I],
      AMessage + ' member order/closure differs at index ' + IntToStr(I));
end;

procedure S8AssertJSONType(AData: TJSONData; AExpected: TJSONType;
  const AMessage: string);
begin
  AssertTrue((AData <> nil) and (AData.JSONType = AExpected), AMessage);
end;

function S8BSIComponentFixture(const AReference, AName, APackageURL,
  AFileName, AOccurrence: string): RawByteString;
begin
  Result := '{' +
    '"type":"file",' +
    '"bom-ref":"' + AReference + '",' +
    '"name":"' + AName + '",' +
    '"version":"1.0.0",' +
    '"purl":"' + APackageURL + '",' +
    '"manufacturer":{"name":"SECRET-COMPONENT-CREATOR",' +
      '"contact":[{"email":"secret-component@example.invalid"}],' +
      '"url":["https://secret-component.example.invalid/contact"]},' +
    '"licenses":[' +
      '{"expression":"MIT","acknowledgement":"declared"},' +
      '{"expression":"MIT","acknowledgement":"concluded"}],' +
    '"properties":[' +
      '{"name":"bsi:component:filename","value":"' + AFileName + '"},' +
      '{"name":"bsi:component:executable","value":"executable"},' +
      '{"name":"bsi:component:archive","value":"no archive"},' +
      '{"name":"bsi:component:structured","value":"structured"},' +
      '{"name":"bsi:component:effectiveLicence","value":"MIT"}],' +
    '"externalReferences":[' +
      '{"type":"distribution","url":"urn:distribution:' + AName + '",' +
        '"hashes":[{"alg":"SHA-512","content":"' +
          StringOfChar('a', 128) + '"}]},' +
      '{"type":"source-distribution","url":"urn:source:' + AName + '",' +
        '"hashes":[{"alg":"SHA-512","content":"' +
          StringOfChar('b', 128) + '"}]},' +
      '{"type":"rfc-9116","url":' +
        '"https://security.example.invalid/.well-known/security.txt"},' +
      '{"type":"bom","url":"urn:bom:' + AName + '"}],' +
    '"evidence":{"occurrences":[{"location":"' + AOccurrence + '"}]}' +
    '}';
end;

function S8BSIRichFixture: RawByteString;
const
  PrimaryReference =
    'file:///home/private/SECRET-ABSOLUTE-PATH/root.bin';
  AlphaReference = 'pkg:npm/alpha@1.0.0';
  ZetaReference = 'src/SECRET-RELATIVE-PATH/zeta.js';
var
  AlphaComponent, PrimaryComponent, ZetaComponent: RawByteString;
begin
  PrimaryComponent := S8BSIComponentFixture(PrimaryReference, 'root',
    'pkg:npm/root@1.0.0', 'root.bin',
    '/home/private/SECRET-ABSOLUTE-OCCURRENCE/root.bin');
  { Deliberately provide ordinary components in reverse ordinal order. }
  ZetaComponent := S8BSIComponentFixture(ZetaReference, 'zeta',
    'pkg:npm/zeta@1.0.0', 'zeta.js',
    'src/SECRET-RELATIVE-OCCURRENCE/zeta.js');
  AlphaComponent := S8BSIComponentFixture(AlphaReference, 'alpha',
    'pkg:npm/alpha@1.0.0', 'alpha.js',
    'src/SECRET-RELATIVE-OCCURRENCE/alpha.js');
  Result := '{' +
    '"bomFormat":"CycloneDX",' +
    '"specVersion":"1.7",' +
    '"serialNumber":"urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",' +
    '"metadata":{' +
      '"timestamp":"2026-08-21T12:00:00Z",' +
      '"manufacturer":{"name":"SECRET-SBOM-CREATOR",' +
        '"contact":[{"email":"secret-sbom@example.invalid"}],' +
        '"url":["https://secret-sbom.example.invalid/contact"]},' +
      '"component":' + PrimaryComponent + '},' +
    '"components":[' + ZetaComponent + ',' + AlphaComponent + '],' +
    '"dependencies":[' +
      '{"ref":"' + PrimaryReference + '","dependsOn":[' +
        '"' + AlphaReference + '","' + ZetaReference + '"]},' +
      '{"ref":"' + ZetaReference + '","dependsOn":[]},' +
      '{"ref":"' + AlphaReference + '","dependsOn":[]}],' +
    '"compositions":[{"aggregate":"complete","assemblies":[' +
      '"' + PrimaryReference + '","' + ZetaReference + '",' +
      '"' + AlphaReference + '"]}],' +
    '"warnings":["SECRET-DIAGNOSTIC-SENTINEL"],' +
    '"known_issue_check":{"diagnostic":' +
      '"SECRET-KNOWN-ISSUE-DIAGNOSTIC",' +
      '"matches":[{"advisory_id":"GHSA-SECRET-KNOWN-ISSUE"}]},' +
    '"vulnerabilities":[{"id":"GHSA-SECRET-SECURITY-FINDING",' +
      '"description":"SECRET-SECURITY-DESCRIPTION"}]' +
    '}';
end;

procedure S8AssertBSIClosedSchema(ARoot: TJSONObject);
var
  Advisories, Blockers, Components, DocumentFields, Fields, LocalBlockers,
    Mappings: TJSONArray;
  ComponentValue, FieldValue, Value: TJSONObject;
  I, J, K: Integer;
begin
  S8AssertJSONObjectKeys(ARoot,
    ['format', 'formatVersion', 'target', 'claim', 'source', 'privacy',
    'summary', 'documentFields', 'components', 'blockers', 'advisories'],
    'BSI report root');
  S8AssertJSONType(ARoot.Find('format'), jtString,
    'BSI report format is not a string');
  S8AssertJSONType(ARoot.Find('formatVersion'), jtNumber,
    'BSI report formatVersion is not numeric');

  Value := JSONObject(ARoot, 'target');
  S8AssertJSONObjectKeys(Value,
    ['guideline', 'guidelineVersion', 'guidelineDate', 'guidelinePdfSha256',
    'cycloneDxMinimum', 'taxonomyVersion', 'taxonomyCommit'],
    'BSI target');
  for I := 0 to Value.Count - 1 do
    S8AssertJSONType(Value.Items[I], jtString,
      'BSI target member is not a string');

  Value := JSONObject(ARoot, 'claim');
  S8AssertJSONObjectKeys(Value, ['kind', 'complianceClaimed', 'text'],
    'BSI claim');
  S8AssertJSONType(Value.Find('kind'), jtString,
    'BSI claim kind is not a string');
  S8AssertJSONType(Value.Find('complianceClaimed'), jtBoolean,
    'BSI claim compliance flag is not Boolean');
  S8AssertJSONType(Value.Find('text'), jtString,
    'BSI claim text is not a string');

  Value := JSONObject(ARoot, 'source');
  S8AssertJSONObjectKeys(Value,
    ['taskId', 'managedSbomSha256', 'bomFormat', 'specVersion',
    'sourceSchemaValidation'], 'BSI source binding');
  for I := 0 to Value.Count - 1 do
    S8AssertJSONType(Value.Items[I], jtString,
      'BSI source-binding member is not a string');

  Value := JSONObject(ARoot, 'privacy');
  S8AssertJSONObjectKeys(Value,
    ['profile', 'absolutePathsIncluded', 'relativePathsIncluded',
    'contactValuesIncluded', 'diagnosticsIncluded',
    'dynamicSecurityFindingsIncluded'], 'BSI privacy declaration');
  S8AssertJSONType(Value.Find('profile'), jtString,
    'BSI privacy profile is not a string');
  for I := 1 to Value.Count - 1 do
    S8AssertJSONType(Value.Items[I], jtBoolean,
      'BSI privacy exclusion is not Boolean');

  Value := JSONObject(ARoot, 'summary');
  S8AssertJSONObjectKeys(Value,
    ['status', 'componentsAssessed', 'mapped', 'derivable', 'notApplicable',
    'notObserved', 'blocked', 'advisoryCount'], 'BSI summary');
  S8AssertJSONType(Value.Find('status'), jtString,
    'BSI summary status is not a string');
  for I := 1 to Value.Count - 1 do
    S8AssertJSONType(Value.Items[I], jtNumber,
      'BSI summary counter is not numeric');

  DocumentFields := JSONArray(ARoot, 'documentFields');
  Components := JSONArray(ARoot, 'components');
  Blockers := JSONArray(ARoot, 'blockers');
  Advisories := JSONArray(ARoot, 'advisories');
  AssertTrue((DocumentFields <> nil) and (Components <> nil) and
    (Blockers <> nil) and (Advisories <> nil),
    'BSI report collection has the wrong JSON type');
  for I := 0 to DocumentFields.Count - 1 do
  begin
    S8AssertJSONType(DocumentFields.Items[I], jtObject,
      'BSI document field is not an object');
    FieldValue := TJSONObject(DocumentFields.Items[I]);
    if FieldValue.Find('blockerCode') <> nil then
      S8AssertJSONObjectKeys(FieldValue,
        ['field', 'requirement', 'status', 'mappings', 'evidence',
        'blockerCode'], 'BSI blocked document field')
    else
      S8AssertJSONObjectKeys(FieldValue,
        ['field', 'requirement', 'status', 'mappings', 'evidence'],
        'BSI document field');
    Mappings := JSONArray(FieldValue, 'mappings');
    AssertTrue(Mappings <> nil, 'BSI document mappings are not an array');
    S8AssertJSONType(FieldValue.Find('field'), jtString,
      'BSI document field name is not a string');
    S8AssertJSONType(FieldValue.Find('requirement'), jtString,
      'BSI document requirement is not a string');
    S8AssertJSONType(FieldValue.Find('status'), jtString,
      'BSI document status is not a string');
    S8AssertJSONType(FieldValue.Find('evidence'), jtString,
      'BSI document evidence is not a string');
    AssertTrue((JSONString(FieldValue, 'status') = 'blocked') =
      (FieldValue.Find('blockerCode') <> nil),
      'BSI document blockerCode presence differs from status');
    for J := 0 to Mappings.Count - 1 do
      S8AssertJSONType(Mappings.Items[J], jtString,
        'BSI document mapping is not a string');
  end;

  for I := 0 to Components.Count - 1 do
  begin
    S8AssertJSONType(Components.Items[I], jtObject,
      'BSI component assessment is not an object');
    ComponentValue := TJSONObject(Components.Items[I]);
    S8AssertJSONObjectKeys(ComponentValue,
      ['componentId', 'role', 'kind', 'descriptionLevel', 'fields',
      'blockers'], 'BSI component assessment');
    S8AssertJSONType(ComponentValue.Find('componentId'), jtString,
      'BSI componentId is not a string');
    S8AssertJSONType(ComponentValue.Find('role'), jtString,
      'BSI component role is not a string');
    S8AssertJSONType(ComponentValue.Find('kind'), jtString,
      'BSI component kind is not a string');
    S8AssertJSONType(ComponentValue.Find('descriptionLevel'), jtString,
      'BSI component description level is not a string');
    Fields := JSONArray(ComponentValue, 'fields');
    LocalBlockers := JSONArray(ComponentValue, 'blockers');
    AssertTrue((Fields <> nil) and (LocalBlockers <> nil),
      'BSI component collection has the wrong type');
    for J := 0 to Fields.Count - 1 do
    begin
      S8AssertJSONType(Fields.Items[J], jtObject,
        'BSI component field is not an object');
      FieldValue := TJSONObject(Fields.Items[J]);
      if FieldValue.Find('blockerCode') <> nil then
        S8AssertJSONObjectKeys(FieldValue,
          ['field', 'requirement', 'status', 'mappings', 'evidence',
          'blockerCode'], 'BSI blocked component field')
      else
        S8AssertJSONObjectKeys(FieldValue,
          ['field', 'requirement', 'status', 'mappings', 'evidence'],
          'BSI component field');
      Mappings := JSONArray(FieldValue, 'mappings');
      AssertTrue(Mappings <> nil, 'BSI component mappings are not an array');
      S8AssertJSONType(FieldValue.Find('field'), jtString,
        'BSI component field name is not a string');
      S8AssertJSONType(FieldValue.Find('requirement'), jtString,
        'BSI component requirement is not a string');
      S8AssertJSONType(FieldValue.Find('status'), jtString,
        'BSI component status is not a string');
      S8AssertJSONType(FieldValue.Find('evidence'), jtString,
        'BSI component evidence is not a string');
      AssertTrue((JSONString(FieldValue, 'status') = 'blocked') =
        (FieldValue.Find('blockerCode') <> nil),
        'BSI component blockerCode presence differs from status');
      for K := 0 to Mappings.Count - 1 do
        S8AssertJSONType(Mappings.Items[K], jtString,
          'BSI component mapping is not a string');
    end;
    for J := 0 to LocalBlockers.Count - 1 do
      S8AssertJSONType(LocalBlockers.Items[J], jtString,
        'BSI local blocker code is not a string');
  end;

  for I := 0 to Blockers.Count - 1 do
  begin
    S8AssertJSONType(Blockers.Items[I], jtObject,
      'BSI blocker is not an object');
    Value := TJSONObject(Blockers.Items[I]);
    if Value.Find('componentId') <> nil then
      S8AssertJSONObjectKeys(Value,
        ['code', 'scope', 'componentId', 'field', 'reason'],
        'BSI component blocker')
    else
      S8AssertJSONObjectKeys(Value, ['code', 'scope', 'field', 'reason'],
        'BSI document blocker');
    for J := 0 to Value.Count - 1 do
      S8AssertJSONType(Value.Items[J], jtString,
        'BSI blocker member is not a string');
  end;
  for I := 0 to Advisories.Count - 1 do
  begin
    S8AssertJSONType(Advisories.Items[I], jtObject,
      'BSI advisory is not an object');
    S8AssertJSONObjectKeys(TJSONObject(Advisories.Items[I]),
      ['code', 'message'], 'BSI advisory');
    Value := TJSONObject(Advisories.Items[I]);
    for J := 0 to Value.Count - 1 do
      S8AssertJSONType(Value.Items[J], jtString,
        'BSI advisory member is not a string');
  end;
end;

procedure S8AssertBSICounters(ARoot: TJSONObject;
  const ASummary: TBSIReadinessSummary);
var
  Blockers, Components, DocumentFields, Fields: TJSONArray;
  FieldValue, SummaryValue: TJSONObject;
  BlockedCount, DerivableCount, I, J, MappedCount, NotApplicableCount,
    NotObservedCount: Int64;

  procedure CountField(AField: TJSONObject);
  var
    StatusValue: string;
  begin
    StatusValue := JSONString(AField, 'status');
    if StatusValue = 'mapped' then
      Inc(MappedCount)
    else if StatusValue = 'derivable' then
      Inc(DerivableCount)
    else if StatusValue = 'not-applicable' then
      Inc(NotApplicableCount)
    else if StatusValue = 'not-observed' then
      Inc(NotObservedCount)
    else
      AssertEqual('blocked', StatusValue,
        'BSI field has an unknown status');
  end;

begin
  MappedCount := 0;
  DerivableCount := 0;
  NotApplicableCount := 0;
  NotObservedCount := 0;
  DocumentFields := JSONArray(ARoot, 'documentFields');
  Components := JSONArray(ARoot, 'components');
  Blockers := JSONArray(ARoot, 'blockers');
  for I := 0 to DocumentFields.Count - 1 do
    CountField(TJSONObject(DocumentFields.Items[I]));
  for I := 0 to Components.Count - 1 do
  begin
    Fields := JSONArray(TJSONObject(Components.Items[I]), 'fields');
    for J := 0 to Fields.Count - 1 do
    begin
      FieldValue := TJSONObject(Fields.Items[J]);
      CountField(FieldValue);
    end;
  end;
  BlockedCount := Blockers.Count;
  AssertEqual(MappedCount, ASummary.Mapped,
    'BSI returned mapped counter differs from fields');
  AssertEqual(DerivableCount, ASummary.Derivable,
    'BSI returned derivable counter differs from fields');
  AssertEqual(NotApplicableCount, ASummary.NotApplicable,
    'BSI returned not-applicable counter differs from fields');
  AssertEqual(NotObservedCount, ASummary.NotObserved,
    'BSI returned not-observed counter differs from fields');
  AssertEqual(BlockedCount, ASummary.Blocked,
    'BSI returned blocker counter differs from blockers');
  AssertEqual(Components.Count, ASummary.ComponentsAssessed,
    'BSI returned component counter differs from components');

  SummaryValue := JSONObject(ARoot, 'summary');
  AssertEqual(BSIReadinessStatusToString(ASummary.Status),
    JSONString(SummaryValue, 'status'),
    'BSI JSON status differs from the returned summary');
  AssertEqual(ASummary.ComponentsAssessed,
    JSONInt64(SummaryValue, 'componentsAssessed'),
    'BSI JSON component counter differs');
  AssertEqual(ASummary.Mapped, JSONInt64(SummaryValue, 'mapped'),
    'BSI JSON mapped counter differs');
  AssertEqual(ASummary.Derivable, JSONInt64(SummaryValue, 'derivable'),
    'BSI JSON derivable counter differs');
  AssertEqual(ASummary.NotApplicable,
    JSONInt64(SummaryValue, 'notApplicable'),
    'BSI JSON not-applicable counter differs');
  AssertEqual(ASummary.NotObserved,
    JSONInt64(SummaryValue, 'notObserved'),
    'BSI JSON not-observed counter differs');
  AssertEqual(ASummary.Blocked, JSONInt64(SummaryValue, 'blocked'),
    'BSI JSON blocker counter differs');
  AssertEqual(ASummary.AdvisoryCount,
    JSONInt64(SummaryValue, 'advisoryCount'),
    'BSI JSON advisory counter differs');
end;

procedure S8AssertBSIError(const ABytes: RawByteString;
  const AExpectedSHA256, ATaskID, AExpectedCode, AMessage: string);
var
  RaisedValue: Boolean;
  Report: UTF8String;
  Summary: TBSIReadinessSummary;
begin
  RaisedValue := False;
  Report := '';
  try
    Report := GenerateBSIReadinessReport(ABytes, AExpectedSHA256,
      ATaskID, Summary);
  except
    on E: EBSIReadinessError do
    begin
      RaisedValue := True;
      AssertEqual(AExpectedCode, E.Code,
        AMessage + ' returned a different stable error code');
    end;
  end;
  AssertTrue(RaisedValue, AMessage + ' was accepted');
  AssertEqual('', string(Report), AMessage + ' returned report bytes');
end;

procedure S8AssertOccurrences(AComponent: TJSONObject;
  const AFirst, ASecond: string);
var
  Evidence: TJSONObject;
  Occurrences: TJSONArray;
begin
  Evidence := JSONObject(AComponent, 'evidence');
  AssertTrue(Evidence <> nil, 'CycloneDX component evidence is missing');
  AssertTrue(Evidence.Find('identity') = nil,
    'CycloneDX evidence.identity was emitted without identity analysis');
  Occurrences := JSONArray(Evidence, 'occurrences');
  AssertTrue((Occurrences <> nil) and (Occurrences.Count = 2),
    'CycloneDX occurrence union/dedup count differs');
  AssertEqual(AFirst,
    JSONString(TJSONObject(Occurrences.Items[0]), 'location'),
    'first CycloneDX occurrence is not ordinal');
  AssertEqual(ASecond,
    JSONString(TJSONObject(Occurrences.Items[1]), 'location'),
    'second CycloneDX occurrence is not ordinal');
end;

procedure S8AddDeclaredHash(AComponent: TComponent;
  const AAlgorithm, ADigest, ASubject, AArtifact, AParser: string);
begin
  AComponent.DeclaredHashes.Add(S8NewDeclaredHash(AAlgorithm, ADigest,
    ASubject, AArtifact, AParser));
end;

procedure TestSprint8DeclaredHashModelAndNormalization;
var
  Component, Loaded, Left, Right, Normalized: TComponent;
  Data, InvalidData: TJSONObject;
  HashValue: TDeclaredHash;
  Hashes: TJSONArray;
  Input, Output: TObjectList;
  I: Integer;
  RaisedValue: Boolean;
begin
  AssertEqual(256, MaximumDeclaredHashesPerComponent,
    'declared-hash model cap changed');
  Component := TComponent.Create;
  Loaded := nil;
  Data := nil;
  try
    Component.Name := 'model-demo';
    Component.SourceArtifact := 'locks/demo.lock';
    Component.SourceParser := 'model-probe';
    S8AddDeclaredHash(Component, 'SHA-256', StringOfChar('a', 64),
      'b.whl', 'locks/demo.lock', 'model-probe');
    S8AddDeclaredHash(Component, 'SHA-256', StringOfChar('a', 64),
      'a.whl', 'locks/demo.lock', 'model-probe');
    S8AddDeclaredHash(Component, 'SHA-256', StringOfChar('a', 64),
      'a.whl', 'locks/demo.lock', 'model-probe');
    AssertEqual(2, Component.DeclaredHashes.Count,
      'declared hashes were not exact-deduplicated');
    AssertEqual('a.whl', Component.DeclaredHashes[0].Subject,
      'declared hashes are not deterministically ordered');
    Data := Component.ToJSON;
    Loaded := TComponent.FromJSON(Data);
    AssertEqual(2, Loaded.DeclaredHashes.Count,
      'declared hashes did not survive component JSON');
    Loaded.DeclaredHashes[0].Subject := 'changed.whl';
    AssertEqual('a.whl', Component.DeclaredHashes[0].Subject,
      'declared-hash clone aliases the source model');
  finally
    Loaded.Free;
    Data.Free;
    Component.Free;
  end;

  Component := TComponent.Create;
  try
    for I := 0 to MaximumDeclaredHashesPerComponent do
      S8AddDeclaredHash(Component, 'SHA-256', StringOfChar('b', 64),
        'archive-' + IntToStr(I), 'cap.lock', 'model-probe');
    AssertEqual(MaximumDeclaredHashesPerComponent,
      Component.DeclaredHashes.Count,
      'declared-hash list crossed its hard cap');
    Component.DeclaredHashes.Add(S8NewDeclaredHash('SHA-256',
      StringOfChar('A', 64), 'invalid-uppercase', 'cap.lock', 'model-probe'));
    AssertEqual(MaximumDeclaredHashesPerComponent,
      Component.DeclaredHashes.Count,
      'non-canonical declared digest was retained');
  finally
    Component.Free;
  end;

  InvalidData := TJSONObject.Create;
  try
    InvalidData.Add('name', 'oversized');
    Hashes := TJSONArray.Create;
    InvalidData.Add('declared_hashes', Hashes);
    for I := 0 to MaximumDeclaredHashesPerComponent do
    begin
      HashValue := S8NewDeclaredHash('SHA-256', StringOfChar('c', 64),
        'archive-' + IntToStr(I), 'cap.lock', 'model-probe');
      try
        Hashes.Add(HashValue.ToJSON);
      finally
        HashValue.Free;
      end;
    end;
    RaisedValue := False;
    try
      Loaded := TComponent.FromJSON(InvalidData);
      Loaded.Free;
    except
      on E: EJSON do
        RaisedValue := True;
    end;
    AssertTrue(RaisedValue,
      'oversized persisted declared-hash collection was accepted');
  finally
    InvalidData.Free;
  end;

  Input := TObjectList.Create(True);
  Output := TObjectList.Create(True);
  try
    Left := TComponent.Create;
    Left.Name := 'merge';
    Left.Version := '1.0.0';
    Left.Ecosystem := 'npm';
    Left.PackageURL := 'pkg:npm/merge@1.0.0';
    Left.SourceArtifact := 'package-lock.json';
    Left.SourceParser := 'package-lock-json';
    Left.EvidencePaths.Add(Left.SourceArtifact);
    S8AddDeclaredHash(Left, 'SHA-512', StringOfChar('d', 128),
      'merge@1.0.0', Left.SourceArtifact, Left.SourceParser);
    Input.Add(Left);
    Right := Left.Clone;
    S8AddDeclaredHash(Right, 'SHA-512', StringOfChar('d', 128),
      'other-archive.tgz', Right.SourceArtifact, Right.SourceParser);
    Input.Add(Right);
    NormalizeComponents(Input, Output);
    AssertEqual(1, Output.Count,
      'normalization did not merge identical component identities');
    Normalized := TComponent(Output[0]);
    AssertEqual(2, Normalized.DeclaredHashes.Count,
      'normalization lost distinct declared-hash provenance');
    AssertEqual('merge@1.0.0', Normalized.DeclaredHashes[0].Subject,
      'normalization changed declared-hash order');
  finally
    Output.Free;
    Input.Free;
  end;
end;

procedure TestSprint8DeclaredHashParsers;
const
  SHA1SRI = 'AAECAwQFBgcICQoLDA0ODxAREhM=';
  SHA256SRI = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
  SHA384SRI = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v';
  SHA512SRI = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==';
var
  Components: TObjectList;
  Component: TComponent;
  ComponentJSON: TJSONObject;
  Persisted, TextValue: string;
begin
  TextValue := '{"lockfileVersion":3,"packages":{' +
    '"":{"name":"root","version":"1.0.0"},' +
    '"node_modules/@scope/pkg":{"version":"2.3.4",' +
    '"resolved":"https://secret.invalid/private/pkg.tgz","integrity":"' +
    'sha1-' + SHA1SRI + ' sha256-' + SHA256SRI + ' ' +
    'sha384-' + SHA384SRI + ' sha512-' + SHA512SRI +
    ' sha256-AAAA sha512-not*base64"}}}';
  Components := S8ParseManifestText(TextValue, 'package-lock.json',
    pkPackageLockJSON);
  try
    Component := S8FindModelComponent(Components, '@scope/pkg');
    AssertTrue(Component <> nil, 'scoped npm lock component is missing');
    AssertEqual(4, Component.DeclaredHashes.Count,
      'npm SRI algorithm or strict-base64 parsing differs');
    AssertEqual('SHA-1', Component.DeclaredHashes[0].Algorithm,
      'npm SRI hashes are not algorithm-ordered');
    AssertEqual('SHA-512', Component.DeclaredHashes[3].Algorithm,
      'npm SHA-512 SRI was not retained');
    AssertEqual('@scope/pkg@2.3.4', Component.DeclaredHashes[0].Subject,
      'scoped npm declared-hash subject differs');
    ComponentJSON := Component.ToJSON;
    try
      Persisted := ComponentJSON.AsJSON;
      AssertTrue(Pos('secret.invalid', Persisted) = 0,
        'npm resolved URL leaked into the component model');
    finally
      ComponentJSON.Free;
    end;
  finally
    Components.Free;
  end;

  TextValue := '{"dependencies":{"legacy":{"version":"1.2.3",' +
    '"resolved":"https://secret.invalid/legacy.tgz","integrity":"sha512-' +
    SHA512SRI + '"}}}';
  Components := S8ParseManifestText(TextValue, 'package-lock.json',
    pkPackageLockJSON);
  try
    Component := S8FindModelComponent(Components, 'legacy');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 1),
      'legacy package-lock integrity was not parsed');
  finally
    Components.Free;
  end;

  TextValue := 'version = 3' + LineEnding + '[[package]]' + LineEnding +
    'name = "cargo-demo"' + LineEnding + 'version = "1.2.3"' + LineEnding +
    'checksum = "' + StringOfChar('D', 64) + '"' + LineEnding +
    '[[package]]' + LineEnding + 'name = "invalid"' + LineEnding +
    'version = "2.0.0"' + LineEnding + 'checksum = "abcd"';
  Components := S8ParseManifestText(TextValue, 'Cargo.lock', pkCargoLock);
  try
    Component := S8FindModelComponent(Components, 'cargo-demo');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 1),
      'Cargo checksum was not parsed');
    AssertEqual(StringOfChar('d', 64),
      Component.DeclaredHashes[0].Digest,
      'Cargo checksum was not canonicalized to lowercase');
    AssertEqual('cargo-demo@1.2.3', Component.DeclaredHashes[0].Subject,
      'Cargo declared-hash subject differs');
    Component := S8FindModelComponent(Components, 'invalid');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 0),
      'invalid Cargo checksum was retained');
  finally
    Components.Free;
  end;

  TextValue := '[[package]]' + LineEnding + 'name = "inline"' + LineEnding +
    'version = "1.0.0"' + LineEnding +
    'files = [{file = "inline.whl", hash = "sha256:' +
    StringOfChar('1', 64) + '"}, {hash = "sha256:' +
    StringOfChar('2', 64) + '", file = "inline.tar.gz"}]' + LineEnding +
    '[[package]]' + LineEnding + 'name = "multiline"' + LineEnding +
    'version = "2.0.0"' + LineEnding + 'files = [' + LineEnding +
    '  { file = "multi-a.whl", hash = "sha256:' +
    StringOfChar('3', 64) + '" },' + LineEnding +
    '  { file = "multi-b.tar.gz", hash = "sha256:' +
    StringOfChar('3', 64) + '" }, # same digest, distinct archive' +
    LineEnding + ']' + LineEnding;
  Components := S8ParseManifestText(TextValue, 'poetry.lock', pkPoetryLock);
  try
    Component := S8FindModelComponent(Components, 'inline');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 2),
      'inline Poetry files array was not parsed');
    Component := S8FindModelComponent(Components, 'multiline');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 2),
      'multiline Poetry files array lost archive hashes');
    AssertEqual('multi-a.whl', Component.DeclaredHashes[0].Subject,
      'first Poetry archive subject differs');
    AssertEqual('multi-b.tar.gz', Component.DeclaredHashes[1].Subject,
      'same-digest Poetry archive subject was collapsed');
  finally
    Components.Free;
  end;

  Components := S8ParseManifestText(
    'example.org/mod v1.2.3 h1:AAAA' + LineEnding,
    'go.sum', pkGoSum);
  try
    Component := S8FindModelComponent(Components, 'example.org/mod');
    AssertTrue((Component <> nil) and
      (Component.DeclaredHashes.Count = 0),
      'Go h1 dirhash was emitted as a standard declared hash');
  finally
    Components.Free;
  end;
end;

procedure TestSprint8DeclaredHashCache;
const
  RelativePath = 'poetry.lock';
var
  Artifact: TArtifact;
  Cache: TScanCache;
  Component: TComponent;
  Components: TObjectList;
  Context: TScanCacheContext;
  Diagnostic, Digest, OldProfile, Profile: string;
  Evidence: TScanCacheEvidence;
  Identity: TVerifiedFileIdentity;
begin
  AssertEqual('purpleray-file-analysis-v2', ScanAnalysisContract,
    'scan-analysis contract was not bumped for declared hashes');
  AssertEqual(2, ScanCacheFormatVersion,
    'scan-cache format was not bumped for declared hashes');

  OldProfile := NewTemporaryDirectory('sprint8-old-cache');
  WriteText(IncludeTrailingPathDelimiter(OldProfile) +
    DefaultScanCacheFileName,
    '{"format":"purpleray-scan-cache","format_version":1}');
  InitializeScanCacheContext(Context, ScanAnalysisContract, 'test-platform',
    ScanCacheProfilePathSHA256(OldProfile), StringOfChar('a', 64),
    'test-root-identity', StringOfChar('b', 64));
  Cache := TScanCache.Create(scmUse, OldProfile, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'old scan-cache format unexpectedly loaded');
    AssertEqual('', Diagnostic,
      'old scan-cache format was not treated as an ordinary miss');
  finally
    Cache.Free;
  end;

  Profile := NewTemporaryDirectory('sprint8-cache-roundtrip');
  InitializeScanCacheContext(Context, ScanAnalysisContract, 'test-platform',
    ScanCacheProfilePathSHA256(Profile), StringOfChar('c', 64),
    'test-root-identity', StringOfChar('d', 64));
  FillChar(Identity, SizeOf(Identity), 0);
  Identity.Valid := True;
  Identity.StorageID := 1;
  Identity.FileID := 2;
  Identity.Size := 123;
  Identity.ModifiedSeconds := 4;
  Identity.ModifiedNanoseconds := 5;
  Identity.ChangedSeconds := 6;
  Identity.ChangedNanoseconds := 7;
  Identity.LinkCount := 1;
  Digest := StringOfChar('e', 64);
  Artifact := TArtifact.Create;
  Components := TObjectList.Create(True);
  try
    Artifact.RelativePath := RelativePath;
    Artifact.ArtifactType := 'Poetry lock';
    Artifact.Ecosystem := 'PyPI';
    Artifact.Status := arsPartiallyParsed;
    Artifact.ParserName := 'conservative-poetry-lock';
    Artifact.FileSize := Identity.Size;
    Artifact.ComponentCount := 1;
    Component := TComponent.Create;
    Component.Name := 'cached-hash';
    Component.Version := '1.0.0';
    Component.Ecosystem := 'PyPI';
    Component.PackageURL := 'pkg:pypi/cached-hash@1.0.0';
    Component.SourceArtifact := RelativePath;
    Component.SourceParser := 'conservative-poetry-lock';
    Component.EvidencePaths.Add(RelativePath);
    S8AddDeclaredHash(Component, 'SHA-256', StringOfChar('f', 64),
      'cached_hash-1.0.0.whl', RelativePath,
      'conservative-poetry-lock');
    Components.Add(Component);
    Cache := TScanCache.Create(scmUse, Profile, Context);
    try
      AssertTrue(Cache.Stage(RelativePath, Identity, Digest, Artifact,
        Components, Diagnostic),
        'declared-hash cache stage failed: ' + Diagnostic);
      AssertTrue(Cache.Commit(Diagnostic),
        'declared-hash cache commit failed: ' + Diagnostic);
    finally
      Cache.Free;
    end;
  finally
    Components.Free;
    Artifact.Free;
  end;

  Cache := TScanCache.Create(scmUse, Profile, Context);
  try
    AssertTrue(Cache.Load(Diagnostic),
      'declared-hash cache load failed: ' + Diagnostic);
    Evidence := nil;
    AssertTrue(Cache.TryLookup(RelativePath, Identity, Digest, Evidence),
      'declared-hash cache lookup missed');
    try
      AssertTrue((Evidence <> nil) and (Evidence.Components.Count = 1),
        'declared-hash cache evidence differs');
      Component := TComponent(Evidence.Components[0]);
      AssertEqual(1, Component.DeclaredHashes.Count,
        'declared hash was lost in cache persistence');
      AssertEqual('cached_hash-1.0.0.whl',
        Component.DeclaredHashes[0].Subject,
        'cache changed declared-hash provenance');
    finally
      Evidence.Free;
    end;
  finally
    Cache.Free;
  end;
end;

procedure TestSprint8CycloneDXEvidence;
var
  AbsoluteText, ExpectedAbsolute, ExpectedProvenance, Text16, Text17,
    Value: string;
  Components, Hashes, Occurrences: TJSONArray;
  EmptyTask, Task: TScanTask;
  Evidence, Metadata, Ordinary, Primary, Root: TJSONObject;
  OrdinaryComponent, ProjectComponent: TComponent;
begin
  Task := TScanTask.Create;
  Root := nil;
  try
    Task.ID := '11111111-1111-4111-8111-111111111111';
    Task.CreatedUTC := '2026-08-21T10:00:00Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := NewTemporaryDirectory('sprint8-cdx-root');
    Task.TargetRootName := 'evidence-root';
    Task.Status := tsCompleted;
    Task.ScannerVersion := '0.0.0-test';
    Task.ScannerCommit := 'sprint8-test';

    ProjectComponent := TComponent.Create;
    ProjectComponent.Name := 'project-package';
    ProjectComponent.Version := '1.0.0';
    ProjectComponent.Ecosystem := 'npm';
    ProjectComponent.PackageURL := 'pkg:npm/project-package@1.0.0';
    ProjectComponent.ComponentType := 'application';
    ProjectComponent.DependencyScope := 'project';
    ProjectComponent.SourceArtifact := 'z/project-lock.json';
    ProjectComponent.SourceParser := 'package-lock-json';
    ProjectComponent.SHA256 := StringOfChar('f', 64);
    ProjectComponent.EvidencePaths.Add('a/project-manifest.json');
    S8AddDeclaredHash(ProjectComponent, 'SHA-256', StringOfChar('f', 64),
      'project-package@1.0.0', 'z/project-lock.json', 'package-lock-json');
    S8AddDeclaredHash(ProjectComponent, 'SHA-512', StringOfChar('e', 128),
      'project-package@1.0.0', 'z/project-lock.json', 'package-lock-json');
    Task.Components.Add(ProjectComponent);

    OrdinaryComponent := TComponent.Create;
    OrdinaryComponent.Name := 'ordinary';
    OrdinaryComponent.Version := '2.0.0';
    OrdinaryComponent.Ecosystem := 'PyPI';
    OrdinaryComponent.PackageURL := 'pkg:pypi/ordinary@2.0.0';
    OrdinaryComponent.SourceArtifact := 'c/poetry.lock';
    OrdinaryComponent.SourceParser := 'conservative-poetry-lock';
    OrdinaryComponent.EvidencePaths.Add('b/pyproject.toml');
    S8AddDeclaredHash(OrdinaryComponent, 'SHA-256', StringOfChar('a', 64),
      'ordinary-2.0.0.whl', 'c/poetry.lock',
      'conservative-poetry-lock');
    S8AddDeclaredHash(OrdinaryComponent, 'SHA-256', StringOfChar('b', 64),
      'ordinary-2.0.0.tar.gz', 'c/poetry.lock',
      'conservative-poetry-lock');
    Task.Components.Add(OrdinaryComponent);

    Text16 := GenerateCycloneDX(Task, cdxSpec16);
    Text17 := GenerateCycloneDX(Task, cdxSpec17);
    AssertEqual(string(Text16), string(GenerateCycloneDX(Task, cdxSpec16)),
      'CycloneDX 1.6 evidence output is not deterministic');
    AssertEqual(string(Text17), string(GenerateCycloneDX(Task, cdxSpec17)),
      'CycloneDX 1.7 evidence output is not deterministic');
    AssertTrue(Pos(Task.TargetDirectory, Text17) = 0,
      'default CycloneDX evidence leaked the absolute scan root');

    Root := S8ParseJSONObject(Text16);
    AssertEqual('1.6', JSONString(Root, 'specVersion'),
      'Sprint 8 evidence changed the CycloneDX 1.6 version');
    AssertEqual('https://cyclonedx.org/schema/bom-1.6.schema.json',
      JSONString(Root, '$schema'),
      'Sprint 8 evidence changed the CycloneDX 1.6 schema');
    Primary := JSONObject(JSONObject(Root, 'metadata'), 'component');
    S8AssertOccurrences(Primary, 'a/project-manifest.json',
      'z/project-lock.json');
    Root.Free;
    Root := nil;

    Root := S8ParseJSONObject(Text17);
    AssertEqual('1.7', JSONString(Root, 'specVersion'),
      'Sprint 8 evidence changed the CycloneDX 1.7 version');
    AssertEqual('https://cyclonedx.org/schema/bom-1.7.schema.json',
      JSONString(Root, '$schema'),
      'Sprint 8 evidence changed the CycloneDX 1.7 schema');
    Metadata := JSONObject(Root, 'metadata');
    Primary := JSONObject(Metadata, 'component');
    S8AssertOccurrences(Primary, 'a/project-manifest.json',
      'z/project-lock.json');
    Hashes := JSONArray(Primary, 'hashes');
    AssertTrue((Hashes <> nil) and (Hashes.Count = 2),
      'local and declared hash union differs on the promoted component');
    AssertEqual('SHA-256', JSONString(TJSONObject(Hashes.Items[0]), 'alg'),
      'promoted component hashes are not ordinal');
    AssertEqual('SHA-512', JSONString(TJSONObject(Hashes.Items[1]), 'alg'),
      'promoted component declared SHA-512 is missing');
    AssertEqual(2, S8CountProperties(Primary,
      'purpleray-sbom-analyzer:declared-hash-provenance', Value),
      'promoted declared-hash provenance count differs');
    ExpectedProvenance := '{"algorithm":"SHA-256","digest":"' +
      StringOfChar('f', 64) + '","subject":"project-package@1.0.0",' +
      '"sourceArtifact":"z/project-lock.json",' +
      '"sourceParser":"package-lock-json",' +
      '"status":"declared-not-locally-verified"}';
    AssertEqual(ExpectedProvenance, Value,
      'declared-hash provenance is not canonical compact fixed-key JSON');

    Components := JSONArray(Root, 'components');
    Ordinary := S8FindJSONComponent(Components, 'ordinary');
    AssertTrue(Ordinary <> nil, 'ordinary evidence component is missing');
    S8AssertOccurrences(Ordinary, 'b/pyproject.toml', 'c/poetry.lock');
    AssertEqual(2, S8CountProperties(Ordinary,
      'purpleray-sbom-analyzer:declared-hash-provenance', Value),
      'ordinary declared-hash provenance count differs');
    Hashes := JSONArray(Ordinary, 'hashes');
    AssertTrue((Hashes <> nil) and (Hashes.Count = 2),
      'same-algorithm Poetry archive hashes were collapsed');
    Root.Free;
    Root := nil;

    Task.Settings.IncludeAbsolutePaths := True;
    AbsoluteText := GenerateCycloneDX(Task, cdxSpec17);
    ExpectedAbsolute := ExpandFileName(IncludeTrailingPathDelimiter(
      Task.TargetDirectory) + 'z' + DirectorySeparator + 'project-lock.json');
    Root := S8ParseJSONObject(AbsoluteText);
    Primary := JSONObject(JSONObject(Root, 'metadata'), 'component');
    Evidence := JSONObject(Primary, 'evidence');
    Occurrences := JSONArray(Evidence, 'occurrences');
    AssertEqual(ExpectedAbsolute,
      JSONString(TJSONObject(Occurrences.Items[1]), 'location'),
      'absolute-path opt-in was not applied to occurrences');
    S8CountProperties(Primary,
      'purpleray-sbom-analyzer:declared-hash-provenance', Value);
    AssertTrue(Pos('"sourceArtifact":"' +
      StringReplace(ExpectedAbsolute, '\', '\\', [rfReplaceAll]) + '"',
      Value) > 0,
      'absolute-path opt-in was not applied to hash provenance');
    Root.Free;
    Root := nil;
    Task.Settings.IncludeAbsolutePaths := False;

    EmptyTask := TScanTask.Create;
    try
      EmptyTask.ID := '22222222-2222-4222-8222-222222222222';
      EmptyTask.CreatedUTC := Task.CreatedUTC;
      EmptyTask.TargetRootName := 'empty';
      Root := S8ParseJSONObject(GenerateCycloneDX(EmptyTask, cdxSpec17));
      Evidence := JSONObject(JSONObject(JSONObject(Root, 'metadata'),
        'component'), 'evidence');
      AssertTrue(Evidence = nil,
        'synthetic root received invented occurrence evidence');
      Root.Free;
      Root := nil;
    finally
      EmptyTask.Free;
    end;
  finally
    Root.Free;
    Task.Free;
  end;
end;

function TS8HugeCandidateStrings.Get(Index: Integer): string;
begin
  Result := '';
  raise Exception.Create('oversized OSV TStrings was indexed');
end;

function TS8HugeCandidateStrings.GetCount: Integer;
begin
  Result := High(Integer);
end;

procedure TS8HugeCandidateStrings.Clear;
begin
  raise Exception.Create('oversized OSV TStrings was mutated');
end;

procedure TS8HugeCandidateStrings.Delete(Index: Integer);
begin
  raise Exception.Create('oversized OSV TStrings was mutated');
end;

procedure TS8HugeCandidateStrings.Insert(Index: Integer; const S: string);
begin
  raise Exception.Create('oversized OSV TStrings was mutated');
end;

constructor TS8FakeOSVTransport.Create;
begin
  inherited Create;
  Requests := TStringList.Create;
  Responses := TStringList.Create;
end;

destructor TS8FakeOSVTransport.Destroy;
begin
  Responses.Free;
  Requests.Free;
  inherited Destroy;
end;

function TS8FakeOSVTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
begin
  Requests.Add(string(ARequestBody));
  AHTTPStatus := 200;
  AResponseBody := '';
  if FResponseIndex >= Responses.Count then
    Exit(otoFailed);
  AResponseBody := RawByteString(Responses[FResponseIndex]);
  Inc(FResponseIndex);
  Result := otoSucceeded;
end;

procedure TS8FakeOSVTransport.Cancel;
begin
  Cancelled := True;
end;

constructor TS8GeneratedOSVTransport.Create(AMode: TS8GeneratedOSVMode);
begin
  inherited Create;
  FMode := AMode;
  Requests := TStringList.Create;
end;

destructor TS8GeneratedOSVTransport.Destroy;
begin
  Requests.Free;
  inherited Destroy;
end;

function TS8GeneratedOSVTransport.QueryCount(
  const ARequestBody: RawByteString): Integer;
var
  Data, QueriesData: TJSONData;
begin
  Result := 0;
  Data := ParseStrictUTF8JSON(ARequestBody);
  try
    if Data.JSONType <> jtObject then
      Exit;
    QueriesData := TJSONObject(Data).Find('queries');
    if (QueriesData <> nil) and (QueriesData.JSONType = jtArray) then
      Result := TJSONArray(QueriesData).Count;
  finally
    Data.Free;
  end;
end;

function TS8GeneratedOSVTransport.EmptyResponse(
  AQueryCount: Integer): RawByteString;
var
  I: Integer;
begin
  Result := '{"results":[';
  for I := 0 to AQueryCount - 1 do
  begin
    if I > 0 then
      Result := Result + ',';
    Result := Result + '{}';
  end;
  Result := Result + ']}';
end;

function TS8GeneratedOSVTransport.AdvisoryOverflowResponse: RawByteString;
var
  I: Integer;
begin
  Result := '{"results":[{"vulns":[';
  for I := 0 to OSVMaximumAdvisoryIDs do
  begin
    if I > 0 then
      Result := Result + ',';
    Result := Result + Format(
      '{"id":"OSV-%d","modified":"2026-01-01T00:00:00Z"}', [I]);
  end;
  Result := Result + ']}]}';
end;

function TS8GeneratedOSVTransport.MatchOverflowResponse: RawByteString;
var
  I, QueryIndex: Integer;
begin
  Result := '{"results":[';
  for QueryIndex := 0 to 2 do
  begin
    if QueryIndex > 0 then
      Result := Result + ',';
    Result := Result + '{"vulns":[';
    if QueryIndex < 2 then
      for I := 0 to OSVMaximumAdvisoryIDs - 1 do
      begin
        if I > 0 then
          Result := Result + ',';
        Result := Result + Format(
          '{"id":"OSV-%d","modified":"2026-01-01T00:00:00Z"}', [I]);
      end
    else
      Result := Result +
        '{"id":"OSV-0","modified":"2026-01-01T00:00:00Z"}';
    Result := Result + ']}';
  end;
  Result := Result + ']}';
end;

function TS8GeneratedOSVTransport.RawDuplicateResponse(
  AQueryCount, AEntryCount: Integer): RawByteString;
var
  EntryIndex, QueryIndex: Integer;
  Stream: TStringStream;
begin
  Stream := TStringStream.Create('');
  try
    Stream.WriteString('{"results":[');
    for QueryIndex := 0 to AQueryCount - 1 do
    begin
      if QueryIndex > 0 then
        Stream.WriteString(',');
      if QueryIndex = 0 then
      begin
        Stream.WriteString('{"vulns":[');
        for EntryIndex := 0 to AEntryCount - 1 do
        begin
          if EntryIndex > 0 then
            Stream.WriteString(',');
          Stream.WriteString('{"id":"OSV-DUPLICATE","modified":' +
            '"2026-01-01T00:00:00Z"}');
        end;
        Stream.WriteString(']}');
      end
      else
        Stream.WriteString('{}');
    end;
    Stream.WriteString(']}');
    Result := RawByteString(Stream.DataString);
  finally
    Stream.Free;
  end;
end;

function TS8GeneratedOSVTransport.JSONNodeOverflowResponse: RawByteString;
var
  I: Integer;
  Stream: TStringStream;
begin
  Stream := TStringStream.Create('');
  try
    Stream.WriteString('{"results":[{"unexpected":[');
    for I := 0 to OSVMaximumResponseJSONNodes do
    begin
      if I > 0 then
        Stream.WriteString(',');
      Stream.WriteString('0');
    end;
    Stream.WriteString(']}]}');
    Result := RawByteString(Stream.DataString);
  finally
    Stream.Free;
  end;
end;

function TS8GeneratedOSVTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
var
  CountValue: Integer;
begin
  Inc(FCallCount);
  Requests.Add(string(ARequestBody));
  CountValue := QueryCount(ARequestBody);
  if CountValue > MaximumQueriesSeen then
    MaximumQueriesSeen := CountValue;
  AHTTPStatus := 200;
  AResponseBody := '';
  case FMode of
    s8gmEmpty:
      AResponseBody := EmptyResponse(CountValue);
    s8gmPagingForever:
      AResponseBody := Format(
        '{"results":[{"next_page_token":"token-%d"}]}', [FCallCount]);
    s8gmOversize:
      begin
        SetLength(AResponseBody, AMaximumResponseBytes + 1);
        FillChar(AResponseBody[1], Length(AResponseBody), Ord(' '));
      end;
    s8gmTransportOversize:
      Exit(otoResponseTooLarge);
    s8gmAggregatePadding:
      begin
        AResponseBody := Format(
          '{"results":[{"next_page_token":"aggregate-%d"}]}',
          [FCallCount]);
        AResponseBody := AResponseBody + StringOfChar(' ',
          AMaximumResponseBytes - Length(AResponseBody));
      end;
    s8gmAdvisoryOverflow:
      AResponseBody := AdvisoryOverflowResponse;
    s8gmMatchOverflow:
      AResponseBody := MatchOverflowResponse;
    s8gmRawEntryLimit:
      AResponseBody := RawDuplicateResponse(CountValue,
        OSVMaximumRawVulnerabilityEntries);
    s8gmRawEntryOverflow:
      AResponseBody := RawDuplicateResponse(CountValue,
        OSVMaximumRawVulnerabilityEntries + 1);
    s8gmJSONNodeOverflow:
      AResponseBody := JSONNodeOverflowResponse;
    s8gmCancelDuringPost:
      begin
        if Assigned(ACancelCheck) and ACancelCheck() then
          Exit(otoCancelled);
        Exit(otoFailed);
      end;
    s8gmTransportFailure:
      Exit(otoFailed);
    s8gmTransportException:
      raise Exception.Create('secret-transport-detail-must-not-leak');
    s8gmEnrichmentException:
      { A non-Exception object bypasses the transport-failure translation and
        exercises Query's outer ownership guard plus the scan service's
        non-standard-exception containment without heaptrc's special handling
        for manually constructed EOutOfMemory instances. }
      raise TObject.Create;
    s8gmHTTPFailure:
      begin
        AHTTPStatus := 503;
        AResponseBody := '{"secret":"raw-response-must-not-leak"}';
      end;
  end;
  Result := otoSucceeded;
end;

procedure TS8GeneratedOSVTransport.Cancel;
begin
  Cancelled := True;
end;

function TS8CancelProbe.Check: Boolean;
begin
  Inc(FChecks);
  Result := (CancelAt <= 0) or (FChecks >= CancelAt);
end;

function TS8TimestampPin.Check: Boolean;
begin
  if (Task <> nil) and (Task.Status = tsCompleted) then
    Task.StartedUTC := '2026-08-21T12:00:00Z';
  Result := False;
end;

procedure TS8FailingEnrichmentProgress.Update(
  const AProgress: TScanProgress);
begin
  if AProgress.CurrentRelativePath =
    'Checking known issues with OSV.dev...' then
  begin
    Inc(EnrichmentCalls);
    raise Exception.Create(
      'post-output-progress-exception-must-not-escape');
  end;
end;

procedure TS8CommittedEnrichmentFailureWorker.PerformScan;
begin
  WriteText(OutputFileName, OutputBytes);
  ResultTask.Status := tsCompleted;
  ResultTask.GeneratedSBOMPath := OutputFileName;
  ResultTask.GeneratedSBOMSHA256 := SHA256String(OutputBytes);
  raise Exception.Create(
    'optional-transport-factory-setup-failure');
end;

constructor TS8SequencingOSVTransport.Create;
begin
  inherited Create;
  Requests := TStringList.Create;
end;

destructor TS8SequencingOSVTransport.Destroy;
begin
  Requests.Free;
  inherited Destroy;
end;

function TS8SequencingOSVTransport.QueryCount(
  const ARequestBody: RawByteString): Integer;
var
  Data, QueriesData: TJSONData;
begin
  Result := 0;
  Data := ParseStrictUTF8JSON(ARequestBody);
  try
    if Data.JSONType <> jtObject then
      Exit;
    QueriesData := TJSONObject(Data).Find('queries');
    if (QueriesData <> nil) and (QueriesData.JSONType = jtArray) then
      Result := TJSONArray(QueriesData).Count;
  finally
    Data.Free;
  end;
end;

function TS8SequencingOSVTransport.EmptyResponse(
  AQueryCount: Integer): RawByteString;
var
  I: Integer;
begin
  Result := '{"results":[';
  for I := 0 to AQueryCount - 1 do
  begin
    if I > 0 then
      Result := Result + ',';
    Result := Result + '{}';
  end;
  Result := Result + ']}';
end;

function TS8SequencingOSVTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
var
  ActivatedOutputFileName, Digest, ExpectedCanonicalFileName: string;
begin
  Requests.Add(string(ARequestBody));
  ActivatedOutputFileName := '';
  ExpectedCanonicalFileName := '';
  if (Task <> nil) and FileExists(Task.GeneratedSBOMPath) and
    FileExists(ExpectedOutputFileName) then
  begin
    ActivatedOutputFileName := CanonicalPath(Task.GeneratedSBOMPath);
    ExpectedCanonicalFileName := CanonicalPath(ExpectedOutputFileName);
  end;
  { The scan service records the identity-backed path returned by its pinned
    output directory. A Windows temporary directory can reach the same file
    through a different drive-letter, junction, or 8.3 spelling, so compare
    the resolved paths rather than the caller's original text. }
  SawActivatedOutput := (ActivatedOutputFileName <> '') and
    SameFileName(ActivatedOutputFileName, ExpectedCanonicalFileName);
  SawMatchingStoredDigest := SawActivatedOutput and
    SHA256File(ActivatedOutputFileName, Digest, nil, nil) and
    (Digest = Task.GeneratedSBOMSHA256);
  SawCommittedCache := FileExists(ExpectedCacheFileName);
  if SawActivatedOutput then
    OutputBytesAtLookup := S8ReadFileBytes(ActivatedOutputFileName);
  AHTTPStatus := 200;
  AResponseBody := EmptyResponse(QueryCount(ARequestBody));
  Result := otoSucceeded;
end;

procedure TS8SequencingOSVTransport.Cancel;
begin
  Cancelled := True;
end;

procedure S8AssertCandidateRejected(const AValue: string;
  AExpected: TOSVCandidateRejectionReason);
var
  Canonical: string;
  Reason: TOSVCandidateRejectionReason;
begin
  AssertTrue(not TryCanonicalOSVPackageURL(AValue, Canonical, Reason),
    'ineligible OSV Package URL was accepted');
  AssertTrue(Reason = AExpected,
    'OSV Package URL rejection differs for code ' +
    OSVCandidateRejectionCode(AExpected));
  AssertEqual('', Canonical,
    'rejected OSV Package URL retained a canonical value');
end;

procedure TestSprint8OSVCandidatePolicy;
var
  Canonical, InvalidUTF8, RequestText: string;
  PageTokens, PURLs: TStringList;
  RaisedValue: Boolean;
  Reason: TOSVCandidateRejectionReason;
begin
  AssertEqual(2048, OSVMaximumCandidates,
    'OSV candidate cap changed');
  AssertEqual(128, OSVMaximumBatchQueries,
    'OSV batch cap changed');
  AssertEqual(32, OSVMaximumRequests,
    'OSV request cap changed');
  AssertEqual(Int64(8) * 1024 * 1024, OSVMaximumResponseBytes,
    'OSV response cap changed');
  AssertEqual(Int64(32) * 1024 * 1024,
    OSVMaximumAggregateResponseBytes,
    'OSV aggregate response cap changed');
  AssertEqual(4096, OSVMaximumAdvisoryIDs,
    'OSV advisory cap changed');
  AssertEqual(8192, OSVMaximumMatches,
    'OSV match cap changed');
  AssertEqual(8192, OSVMaximumRawVulnerabilityEntries,
    'OSV raw vulnerability-entry cap changed');
  AssertEqual(65536, OSVMaximumResponseJSONNodes,
    'OSV response JSON-node cap changed');
  AssertEqual(30000, OSVTotalTimeoutMilliseconds,
    'OSV lookup-wide timeout changed');

  AssertTrue(TryCanonicalOSVPackageURL(
    'PKG:NPM/foo%2Ebar@1%2e0%2E0', Canonical, Reason),
    'canonical OSV candidate was rejected');
  AssertEqual('pkg:npm/foo.bar@1.0.0', Canonical,
    'OSV Package URL canonicalization differs');
  AssertTrue(TryCanonicalOSVPackageURL(
    'pkg:npm/%40scope/pkg@1.0.0', Canonical, Reason),
    'encoded scoped npm Package URL was rejected');
  AssertEqual('pkg:npm/%40scope/pkg@1.0.0', Canonical,
    'scoped npm Package URL was changed');
  AssertTrue(TryCanonicalOSVPackageURL(
    'pkg:deb/debian/openssl@3.0.0', Canonical, Reason),
    'known Debian namespace was rejected');
  AssertTrue(TryCanonicalOSVPackageURL(
    'pkg:rpm/redhat/openssl@3.0.0', Canonical, Reason),
    'known RPM namespace was rejected');

  S8AssertCandidateRejected('', ocrEmpty);
  S8AssertCandidateRejected(StringOfChar('a', OSVMaximumPURLBytes + 1),
    ocrTooLong);
  InvalidUTF8 := 'pkg:npm/' + AnsiChar($C3) + AnsiChar($28) + '@1.0.0';
  S8AssertCandidateRejected(InvalidUTF8, ocrInvalidEncoding);
  S8AssertCandidateRejected('pkg:npm/foo bar@1.0.0',
    ocrWhitespaceOrControl);
  S8AssertCandidateRejected('https://example.invalid/package',
    ocrNotPackageURL);
  S8AssertCandidateRejected('pkg:/foo@1.0.0', ocrMalformedPackageURL);
  S8AssertCandidateRejected('pkg:npm/foo%ZZ@1.0.0',
    ocrMalformedPackageURL);
  S8AssertCandidateRejected('pkg:generic/foo@1.0.0',
    ocrGenericPackageURL);
  S8AssertCandidateRejected('pkg:oci/foo@1.0.0',
    ocrUnsupportedEcosystem);
  S8AssertCandidateRejected('pkg:deb/unknown/openssl@3.0.0',
    ocrUnsupportedEcosystem);
  S8AssertCandidateRejected('pkg:npm/foo@1.0.0?secret=token',
    ocrHasQualifiers);
  S8AssertCandidateRejected('pkg:npm/foo@1.0.0#private/path',
    ocrHasSubpath);
  S8AssertCandidateRejected('pkg:npm/foo', ocrUnversioned);

  PURLs := TStringList.Create;
  PageTokens := TStringList.Create;
  try
    PURLs.Add('pkg:npm/alpha@1.0.0');
    PURLs.Add('pkg:pypi/bravo@2.0.0');
    PageTokens.Add('');
    PageTokens.Add('page-two');
    RequestText := string(BuildOSVQueryBatchRequest(PURLs, PageTokens));
    AssertEqual('{"queries":[{"package":{"purl":' +
      '"pkg:npm/alpha@1.0.0"}},{"package":{"purl":' +
      '"pkg:pypi/bravo@2.0.0"},"page_token":"page-two"}]}',
      RequestText,
      'OSV request contains fields beyond package.purl and page_token');

    while PURLs.Count <= OSVMaximumBatchQueries do
      PURLs.Add('pkg:npm/package-' + IntToStr(PURLs.Count) + '@1.0.0');
    RaisedValue := False;
    try
      RequestText := string(BuildOSVQueryBatchRequest(PURLs, nil));
    except
      on E: EArgumentOutOfRangeException do
        RaisedValue := True;
    end;
    AssertTrue(RaisedValue, 'OSV request builder crossed its batch cap');

    PURLs.Clear;
    PURLs.Add('pkg:npm/alpha@1.0.0');
    PageTokens.Clear;
    PageTokens.Add(StringOfChar('x', OSVMaximumPageTokenBytes + 1));
    RaisedValue := False;
    try
      RequestText := string(BuildOSVQueryBatchRequest(PURLs, PageTokens));
    except
      on E: EArgumentException do
        RaisedValue := True;
    end;
    AssertTrue(RaisedValue,
      'OSV request builder accepted an oversized page token');
  finally
    PageTokens.Free;
    PURLs.Free;
  end;
end;

procedure TestSprint8OSVDeterminismAndPrivacy;
var
  Candidates: TStringList;
  Client: TOSVClient;
  Fake: TS8FakeOSVTransport;
  Rejection: TOSVCandidateRejection;
  ResultValue: TOSVLookupResult;
  RetainedText: string;
  Transport: IOSVTransport;
begin
  Fake := TS8FakeOSVTransport.Create;
  Transport := Fake;
  Fake.Responses.Add(
    '{"results":[{"vulns":[{"id":"OSV-Z","modified":' +
    '"2026-01-02T00:00:00Z"}],"next_page_token":"token-A"},' +
    '{"vulns":[{"id":"OSV-A","modified":' +
    '"2026-01-01T00:00:00Z"}]}]}');
  Fake.Responses.Add(
    '{"results":[{"vulns":[{"id":"OSV-B","modified":' +
    '"2026-01-03T00:00:00Z"},{"id":"OSV-Z","modified":' +
    '"2026-01-04T00:00:00Z"}]}]}');
  Client := TOSVClient.Create(Transport);
  Candidates := TStringList.Create;
  try
    Candidates.Add('pkg:npm/zed@1.0.0');
    Candidates.Add('pkg:npm/alpha@2.0.0');
    Candidates.Add('pkg:npm/alpha@2.0.0');
    Candidates.Add('pkg:npm/rejected@1.0.0?secret-token=private');
    ResultValue := Client.Query(Candidates);
    try
      AssertTrue(ResultValue.Outcome = osoSucceeded,
        ResultValue.Diagnostic);
      AssertEqual(1, ResultValue.DuplicateCandidateCount,
        'OSV candidate deduplication count differs');
      AssertEqual(1, ResultValue.RejectedCandidates.Count,
        'OSV rejection accounting differs');
      Rejection := TOSVCandidateRejection(
        ResultValue.RejectedCandidates[0]);
      AssertEqual(3, Rejection.InputIndex,
        'OSV rejection did not retain only the input index');
      AssertTrue(Rejection.Reason = ocrHasQualifiers,
        'OSV rejection reason differs');
      AssertEqual(2, ResultValue.RequestCount,
        'OSV per-query pagination did not use one subset request');
      AssertEqual('{"queries":[{"package":{"purl":' +
        '"pkg:npm/alpha@2.0.0"}},{"package":{"purl":' +
        '"pkg:npm/zed@1.0.0"}}]}', Fake.Requests[0],
        'OSV initial request order or payload privacy differs');
      AssertEqual('{"queries":[{"package":{"purl":' +
        '"pkg:npm/alpha@2.0.0"},"page_token":"token-A"}]}',
        Fake.Requests[1],
        'OSV pagination did not query only the affected package subset');
      AssertEqual('OSV-A' + LineEnding + 'OSV-B' + LineEnding +
        'OSV-Z' + LineEnding, ResultValue.AdvisoryIDs.Text,
        'OSV advisory IDs are not unique and ordinal-sorted');
      AssertEqual(3, ResultValue.Matches.Count,
        'OSV duplicate package/advisory matches were not collapsed');
      AssertEqual('pkg:npm/alpha@2.0.0',
        TOSVMatch(ResultValue.Matches[0]).PackageURL,
        'OSV matches are not Package URL ordered');
      AssertEqual('OSV-B',
        TOSVMatch(ResultValue.Matches[0]).AdvisoryID,
        'OSV matches are not advisory ordered');
      AssertEqual('2026-01-04T00:00:00Z',
        TOSVMatch(ResultValue.Matches[1]).Modified,
        'OSV duplicate match did not retain the latest modified value');
      RetainedText := ResultValue.EligibleCandidates.Text +
        ResultValue.AdvisoryIDs.Text + ResultValue.DiagnosticCode +
        ResultValue.Diagnostic;
      AssertTrue(Pos('secret-token', RetainedText) = 0,
        'rejected OSV candidate content leaked into result state');
      AssertTrue(Pos('secret-token', Fake.Requests.Text) = 0,
        'rejected OSV qualifiers leaked into a request');
    finally
      ResultValue.Free;
    end;
  finally
    Candidates.Free;
    Client.Free;
    Transport := nil;
  end;
end;

procedure TestSprint8OSVLimits;
var
  Candidates: TStringList;
  Client: TOSVClient;
  Generated: TS8GeneratedOSVTransport;
  HugeCandidates: TS8HugeCandidateStrings;
  I: Integer;
  ResultValue: TOSVLookupResult;
  Transport: IOSVTransport;

  procedure QueryGenerated(AMode: TS8GeneratedOSVMode;
    AExpected: TOSVOutcome);
  begin
    Generated := TS8GeneratedOSVTransport.Create(AMode);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = AExpected,
          'OSV limit outcome differs: ' + ResultValue.DiagnosticCode);
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;
  end;

begin
  Candidates := TStringList.Create;
  try
    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      for I := 0 to OSVMaximumCandidates do
        Candidates.Add(Format('pkg:npm/package-%d@1.0.0', [I]));
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoCandidateLimitExceeded,
          'OSV total-input candidate cap was not fail-closed');
        AssertEqual(0, ResultValue.RejectedCandidates.Count,
          'OSV over-cap input allocated rejection records');
        AssertEqual(0, Generated.Requests.Count,
          'OSV over-cap input reached the transport');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    HugeCandidates := TS8HugeCandidateStrings.Create;
    try
      ResultValue := Client.Query(HugeCandidates);
      try
        AssertTrue(ResultValue.Outcome = osoCandidateLimitExceeded,
          'OSV huge caller-owned count was not fail-closed');
        AssertEqual(0, ResultValue.RejectedCandidates.Count,
          'OSV huge count allocated rejection records');
        AssertEqual(0, Generated.Requests.Count,
          'OSV huge count reached the transport');
      finally
        ResultValue.Free;
      end;
    finally
      HugeCandidates.Free;
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    for I := 0 to OSVMaximumCandidates - 1 do
      Candidates.Add(Format('pkg:generic/rejected-%d@1.0.0', [I]));
    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoNoEligibleCandidates,
          'all-invalid bounded OSV input has the wrong outcome');
        AssertEqual(OSVMaximumCandidates,
          ResultValue.RejectedCandidates.Count,
          'bounded OSV rejection count differs');
        AssertEqual(0, Generated.Requests.Count,
          'all-invalid OSV input reached the transport');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    for I := 0 to OSVMaximumCandidates - 1 do
      Candidates.Add(Format('pkg:npm/batch-%d@1.0.0', [I]));
    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoSucceeded,
          ResultValue.Diagnostic);
        AssertEqual(OSVMaximumCandidates div OSVMaximumBatchQueries,
          ResultValue.RequestCount,
          'maximum OSV candidate set used the wrong request count');
        AssertEqual(OSVMaximumBatchQueries, Generated.MaximumQueriesSeen,
          'OSV request crossed or missed the batch boundary');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    Candidates.Add('pkg:npm/paginated@1.0.0');
    Generated := TS8GeneratedOSVTransport.Create(s8gmPagingForever);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoRequestLimitExceeded,
          'OSV request cap did not stop endless pagination');
        AssertEqual(OSVMaximumRequests, ResultValue.RequestCount,
          'OSV request cap was not exact');
        AssertEqual(OSVMaximumRequests, Generated.Requests.Count,
          'OSV transport crossed the request cap');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    Candidates.Add('pkg:pypi/capped@1.0.0');
    QueryGenerated(s8gmOversize, osoResponseLimitExceeded);
    QueryGenerated(s8gmTransportOversize, osoResponseLimitExceeded);

    Generated := TS8GeneratedOSVTransport.Create(s8gmAggregatePadding);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome =
          osoAggregateResponseLimitExceeded,
          'OSV aggregate response cap was not enforced');
        AssertEqual(5, ResultValue.RequestCount,
          'OSV aggregate cap did not reject the fifth 8 MiB response');
        AssertEqual(OSVMaximumAggregateResponseBytes,
          ResultValue.AggregateResponseBytes,
          'OSV aggregate byte accounting crossed its hard cap');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    Candidates.Add('pkg:cargo/advisories@1.0.0');
    Generated := TS8GeneratedOSVTransport.Create(s8gmAdvisoryOverflow);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoAdvisoryLimitExceeded,
          'OSV unique-advisory cap was not enforced');
        AssertEqual(0, ResultValue.AdvisoryIDs.Count,
          'overflowing OSV advisory response was partially applied');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    Candidates.Add('pkg:cargo/match-a@1.0.0');
    Candidates.Add('pkg:cargo/match-b@1.0.0');
    Candidates.Add('pkg:cargo/match-c@1.0.0');
    Generated := TS8GeneratedOSVTransport.Create(s8gmMatchOverflow);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoMatchLimitExceeded,
          'OSV candidate/advisory match cap was not enforced');
        AssertEqual(0, ResultValue.Matches.Count,
          'overflowing OSV match response was partially applied');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Candidates.Clear;
    Candidates.Add('pkg:cargo/raw-entry-cap@1.0.0');
    Generated := TS8GeneratedOSVTransport.Create(s8gmRawEntryLimit);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoSucceeded,
          'OSV exact raw-entry boundary was rejected');
        AssertEqual(1, ResultValue.AdvisoryIDs.Count,
          'OSV exact raw-entry boundary did not deduplicate advisories');
        AssertEqual(1, ResultValue.Matches.Count,
          'OSV exact raw-entry boundary did not deduplicate matches');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;
    QueryGenerated(s8gmRawEntryOverflow, osoMatchLimitExceeded);
    QueryGenerated(s8gmJSONNodeOverflow, osoMatchLimitExceeded);
  finally
    Candidates.Free;
  end;
end;

function S8QueryOneOSVResponse(const AResponse: RawByteString): TOSVOutcome;
var
  Candidates: TStringList;
  Client: TOSVClient;
  Fake: TS8FakeOSVTransport;
  ResultValue: TOSVLookupResult;
  Transport: IOSVTransport;
begin
  Fake := TS8FakeOSVTransport.Create;
  Transport := Fake;
  Fake.Responses.Add(string(AResponse));
  Client := TOSVClient.Create(Transport);
  Candidates := TStringList.Create;
  try
    Candidates.Add('pkg:maven/example/core@1.0.0');
    ResultValue := Client.Query(Candidates);
    try
      Result := ResultValue.Outcome;
    finally
      ResultValue.Free;
    end;
  finally
    Candidates.Free;
    Client.Free;
    Transport := nil;
  end;
end;

procedure TestSprint8OSVFailuresCancellationAndStrictJSON;
const
  InvalidResponses: array[0..8] of string = (
    '{"results":[]}',
    '{"results":[{"vulns":[{"id":"OSV-1"}]}]}',
    '{"results":[{}],"results":[{}]}',
    '{"results":[{}],"unexpected":true}',
    '{"results":[{"vulns":{}}]}',
    '{"results":[{"vulns":[{"id":"OSV-1","modified":1}]}]}',
    '{"results":[{"vulns":[{"id":"OSV-1","modified":' +
      '"2026-01-01T00:00:00Z","details":"secret"}]}]}',
    '[{"results":[{}]}]',
    '{"results":[{}]} {"second":true}'
  );
var
  CancelProbe: TS8CancelProbe;
  Candidates: TStringList;
  Client: TOSVClient;
  Fake: TS8FakeOSVTransport;
  Generated: TS8GeneratedOSVTransport;
  I: Integer;
  InvalidUTF8: RawByteString;
  NilRaised: Boolean;
  ResultValue: TOSVLookupResult;
  Transport: IOSVTransport;
begin
  Client := nil;
  NilRaised := False;
  try
    try
      Client := TOSVClient.Create(nil);
    except
      on E: EArgumentNilException do
        NilRaised := True;
    end;
  finally
    Client.Free;
  end;
  AssertTrue(NilRaised,
    'nil OSV transport did not fail through its constructor-safe boundary');

  for I := Low(InvalidResponses) to High(InvalidResponses) do
    AssertTrue(S8QueryOneOSVResponse(InvalidResponses[I]) =
      osoMalformedResponse,
      Format('strict OSV protocol negative %d was accepted', [I]));
  InvalidUTF8 := '{"results":[{"vulns":[{"id":"OSV-' +
    AnsiChar($C3) + AnsiChar($28) + '","modified":' +
    '"2026-01-01T00:00:00Z"}]}]}';
  AssertTrue(S8QueryOneOSVResponse(InvalidUTF8) = osoMalformedResponse,
    'OSV response with invalid UTF-8 was accepted');
  AssertTrue(S8QueryOneOSVResponse('{"results":[{' +
    '"next_page_token":"bad token"}]}') = osoMalformedResponse,
    'OSV response with a whitespace page token was accepted');

  Fake := TS8FakeOSVTransport.Create;
  Transport := Fake;
  Fake.Responses.Add('{"results":[{"next_page_token":"repeat"}]}');
  Fake.Responses.Add('{"results":[{"next_page_token":"repeat"}]}');
  Client := TOSVClient.Create(Transport);
  Candidates := TStringList.Create;
  try
    Candidates.Add('pkg:maven/example/core@1.0.0');
    ResultValue := Client.Query(Candidates);
    try
      AssertTrue(ResultValue.Outcome = osoMalformedResponse,
        'repeated OSV pagination token was accepted');
      AssertEqual(2, ResultValue.RequestCount,
        'repeated OSV pagination token was not caught on its exact page');
    finally
      ResultValue.Free;
    end;
  finally
    Candidates.Free;
    Client.Free;
    Transport := nil;
  end;

  Candidates := TStringList.Create;
  Candidates.Add('pkg:nuget/Example@1.0.0');
  try
    Generated := TS8GeneratedOSVTransport.Create(s8gmTransportFailure);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue((ResultValue.Outcome = osoTransportFailed) and
          (ResultValue.DiagnosticCode = 'transport-failed'),
          'OSV transport failure mapping differs');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmTransportException);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue(ResultValue.Outcome = osoTransportFailed,
          'OSV transport exception escaped the core boundary');
        AssertTrue(Pos('secret-transport-detail', ResultValue.Diagnostic) = 0,
          'OSV transport exception details leaked into result state');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmHTTPFailure);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      ResultValue := Client.Query(Candidates);
      try
        AssertTrue((ResultValue.Outcome = osoHTTPStatusFailed) and
          (ResultValue.HTTPStatus = 503),
          'OSV non-200 status mapping differs');
        AssertEqual('OSV returned HTTP status 503.', ResultValue.Diagnostic,
          'OSV HTTP diagnostic differs');
        AssertTrue(Pos('raw-response-must-not-leak',
          ResultValue.Diagnostic) = 0,
          'OSV HTTP response body leaked into result state');
      finally
        ResultValue.Free;
      end;
    finally
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    CancelProbe := TS8CancelProbe.Create;
    try
      CancelProbe.CancelAt := 1;
      ResultValue := Client.Query(Candidates, @CancelProbe.Check);
      try
        AssertTrue(ResultValue.Outcome = osoCancelled,
          'pre-validation OSV cancellation was ignored');
        AssertEqual(0, Generated.Requests.Count,
          'pre-validation OSV cancellation sent a request');
        AssertTrue(Generated.Cancelled,
          'pre-validation OSV cancellation did not reach the transport');
      finally
        ResultValue.Free;
      end;
    finally
      CancelProbe.Free;
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmCancelDuringPost);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    CancelProbe := TS8CancelProbe.Create;
    try
      { Candidate validation is check 1, the pre-request boundary is check 2,
        and the injected transport polls at check 3. }
      CancelProbe.CancelAt := 3;
      ResultValue := Client.Query(Candidates, @CancelProbe.Check);
      try
        AssertTrue(ResultValue.Outcome = osoCancelled,
          'mid-transport OSV cancellation was not preserved');
        AssertEqual(1, Generated.Requests.Count,
          'mid-transport OSV cancellation happened at the wrong boundary');
      finally
        ResultValue.Free;
      end;
      Client.Cancel;
      AssertTrue(Generated.Cancelled,
        'explicit OSV client cancellation did not reach the transport');
    finally
      CancelProbe.Free;
      Client.Free;
      Transport := nil;
    end;

    Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
    Transport := Generated;
    Client := TOSVClient.Create(Transport);
    try
      NilRaised := False;
      try
        ResultValue := Client.Query(nil);
        ResultValue.Free;
      except
        on E: EArgumentNilException do
          NilRaised := True;
      end;
      AssertTrue(NilRaised,
        'nil OSV candidate list did not raise EArgumentNilException');
    finally
      Client.Free;
      Transport := nil;
    end;
  finally
    Candidates.Free;
  end;
end;

procedure S8AssertKnownIssueJSONRejected(AObject: TJSONObject;
  const AMessage: string);
var
  Check: TKnownIssueCheck;
  RaisedValue: Boolean;
begin
  Check := nil;
  RaisedValue := False;
  try
    try
      Check := TKnownIssueCheck.FromJSON(AObject);
    except
      on E: Exception do
        RaisedValue := True;
    end;
  finally
    Check.Free;
  end;
  AssertTrue(RaisedValue, AMessage);
end;

procedure TestSprint8KnownIssueModelPersistence;
var
  CapCheck, Check, ClonedCheck, LoadedCheck, SanitizedCheck: TKnownIssueCheck;
  CheckJSON, InvalidJSON, OutputJSON, TaskJSON: TJSONObject;
  Data: TJSONData;
  I: Integer;
  MatchValues: TJSONArray;
  Persisted: string;
  RaisedValue: Boolean;
  Task, TaskClone, TaskLoaded, UnrequestedTask: TScanTask;
begin
  AssertEqual(OSVMaximumMatches, MaximumKnownIssueMatches,
    'known-issue match cap diverged from the OSV core');
  AssertEqual(OSVMaximumAdvisoryIDs, MaximumKnownIssueAdvisories,
    'known-issue advisory cap diverged from the OSV core');

  Check := TKnownIssueCheck.Create;
  CheckJSON := nil;
  LoadedCheck := nil;
  ClonedCheck := nil;
  try
    Check.Requested := True;
    Check.CheckedUTC := '2026-08-21T12:00:00Z';
    Check.OutcomeCode := 'ok';
    Check.HTTPStatus := 200;
    Check.RequestCount := 2;
    Check.AggregateResponseBytes := 512;
    Check.EligibleCandidateCount := 2;
    Check.RejectedCandidateCount := 1;
    Check.DuplicateCandidateCount := 1;
    AssertTrue(Check.AddMatch(S8NewKnownIssueMatch(
      'pkg:npm/zed@2.0.0', 'OSV-Z', '2026-08-20T00:00:00Z')),
      'valid known-issue match was rejected');
    AssertTrue(Check.AddMatch(S8NewKnownIssueMatch(
      'pkg:npm/alpha@1.0.0', 'OSV-A', '2026-08-19T00:00:00Z')),
      'second valid known-issue match was rejected');
    AssertTrue(not Check.AddMatch(S8NewKnownIssueMatch(
      'pkg:npm/alpha@1.0.0', 'OSV-A', '2026-08-21T00:00:00Z')),
      'duplicate package/advisory known-issue match was accepted');
    AssertEqual(2, Check.MatchCount,
      'known-issue duplicate rejection changed the match count');
    AssertEqual(2, Check.AdvisoryCount,
      'known-issue advisory deduplication differs');
    AssertEqual('pkg:npm/alpha@1.0.0', Check.Matches[0].PackageURL,
      'known-issue matches are not ordinal-sorted');
    AssertEqual(1,
      Check.MatchCountForPackageURL('pkg:npm/alpha@1.0.0'),
      'known-issue package match count differs');

    CheckJSON := Check.ToJSON;
    Persisted := CheckJSON.AsJSON;
    AssertTrue((Pos('raw_response', Persisted) = 0) and
      (Pos('page_token', Persisted) = 0) and
      (Pos('consent', Persisted) = 0) and
      (Pos('secret', Persisted) = 0),
      'known-issue persistence retained raw response, token, or consent');
    LoadedCheck := TKnownIssueCheck.FromJSON(CheckJSON);
    AssertTrue(LoadedCheck.Requested and
      (LoadedCheck.MatchCount = 2) and
      (LoadedCheck.AdvisoryCount = 2),
      'known-issue JSON round trip differs');
    ClonedCheck := Check.Clone;
    ClonedCheck.Matches[0].AdvisoryID := 'OSV-CHANGED';
    AssertEqual('OSV-A', Check.Matches[0].AdvisoryID,
      'known-issue clone aliases the source match');
  finally
    ClonedCheck.Free;
    LoadedCheck.Free;
    CheckJSON.Free;
    Check.Free;
  end;

  InvalidJSON := S8BaseKnownIssueJSON;
  try
    { Unknown privacy-sensitive fields may be read from future/untrusted
      history, but must be discarded rather than retained on reserialization. }
    InvalidJSON.Add('raw_response', 'secret-raw-response');
    InvalidJSON.Add('page_token', 'secret-page-token');
    InvalidJSON.Add('consent', 'secret-consent');
    SanitizedCheck := TKnownIssueCheck.FromJSON(InvalidJSON);
    try
      OutputJSON := SanitizedCheck.ToJSON;
      try
        Persisted := OutputJSON.AsJSON;
        AssertTrue((Pos('secret-raw-response', Persisted) = 0) and
          (Pos('secret-page-token', Persisted) = 0) and
          (Pos('secret-consent', Persisted) = 0),
          'privacy-sensitive unknown history fields were retained');
      finally
        OutputJSON.Free;
      end;
    finally
      SanitizedCheck.Free;
    end;
  finally
    InvalidJSON.Free;
  end;

  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Booleans['requested'] := False;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'unrequested persisted known-issue result was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Strings['source'] := 'untrusted.example';
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'unsupported persisted known-issue source was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Strings['request_count'] := '1';
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'string known-issue request count was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Floats['request_count'] := 1.5;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'fractional known-issue request count was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Delete('request_count');
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'missing known-issue request count was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Integers['checked_utc'] := 7;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'non-string known-issue check time was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Booleans['outcome'] := True;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'non-string known-issue outcome was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Integers['request_count'] := OSVMaximumRequests + 1;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'known-issue request count crossed its cap');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    InvalidJSON.Int64s['aggregate_response_bytes'] :=
      OSVMaximumAggregateResponseBytes + 1;
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'known-issue aggregate response bytes crossed their cap');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    MatchValues := JSONArray(InvalidJSON, 'matches');
    MatchValues.Add(S8KnownIssueMatchJSON('pkg:npm/example@1.0.0',
      'OSV-1', '2026-08-20T00:00:00Z'));
    MatchValues.Add(S8KnownIssueMatchJSON('pkg:npm/example@1.0.0',
      'OSV-1', '2026-08-21T00:00:00Z'));
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'duplicate persisted known-issue match was accepted');
  finally
    InvalidJSON.Free;
  end;
  InvalidJSON := S8BaseKnownIssueJSON;
  try
    MatchValues := JSONArray(InvalidJSON, 'matches');
    for I := 0 to MaximumKnownIssueMatches do
      MatchValues.Add(0);
    S8AssertKnownIssueJSONRejected(InvalidJSON,
      'persisted known-issue match collection crossed its cap');
  finally
    InvalidJSON.Free;
  end;

  CapCheck := TKnownIssueCheck.Create;
  try
    CapCheck.Requested := True;
    CapCheck.CheckedUTC := '2026-08-21T12:00:00Z';
    CapCheck.OutcomeCode := 'ok';
    for I := 0 to MaximumKnownIssueAdvisories - 1 do
      AssertTrue(CapCheck.AddMatch(S8NewKnownIssueMatch(
        'pkg:npm/advisory-cap@1.0.0', Format('OSV-%d', [I]),
        '2026-08-21T00:00:00Z')),
        'known-issue model rejected a match below the advisory cap');
    AssertTrue(not CapCheck.AddMatch(S8NewKnownIssueMatch(
      'pkg:npm/advisory-cap@1.0.0', 'OSV-OVER-CAP',
      '2026-08-21T00:00:00Z')),
      'known-issue model crossed the advisory cap');
    AssertEqual(MaximumKnownIssueAdvisories, CapCheck.AdvisoryCount,
      'known-issue advisory cap was not exact');

    CapCheck.RequestCount := OSVMaximumRequests + 1;
    RaisedValue := False;
    OutputJSON := nil;
    try
      try
        OutputJSON := CapCheck.ToJSON;
      except
        on E: Exception do
          RaisedValue := True;
      end;
    finally
      OutputJSON.Free;
    end;
    AssertTrue(RaisedValue,
      'known-issue serialization accepted an over-cap scalar');
  finally
    CapCheck.Free;
  end;

  UnrequestedTask := TScanTask.Create;
  try
    TaskJSON := UnrequestedTask.ToJSON;
    try
      AssertTrue(TaskJSON.Find('known_issue_check') = nil,
        'default/offline task persisted a known-issue check');
    finally
      TaskJSON.Free;
    end;
  finally
    UnrequestedTask.Free;
  end;

  Task := TScanTask.Create;
  TaskClone := nil;
  TaskLoaded := nil;
  TaskJSON := nil;
  Check := TKnownIssueCheck.Create;
  try
    Check.Requested := True;
    Check.CheckedUTC := '2026-08-21T12:00:00Z';
    Check.OutcomeCode := 'ok';
    AssertTrue(Check.AddMatch(S8NewKnownIssueMatch(
      'pkg:pypi/example@1.0.0', 'PYSEC-1',
      '2026-08-21T00:00:00Z')),
      'task known-issue fixture match was rejected');
    Task.KnownIssueCheck.Assign(Check);
    TaskJSON := Task.ToJSON;
    AssertTrue(TaskJSON.Find('known_issue_check') <> nil,
      'requested task omitted persisted known-issue state');
    TaskLoaded := TScanTask.FromJSON(TaskJSON);
    AssertEqual(1, TaskLoaded.KnownIssueCheck.MatchCount,
      'task known-issue JSON round trip differs');
    TaskClone := Task.Clone;
    TaskClone.KnownIssueCheck.Matches[0].AdvisoryID := 'PYSEC-CHANGED';
    AssertEqual('PYSEC-1', Task.KnownIssueCheck.Matches[0].AdvisoryID,
      'task clone aliases known-issue match state');
  finally
    Check.Free;
    TaskJSON.Free;
    TaskLoaded.Free;
    TaskClone.Free;
    Task.Free;
  end;

  TaskJSON := TJSONObject.Create;
  try
    TaskJSON.Add('known_issue_check', 7);
    RaisedValue := False;
    TaskLoaded := nil;
    try
      try
        TaskLoaded := TScanTask.FromJSON(TaskJSON);
      except
        on E: Exception do
          RaisedValue := True;
      end;
    finally
      TaskLoaded.Free;
    end;
    AssertTrue(RaisedValue,
      'task accepted non-object known_issue_check history state');
  finally
    TaskJSON.Free;
  end;

  TaskJSON := TJSONObject.Create;
  try
    InvalidJSON := S8BaseKnownIssueJSON;
    InvalidJSON.Strings['request_count'] := '1';
    TaskJSON.Add('known_issue_check', InvalidJSON);
    InvalidJSON := nil;
    RaisedValue := False;
    TaskLoaded := nil;
    try
      try
        TaskLoaded := TScanTask.FromJSON(TaskJSON);
      except
        on E: Exception do
          RaisedValue := True;
      end;
    finally
      TaskLoaded.Free;
    end;
    AssertTrue(RaisedValue,
      'task accepted malformed inner known_issue_check history state');
  finally
    TaskJSON.Free;
  end;

  Data := nil;
  RaisedValue := False;
  try
    try
      Data := ParseStrictUTF8JSON(
        '{"known_issue_check":{},"known_issue_check":{}}');
    except
      on E: Exception do
        RaisedValue := True;
    end;
  finally
    Data.Free;
  end;
  AssertTrue(RaisedValue,
    'strict history JSON accepted duplicate known_issue_check members');
end;

procedure TestSprint8KnownIssueOwnershipScaleAndBudget;
const
  { 2048 + (922 * 9088) = 8,381,184 bytes, 7,424 bytes below
    MaximumKnownIssueSerializedBytes. One more maximum-width match exceeds
    the boundary. }
  BoundaryMatchCount = 922;
  MaximumNameFiller = 4082;
var
  AdvisoryValue, ModifiedValue, PackageURL: string;
  BoundaryJSON, InvalidJSON: TJSONObject;
  BoundaryMatches: TJSONArray;
  Check, ClonedCheck, ScaleCheck, ScaleClone: TKnownIssueCheck;
  I: Integer;
begin
  AssertEqual(Int64(8) * 1024 * 1024,
    MaximumKnownIssueSerializedBytes,
    'known-issue serialized-size budget changed');

  { Repeated malformed objects make the formerly leaked ownership path
    visible to the checked heap-trace run without retaining any object here. }
  for I := 1 to 128 do
  begin
    InvalidJSON := S8BaseKnownIssueJSON;
    try
      BoundaryMatches := JSONArray(InvalidJSON, 'matches');
      BoundaryJSON := TJSONObject.Create;
      BoundaryJSON.Add('package_url', 'pkg:npm/malformed@1.0.0');
      BoundaryJSON.Add('advisory_id', 'OSV-MALFORMED');
      { The required modified string is intentionally absent. }
      BoundaryMatches.Add(BoundaryJSON);
      S8AssertKnownIssueJSONRejected(InvalidJSON,
        'malformed persisted match was accepted');
    finally
      InvalidJSON.Free;
    end;
  end;

  { Exercise the public match cap with compact typical values. Insertion and
    cloning at full scale protect the sorted-key implementation from a return
    to per-add full-list scans or sorts. }
  ScaleCheck := TKnownIssueCheck.Create;
  ScaleClone := nil;
  try
    ScaleCheck.Requested := True;
    ScaleCheck.CheckedUTC := '2026-08-21T12:00:00Z';
    ScaleCheck.OutcomeCode := 'ok';
    for I := 0 to MaximumKnownIssueMatches - 1 do
      AssertTrue(ScaleCheck.AddMatch(S8NewKnownIssueMatch(
        Format('pkg:npm/scale-%.4d@1', [I]), 'OSV-SCALE',
        '2026-08-21T00:00:00Z')),
        'known-issue full-scale insertion failed below the match cap');
    AssertEqual(MaximumKnownIssueMatches, ScaleCheck.MatchCount,
      'known-issue full-scale insertion count differs');
    AssertEqual(1, ScaleCheck.AdvisoryCount,
      'known-issue full-scale advisory deduplication differs');
    AssertTrue(not ScaleCheck.AddMatch(S8NewKnownIssueMatch(
      'pkg:npm/scale-overflow@1', 'OSV-SCALE',
      '2026-08-21T00:00:00Z')),
      'known-issue model crossed its match-count cap');
    ScaleClone := ScaleCheck.Clone;
    AssertEqual(MaximumKnownIssueMatches, ScaleClone.MatchCount,
      'known-issue full-scale clone lost matches');
    AssertEqual(ScaleCheck.Matches[MaximumKnownIssueMatches - 1].PackageURL,
      ScaleClone.Matches[MaximumKnownIssueMatches - 1].PackageURL,
      'known-issue full-scale clone changed deterministic order');
    ScaleClone.Matches[0].Modified := 'clone-only-change';
    AssertEqual('2026-08-21T00:00:00Z', ScaleCheck.Matches[0].Modified,
      'known-issue full-scale clone aliases source ownership');
  finally
    ScaleClone.Free;
    ScaleCheck.Free;
  end;

  Check := TKnownIssueCheck.Create;
  ClonedCheck := nil;
  BoundaryJSON := nil;
  try
    Check.Requested := True;
    Check.CheckedUTC := '2026-08-21T12:00:00Z';
    Check.OutcomeCode := 'ok';
    AdvisoryValue := StringOfChar('A', 256);
    ModifiedValue := StringOfChar('M', 128);
    for I := 0 to BoundaryMatchCount - 1 do
    begin
      PackageURL := 'pkg:npm/' + Format('%.4d', [I]) +
        StringOfChar('a', MaximumNameFiller) + '@1';
      AssertEqual(OSVMaximumPURLBytes, Length(PackageURL),
        'known-issue boundary Package URL width differs');
      AssertTrue(Check.AddMatch(S8NewKnownIssueMatch(PackageURL,
        AdvisoryValue, ModifiedValue)),
        'known-issue large insertion failed below its limits');
    end;
    AssertEqual(BoundaryMatchCount, Check.MatchCount,
      'known-issue large insertion count differs');
    AssertEqual(1, Check.AdvisoryCount,
      'known-issue large insertion advisory deduplication differs');

    BoundaryJSON := Check.ToJSON;
    AssertEqual(BoundaryMatchCount,
      JSONArray(BoundaryJSON, 'matches').Count,
      'known-issue just-under-budget result did not serialize');
    PackageURL := 'pkg:npm/' + Format('%.4d', [BoundaryMatchCount]) +
      StringOfChar('a', MaximumNameFiller) + '@1';
    JSONArray(BoundaryJSON, 'matches').Add(S8KnownIssueMatchJSON(
      PackageURL, AdvisoryValue, ModifiedValue));
    S8AssertKnownIssueJSONRejected(BoundaryJSON,
      'over-budget persisted known-issue result was accepted');
    BoundaryJSON.Free;
    BoundaryJSON := nil;

    ClonedCheck := Check.Clone;
    AssertEqual(BoundaryMatchCount, ClonedCheck.MatchCount,
      'known-issue large clone lost matches');
    AssertEqual(Check.Matches[BoundaryMatchCount - 1].PackageURL,
      ClonedCheck.Matches[BoundaryMatchCount - 1].PackageURL,
      'known-issue large clone changed deterministic order');
    ClonedCheck.Matches[0].Modified := 'clone-only-change';
    AssertEqual(ModifiedValue, Check.Matches[0].Modified,
      'known-issue large clone aliases source ownership');
    ClonedCheck.Free;
    ClonedCheck := nil;

    AssertTrue(not Check.AddMatch(S8NewKnownIssueMatch(PackageURL,
      AdvisoryValue, ModifiedValue)),
      'known-issue model crossed its serialized-size budget');
    AssertEqual(BoundaryMatchCount, Check.MatchCount,
      'known-issue over-budget rejection changed the retained match count');
  finally
    BoundaryJSON.Free;
    ClonedCheck.Free;
    Check.Free;
  end;
end;

procedure TestSprint8HistoryWriterBounds;
const
  AggregateStringBytes = 33 * 1024 * 1024;
var
  ActiveBytes, BackupBytes: RawByteString;
  BackupFileName, DirectoryName, LargeValue, WarningText: string;
  HistoryStore: TTaskHistoryStore;
  I: Integer;
  Loaded, Tasks: TObjectList;
  NodeTask, OversizeTask, SeedTask: TScanTask;
  RaisedValue: Boolean;

  procedure AssertPriorHistoryPreserved(const AContext: string);
  begin
    AssertEqual(string(ActiveBytes),
      string(S8ReadFileBytes(HistoryStore.HistoryFileName)),
      AContext + ' changed the active history bytes');
    AssertEqual(string(BackupBytes), string(S8ReadFileBytes(BackupFileName)),
      AContext + ' changed the backup history bytes');
    AssertEqual(0, S8CountHistoryTemporaryFiles(DirectoryName),
      AContext + ' left an atomic-write temporary file');
    Loaded.Clear;
    WarningText := '';
    AssertTrue(HistoryStore.Load(Loaded, WarningText),
      AContext + ' made the prior active history unreadable');
    AssertEqual('', WarningText,
      AContext + ' caused recovery instead of loading the active history');
    AssertEqual(2, Loaded.Count,
      AContext + ' changed the prior active task count');
    AssertEqual('active-first', TScanTask(Loaded[0]).TargetRootName,
      AContext + ' changed the first prior task');
    AssertEqual('active-second', TScanTask(Loaded[1]).TargetRootName,
      AContext + ' changed the second prior task');
  end;

begin
  DirectoryName := NewTemporaryDirectory('sprint8-history-writer-bounds');
  HistoryStore := TTaskHistoryStore.Create(DirectoryName);
  Tasks := TObjectList.Create(True);
  Loaded := TObjectList.Create(True);
  try
    SeedTask := TScanTask.Create;
    SeedTask.TargetRootName := 'active-first';
    SeedTask.Status := tsCompleted;
    Tasks.Add(SeedTask);
    HistoryStore.Save(Tasks);

    SeedTask := TScanTask.Create;
    SeedTask.TargetRootName := 'active-second';
    SeedTask.Status := tsCompleted;
    Tasks.Add(SeedTask);
    HistoryStore.Save(Tasks);
    BackupFileName := HistoryStore.HistoryFileName + '.bak';
    AssertTrue(FileExists(BackupFileName),
      'history writer fixture did not create its prior backup');
    ActiveBytes := S8ReadFileBytes(HistoryStore.HistoryFileName);
    BackupBytes := S8ReadFileBytes(BackupFileName);

    { Each added task is individually far below the reader byte limit, but
      their aggregate serialized history is above 64 MiB. }
    LargeValue := StringOfChar('X', AggregateStringBytes);
    for I := 1 to 2 do
    begin
      OversizeTask := TScanTask.Create;
      try
        OversizeTask.TargetRootName := 'aggregate-oversize-' + IntToStr(I);
        OversizeTask.Warnings.Add(LargeValue);
        Tasks.Add(OversizeTask);
        OversizeTask := nil;
      finally
        OversizeTask.Free;
      end;
    end;
    RaisedValue := False;
    try
      HistoryStore.Save(Tasks);
    except
      on E: EWriteError do
        RaisedValue := True;
    end;
    AssertTrue(RaisedValue,
      'history writer accepted an aggregate document above 64 MiB');
    while Tasks.Count > 2 do
      Tasks.Delete(Tasks.Count - 1);
    LargeValue := '';
    AssertPriorHistoryPreserved('oversized history rejection');

    { Empty warning strings make a compact document whose tree exceeds the
      strict reader node cap without approaching the byte cap. }
    NodeTask := TScanTask.Create;
    try
      NodeTask.TargetRootName := 'node-overflow-not-persisted';
      for I := 1 to MaximumJSONNodeCount do
        NodeTask.Warnings.Add('');
      Tasks.Add(NodeTask);
      NodeTask := nil;
    finally
      NodeTask.Free;
    end;
    RaisedValue := False;
    try
      HistoryStore.Save(Tasks);
    except
      on E: EJSONParser do
        RaisedValue := True;
    end;
    AssertTrue(RaisedValue,
      'history writer accepted a sub-64-MiB document above the node cap');
    Tasks.Delete(Tasks.Count - 1);
    AssertPriorHistoryPreserved('node-overflow history rejection');
  finally
    Loaded.Free;
    Tasks.Free;
    HistoryStore.Free;
  end;
end;

procedure S8AddOSVComponent(ATask: TScanTask; const AName,
  APackageURL: string);
var
  Component: TComponent;
begin
  Component := TComponent.Create;
  Component.Name := AName;
  Component.Version := '1.0.0';
  Component.Ecosystem := 'npm';
  Component.PackageURL := APackageURL;
  ATask.Components.Add(Component);
end;

procedure TestSprint8KnownIssueServiceOutcomes;
var
  CancelProbe: TS8CancelProbe;
  Fake: TS8FakeOSVTransport;
  Generated: TS8GeneratedOSVTransport;
  Task: TScanTask;
  Transport: IOSVTransport;
begin
  Task := TScanTask.Create;
  Fake := TS8FakeOSVTransport.Create;
  Transport := Fake;
  try
    Task.Status := tsCompleted;
    S8AddOSVComponent(Task, 'example', 'pkg:npm/example@1.0.0');
    Fake.Responses.Add('{"results":[{"vulns":[{' +
      '"id":"GHSA-TEST-0001","modified":' +
      '"2026-08-21T00:00:00Z"}]}]}');
    ExecuteKnownIssueCheck(Task, Transport, nil);
    AssertTrue(Task.Status = tsCompleted,
      'successful known-issue lookup changed completed inventory status');
    AssertTrue(Task.KnownIssueCheck.Requested and
      (Task.KnownIssueCheck.OutcomeCode = 'ok'),
      'successful known-issue outcome was not persisted');
    AssertEqual(1, Task.KnownIssueCheck.MatchCount,
      'successful known-issue match was not persisted');
    AssertEqual('GHSA-TEST-0001',
      Task.KnownIssueCheck.Matches[0].AdvisoryID,
      'successful known-issue advisory differs');
    AssertEqual(0, Task.Warnings.Count,
      'successful known-issue lookup added a warning');
  finally
    Task.Free;
    Transport := nil;
  end;

  Task := TScanTask.Create;
  Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
  Transport := Generated;
  try
    Task.Status := tsCompleted;
    S8AddOSVComponent(Task, 'generic', 'pkg:generic/example@1.0.0');
    ExecuteKnownIssueCheck(Task, Transport, nil);
    AssertTrue(Task.Status = tsCompleted,
      'no-eligible known-issue lookup changed inventory status');
    AssertEqual('no-eligible-candidates',
      Task.KnownIssueCheck.OutcomeCode,
      'no-eligible known-issue outcome differs');
    AssertEqual(0, Generated.Requests.Count,
      'no-eligible known-issue lookup reached the transport');
    AssertTrue(Pos('no eligible', LowerCase(Task.Warnings.Text)) > 0,
      'no-eligible known-issue lookup omitted its warning');
  finally
    Task.Free;
    Transport := nil;
  end;

  Task := TScanTask.Create;
  try
    Task.Status := tsCompleted;
    ExecuteKnownIssueCheck(Task, nil, nil);
    AssertTrue(Task.Status = tsCompleted,
      'nil known-issue transport changed inventory status');
    AssertEqual('transport-unavailable',
      Task.KnownIssueCheck.OutcomeCode,
      'nil known-issue transport outcome differs');
    AssertTrue(Pos('unavailable', LowerCase(Task.Warnings.Text)) > 0,
      'nil known-issue transport omitted its warning');
  finally
    Task.Free;
  end;

  Task := TScanTask.Create;
  Generated := TS8GeneratedOSVTransport.Create(s8gmTransportFailure);
  Transport := Generated;
  try
    Task.Status := tsCompleted;
    S8AddOSVComponent(Task, 'failed', 'pkg:npm/failed@1.0.0');
    ExecuteKnownIssueCheck(Task, Transport, nil);
    AssertTrue(Task.Status = tsCompleted,
      'failed known-issue transport invalidated inventory status');
    AssertEqual('transport-failed', Task.KnownIssueCheck.OutcomeCode,
      'failed known-issue transport outcome differs');
    AssertTrue(Pos('did not complete', LowerCase(Task.Warnings.Text)) > 0,
      'failed known-issue transport omitted its warning');
  finally
    Task.Free;
    Transport := nil;
  end;

  Task := TScanTask.Create;
  Generated := TS8GeneratedOSVTransport.Create(s8gmEmpty);
  Transport := Generated;
  CancelProbe := TS8CancelProbe.Create;
  try
    Task.Status := tsCompleted;
    S8AddOSVComponent(Task, 'cancelled', 'pkg:npm/cancelled@1.0.0');
    CancelProbe.CancelAt := 1;
    ExecuteKnownIssueCheck(Task, Transport, @CancelProbe.Check);
    AssertTrue(Task.Status = tsCompleted,
      'cancelled known-issue lookup invalidated inventory status');
    AssertEqual('cancelled', Task.KnownIssueCheck.OutcomeCode,
      'cancelled known-issue outcome differs');
    AssertTrue(Generated.Cancelled,
      'cancelled known-issue lookup did not reach the transport');
    AssertTrue(Pos('cancelled after the inventory SBOM was written',
      Task.Warnings.Text) > 0,
      'cancelled known-issue lookup omitted the post-output warning');
  finally
    CancelProbe.Free;
    Task.Free;
    Transport := nil;
  end;
end;

procedure S8ConfigureScanServiceTask(ATask: TScanTask;
  const ATargetDirectory: string);
begin
  ATask.ID := '33333333-3333-4333-8333-333333333333';
  ATask.CreatedUTC := '2026-08-21T12:00:00Z';
  ATask.TargetDirectory := ATargetDirectory;
  ATask.TargetRootName := 'sprint8-service-target';
  ATask.ScannerVersion := '0.0.0-test';
  ATask.ScannerCommit := 'sprint8-test';
  ATask.Settings.CalculateSHA256 := True;
  ATask.Settings.UseRescanCache := True;
end;

procedure TestSprint8KnownIssuePostOutputTransaction;
var
  CLIText, EnrichmentFailureOutput, FailureBytes, OfflineBytes, OfflineDigest,
    OnlineBytes, ProgressFailureOutput, SettingsText: string;
  CLILines: TStringList;
  EnrichmentFailureCache, OfflineCache, OfflineOutput, OnlineCache,
    OnlineOutput, OutputAliasDirectory, OutputDirectory, ProgressFailureCache,
    TargetDirectory: string;
  EnrichmentFailurePin, OfflinePin, OnlinePin,
    ProgressFailurePin: TS8TimestampPin;
  EnrichmentFailureTask, OfflineTask, OnlineTask,
    ProgressFailureTask: TScanTask;
  EnrichmentFailureTransport, OfflineTransport, OnlineTransport,
    ProgressFailureTransport: IOSVTransport;
  EnrichmentFailureFake, ProgressFailureFake: TS8GeneratedOSVTransport;
  FailingProgress: TS8FailingEnrichmentProgress;
  Sequencing: TS8SequencingOSVTransport;
  SettingsJSON: TJSONObject;
  Trap: TS8GeneratedOSVTransport;
begin
  TargetDirectory := NewTemporaryDirectory('sprint8-service-target');
  OutputDirectory := NewTemporaryDirectory('sprint8-service-output');
  OfflineCache := NewTemporaryDirectory('sprint8-offline-cache');
  OnlineCache := NewTemporaryDirectory('sprint8-online-cache');
  ProgressFailureCache := NewTemporaryDirectory(
    'sprint8-progress-failure-cache');
  EnrichmentFailureCache := NewTemporaryDirectory(
    'sprint8-enrichment-failure-cache');
  OutputAliasDirectory := IncludeTrailingPathDelimiter(OutputDirectory) +
    'path-alias';
  if not ForceDirectories(OutputAliasDirectory) then
    Fail('Unable to create the Sprint 8 output-path alias fixture');
  WriteText(IncludeTrailingPathDelimiter(TargetDirectory) + 'package.json',
    '{"name":"sprint8-service","version":"1.0.0",' +
    '"dependencies":{"left-pad":"1.3.0"}}');
  OfflineOutput := IncludeTrailingPathDelimiter(OutputDirectory) +
    'offline.cdx.json';
  OnlineOutput := IncludeTrailingPathDelimiter(OutputDirectory) +
    'online.cdx.json';
  ProgressFailureOutput := IncludeTrailingPathDelimiter(OutputDirectory) +
    'progress-failure.cdx.json';
  EnrichmentFailureOutput := IncludeTrailingPathDelimiter(OutputDirectory) +
    'enrichment-failure.cdx.json';

  OfflineTask := TScanTask.Create;
  OfflinePin := TS8TimestampPin.Create;
  Trap := TS8GeneratedOSVTransport.Create(s8gmTransportException);
  OfflineTransport := Trap;
  try
    S8ConfigureScanServiceTask(OfflineTask, TargetDirectory);
    OfflineTask.KnownIssueCheck.MarkUnavailable(
      '2026-08-20T00:00:00Z', 'transport-unavailable',
      'Stale prior per-scan state.');
    OfflinePin.Task := OfflineTask;
    AssertTrue(ExecuteScanToFile(OfflineTask, OfflineOutput,
      @OfflinePin.Check, nil, sopRequireOutsideTarget, OfflineCache,
      False, OfflineTransport),
      'offline scan-service inventory failed');
    AssertTrue(OfflineTask.Status = tsCompleted,
      'offline scan-service inventory did not complete');
    AssertTrue(not OfflineTask.KnownIssueCheck.Requested,
      'offline scan-service path persisted a known-issue check');
    AssertEqual(0, Trap.Requests.Count,
      'offline scan-service path invoked its injected transport');
    OfflineBytes := string(S8ReadFileBytes(OfflineOutput));
    OfflineDigest := OfflineTask.GeneratedSBOMSHA256;
    SettingsJSON := OfflineTask.Settings.ToJSON;
    try
      SettingsText := SettingsJSON.AsJSON;
      AssertTrue((Pos('known_issue', SettingsText) = 0) and
        (Pos('consent', SettingsText) = 0),
        'per-scan online choice leaked into persisted scan settings');
    finally
      SettingsJSON.Free;
    end;
  finally
    OfflinePin.Free;
    OfflineTask.Free;
    OfflineTransport := nil;
  end;

  OnlineTask := TScanTask.Create;
  OnlinePin := TS8TimestampPin.Create;
  Sequencing := TS8SequencingOSVTransport.Create;
  OnlineTransport := Sequencing;
  try
    S8ConfigureScanServiceTask(OnlineTask, TargetDirectory);
    OnlinePin.Task := OnlineTask;
    Sequencing.Task := OnlineTask;
    { Keep a textually different path to the same output. This makes the
      Windows pinned-handle spelling regression deterministic on every host. }
    Sequencing.ExpectedOutputFileName := IncludeTrailingPathDelimiter(
      OutputAliasDirectory) + '..' + DirectorySeparator +
      ExtractFileName(OnlineOutput);
    Sequencing.ExpectedCacheFileName := IncludeTrailingPathDelimiter(
      OnlineCache) + DefaultScanCacheFileName;
    AssertTrue(ExecuteScanToFile(OnlineTask, OnlineOutput,
      @OnlinePin.Check, nil, sopRequireOutsideTarget, OnlineCache,
      True, OnlineTransport),
      'online-enriched scan-service inventory failed');
    AssertTrue(OnlineTask.Status = tsCompleted,
      'online enrichment changed the completed inventory status');
    AssertTrue(OnlineTask.KnownIssueCheck.Requested and
      (OnlineTask.KnownIssueCheck.OutcomeCode = 'ok'),
      'online scan-service result was not persisted');
    AssertTrue(Sequencing.SawActivatedOutput,
      'OSV transport ran before atomic SBOM activation');
    AssertTrue(Sequencing.SawMatchingStoredDigest,
      'OSV transport ran before the managed SBOM digest was stored');
    AssertTrue(Sequencing.SawCommittedCache,
      'OSV transport ran before the rescan cache committed');
    AssertTrue(Sequencing.Requests.Count > 0,
      'online scan-service path did not reach the injected transport');
    OnlineBytes := string(S8ReadFileBytes(OnlineOutput));
    AssertEqual(string(Sequencing.OutputBytesAtLookup), OnlineBytes,
      'online lookup mutated the already-activated SBOM bytes');
    AssertEqual(OfflineBytes, OnlineBytes,
      'inventory SBOM bytes differ between offline and online opt-in');
    AssertEqual(OfflineDigest, OnlineTask.GeneratedSBOMSHA256,
      'inventory SBOM digest differs between offline and online opt-in');
  finally
    OnlinePin.Free;
    OnlineTask.Free;
    OnlineTransport := nil;
  end;

  ProgressFailureTask := TScanTask.Create;
  ProgressFailurePin := TS8TimestampPin.Create;
  FailingProgress := TS8FailingEnrichmentProgress.Create;
  ProgressFailureFake := TS8GeneratedOSVTransport.Create(s8gmEmpty);
  ProgressFailureTransport := ProgressFailureFake;
  try
    S8ConfigureScanServiceTask(ProgressFailureTask, TargetDirectory);
    ProgressFailurePin.Task := ProgressFailureTask;
    AssertTrue(ExecuteScanToFile(ProgressFailureTask,
      ProgressFailureOutput, @ProgressFailurePin.Check,
      @FailingProgress.Update, sopRequireOutsideTarget,
      ProgressFailureCache, True, ProgressFailureTransport),
      'post-output progress failure invalidated the scan result');
    AssertTrue(ProgressFailureTask.Status = tsCompleted,
      'post-output progress failure changed completed inventory status');
    AssertEqual(1, FailingProgress.EnrichmentCalls,
      'post-output enrichment progress boundary was not invoked once');
    AssertEqual(0, ProgressFailureFake.Requests.Count,
      'OSV transport ran after its enrichment progress callback failed');
    AssertTrue(ProgressFailureTask.KnownIssueCheck.Requested and
      (ProgressFailureTask.KnownIssueCheck.OutcomeCode = 'lookup-failed'),
      'post-output progress failure did not record a bounded outcome');
    FailureBytes := string(S8ReadFileBytes(ProgressFailureOutput));
    AssertEqual(OfflineBytes, FailureBytes,
      'post-output progress failure changed committed SBOM bytes');
    AssertEqual(OfflineDigest,
      ProgressFailureTask.GeneratedSBOMSHA256,
      'post-output progress failure changed the committed digest');
  finally
    FailingProgress.Free;
    ProgressFailurePin.Free;
    ProgressFailureTask.Free;
    ProgressFailureTransport := nil;
  end;

  EnrichmentFailureTask := TScanTask.Create;
  EnrichmentFailurePin := TS8TimestampPin.Create;
  EnrichmentFailureFake := TS8GeneratedOSVTransport.Create(
    s8gmEnrichmentException);
  EnrichmentFailureTransport := EnrichmentFailureFake;
  try
    S8ConfigureScanServiceTask(EnrichmentFailureTask, TargetDirectory);
    EnrichmentFailurePin.Task := EnrichmentFailureTask;
    AssertTrue(ExecuteScanToFile(EnrichmentFailureTask,
      EnrichmentFailureOutput, @EnrichmentFailurePin.Check, nil,
      sopRequireOutsideTarget, EnrichmentFailureCache, True,
      EnrichmentFailureTransport),
      'post-output enrichment exception invalidated the scan result');
    AssertTrue(EnrichmentFailureTask.Status = tsCompleted,
      'post-output enrichment exception changed completed inventory status');
    AssertEqual(1, EnrichmentFailureFake.Requests.Count,
      'post-output enrichment exception occurred outside the request seam');
    AssertTrue(EnrichmentFailureTask.KnownIssueCheck.Requested and
      (EnrichmentFailureTask.KnownIssueCheck.OutcomeCode = 'lookup-failed'),
      'post-output enrichment exception did not record a bounded outcome');
    AssertTrue(Pos('post-output-enrichment-exception',
      EnrichmentFailureTask.KnownIssueCheck.Diagnostic) = 0,
      'post-output enrichment exception detail leaked into persistence');
    FailureBytes := string(S8ReadFileBytes(EnrichmentFailureOutput));
    AssertEqual(OfflineBytes, FailureBytes,
      'post-output enrichment exception changed committed SBOM bytes');
    AssertEqual(OfflineDigest,
      EnrichmentFailureTask.GeneratedSBOMSHA256,
      'post-output enrichment exception changed the committed digest');
  finally
    EnrichmentFailurePin.Free;
    EnrichmentFailureTask.Free;
    EnrichmentFailureTransport := nil;
  end;

  CLILines := TStringList.Create;
  try
    CLILines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uCommandLine.pas');
    CLIText := CLILines.Text;
    AssertTrue(Pos('ExecuteScanToFile(Task, OutputPath, nil, nil)',
      CLIText) > 0,
      'headless CLI no longer uses the offline-default service call');
    AssertTrue(Pos('Headless scans are offline', CLIText) > 0,
      'headless CLI no longer discloses its offline contract');
    AssertTrue(Pos('CreateProductionOSVTransport', CLIText) = 0,
      'headless CLI gained an online transport path');
  finally
    CLILines.Free;
  end;
end;

procedure TestSprint8WorkerCommittedEnrichmentFailure;
var
  ConstructionTask: TScanTask;
  Deadline: QWord;
  GuardText, OutputDirectory, OutputFileName, WorkerSource: string;
  GuardEnd, GuardStart: SizeInt;
  NilRaised: Boolean;
  Observer: TCompletionObserver;
  SourceTask: TScanTask;
  UnstartedObserver: TCompletionObserver;
  UnstartedWorker: TScanWorker;
  Worker: TS8CommittedEnrichmentFailureWorker;
  WorkerLines: TStringList;
begin
  OutputDirectory := NewTemporaryDirectory(
    'sprint8-worker-committed-enrichment');
  OutputFileName := IncludeTrailingPathDelimiter(OutputDirectory) +
    'committed.cdx.json';

  UnstartedWorker := nil;
  NilRaised := False;
  try
    try
      UnstartedWorker := TScanWorker.Create(nil, OutputDirectory);
    except
      on E: EArgumentNilException do
        NilRaised := True;
    end;
  finally
    UnstartedWorker.Free;
  end;
  AssertTrue(NilRaised,
    'nil scan-worker construction did not fail through a safe destructor');

  ConstructionTask := TScanTask.Create;
  UnstartedObserver := nil;
  UnstartedWorker := nil;
  try
    UnstartedObserver := TCompletionObserver.Create;
    UnstartedWorker := TScanWorker.Create(ConstructionTask, OutputDirectory);
    UnstartedWorker.OnComplete := @UnstartedObserver.Complete;
    UnstartedWorker.Free;
    UnstartedWorker := nil;
    CheckSynchronize(10);
    AssertEqual(0, UnstartedObserver.Count,
      'freeing an unstarted scan worker queued a completion callback');
  finally
    UnstartedWorker.Free;
    UnstartedObserver.Free;
    ConstructionTask.Free;
  end;

  SourceTask := TScanTask.Create;
  Observer := TCompletionObserver.Create;
  Worker := TS8CommittedEnrichmentFailureWorker.Create(SourceTask,
    OutputDirectory, True);
  try
    Worker.OutputFileName := OutputFileName;
    Worker.OutputBytes := '{"committedInventory":true}';
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
      'committed-enrichment worker completion was not delivered once');
    AssertTrue((Observer.Status = tsCompleted) and
      (Worker.ResultTask.Status = tsCompleted),
      'worker relabeled a committed inventory after enrichment failure');
    AssertEqual(OutputFileName, Worker.ResultTask.GeneratedSBOMPath,
      'worker discarded the committed inventory path');
    AssertEqual(SHA256String(Worker.OutputBytes),
      Worker.ResultTask.GeneratedSBOMSHA256,
      'worker discarded the committed inventory digest');
    AssertEqual(string(Worker.OutputBytes),
      string(S8ReadFileBytes(OutputFileName)),
      'worker changed committed inventory bytes after enrichment failure');
    AssertTrue(Pos('A post-inventory operation did not complete.',
      Worker.ResultTask.Warnings.Text) > 0,
      'worker omitted its bounded post-inventory warning');
    AssertTrue(Pos('optional-transport-factory-setup-failure',
      Worker.ResultTask.Errors.Text) = 0,
      'worker persisted an online-only factory exception as inventory error');
  finally
    Worker.Free;
    Observer.Free;
    SourceTask.Free;
  end;

  WorkerLines := TStringList.Create;
  try
    WorkerLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanWorker.pas');
    WorkerSource := WorkerLines.Text;
    GuardStart := Pos('if FCheckKnownIssues then', WorkerSource);
    if GuardStart > 0 then
    begin
      GuardText := Copy(WorkerSource, GuardStart,
        Length(WorkerSource) - GuardStart + 1);
      GuardEnd := Pos('EnterCriticalSection(FProgressLock)', GuardText);
      if GuardEnd > 0 then
        Delete(GuardText, GuardEnd, Length(GuardText) - GuardEnd + 1)
      else
        GuardText := '';
    end
    else
      GuardText := '';
    AssertTrue((Pos('if FCheckKnownIssues then', WorkerSource) > 0) and
      (Pos('Transport := CreateProductionOSVTransport', GuardText) > 0) and
      (Pos('on EOutOfMemory do', GuardText) > 0) and
      (CountTextOccurrences(GuardText, 'Transport := nil;') = 2) and
      (Pos('if InventoryWasCommitted then', WorkerSource) > 0),
      'worker transport creation no longer converts allocation failure to ' +
      'nil or guards committed inventory');
  finally
    WorkerLines.Free;
  end;
end;

procedure TestSprint8BSIReadinessContract;
const
  RichTaskIDUpper = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA';
  RichTaskIDLower = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  OtherTaskID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  PrimaryReference =
    'file:///home/private/SECRET-ABSOLUTE-PATH/root.bin';
  AlphaReference = 'pkg:npm/alpha@1.0.0';
  ZetaReference = 'src/SECRET-RELATIVE-PATH/zeta.js';
var
  Advisories, Blockers, Components, DocumentFields, Fields: TJSONArray;
  AlteredBytes, MinimalBytes, RichBytes: RawByteString;
  AlteredDigest, MinimalDigest, RichDigest: string;
  AlteredReport, MinimalReport, MinimalReportAgain, OtherTaskReport,
    RichReport, RichReportAgain: UTF8String;
  AlteredRoot, ClaimValue, MinimalRoot, OtherTaskRoot, PrivacyValue,
    RichRoot, SourceValue, SummaryValue, TargetValue: TJSONObject;
  I: Integer;
  MinimalSummary, OtherTaskSummary, RichSummary,
    SecondSummary: TBSIReadinessSummary;
begin
  AssertEqual('purpleray-bsi-tr-03183-2-readiness',
    BSIReadinessReportFormat, 'BSI report discriminator changed');
  AssertEqual(1, BSIReadinessReportFormatVersion,
    'BSI report schema version changed');
  AssertEqual('.bsi-tr-03183-2-v2.1.0-readiness.json',
    BSIReadinessSuggestedExtension,
    'BSI readiness suggested extension changed');
  AssertEqual('blocked', BSIReadinessStatusToString(brsBlocked),
    'BSI blocked status spelling changed');
  AssertEqual('review-required',
    BSIReadinessStatusToString(brsReviewRequired),
    'BSI review-required status spelling changed');

  RichBytes := S8BSIRichFixture;
  RichDigest := SHA256String(RichBytes);
  RichReport := GenerateBSIReadinessReport(RichBytes,
    UpperCase(RichDigest), RichTaskIDUpper, RichSummary);
  RichReportAgain := GenerateBSIReadinessReport(RichBytes,
    RichDigest, RichTaskIDLower, SecondSummary);
  AssertEqual(string(RichReport), string(RichReportAgain),
    'rich BSI readiness output is not deterministic');
  AssertEqual(RichSummary.ComponentsAssessed,
    SecondSummary.ComponentsAssessed,
    'rich BSI deterministic summary differs');

  RichRoot := S8ParseJSONObject(RichReport);
  try
    S8AssertBSIClosedSchema(RichRoot);
    S8AssertBSICounters(RichRoot, RichSummary);

    AssertEqual(BSIReadinessReportFormat, JSONString(RichRoot, 'format'),
      'rich BSI report format differs');
    AssertEqual(BSIReadinessReportFormatVersion,
      JSONInt64(RichRoot, 'formatVersion'),
      'rich BSI report schema version differs');
    TargetValue := JSONObject(RichRoot, 'target');
    AssertEqual('BSI TR-03183-2', JSONString(TargetValue, 'guideline'),
      'BSI guideline binding differs');
    AssertEqual('2.1.0', JSONString(TargetValue, 'guidelineVersion'),
      'BSI guideline version binding differs');
    AssertEqual('2025-08-20', JSONString(TargetValue, 'guidelineDate'),
      'BSI guideline date binding differs');
    AssertEqual(
      'dda0ccd9b6148571d1d12241a1618b30027f22bc15e24248fdd21a011e62845c',
      JSONString(TargetValue, 'guidelinePdfSha256'),
      'BSI guideline digest binding differs');
    AssertEqual('1.6', JSONString(TargetValue, 'cycloneDxMinimum'),
      'BSI CycloneDX minimum binding differs');
    AssertEqual('0.1.2', JSONString(TargetValue, 'taxonomyVersion'),
      'BSI taxonomy version binding differs');
    AssertEqual('f4c887cae2f46ec284e52ea0a86407bcffaecb91',
      JSONString(TargetValue, 'taxonomyCommit'),
      'BSI taxonomy commit binding differs');

    ClaimValue := JSONObject(RichRoot, 'claim');
    AssertEqual('readiness-assessment', JSONString(ClaimValue, 'kind'),
      'BSI report claim kind differs');
    AssertTrue(not JSONBoolean(ClaimValue, 'complianceClaimed', True),
      'BSI readiness output claims compliance');
    AssertEqual('This is a deterministic field-availability assessment, ' +
      'not a statement of conformity or certification.',
      JSONString(ClaimValue, 'text'),
      'BSI non-conformity claim text differs');
    AssertTrue((Pos('"status": "pass"',
      LowerCase(string(RichReport))) = 0) and
      (Pos('"status": "compliant"',
      LowerCase(string(RichReport))) = 0) and
      (Pos('"complianceclaimed": true',
      LowerCase(string(RichReport))) = 0) and
      (Pos('compliant', LowerCase(string(RichReport))) = 0),
      'BSI readiness output gained compliance/pass wording');

    SourceValue := JSONObject(RichRoot, 'source');
    AssertEqual(RichTaskIDLower, JSONString(SourceValue, 'taskId'),
      'BSI report did not normalize and bind the exact task ID');
    AssertEqual(RichDigest,
      JSONString(SourceValue, 'managedSbomSha256'),
      'BSI report did not bind the exact managed-SBOM digest');
    AssertEqual('CycloneDX', JSONString(SourceValue, 'bomFormat'),
      'BSI source format differs');
    AssertEqual('1.7', JSONString(SourceValue, 'specVersion'),
      'BSI source version differs');
    AssertEqual('not-performed',
      JSONString(SourceValue, 'sourceSchemaValidation'),
      'BSI source schema-validation disclosure differs');

    PrivacyValue := JSONObject(RichRoot, 'privacy');
    AssertEqual('shareable-minimal', JSONString(PrivacyValue, 'profile'),
      'BSI privacy profile differs');
    AssertTrue(not JSONBoolean(PrivacyValue, 'absolutePathsIncluded', True),
      'BSI report declares absolute paths included');
    AssertTrue(not JSONBoolean(PrivacyValue, 'relativePathsIncluded', True),
      'BSI report declares relative paths included');
    AssertTrue(not JSONBoolean(PrivacyValue, 'contactValuesIncluded', True),
      'BSI report declares contacts included');
    AssertTrue(not JSONBoolean(PrivacyValue, 'diagnosticsIncluded', True),
      'BSI report declares diagnostics included');
    AssertTrue(not JSONBoolean(PrivacyValue,
      'dynamicSecurityFindingsIncluded', True),
      'BSI report declares dynamic security findings included');
    AssertTrue((Pos('secret-', LowerCase(string(RichReport))) = 0) and
      (Pos('known_issue_check', LowerCase(string(RichReport))) = 0) and
      (Pos('ghsa-secret', LowerCase(string(RichReport))) = 0) and
      (Pos('/home/private/', LowerCase(string(RichReport))) = 0) and
      (Pos('src/secret-relative', LowerCase(string(RichReport))) = 0),
      'BSI privacy whitelist leaked a path, contact, diagnostic, known-issue, ' +
      'or security-finding value');

    SummaryValue := JSONObject(RichRoot, 'summary');
    AssertTrue(RichSummary.Status = brsBlocked,
      'rich BSI fixture did not remain honestly blocked');
    AssertEqual(3, RichSummary.ComponentsAssessed,
      'rich BSI component count differs');
    AssertEqual(59, RichSummary.Mapped,
      'rich BSI mapped count differs');
    AssertEqual(0, RichSummary.Derivable,
      'rich BSI derivable count differs');
    AssertEqual(0, RichSummary.NotApplicable,
      'rich BSI not-applicable count differs');
    AssertEqual(0, RichSummary.NotObserved,
      'rich BSI not-observed count differs');
    AssertEqual(5, RichSummary.Blocked,
      'rich BSI blocker count differs');
    AssertEqual(3, RichSummary.AdvisoryCount,
      'rich BSI advisory count differs');
    AssertEqual('blocked', JSONString(SummaryValue, 'status'),
      'rich BSI serialized status differs');

    DocumentFields := JSONArray(RichRoot, 'documentFields');
    AssertEqual(7, DocumentFields.Count,
      'BSI document-field count differs');
    AssertEqual('sbom.format',
      JSONString(TJSONObject(DocumentFields.Items[0]), 'field'),
      'BSI document-field order differs at format');
    AssertEqual('sbom.vulnerabilityInformation',
      JSONString(TJSONObject(DocumentFields.Items[1]), 'field'),
      'BSI document-field order differs at vulnerability information');
    AssertEqual('sbom.creator',
      JSONString(TJSONObject(DocumentFields.Items[2]), 'field'),
      'BSI document-field order differs at creator');
    AssertEqual('sbom.timestamp',
      JSONString(TJSONObject(DocumentFields.Items[3]), 'field'),
      'BSI document-field order differs at timestamp');
    AssertEqual('sbom.uri',
      JSONString(TJSONObject(DocumentFields.Items[4]), 'field'),
      'BSI document-field order differs at URI');
    AssertEqual('sbom.dependencies',
      JSONString(TJSONObject(DocumentFields.Items[5]), 'field'),
      'BSI document-field order differs at dependencies');
    AssertEqual('sbom.buildEquivalence',
      JSONString(TJSONObject(DocumentFields.Items[6]), 'field'),
      'BSI document-field order differs at build equivalence');

    Components := JSONArray(RichRoot, 'components');
    AssertEqual(3, Components.Count,
      'BSI rich component assessment count differs');
    AssertEqual('sha256:' + SHA256String(RawByteString(PrimaryReference)),
      JSONString(TJSONObject(Components.Items[0]), 'componentId'),
      'BSI primary component binding/order differs');
    AssertEqual('primary',
      JSONString(TJSONObject(Components.Items[0]), 'role'),
      'BSI primary component role differs');
    AssertEqual('sha256:' + SHA256String(RawByteString(AlphaReference)),
      JSONString(TJSONObject(Components.Items[1]), 'componentId'),
      'BSI ordinary component ordering differs at alpha');
    AssertEqual('sha256:' + SHA256String(RawByteString(ZetaReference)),
      JSONString(TJSONObject(Components.Items[2]), 'componentId'),
      'BSI ordinary component ordering differs at zeta');
    for I := 0 to Components.Count - 1 do
    begin
      Fields := JSONArray(TJSONObject(Components.Items[I]), 'fields');
      AssertEqual(18, Fields.Count,
        'BSI component field count differs');
      AssertEqual('component.creator',
        JSONString(TJSONObject(Fields.Items[0]), 'field'),
        'BSI component field order differs at creator');
      AssertEqual('component.name',
        JSONString(TJSONObject(Fields.Items[1]), 'field'),
        'BSI component field order differs at name');
      AssertEqual('component.referencedBom',
        JSONString(TJSONObject(Fields.Items[17]), 'field'),
        'BSI component field order differs at referenced BOM');
    end;

    Blockers := JSONArray(RichRoot, 'blockers');
    AssertEqual(5, Blockers.Count,
      'BSI rich blocker collection differs');
    AssertEqual('BSI210-D002-VULNERABILITY-INFORMATION-PRESENT',
      JSONString(TJSONObject(Blockers.Items[0]), 'code'),
      'BSI blocker order differs at security information');
    AssertEqual('BSI210-D006-BUILD-EQUIVALENCE-UNPROVEN',
      JSONString(TJSONObject(Blockers.Items[1]), 'code'),
      'BSI blocker order differs at build equivalence');
    for I := 2 to 4 do
      AssertEqual('BSI210-C002-DESCRIPTION-LEVEL-UNKNOWN',
        JSONString(TJSONObject(Blockers.Items[I]), 'code'),
        'BSI component blocker order differs');

    Advisories := JSONArray(RichRoot, 'advisories');
    AssertEqual(3, Advisories.Count,
      'BSI advisory count differs');
    AssertEqual('BSI210-A001-SOURCE-SCHEMA-NOT-VALIDATED',
      JSONString(TJSONObject(Advisories.Items[0]), 'code'),
      'BSI advisory order differs at schema validation');
    AssertEqual('BSI210-A002-EFFECTIVE-LICENCE-SPELLING-CONFLICT',
      JSONString(TJSONObject(Advisories.Items[1]), 'code'),
      'BSI advisory order differs at licence spelling');
    AssertEqual('BSI210-A003-TARGET-CURRENTNESS-NOT-ASSERTED',
      JSONString(TJSONObject(Advisories.Items[2]), 'code'),
      'BSI advisory order differs at target currentness');
  finally
    RichRoot.Free;
  end;

  OtherTaskReport := GenerateBSIReadinessReport(RichBytes, RichDigest,
    OtherTaskID, OtherTaskSummary);
  AssertTrue(OtherTaskReport <> RichReport,
    'BSI output is not bound to the supplied task ID');
  OtherTaskRoot := S8ParseJSONObject(OtherTaskReport);
  try
    AssertEqual(OtherTaskID,
      JSONString(JSONObject(OtherTaskRoot, 'source'), 'taskId'),
      'BSI alternate task binding differs');
    AssertEqual(RichDigest,
      JSONString(JSONObject(OtherTaskRoot, 'source'),
      'managedSbomSha256'),
      'BSI alternate task changed the source digest binding');
  finally
    OtherTaskRoot.Free;
  end;

  AlteredBytes := RichBytes + LineEnding;
  AlteredDigest := SHA256String(AlteredBytes);
  AlteredReport := GenerateBSIReadinessReport(AlteredBytes, AlteredDigest,
    RichTaskIDLower, SecondSummary);
  AssertTrue(AlteredReport <> RichReport,
    'BSI output is not bound to exact managed-SBOM bytes');
  AlteredRoot := S8ParseJSONObject(AlteredReport);
  try
    AssertEqual(AlteredDigest,
      JSONString(JSONObject(AlteredRoot, 'source'), 'managedSbomSha256'),
      'BSI altered-byte digest binding differs');
  finally
    AlteredRoot.Free;
  end;

  MinimalBytes := '{}';
  MinimalDigest := SHA256String(MinimalBytes);
  MinimalReport := GenerateBSIReadinessReport(MinimalBytes, MinimalDigest,
    RichTaskIDLower, MinimalSummary);
  MinimalReportAgain := GenerateBSIReadinessReport(MinimalBytes,
    MinimalDigest, RichTaskIDLower, SecondSummary);
  AssertEqual(string(MinimalReport), string(MinimalReportAgain),
    'minimal BSI readiness output is not deterministic');
  MinimalRoot := S8ParseJSONObject(MinimalReport);
  try
    S8AssertBSIClosedSchema(MinimalRoot);
    S8AssertBSICounters(MinimalRoot, MinimalSummary);
    AssertTrue(MinimalSummary.Status = brsBlocked,
      'minimal BSI fixture did not fail closed');
    AssertEqual(1, MinimalSummary.ComponentsAssessed,
      'minimal BSI component count differs');
    AssertEqual(1, MinimalSummary.Mapped,
      'minimal BSI mapped count differs');
    AssertEqual(1, MinimalSummary.Derivable,
      'minimal BSI derivable count differs');
    AssertEqual(0, MinimalSummary.NotApplicable,
      'minimal BSI not-applicable count differs');
    AssertEqual(4, MinimalSummary.NotObserved,
      'minimal BSI not-observed count differs');
    AssertEqual(21, MinimalSummary.Blocked,
      'minimal BSI blocker count differs');
    AssertEqual(3, MinimalSummary.AdvisoryCount,
      'minimal BSI advisory count differs');
    SourceValue := JSONObject(MinimalRoot, 'source');
    AssertEqual('unrecognized', JSONString(SourceValue, 'bomFormat'),
      'minimal BSI source format did not fail closed');
    AssertEqual('unrecognized', JSONString(SourceValue, 'specVersion'),
      'minimal BSI source version did not fail closed');
    Components := JSONArray(MinimalRoot, 'components');
    AssertEqual('sha256:' + SHA256String(RawByteString(
      'missing-bom-ref'#0 + RichTaskIDLower + #0'primary'#0'0')),
      JSONString(TJSONObject(Components.Items[0]), 'componentId'),
      'minimal BSI missing-reference component is not task-bound');
  finally
    MinimalRoot.Free;
  end;
end;

procedure TestSprint8BSIInputErrors;
const
  TaskID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  ErrorTaskID = 'BSI210-E001-SOURCE-TASK-ID-INVALID';
  ErrorSourceSize = 'BSI210-E002-SOURCE-SIZE-INVALID';
  ErrorExpectedHash = 'BSI210-E003-SOURCE-HASH-MISSING';
  ErrorHashMismatch = 'BSI210-E004-SOURCE-HASH-MISMATCH';
  ErrorJSON = 'BSI210-E005-SOURCE-JSON-INVALID';
var
  Bytes, InvalidUTF8, Oversize: RawByteString;
  Digest: string;
begin
  Bytes := '{"bomFormat":"CycloneDX","specVersion":"1.7"}';
  Digest := SHA256String(Bytes);
  S8AssertBSIError(Bytes, Digest, '{' + TaskID + '}', ErrorTaskID,
    'non-canonical BSI task ID');
  S8AssertBSIError('', StringOfChar('0', 64), TaskID, ErrorSourceSize,
    'empty BSI managed-SBOM input');

  SetLength(Oversize, SizeInt(DefaultMaximumJSONBytes + 1));
  try
    S8AssertBSIError(Oversize, StringOfChar('0', 64), TaskID,
      ErrorSourceSize, 'oversized BSI managed-SBOM input');
  finally
    Oversize := '';
  end;

  S8AssertBSIError(Bytes, '', TaskID, ErrorExpectedHash,
    'missing BSI expected digest');
  S8AssertBSIError(Bytes, StringOfChar('z', 64), TaskID,
    ErrorExpectedHash, 'malformed BSI expected digest');
  S8AssertBSIError(Bytes, StringOfChar('0', 64), TaskID,
    ErrorHashMismatch, 'mismatched BSI expected digest');
  S8AssertBSIError(Bytes + LineEnding, Digest, TaskID,
    ErrorHashMismatch, 'BSI exact source-byte binding');

  Bytes := '{';
  S8AssertBSIError(Bytes, SHA256String(Bytes), TaskID, ErrorJSON,
    'malformed BSI JSON');
  Bytes := '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}';
  S8AssertBSIError(Bytes, SHA256String(Bytes), TaskID, ErrorJSON,
    'duplicate-member BSI JSON');
  InvalidUTF8 := RawByteString('{"value":"') + #$C0#$AF + '"}';
  S8AssertBSIError(InvalidUTF8, SHA256String(InvalidUTF8), TaskID,
    ErrorJSON, 'invalid-UTF-8 BSI JSON');
  Bytes := '[]';
  S8AssertBSIError(Bytes, SHA256String(Bytes), TaskID, ErrorJSON,
    'non-object BSI JSON root');
end;

procedure RunSprint8RegressionTests;
begin
  RunTest('Sprint 8 declared-hash model and normalization',
    @TestSprint8DeclaredHashModelAndNormalization);
  RunTest('Sprint 8 declared lockfile hashes',
    @TestSprint8DeclaredHashParsers);
  RunTest('Sprint 8 declared-hash cache contract',
    @TestSprint8DeclaredHashCache);
  RunTest('Sprint 8 CycloneDX occurrence evidence',
    @TestSprint8CycloneDXEvidence);
  RunTest('Sprint 8 OSV candidate and request policy',
    @TestSprint8OSVCandidatePolicy);
  RunTest('Sprint 8 OSV determinism and privacy',
    @TestSprint8OSVDeterminismAndPrivacy);
  RunTest('Sprint 8 OSV hard limits', @TestSprint8OSVLimits);
  RunTest('Sprint 8 OSV failure and cancellation policy',
    @TestSprint8OSVFailuresCancellationAndStrictJSON);
  RunTest('Sprint 8 known-issue model persistence',
    @TestSprint8KnownIssueModelPersistence);
  RunTest('Sprint 8 known-issue ownership, scale, and byte budget',
    @TestSprint8KnownIssueOwnershipScaleAndBudget);
  RunTest('Sprint 8 history writer byte and structure bounds',
    @TestSprint8HistoryWriterBounds);
  RunTest('Sprint 8 known-issue service outcomes',
    @TestSprint8KnownIssueServiceOutcomes);
  RunTest('Sprint 8 known-issue post-output transaction',
    @TestSprint8KnownIssuePostOutputTransaction);
  RunTest('Sprint 8 worker committed-enrichment containment',
    @TestSprint8WorkerCommittedEnrichmentFailure);
  RunTest('Sprint 8 BSI readiness schema and privacy contract',
    @TestSprint8BSIReadinessContract);
  RunTest('Sprint 8 BSI readiness input failures',
    @TestSprint8BSIInputErrors);
end;
