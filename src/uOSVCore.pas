(**
  PurpleRay SBOM Analyzer OSV querybatch core.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  This unit is deliberately LCL-free.  It validates privacy-bounded Package
  URL candidates, builds the OSV ``POST /v1/querybatch`` wire representation,
  coordinates ordered pagination through an injected transport, and parses
  responses under explicit global limits.  It never selects or opens a
  network endpoint itself.
*)
unit uOSVCore;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs;

const
  OSVMaximumCandidates = 2048;
  OSVMaximumBatchQueries = 128;
  OSVMaximumRequests = 32;
  OSVMaximumResponseBytes = Int64(8) * 1024 * 1024;
  OSVMaximumAggregateResponseBytes = Int64(32) * 1024 * 1024;
  OSVMaximumAdvisoryIDs = 4096;
  OSVMaximumMatches = 8192;
  OSVMaximumRawVulnerabilityEntries = 8192;
  OSVMaximumResponseJSONNodes = 65536;
  OSVMaximumPURLBytes = 4096;
  OSVMaximumPageTokenBytes = 4096;
  OSVTotalTimeoutMilliseconds = 30000;

type
  { Cancellation checks must be fast, thread-safe when a transport documents
    that it polls on a helper thread, and must not raise exceptions. }
  TOSVCancelCheck = function: Boolean of object;

  TOSVTransportOutcome = (
    otoSucceeded,
    otoCancelled,
    otoFailed,
    otoResponseTooLarge
  );

  { The transport owns endpoint selection and TLS policy.  Implementations
    must return at most AMaximumResponseBytes, although the core independently
    enforces the same boundary.  HTTP error statuses are successful transport
    operations and are returned through AHTTPStatus.  Cancel may be invoked
    concurrently with PostQueryBatch and must actively interrupt a blocked
    operation without freeing state still in use by that operation.  The core
    also uses ACancelCheck to convey its remaining lookup-wide deadline. }
  IOSVTransport = interface
    ['{BBF4F311-5F59-4B05-96C3-F5B82EE6A092}']
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    procedure Cancel;
  end;

  TOSVCandidateRejectionReason = (
    ocrEmpty,
    ocrTooLong,
    ocrInvalidEncoding,
    ocrWhitespaceOrControl,
    ocrNotPackageURL,
    ocrMalformedPackageURL,
    ocrGenericPackageURL,
    ocrUnsupportedEcosystem,
    ocrHasQualifiers,
    ocrHasSubpath,
    ocrUnversioned
  );

  TOSVOutcome = (
    osoSucceeded,
    osoNoEligibleCandidates,
    osoCancelled,
    osoCandidateLimitExceeded,
    osoRequestLimitExceeded,
    osoResponseLimitExceeded,
    osoAggregateResponseLimitExceeded,
    osoAdvisoryLimitExceeded,
    osoMatchLimitExceeded,
    osoTransportFailed,
    osoHTTPStatusFailed,
    osoMalformedResponse
  );

  TOSVCandidateRejection = class
  public
    InputIndex: Integer;
    Reason: TOSVCandidateRejectionReason;
  end;

  TOSVMatch = class
  public
    PackageURL: string;
    AdvisoryID: string;
    Modified: string;
  end;

  { Caller-owned result.  Lists use ordinal, case-sensitive ordering.
    Rejections retain input indexes and reason codes, but intentionally do not
    copy rejected Package URLs into long-lived result state. }
  TOSVLookupResult = class
  public
    Outcome: TOSVOutcome;
    DiagnosticCode: string;
    Diagnostic: string;
    HTTPStatus: Integer;
    RequestCount: Integer;
    AggregateResponseBytes: Int64;
    DuplicateCandidateCount: Integer;
    EligibleCandidates: TStringList;
    RejectedCandidates: TObjectList;
    AdvisoryIDs: TStringList;
    Matches: TObjectList;
    constructor Create;
    destructor Destroy; override;
  end;

  TOSVClient = class
  private
    FActiveCancelCheck: TOSVCancelCheck;
    FCancelled: Boolean;
    FCancelForwardPending: Boolean;
    FCancelGate: TRTLCriticalSection;
    FCancelGateInitialized: Boolean;
    FDeadline: QWord;
    FLock: TRTLCriticalSection;
    FLockInitialized: Boolean;
    FQueryActive: Boolean;
    FQueryGeneration: QWord;
    FTimedOut: Boolean;
    FTransport: IOSVTransport;
    FTransportCallActive: Boolean;
    function BeginQuery(ACancelCheck: TOSVCancelCheck): Boolean;
    function BeginTransportCall: Boolean;
    function CheckCancelled: Boolean;
    procedure EndQuery(AResult: TOSVLookupResult);
    procedure EndTransportCall;
    procedure ForwardPendingCancellation(AGeneration: QWord);
  public
    { Retains one reference-counted injected transport. }
    constructor Create(const ATransport: IOSVTransport);
    destructor Destroy; override;
    { Performs one complete deterministic querybatch exchange.  The caller
      owns the returned result even for cancellation and failure outcomes.
      Validation, every batch/page, parsing, result application, and terminal
      publication share one OSVTotalTimeoutMilliseconds budget.
      More than OSVMaximumCandidates supplied strings fails before any item is
      indexed; a nil list raises EArgumentNilException. }
    function Query(const ACandidatePackageURLs: TStrings;
      ACancelCheck: TOSVCancelCheck = nil): TOSVLookupResult;
    { Thread-safe when used with a conforming IOSVTransport; forwards active
      cancellation so a blocked native operation is interrupted. }
    procedure Cancel;
  end;

function OSVCandidateRejectionCode(
  AReason: TOSVCandidateRejectionReason): string;
function OSVOutcomeCode(AOutcome: TOSVOutcome): string;

{ Validates and canonicalizes one versioned, non-generic ecosystem Package
  URL.  Qualifiers and subpaths are rejected because sending them would expose
  metadata that is unnecessary for an OSV version lookup. }
function TryCanonicalOSVPackageURL(const APURL: string;
  out ACanonicalPURL: string;
  out AReason: TOSVCandidateRejectionReason): Boolean;

{ Builds the exact deterministic request used by the client.  APURLs must
  contain one through OSVMaximumBatchQueries canonical eligible Package URLs.
  APageTokens may be nil (all first pages) or contain one token per URL.  Each
  query contains only ``package.purl`` and, for pagination, ``page_token``. }
function BuildOSVQueryBatchRequest(const APURLs,
  APageTokens: TStrings): RawByteString;

{$IFDEF OSV_CORE_TEST_HOOKS}
{ Ignored-probe hook; absent from production builds. }
procedure OSVTestSetTotalTimeoutMilliseconds(AValue: QWord);
{$ENDIF}

implementation

uses
  fpjson, uJSONUtils;

const
  OSVMaximumResponseJSONDepth = 128;

type
  EOSVProtocolError = class(Exception);
  EOSVResponseCancelled = class(Exception);
  EOSVResponseMatchLimit = class(Exception);

  TOSVPendingQuery = class
  public
    PackageURL: string;
    PageToken: string;
  end;

  TOSVParsedVulnerability = class
  public
    AdvisoryID: string;
    Modified: string;
  end;

  TOSVParsedQueryResult = class
  public
    Vulnerabilities: TObjectList;
    NextPageToken: string;
    constructor Create;
    destructor Destroy; override;
  end;

  TOSVParsedBatch = class
  public
    Results: TObjectList;
    constructor Create;
    destructor Destroy; override;
  end;

{$IFDEF OSV_CORE_TEST_HOOKS}
var
  OSVTestTotalTimeoutMilliseconds: QWord = OSVTotalTimeoutMilliseconds;

procedure OSVTestSetTotalTimeoutMilliseconds(AValue: QWord);
begin
  if AValue = 0 then
    OSVTestTotalTimeoutMilliseconds := OSVTotalTimeoutMilliseconds
  else
    OSVTestTotalTimeoutMilliseconds := AValue;
end;
{$ENDIF}

function QueryTotalTimeoutMilliseconds: QWord; inline;
begin
  {$IFDEF OSV_CORE_TEST_HOOKS}
  Result := OSVTestTotalTimeoutMilliseconds;
  {$ELSE}
  Result := OSVTotalTimeoutMilliseconds;
  {$ENDIF}
end;

function NewOrdinalStringList: TStringList;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.CaseSensitive := True;
  Result.UseLocale := False;
  Result.Duplicates := dupIgnore;
end;

constructor TOSVLookupResult.Create;
begin
  inherited Create;
  EligibleCandidates := NewOrdinalStringList;
  RejectedCandidates := TObjectList.Create(True);
  AdvisoryIDs := NewOrdinalStringList;
  Matches := TObjectList.Create(True);
  Outcome := osoNoEligibleCandidates;
end;

destructor TOSVLookupResult.Destroy;
begin
  Matches.Free;
  AdvisoryIDs.Free;
  RejectedCandidates.Free;
  EligibleCandidates.Free;
  inherited Destroy;
end;

constructor TOSVParsedQueryResult.Create;
begin
  inherited Create;
  Vulnerabilities := TObjectList.Create(True);
end;

destructor TOSVParsedQueryResult.Destroy;
begin
  Vulnerabilities.Free;
  inherited Destroy;
end;

constructor TOSVParsedBatch.Create;
begin
  inherited Create;
  Results := TObjectList.Create(True);
end;

destructor TOSVParsedBatch.Destroy;
begin
  Results.Free;
  inherited Destroy;
end;

function OSVCandidateRejectionCode(
  AReason: TOSVCandidateRejectionReason): string;
begin
  Result := '';
  case AReason of
    ocrEmpty: Result := 'empty';
    ocrTooLong: Result := 'too-long';
    ocrInvalidEncoding: Result := 'invalid-utf8';
    ocrWhitespaceOrControl: Result := 'whitespace-or-control';
    ocrNotPackageURL: Result := 'not-package-url';
    ocrMalformedPackageURL: Result := 'malformed-package-url';
    ocrGenericPackageURL: Result := 'generic-package-url';
    ocrUnsupportedEcosystem: Result := 'unsupported-ecosystem';
    ocrHasQualifiers: Result := 'qualifiers-not-allowed';
    ocrHasSubpath: Result := 'subpath-not-allowed';
    ocrUnversioned: Result := 'version-required';
  end;
end;

function OSVOutcomeCode(AOutcome: TOSVOutcome): string;
begin
  Result := '';
  case AOutcome of
    osoSucceeded: Result := 'ok';
    osoNoEligibleCandidates: Result := 'no-eligible-candidates';
    osoCancelled: Result := 'cancelled';
    osoCandidateLimitExceeded: Result := 'candidate-limit-exceeded';
    osoRequestLimitExceeded: Result := 'request-limit-exceeded';
    osoResponseLimitExceeded: Result := 'response-limit-exceeded';
    osoAggregateResponseLimitExceeded:
      Result := 'aggregate-response-limit-exceeded';
    osoAdvisoryLimitExceeded: Result := 'advisory-limit-exceeded';
    osoMatchLimitExceeded: Result := 'match-limit-exceeded';
    osoTransportFailed: Result := 'transport-failed';
    osoHTTPStatusFailed: Result := 'http-status-failed';
    osoMalformedResponse: Result := 'malformed-response';
  end;
end;

function OSVOutcomeDiagnostic(AOutcome: TOSVOutcome;
  AHTTPStatus: Integer): string;
begin
  Result := '';
  case AOutcome of
    osoSucceeded: Result := '';
    osoNoEligibleCandidates:
      Result := 'No eligible versioned ecosystem Package URLs were supplied.';
    osoCancelled: Result := 'The OSV lookup was cancelled.';
    osoCandidateLimitExceeded:
      Result := 'The OSV lookup exceeded the 2048-candidate limit.';
    osoRequestLimitExceeded:
      Result := 'The OSV lookup exceeded the 32-request limit.';
    osoResponseLimitExceeded:
      Result := 'An OSV response exceeded the 8 MiB limit.';
    osoAggregateResponseLimitExceeded:
      Result := 'OSV responses exceeded the 32 MiB aggregate limit.';
    osoAdvisoryLimitExceeded:
      Result := 'The OSV lookup exceeded the 4096-advisory limit.';
    osoMatchLimitExceeded:
      Result := 'The OSV lookup exceeded the 8192-match limit.';
    osoTransportFailed:
      Result := 'The OSV transport failed.';
    osoHTTPStatusFailed:
      Result := Format('OSV returned HTTP status %d.', [AHTTPStatus]);
    osoMalformedResponse:
      Result := 'The OSV querybatch response did not match its strict schema.';
  end;
end;

function ASCIILower(const AValue: string): string;
var
  I: SizeInt;
begin
  Result := AValue;
  for I := 1 to Length(Result) do
    if Result[I] in ['A'..'Z'] then
      Result[I] := Chr(Ord(Result[I]) + Ord('a') - Ord('A'));
end;

function IsPURLUnreserved(AValue: Byte): Boolean; inline;
begin
  Result := (AValue in [Ord('A')..Ord('Z'), Ord('a')..Ord('z'),
    Ord('0')..Ord('9')]) or
    (AValue in [Ord('.'), Ord('-'), Ord('_'), Ord('~')]);
end;

function HexDigitValue(AValue: Char): Integer; inline;
begin
  case AValue of
    '0'..'9': Result := Ord(AValue) - Ord('0');
    'A'..'F': Result := Ord(AValue) - Ord('A') + 10;
    'a'..'f': Result := Ord(AValue) - Ord('a') + 10;
  else
    Result := -1;
  end;
end;

function HasWhitespaceOrControl(const AValue: string): Boolean;
var
  I: SizeInt;
begin
  for I := 1 to Length(AValue) do
    if (Byte(AValue[I]) <= 32) or (Byte(AValue[I]) = 127) then
      Exit(True);
  Result := False;
end;

function IsSupportedOSVPURLType(const AType: string): Boolean;
begin
  { This fixed set mirrors the ecosystem-backed PURL parsers in the OSV
    service.  Keeping it versioned in the client prevents an unknown PURL type
    from turning an otherwise valid batch into an HTTP 400 response. }
  case AType of
    'apk', 'bitnami', 'cargo', 'composer', 'conan', 'cran', 'deb', 'dhi',
    'gem', 'golang', 'gradle', 'hackage', 'hex', 'julia', 'maven', 'npm',
    'nuget', 'opam', 'pub', 'pypi', 'rpm', 'swift': Result := True;
  else
    Result := False;
  end;
end;

function IsSupportedOSNamespace(const AType, APath: string): Boolean;
var
  NamespaceValue: string;
  SlashIndex: SizeInt;
begin
  Result := False;
  if (AType <> 'apk') and (AType <> 'deb') and (AType <> 'rpm') then
    Exit(True);
  SlashIndex := Pos('/', APath);
  if SlashIndex <= 1 then
    Exit(False);
  NamespaceValue := Copy(APath, 1, SlashIndex - 1);
  case AType of
    'apk':
      case NamespaceValue of
        'alpaquita', 'alpine', 'bellsoft-hardened-containers', 'chainguard',
        'dhi', 'minimos', 'wolfi': Result := True;
      else
        Result := False;
      end;
    'deb':
      case NamespaceValue of
        'debian', 'dhi', 'echo', 'ubuntu': Result := True;
      else
        Result := False;
      end;
    'rpm':
      case NamespaceValue of
        'almalinux', 'azure-linux', 'mageia', 'openeuler', 'opensuse',
        'redhat', 'rocky-linux', 'suse': Result := True;
      else
        Result := False;
      end;
  end;
end;

function CanonicalizePURLComponent(const AValue: string;
  out ACanonical: string): Boolean;
const
  HexDigits = '0123456789ABCDEF';
var
  CanonicalBuffer, Decoded: RawByteString;
  ByteValue: Byte;
  CanonicalLength, DecodedLength, HighDigit, I, LowDigit: SizeInt;
begin
  Result := False;
  ACanonical := '';
  CanonicalBuffer := '';
  Decoded := '';
  if AValue = '' then
    Exit;
  { Canonical output is never longer than its encoded input: a decoded
    reserved byte is emitted as the same three-byte percent escape. }
  SetLength(Decoded, Length(AValue));
  SetLength(CanonicalBuffer, Length(AValue));
  DecodedLength := 0;
  CanonicalLength := 0;
  I := 1;
  while I <= Length(AValue) do
  begin
    if AValue[I] = '%' then
    begin
      if I + 2 > Length(AValue) then
        Exit;
      HighDigit := HexDigitValue(AValue[I + 1]);
      LowDigit := HexDigitValue(AValue[I + 2]);
      if (HighDigit < 0) or (LowDigit < 0) then
        Exit;
      ByteValue := Byte((HighDigit shl 4) or LowDigit);
      Inc(I, 3);
    end
    else
    begin
      ByteValue := Byte(AValue[I]);
      if (ByteValue > 127) or
        (not IsPURLUnreserved(ByteValue) and (ByteValue <> Ord(':'))) then
        Exit;
      Inc(I);
    end;
    if (ByteValue <= 32) or (ByteValue = 127) or
      (ByteValue = Ord('/')) then
      Exit;
    Inc(DecodedLength);
    Decoded[DecodedLength] := AnsiChar(ByteValue);
    if IsPURLUnreserved(ByteValue) or (ByteValue = Ord(':')) then
    begin
      Inc(CanonicalLength);
      CanonicalBuffer[CanonicalLength] := AnsiChar(ByteValue);
    end
    else
    begin
      Inc(CanonicalLength);
      CanonicalBuffer[CanonicalLength] := '%';
      Inc(CanonicalLength);
      CanonicalBuffer[CanonicalLength] := HexDigits[(ByteValue shr 4) + 1];
      Inc(CanonicalLength);
      CanonicalBuffer[CanonicalLength] := HexDigits[(ByteValue and $0F) + 1];
    end;
  end;
  SetLength(Decoded, DecodedLength);
  SetLength(CanonicalBuffer, CanonicalLength);
  Result := IsValidUTF8Bytes(Decoded);
  if Result then
    ACanonical := string(CanonicalBuffer);
end;

function CanonicalizePURLPath(const AValue: string;
  out ACanonical: string): Boolean;
var
  I, SegmentStart: SizeInt;
  CanonicalSegment, SegmentValue: string;
begin
  Result := False;
  ACanonical := '';
  CanonicalSegment := '';
  if (AValue = '') or (AValue[1] = '/') or
    (AValue[Length(AValue)] = '/') then
    Exit;
  SegmentStart := 1;
  for I := 1 to Length(AValue) + 1 do
    if (I > Length(AValue)) or (AValue[I] = '/') then
    begin
      if I = SegmentStart then
        Exit;
      SegmentValue := Copy(AValue, SegmentStart, I - SegmentStart);
      if not CanonicalizePURLComponent(SegmentValue, CanonicalSegment) or
        (CanonicalSegment = '.') or (CanonicalSegment = '..') then
        Exit;
      if ACanonical <> '' then
        ACanonical := ACanonical + '/';
      ACanonical := ACanonical + CanonicalSegment;
      SegmentStart := I + 1;
    end;
  Result := ACanonical <> '';
end;

function TryCanonicalOSVPackageURL(const APURL: string;
  out ACanonicalPURL: string;
  out AReason: TOSVCandidateRejectionReason): Boolean;
var
  CoreValue, PathAndVersion, PathValue, TypeValue, VersionValue,
    CanonicalPath, CanonicalVersion: string;
  AtIndex, I, SlashIndex: SizeInt;
begin
  Result := False;
  ACanonicalPURL := '';
  AReason := ocrMalformedPackageURL;
  if APURL = '' then
  begin
    AReason := ocrEmpty;
    Exit;
  end;
  if Length(APURL) > OSVMaximumPURLBytes then
  begin
    AReason := ocrTooLong;
    Exit;
  end;
  if not IsValidUTF8Bytes(RawByteString(APURL)) then
  begin
    AReason := ocrInvalidEncoding;
    Exit;
  end;
  if HasWhitespaceOrControl(APURL) then
  begin
    AReason := ocrWhitespaceOrControl;
    Exit;
  end;
  if ASCIILower(Copy(APURL, 1, 4)) <> 'pkg:' then
  begin
    AReason := ocrNotPackageURL;
    Exit;
  end;
  if Pos('?', APURL) > 0 then
  begin
    AReason := ocrHasQualifiers;
    Exit;
  end;
  if Pos('#', APURL) > 0 then
  begin
    AReason := ocrHasSubpath;
    Exit;
  end;
  CoreValue := Copy(APURL, 5, MaxInt);
  SlashIndex := Pos('/', CoreValue);
  if (SlashIndex <= 1) or (SlashIndex = Length(CoreValue)) then
    Exit;
  TypeValue := Copy(CoreValue, 1, SlashIndex - 1);
  if not (TypeValue[1] in ['A'..'Z', 'a'..'z']) then
    Exit;
  for I := 1 to Length(TypeValue) do
    if not (TypeValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '.', '+', '-']) then
      Exit;
  TypeValue := ASCIILower(TypeValue);
  if TypeValue = 'generic' then
  begin
    AReason := ocrGenericPackageURL;
    Exit;
  end;
  if not IsSupportedOSVPURLType(TypeValue) then
  begin
    AReason := ocrUnsupportedEcosystem;
    Exit;
  end;
  PathAndVersion := Copy(CoreValue, SlashIndex + 1, MaxInt);
  AtIndex := Pos('@', PathAndVersion);
  if AtIndex = 0 then
  begin
    AReason := ocrUnversioned;
    Exit;
  end;
  if (AtIndex = 1) or (AtIndex = Length(PathAndVersion)) or
    (Pos('@', Copy(PathAndVersion, AtIndex + 1, MaxInt)) > 0) then
    Exit;
  PathValue := Copy(PathAndVersion, 1, AtIndex - 1);
  VersionValue := Copy(PathAndVersion, AtIndex + 1, MaxInt);
  if not CanonicalizePURLPath(PathValue, CanonicalPath) or
    not CanonicalizePURLComponent(VersionValue, CanonicalVersion) then
    Exit;
  if not IsSupportedOSNamespace(TypeValue, CanonicalPath) then
  begin
    AReason := ocrUnsupportedEcosystem;
    Exit;
  end;
  ACanonicalPURL := 'pkg:' + TypeValue + '/' + CanonicalPath + '@' +
    CanonicalVersion;
  Result := True;
end;

function IsValidPageToken(const AValue: string): Boolean;
begin
  Result := (Length(AValue) <= OSVMaximumPageTokenBytes) and
    IsValidUTF8Bytes(RawByteString(AValue)) and
    not HasWhitespaceOrControl(AValue);
end;

function BuildOSVQueryBatchRequest(const APURLs,
  APageTokens: TStrings): RawByteString;
var
  CanonicalPURL: string;
  I: Integer;
  PackageObject, QueryObject, Root: TJSONObject;
  Queries: TJSONArray;
  Reason: TOSVCandidateRejectionReason;
  Token: string;
begin
  if APURLs = nil then
    raise EArgumentNilException.Create('OSV Package URL list is nil');
  if (APURLs.Count < 1) or (APURLs.Count > OSVMaximumBatchQueries) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'OSV querybatch requires 1..%d Package URLs',
      [OSVMaximumBatchQueries]);
  if (APageTokens <> nil) and (APageTokens.Count <> APURLs.Count) then
    raise EArgumentException.Create(
      'OSV page-token count must match the Package URL count');
  Root := TJSONObject.Create;
  try
    Queries := TJSONArray.Create;
    try
      Root.Add('queries', Queries);
    except
      Queries.Free;
      raise;
    end;
    for I := 0 to APURLs.Count - 1 do
    begin
      if not TryCanonicalOSVPackageURL(APURLs[I], CanonicalPURL, Reason) or
        (CanonicalPURL <> APURLs[I]) then
        raise EArgumentException.CreateFmt(
          'OSV Package URL at index %d is not canonical and eligible', [I]);
      Token := '';
      if APageTokens <> nil then
        Token := APageTokens[I];
      if not IsValidPageToken(Token) then
        raise EArgumentException.CreateFmt(
          'OSV page token at index %d is invalid', [I]);
      QueryObject := TJSONObject.Create;
      try
        Queries.Add(QueryObject);
      except
        QueryObject.Free;
        raise;
      end;
      PackageObject := TJSONObject.Create;
      try
        QueryObject.Add('package', PackageObject);
      except
        PackageObject.Free;
        raise;
      end;
      PackageObject.Add('purl', CanonicalPURL);
      if Token <> '' then
        QueryObject.Add('page_token', Token);
    end;
    Result := RawByteString(SerializeJSONUTF8(Root, AsCompressedJSON, 0,
      False));
  finally
    Root.Free;
  end;
end;

function IsCancelled(ACancelCheck: TOSVCancelCheck): Boolean; inline;
begin
  Result := Assigned(ACancelCheck) and ACancelCheck();
end;

procedure RaiseIfResponseCancelled(ACancelCheck: TOSVCancelCheck); inline;
begin
  if IsCancelled(ACancelCheck) then
    raise EOSVResponseCancelled.Create('cancelled');
end;

procedure PreflightOSVResponseNodes(const AResponse: RawByteString;
  ACancelCheck: TOSVCancelCheck);
var
  C: AnsiChar;
  Escaped, InString: Boolean;
  Depth, I, NodeCount: SizeInt;
begin
  Depth := 0;
  Escaped := False;
  InString := False;
  I := 1;
  NodeCount := 0;
  while I <= Length(AResponse) do
  begin
    if (I and $FFF) = 0 then
      RaiseIfResponseCancelled(ACancelCheck);
    C := AResponse[I];
    if InString then
    begin
      if Escaped then
        Escaped := False
      else if C = '\' then
        Escaped := True
      else if C = '"' then
        InString := False;
      Inc(I);
      Continue;
    end;
    case C of
      '"':
        begin
          InString := True;
          Inc(NodeCount);
        end;
      '{', '[':
        begin
          Inc(NodeCount);
          Inc(Depth);
          if Depth > OSVMaximumResponseJSONDepth then
            raise EOSVResponseMatchLimit.Create('json-depth');
        end;
      '}', ']':
        if Depth > 0 then
          Dec(Depth);
      '-', '0'..'9':
        begin
          Inc(NodeCount);
          repeat
            Inc(I);
          until (I > Length(AResponse)) or
            not (AResponse[I] in ['0'..'9', '+', '-', '.', 'e', 'E']);
          if NodeCount > OSVMaximumResponseJSONNodes then
            raise EOSVResponseMatchLimit.Create('json-nodes');
          Continue;
        end;
      't', 'f', 'n':
        Inc(NodeCount);
    end;
    if NodeCount > OSVMaximumResponseJSONNodes then
      raise EOSVResponseMatchLimit.Create('json-nodes');
    Inc(I);
  end;
  RaiseIfResponseCancelled(ACancelCheck);
end;

function ObjectHasOnlyMembers(AObject: TJSONObject;
  const AAllowed: array of string;
  ACancelCheck: TOSVCancelCheck): Boolean;
var
  I, J: Integer;
  Found: Boolean;
begin
  for I := 0 to AObject.Count - 1 do
  begin
    if (I and $3F) = 0 then
      RaiseIfResponseCancelled(ACancelCheck);
    Found := False;
    for J := Low(AAllowed) to High(AAllowed) do
      if AObject.Names[I] = AAllowed[J] then
      begin
        Found := True;
        Break;
      end;
    if not Found then
      Exit(False);
  end;
  Result := True;
end;

function IsVisibleASCII(const AValue: string; AMaximumLength: SizeInt): Boolean;
var
  I: SizeInt;
begin
  Result := (AValue <> '') and (Length(AValue) <= AMaximumLength);
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Byte(AValue[I]) < 33) or (Byte(AValue[I]) > 126) then
      Exit(False);
end;

function ParseOSVQueryBatchResponse(const AResponse: RawByteString;
  AExpectedResultCount: Integer; ACancelCheck: TOSVCancelCheck;
  var ARawVulnerabilityEntries: Integer): TOSVParsedBatch;
var
  BatchResult: TOSVParsedQueryResult;
  Data, FieldData: TJSONData;
  I, J: Integer;
  Root: TJSONObject;
  ResultsArray, VulnerabilitiesArray: TJSONArray;
  ResultObject, VulnerabilityObject: TJSONObject;
  Vulnerability: TOSVParsedVulnerability;
begin
  Result := nil;
  RaiseIfResponseCancelled(ACancelCheck);
  PreflightOSVResponseNodes(AResponse, ACancelCheck);
  RaiseIfResponseCancelled(ACancelCheck);
  Data := ParseStrictUTF8JSON(AResponse);
  try
    RaiseIfResponseCancelled(ACancelCheck);
    if Data.JSONType <> jtObject then
      raise EOSVProtocolError.Create('root');
    Root := TJSONObject(Data);
    if not ObjectHasOnlyMembers(Root, ['results'], ACancelCheck) then
      raise EOSVProtocolError.Create('root-members');
    FieldData := Root.Find('results');
    if (FieldData = nil) or (FieldData.JSONType <> jtArray) then
      raise EOSVProtocolError.Create('results');
    ResultsArray := TJSONArray(FieldData);
    if ResultsArray.Count <> AExpectedResultCount then
      raise EOSVProtocolError.Create('result-count');
    Result := TOSVParsedBatch.Create;
    try
      for I := 0 to ResultsArray.Count - 1 do
      begin
        RaiseIfResponseCancelled(ACancelCheck);
        if ResultsArray.Items[I].JSONType <> jtObject then
          raise EOSVProtocolError.Create('result-item');
        ResultObject := TJSONObject(ResultsArray.Items[I]);
        if not ObjectHasOnlyMembers(ResultObject,
          ['vulns', 'next_page_token'], ACancelCheck) then
          raise EOSVProtocolError.Create('result-members');
        BatchResult := TOSVParsedQueryResult.Create;
        try
          FieldData := ResultObject.Find('next_page_token');
          if FieldData <> nil then
          begin
            if FieldData.JSONType <> jtString then
              raise EOSVProtocolError.Create('next-page-token-type');
            BatchResult.NextPageToken := FieldData.AsString;
            if not IsValidPageToken(BatchResult.NextPageToken) then
              raise EOSVProtocolError.Create('next-page-token-value');
          end;
          FieldData := ResultObject.Find('vulns');
          if FieldData <> nil then
          begin
            if FieldData.JSONType <> jtArray then
              raise EOSVProtocolError.Create('vulns');
            VulnerabilitiesArray := TJSONArray(FieldData);
            for J := 0 to VulnerabilitiesArray.Count - 1 do
            begin
              if (J and $3F) = 0 then
                RaiseIfResponseCancelled(ACancelCheck);
              Inc(ARawVulnerabilityEntries);
              if ARawVulnerabilityEntries >
                OSVMaximumRawVulnerabilityEntries then
                raise EOSVResponseMatchLimit.Create('raw-vulnerabilities');
              if VulnerabilitiesArray.Items[J].JSONType <> jtObject then
                raise EOSVProtocolError.Create('vulnerability-item');
              VulnerabilityObject :=
                TJSONObject(VulnerabilitiesArray.Items[J]);
              if not ObjectHasOnlyMembers(VulnerabilityObject,
                ['id', 'modified'], ACancelCheck) then
                raise EOSVProtocolError.Create('vulnerability-members');
              FieldData := VulnerabilityObject.Find('id');
              if (FieldData = nil) or (FieldData.JSONType <> jtString) or
                not IsVisibleASCII(FieldData.AsString, 256) then
                raise EOSVProtocolError.Create('vulnerability-id');
              Vulnerability := TOSVParsedVulnerability.Create;
              try
                Vulnerability.AdvisoryID := FieldData.AsString;
                FieldData := VulnerabilityObject.Find('modified');
                if (FieldData = nil) or (FieldData.JSONType <> jtString) or
                  not IsVisibleASCII(FieldData.AsString, 128) then
                  raise EOSVProtocolError.Create('vulnerability-modified');
                Vulnerability.Modified := FieldData.AsString;
                BatchResult.Vulnerabilities.Add(Vulnerability);
                Vulnerability := nil;
              finally
                Vulnerability.Free;
              end;
            end;
          end;
          Result.Results.Add(BatchResult);
          BatchResult := nil;
        finally
          BatchResult.Free;
        end;
      end;
      RaiseIfResponseCancelled(ACancelCheck);
    except
      FreeAndNil(Result);
      raise;
    end;
  finally
    Data.Free;
  end;
end;

function MatchKey(const APURL, AAdvisoryID: string): string; inline;
begin
  { Both validated values exclude control bytes, so #1 is an injective field
    separator and preserves Package URL then advisory ordinal ordering. }
  Result := APURL + #1 + AAdvisoryID;
end;

function PaginationKey(const APURL, AToken: string): string; inline;
begin
  Result := APURL + #1 + AToken;
end;

procedure SetResultOutcome(AResult: TOSVLookupResult; AOutcome: TOSVOutcome;
  AHTTPStatus: Integer = 0);
begin
  AResult.Outcome := AOutcome;
  AResult.HTTPStatus := AHTTPStatus;
  AResult.DiagnosticCode := OSVOutcomeCode(AOutcome);
  AResult.Diagnostic := OSVOutcomeDiagnostic(AOutcome, AHTTPStatus);
end;

constructor TOSVClient.Create(const ATransport: IOSVTransport);
begin
  inherited Create;
  { A failing Object Pascal constructor invokes the virtual destructor.  Keep
    the initialization state explicit so even the nil-transport path is safe. }
  FLockInitialized := False;
  FCancelGateInitialized := False;
  if ATransport = nil then
    raise EArgumentNilException.Create('OSV transport is nil');
  InitCriticalSection(FLock);
  FLockInitialized := True;
  InitCriticalSection(FCancelGate);
  FCancelGateInitialized := True;
  FTransport := ATransport;
end;

destructor TOSVClient.Destroy;
begin
  if FLockInitialized and FCancelGateInitialized then
    Cancel;
  FTransport := nil;
  if FCancelGateInitialized then
  begin
    FCancelGateInitialized := False;
    DoneCriticalSection(FCancelGate);
  end;
  if FLockInitialized then
  begin
    FLockInitialized := False;
    DoneCriticalSection(FLock);
  end;
  inherited Destroy;
end;

function TOSVClient.BeginQuery(ACancelCheck: TOSVCancelCheck): Boolean;
begin
  { The cancellation gate prevents a Cancel already committed to the prior
    query from reaching the transport after a new query has begun.  Native
    transport code is never called while FLock is held. }
  EnterCriticalSection(FCancelGate);
  try
    EnterCriticalSection(FLock);
    try
      Result := not FQueryActive;
      if Result then
      begin
        Inc(FQueryGeneration);
        if FQueryGeneration = 0 then
          Inc(FQueryGeneration);
        FQueryActive := True;
        FCancelled := False;
        FCancelForwardPending := False;
        FTimedOut := False;
        FTransportCallActive := False;
        FDeadline := GetTickCount64 + QueryTotalTimeoutMilliseconds;
        FActiveCancelCheck := ACancelCheck;
      end;
    finally
      LeaveCriticalSection(FLock);
    end;
  finally
    LeaveCriticalSection(FCancelGate);
  end;
end;

function TOSVClient.BeginTransportCall: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FQueryActive and not FCancelled and
      not FTransportCallActive;
    if Result then
      FTransportCallActive := True;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVClient.ForwardPendingCancellation(AGeneration: QWord);
var
  MustForward: Boolean;
begin
  MustForward := False;
  EnterCriticalSection(FCancelGate);
  try
    EnterCriticalSection(FLock);
    try
      if FQueryActive and (FQueryGeneration = AGeneration) and
        FCancelForwardPending and not FTransportCallActive then
      begin
        FCancelForwardPending := False;
        MustForward := True;
      end;
    finally
      LeaveCriticalSection(FLock);
    end;
    if MustForward then
      FTransport.Cancel;
  finally
    LeaveCriticalSection(FCancelGate);
  end;
end;

procedure TOSVClient.EndTransportCall;
var
  Generation: QWord;
begin
  EnterCriticalSection(FLock);
  try
    Generation := FQueryGeneration;
    FTransportCallActive := False;
  finally
    LeaveCriticalSection(FLock);
  end;
  { A callback invoked by PostQueryBatch cannot safely call back into a
    transport that may hold its own state lock.  Forward that cancellation
    immediately after PostQueryBatch has unwound instead. }
  ForwardPendingCancellation(Generation);
end;

function TOSVClient.CheckCancelled: Boolean;
var
  CancelCheck: TOSVCancelCheck;
  CallbackRequested, DeadlineExpired, ForwardNow: Boolean;
  Deadline, Generation: QWord;
begin
  ForwardNow := False;
  EnterCriticalSection(FLock);
  try
    Result := FQueryActive and FCancelled;
    CancelCheck := FActiveCancelCheck;
    Deadline := FDeadline;
    Generation := FQueryGeneration;
  finally
    LeaveCriticalSection(FLock);
  end;
  if Result then
    Exit;
  DeadlineExpired := (Deadline <> 0) and (GetTickCount64 >= Deadline);
  CallbackRequested := not DeadlineExpired and Assigned(CancelCheck) and
    CancelCheck();
  DeadlineExpired := DeadlineExpired or
    ((Deadline <> 0) and (GetTickCount64 >= Deadline));
  EnterCriticalSection(FLock);
  try
    if FQueryActive and (FQueryGeneration = Generation) and
      (CallbackRequested or DeadlineExpired) then
    begin
      FCancelled := True;
      FCancelForwardPending := True;
      ForwardNow := not FTransportCallActive;
      if DeadlineExpired then
        FTimedOut := True;
    end;
    Result := FQueryActive and FCancelled;
  finally
    LeaveCriticalSection(FLock);
  end;
  { When called by PostQueryBatch, returning True is the immediate abort
    signal.  ForwardPendingCancellation defers the explicit Cancel call until
    the Post callback has unwound, avoiding a transport-lock inversion. }
  if Result and ForwardNow then
    ForwardPendingCancellation(Generation);
end;

procedure TOSVClient.EndQuery(AResult: TOSVLookupResult);
var
  WasCancelled, WasTimedOut: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    if FQueryActive and (FDeadline <> 0) and
      (GetTickCount64 >= FDeadline) then
    begin
      FCancelled := True;
      FTimedOut := True;
    end;
    WasCancelled := FQueryActive and FCancelled;
    WasTimedOut := FQueryActive and FTimedOut;
    FQueryActive := False;
    FCancelled := False;
    FCancelForwardPending := False;
    FTimedOut := False;
    FDeadline := 0;
    FTransportCallActive := False;
    FActiveCancelCheck := nil;
  finally
    LeaveCriticalSection(FLock);
  end;
  if WasTimedOut then
    SetResultOutcome(AResult, osoTransportFailed)
  else if WasCancelled then
    SetResultOutcome(AResult, osoCancelled);
end;

procedure TOSVClient.Cancel;
var
  MustForward: Boolean;
begin
  { Serialize an outbound native Cancel with BeginQuery, but never hold the
    client state lock while entering transport code. }
  EnterCriticalSection(FCancelGate);
  try
    EnterCriticalSection(FLock);
    try
      MustForward := FQueryActive;
      if MustForward then
      begin
        FCancelled := True;
        FCancelForwardPending := False;
      end;
    finally
      LeaveCriticalSection(FLock);
    end;
    if MustForward then
      FTransport.Cancel;
  finally
    LeaveCriticalSection(FCancelGate);
  end;
end;

function TOSVClient.Query(const ACandidatePackageURLs: TStrings;
  ACancelCheck: TOSVCancelCheck): TOSVLookupResult;
var
  BatchCount, CandidateIndex, HTTPStatus, I, J, MatchIndex,
    RawVulnerabilityEntries: Integer;
  CanonicalPURL, Key, PageToken: string;
  ResponseBody: RawByteString;
  CandidateReason: TOSVCandidateRejectionReason;
  Match, ExistingMatch: TOSVMatch;
  MatchKeys, PageTokens, PURLs, SeenPagination, TemporaryAdvisories,
    TemporaryMatches, TemporaryPagination: TStringList;
  NextQuery, PendingQuery: TOSVPendingQuery;
  ParsedBatch: TOSVParsedBatch;
  ParsedQuery: TOSVParsedQueryResult;
  ParsedVulnerability: TOSVParsedVulnerability;
  Pending: TObjectList;
  Rejection: TOSVCandidateRejection;
  RequestBody: RawByteString;
  TransportOutcome: TOSVTransportOutcome;

  procedure TransferMatches;
  var
    OwnedMatch: TObject;
  begin
    while MatchKeys.Count > 0 do
    begin
      if (Result.Matches.Count and $3F) = 0 then
        CheckCancelled;
      OwnedMatch := MatchKeys.Objects[0];
      { MatchKeys remains the conceptual owner until TObjectList.Add has
        succeeded.  This makes an allocation failure during transfer safe. }
      Result.Matches.Add(OwnedMatch);
      MatchKeys.Objects[0] := nil;
      MatchKeys.Delete(0);
    end;
  end;

  procedure FreeUntransferredMatches;
  var
    FreeIndex: Integer;
  begin
    if MatchKeys = nil then
      Exit;
    for FreeIndex := 0 to MatchKeys.Count - 1 do
    begin
      MatchKeys.Objects[FreeIndex].Free;
      MatchKeys.Objects[FreeIndex] := nil;
    end;
  end;

  procedure Fail(AOutcome: TOSVOutcome; AStatus: Integer = 0);
  begin
    SetResultOutcome(Result, AOutcome, AStatus);
  end;

  function StopForCancellation: Boolean;
  begin
    Result := CheckCancelled;
    if Result then
      Fail(osoCancelled);
  end;

begin
  if ACandidatePackageURLs = nil then
    raise EArgumentNilException.Create('OSV candidate list is nil');
  Result := TOSVLookupResult.Create;
  try
    if not BeginQuery(ACancelCheck) then
    begin
      SetResultOutcome(Result, osoTransportFailed);
      Exit;
    end;
    Pending := nil;
    MatchKeys := nil;
    SeenPagination := nil;
    PURLs := nil;
    PageTokens := nil;
    TemporaryAdvisories := nil;
    TemporaryMatches := nil;
    TemporaryPagination := nil;
    RawVulnerabilityEntries := 0;
    try
      Pending := TObjectList.Create(True);
    MatchKeys := NewOrdinalStringList;
    SeenPagination := NewOrdinalStringList;
    PURLs := TStringList.Create;
    PageTokens := TStringList.Create;
    TemporaryAdvisories := NewOrdinalStringList;
    TemporaryMatches := NewOrdinalStringList;
    TemporaryPagination := NewOrdinalStringList;
    { Bound the caller-owned input cardinality before indexing it or copying a
      rejected value into result metadata.  Invalid and duplicate candidates
      count toward the same privacy/resource boundary as eligible ones. }
    if ACandidatePackageURLs.Count > OSVMaximumCandidates then
    begin
      Fail(osoCandidateLimitExceeded);
      Exit;
    end;
    for CandidateIndex := 0 to ACandidatePackageURLs.Count - 1 do
    begin
      if CheckCancelled then
      begin
        Fail(osoCancelled);
        Exit;
      end;
      if TryCanonicalOSVPackageURL(ACandidatePackageURLs[CandidateIndex],
        CanonicalPURL, CandidateReason) then
      begin
        if Result.EligibleCandidates.IndexOf(CanonicalPURL) >= 0 then
          Inc(Result.DuplicateCandidateCount)
        else
        begin
          if Result.EligibleCandidates.Count >= OSVMaximumCandidates then
          begin
            Fail(osoCandidateLimitExceeded);
            Exit;
          end;
          Result.EligibleCandidates.Add(CanonicalPURL);
        end;
      end
      else
      begin
        Rejection := TOSVCandidateRejection.Create;
        try
          Rejection.InputIndex := CandidateIndex;
          Rejection.Reason := CandidateReason;
          Result.RejectedCandidates.Add(Rejection);
          Rejection := nil;
        finally
          Rejection.Free;
        end;
      end;
    end;
    if Result.EligibleCandidates.Count = 0 then
    begin
      Fail(osoNoEligibleCandidates);
      Exit;
    end;
    for I := 0 to Result.EligibleCandidates.Count - 1 do
    begin
      PendingQuery := TOSVPendingQuery.Create;
      try
        PendingQuery.PackageURL := Result.EligibleCandidates[I];
        Pending.Add(PendingQuery);
        PendingQuery := nil;
      finally
        PendingQuery.Free;
      end;
    end;
    while Pending.Count > 0 do
    begin
      if CheckCancelled then
      begin
        Fail(osoCancelled);
        Exit;
      end;
      if Result.RequestCount >= OSVMaximumRequests then
      begin
        Fail(osoRequestLimitExceeded);
        Exit;
      end;
      BatchCount := Pending.Count;
      if BatchCount > OSVMaximumBatchQueries then
        BatchCount := OSVMaximumBatchQueries;
      PURLs.Clear;
      PageTokens.Clear;
      for I := 0 to BatchCount - 1 do
      begin
        PendingQuery := TOSVPendingQuery(Pending[I]);
        PURLs.Add(PendingQuery.PackageURL);
        PageTokens.Add(PendingQuery.PageToken);
      end;
      RequestBody := BuildOSVQueryBatchRequest(PURLs, PageTokens);
      HTTPStatus := 0;
      ResponseBody := '';
      Inc(Result.RequestCount);
      if not BeginTransportCall then
      begin
        Fail(osoCancelled);
        Exit;
      end;
      try
        try
          TransportOutcome := FTransport.PostQueryBatch(RequestBody,
            OSVMaximumResponseBytes, @CheckCancelled, HTTPStatus,
            ResponseBody);
        except
          on E: EOutOfMemory do
            raise;
          on E: Exception do
          begin
            if CheckCancelled then
              Fail(osoCancelled)
            else
              Fail(osoTransportFailed);
            Exit;
          end;
        end;
      finally
        EndTransportCall;
      end;
      case TransportOutcome of
        otoCancelled:
          begin
            Fail(osoCancelled);
            Exit;
          end;
        otoResponseTooLarge:
          begin
            Fail(osoResponseLimitExceeded);
            Exit;
          end;
        otoFailed:
          begin
            if CheckCancelled then
              Fail(osoCancelled)
            else
              Fail(osoTransportFailed);
            Exit;
          end;
      end;
      if StopForCancellation then
        Exit;
      if Length(ResponseBody) > OSVMaximumResponseBytes then
      begin
        Fail(osoResponseLimitExceeded);
        Exit;
      end;
      if Result.AggregateResponseBytes + Length(ResponseBody) >
        OSVMaximumAggregateResponseBytes then
      begin
        Fail(osoAggregateResponseLimitExceeded);
        Exit;
      end;
      Inc(Result.AggregateResponseBytes, Length(ResponseBody));
      if HTTPStatus <> 200 then
      begin
        Fail(osoHTTPStatusFailed, HTTPStatus);
        Exit;
      end;
      ParsedBatch := nil;
      try
        try
          ParsedBatch := ParseOSVQueryBatchResponse(ResponseBody, BatchCount,
            @CheckCancelled, RawVulnerabilityEntries);
        except
          on E: EOSVResponseCancelled do
          begin
            Fail(osoCancelled);
            Exit;
          end;
          on E: EOSVResponseMatchLimit do
          begin
            Fail(osoMatchLimitExceeded);
            Exit;
          end;
          on E: EOutOfMemory do
            raise;
          on E: Exception do
          begin
            Fail(osoMalformedResponse);
            Exit;
          end;
        end;

        { Validate all global-count and pagination invariants before applying
          any part of this response. }
        if StopForCancellation then
          Exit;
        TemporaryAdvisories.Assign(Result.AdvisoryIDs);
        if StopForCancellation then
          Exit;
        TemporaryMatches.Assign(MatchKeys);
        if StopForCancellation then
          Exit;
        TemporaryPagination.Assign(SeenPagination);
        for I := 0 to BatchCount - 1 do
        begin
          if StopForCancellation then
            Exit;
          PendingQuery := TOSVPendingQuery(Pending[I]);
          ParsedQuery := TOSVParsedQueryResult(ParsedBatch.Results[I]);
          for J := 0 to ParsedQuery.Vulnerabilities.Count - 1 do
          begin
            if ((J and $3F) = 0) and StopForCancellation then
              Exit;
            ParsedVulnerability :=
              TOSVParsedVulnerability(ParsedQuery.Vulnerabilities[J]);
            TemporaryAdvisories.Add(ParsedVulnerability.AdvisoryID);
            if TemporaryAdvisories.Count > OSVMaximumAdvisoryIDs then
            begin
              Fail(osoAdvisoryLimitExceeded);
              Exit;
            end;
            TemporaryMatches.Add(MatchKey(PendingQuery.PackageURL,
              ParsedVulnerability.AdvisoryID));
            if TemporaryMatches.Count > OSVMaximumMatches then
            begin
              Fail(osoMatchLimitExceeded);
              Exit;
            end;
          end;
          PageToken := ParsedQuery.NextPageToken;
          if PageToken <> '' then
          begin
            Key := PaginationKey(PendingQuery.PackageURL, PageToken);
            if TemporaryPagination.IndexOf(Key) >= 0 then
            begin
              Fail(osoMalformedResponse);
              Exit;
            end;
            TemporaryPagination.Add(Key);
          end;
        end;

        { The response is applied atomically only after every schema, cap,
          pagination, and cancellation check above has succeeded. }
        if StopForCancellation then
          Exit;
        for I := 0 to BatchCount - 1 do
        begin
          if StopForCancellation then
            Exit;
          PendingQuery := TOSVPendingQuery(Pending[I]);
          ParsedQuery := TOSVParsedQueryResult(ParsedBatch.Results[I]);
          for J := 0 to ParsedQuery.Vulnerabilities.Count - 1 do
          begin
            if ((J and $3F) = 0) and StopForCancellation then
              Exit;
            ParsedVulnerability :=
              TOSVParsedVulnerability(ParsedQuery.Vulnerabilities[J]);
            Result.AdvisoryIDs.Add(ParsedVulnerability.AdvisoryID);
            Key := MatchKey(PendingQuery.PackageURL,
              ParsedVulnerability.AdvisoryID);
            MatchIndex := MatchKeys.IndexOf(Key);
            if MatchIndex < 0 then
            begin
              Match := TOSVMatch.Create;
              try
                Match.PackageURL := PendingQuery.PackageURL;
                Match.AdvisoryID := ParsedVulnerability.AdvisoryID;
                Match.Modified := ParsedVulnerability.Modified;
                MatchKeys.AddObject(Key, Match);
                Match := nil;
              finally
                Match.Free;
              end;
            end
            else
            begin
              ExistingMatch := TOSVMatch(MatchKeys.Objects[MatchIndex]);
              if CompareStr(ParsedVulnerability.Modified,
                ExistingMatch.Modified) > 0 then
                ExistingMatch.Modified := ParsedVulnerability.Modified;
            end;
          end;
          PageToken := ParsedQuery.NextPageToken;
          if PageToken <> '' then
          begin
            SeenPagination.Add(PaginationKey(PendingQuery.PackageURL,
              PageToken));
            NextQuery := TOSVPendingQuery.Create;
            try
              NextQuery.PackageURL := PendingQuery.PackageURL;
              NextQuery.PageToken := PageToken;
              Pending.Add(NextQuery);
              NextQuery := nil;
            finally
              NextQuery.Free;
            end;
          end;
        end;
        if StopForCancellation then
          Exit;
      finally
        ParsedBatch.Free;
      end;
      for I := 1 to BatchCount do
      begin
        if StopForCancellation then
          Exit;
        Pending.Delete(0);
      end;
    end;
    if StopForCancellation then
      Exit;
    SetResultOutcome(Result, osoSucceeded, HTTPStatus);
    finally
      try
        if MatchKeys <> nil then
          TransferMatches;
      finally
        FreeUntransferredMatches;
        TemporaryPagination.Free;
        TemporaryMatches.Free;
        TemporaryAdvisories.Free;
        PageTokens.Free;
        PURLs.Free;
        SeenPagination.Free;
        MatchKeys.Free;
        Pending.Free;
        { This is the terminal cancellation/deadline linearization point.
          Cancel or the lookup-wide deadline either marks this query before
          the lock is taken, or observes the client idle after it; success
          cannot be published through the gap. }
        EndQuery(Result);
      end;
    end;
  except
    { The function is the sole owner until a normal return assigns Result to
      its caller.  Deliberately propagated OOM/callback exceptions therefore
      release candidates, rejections, and any already-transferred matches. }
    Result.Free;
    Result := nil;
    raise;
  end;
end;

end.
