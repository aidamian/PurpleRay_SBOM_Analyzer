(**
  PurpleRay SBOM Analyzer deterministic security-findings export.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  This LCL-free unit projects one complete retained OSV.dev snapshot through
  a privacy-minimal whitelist. It neither opens the managed SBOM nor changes
  the scan task, task history, or inventory document.
*)
unit uSecurityFindings;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

const
  SecurityFindingsFormat = 'purpleray-security-findings';
  SecurityFindingsFormatVersion = 1;
  SecurityFindingsSuggestedExtension = '.security-findings.json';

type
  { Fail-closed input error with a stable machine-readable code. }
  ESecurityFindingsError = class(Exception)
  private
    FCode: string;
  public
    constructor Create(const ACode, AMessage: string); reintroduce;
    property Code: string read FCode;
  end;

(**
  Performs the cheap eligibility check used by the desktop action.

  The check does not allocate, serialize, hash, or walk match entries. A True
  result means generation may be attempted; GenerateSecurityFindings remains
  the strict validation boundary for mutable in-memory snapshot fields.
*)
function CanGenerateSecurityFindings(ATask: TScanTask): Boolean;

(**
  Generates one deterministic security-findings document.

  The returned value contains verified UTF-8 JSON and exactly one final line
  feed. Identical task state produces identical bytes. The canonical retained
  known-issue snapshot is hashed as compact UTF-8 JSON without a final line
  feed and bound into the report.

  Raises ESecurityFindingsError with a stable Code for invalid input. Memory
  allocation failures may propagate unchanged.
*)
function GenerateSecurityFindings(ATask: TScanTask): UTF8String;

implementation

uses
  Classes, fpjson, uJSONUtils, uKnownIssues, uKnownIssueService, uOSVCore,
  uSHA256;

const
  ErrorTaskMissing = 'PRSF-E001-TASK-MISSING';
  ErrorTaskNotCompleted = 'PRSF-E002-TASK-NOT-COMPLETED';
  ErrorTaskIDInvalid = 'PRSF-E003-TASK-ID-INVALID';
  ErrorSBOMHashInvalid = 'PRSF-E004-SBOM-HASH-INVALID';
  ErrorSnapshotIncomplete = 'PRSF-E005-SNAPSHOT-INCOMPLETE';
  ErrorSnapshotInvalid = 'PRSF-E006-SNAPSHOT-INVALID';

  AdvisoryClaim =
    'Entries are advisory matches from the retained OSV.dev snapshot, not ' +
    'confirmed vulnerabilities.';
  ReachabilityLimitation =
    'An advisory match does not establish reachability or exploitability.';
  CoverageLimitation =
    'The absence of advisory matches is not a clean bill of health.';

constructor ESecurityFindingsError.Create(const ACode, AMessage: string);
begin
  FCode := ACode;
  inherited Create(ACode + ': ' + AMessage);
end;

function IsCanonicalTaskID(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := Length(AValue) = 36;
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if I in [9, 14, 19, 24] then
    begin
      if AValue[I] <> '-' then
        Exit(False);
    end
    else if not (AValue[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
end;

function IsSHA256(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := Length(AValue) = 64;
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
end;

function IsUTCTimestamp(const AValue: string;
  AAppPrecisionOnly: Boolean): Boolean;
var
  Day, Hour, I, Minute, Month, Second, Year: Integer;

  function Digits(AFirst, ACount: Integer): Integer;
  var
    DigitIndex: Integer;
  begin
    Result := 0;
    for DigitIndex := AFirst to AFirst + ACount - 1 do
      Result := (Result * 10) + (Ord(AValue[DigitIndex]) - Ord('0'));
  end;

  function DaysInMonth(AYear, AMonth: Integer): Integer;
  begin
    case AMonth of
      2:
        if ((AYear mod 4 = 0) and (AYear mod 100 <> 0)) or
          (AYear mod 400 = 0) then
          Result := 29
        else
          Result := 28;
      4, 6, 9, 11: Result := 30;
    else
      Result := 31;
    end;
  end;
begin
  if AAppPrecisionOnly then
    Result := (Length(AValue) = 20) or (Length(AValue) = 24)
  else
    Result := (Length(AValue) = 20) or
      ((Length(AValue) >= 22) and (Length(AValue) <= 30));
  if not Result or (AValue[5] <> '-') or (AValue[8] <> '-') or
    (AValue[11] <> 'T') or (AValue[14] <> ':') or (AValue[17] <> ':') or
    (AValue[Length(AValue)] <> 'Z') then
    Exit(False);
  if (Length(AValue) > 20) and (AValue[20] <> '.') then
    Exit(False);
  for I := 1 to 19 do
    if not (I in [5, 8, 11, 14, 17]) and
      not (AValue[I] in ['0'..'9']) then
      Exit(False);
  for I := 21 to Length(AValue) - 1 do
    if not (AValue[I] in ['0'..'9']) then
      Exit(False);
  Year := Digits(1, 4);
  Month := Digits(6, 2);
  Day := Digits(9, 2);
  Hour := Digits(12, 2);
  Minute := Digits(15, 2);
  Second := Digits(18, 2);
  Result := (Year > 0) and (Month >= 1) and (Month <= 12) and
    (Day >= 1) and (Day <= DaysInMonth(Year, Month)) and
    (Hour <= 23) and (Minute <= 59) and (Second <= 59);
end;

function IsVisibleASCII(const AValue: string; AMaximumBytes: Integer;
  AAllowEmpty: Boolean): Boolean;
var
  I: Integer;
begin
  Result := (Length(AValue) <= AMaximumBytes) and
    (AAllowEmpty or (AValue <> ''));
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Byte(AValue[I]) < 32) or (Byte(AValue[I]) > 126) then
      Exit(False);
end;

function BasicSnapshotFieldsAreValid(ACheck: TKnownIssueCheck): Boolean;
var
  CandidateTotal: Int64;
begin
  Result := KnownIssueCheckCanReplace(ACheck) and
    IsUTCTimestamp(ACheck.CheckedUTC, True) and
    IsVisibleASCII(ACheck.Diagnostic,
      MaximumKnownIssueDiagnosticBytes, True) and
    (ACheck.HTTPStatus >= 0) and (ACheck.HTTPStatus <= 599) and
    (ACheck.RequestCount >= 0) and
    (ACheck.RequestCount <= OSVMaximumRequests) and
    (ACheck.AggregateResponseBytes >= 0) and
    (ACheck.AggregateResponseBytes <= OSVMaximumAggregateResponseBytes) and
    (ACheck.EligibleCandidateCount >= 0) and
    (ACheck.EligibleCandidateCount <= OSVMaximumCandidates) and
    (ACheck.RejectedCandidateCount >= 0) and
    (ACheck.RejectedCandidateCount <= OSVMaximumCandidates) and
    (ACheck.DuplicateCandidateCount >= 0) and
    (ACheck.DuplicateCandidateCount <= OSVMaximumCandidates) and
    (ACheck.AdvisoryCount >= 0) and
    (ACheck.AdvisoryCount <= MaximumKnownIssueAdvisories) and
    (ACheck.MatchCount >= 0) and
    (ACheck.MatchCount <= MaximumKnownIssueMatches);
  if not Result then
    Exit;
  CandidateTotal := Int64(ACheck.EligibleCandidateCount) +
    ACheck.RejectedCandidateCount + ACheck.DuplicateCandidateCount;
  Result := CandidateTotal <= OSVMaximumCandidates;
  if not Result then
    Exit;
  if ACheck.OutcomeCode = OSVOutcomeCode(osoNoEligibleCandidates) then
    Result := (ACheck.EligibleCandidateCount = 0) and
      (ACheck.AdvisoryCount = 0) and (ACheck.MatchCount = 0) and
      (ACheck.HTTPStatus = 0) and (ACheck.RequestCount = 0) and
      (ACheck.AggregateResponseBytes = 0)
  else if ACheck.OutcomeCode = OSVOutcomeCode(osoSucceeded) then
    Result := (ACheck.EligibleCandidateCount > 0) and
      (ACheck.HTTPStatus = 200) and (ACheck.RequestCount > 0);
end;

function CanGenerateSecurityFindings(ATask: TScanTask): Boolean;
begin
  Result := (ATask <> nil) and (ATask.Status = tsCompleted) and
    IsCanonicalTaskID(ATask.ID) and IsSHA256(ATask.GeneratedSBOMSHA256) and
    BasicSnapshotFieldsAreValid(ATask.KnownIssueCheck);
end;

procedure RequireEligibleTask(ATask: TScanTask);
begin
  if ATask = nil then
    raise ESecurityFindingsError.Create(ErrorTaskMissing,
      'Scan task must not be nil');
  if ATask.Status <> tsCompleted then
    raise ESecurityFindingsError.Create(ErrorTaskNotCompleted,
      'Security findings require a completed scan task');
  if not IsCanonicalTaskID(ATask.ID) then
    raise ESecurityFindingsError.Create(ErrorTaskIDInvalid,
      'Task identifier must be a canonical UUID without braces');
  if not IsSHA256(ATask.GeneratedSBOMSHA256) then
    raise ESecurityFindingsError.Create(ErrorSBOMHashInvalid,
      'Managed-SBOM SHA-256 is missing or invalid');
  if not KnownIssueCheckCanReplace(ATask.KnownIssueCheck) then
    raise ESecurityFindingsError.Create(ErrorSnapshotIncomplete,
      'A complete retained OSV.dev snapshot is required');
  if not BasicSnapshotFieldsAreValid(ATask.KnownIssueCheck) then
    raise ESecurityFindingsError.Create(ErrorSnapshotInvalid,
      'Retained OSV.dev snapshot fields are malformed or exceed limits');
end;

function CompareOrdinalBytes(const AFirst, ASecond: string): Integer;
var
  I, Limit: Integer;
begin
  Limit := Length(AFirst);
  if Length(ASecond) < Limit then
    Limit := Length(ASecond);
  for I := 1 to Limit do
  begin
    if Byte(AFirst[I]) < Byte(ASecond[I]) then
      Exit(-1);
    if Byte(AFirst[I]) > Byte(ASecond[I]) then
      Exit(1);
  end;
  if Length(AFirst) < Length(ASecond) then
    Result := -1
  else if Length(AFirst) > Length(ASecond) then
    Result := 1
  else
    Result := 0;
end;

procedure ValidateSnapshotMatches(ACheck: TKnownIssueCheck);
var
  Advisories: TStringList;
  CanonicalPURL, PreviousAdvisory, PreviousPURL: string;
  I, PURLComparison: Integer;
  Match: TKnownIssueMatch;
  RejectionReason: TOSVCandidateRejectionReason;
begin
  Advisories := TStringList.Create;
  try
    Advisories.Sorted := True;
    Advisories.CaseSensitive := True;
    Advisories.UseLocale := False;
    Advisories.Duplicates := dupIgnore;
    PreviousPURL := '';
    PreviousAdvisory := '';
    for I := 0 to ACheck.MatchCount - 1 do
    begin
      Match := ACheck.Matches[I];
      CanonicalPURL := '';
      if (Match = nil) or
        not TryCanonicalOSVPackageURL(Match.PackageURL, CanonicalPURL,
          RejectionReason) or (CanonicalPURL <> Match.PackageURL) or
        not IsVisibleASCII(Match.AdvisoryID, 256, False) or
        (Pos(' ', Match.AdvisoryID) > 0) or
        not IsVisibleASCII(Match.Modified, 128, False) or
        (Pos(' ', Match.Modified) > 0) or
        not IsUTCTimestamp(Match.Modified, False) then
        raise ESecurityFindingsError.Create(ErrorSnapshotInvalid,
          'Retained OSV.dev snapshot contains an invalid advisory match');
      if I > 0 then
      begin
        PURLComparison := CompareOrdinalBytes(PreviousPURL, Match.PackageURL);
        if (PURLComparison > 0) or ((PURLComparison = 0) and
          (CompareOrdinalBytes(PreviousAdvisory, Match.AdvisoryID) >= 0)) then
          raise ESecurityFindingsError.Create(ErrorSnapshotInvalid,
            'Retained OSV.dev advisory matches are not in canonical order');
      end;
      PreviousPURL := Match.PackageURL;
      PreviousAdvisory := Match.AdvisoryID;
      Advisories.Add(Match.AdvisoryID);
    end;
    if Advisories.Count <> ACheck.AdvisoryCount then
      raise ESecurityFindingsError.Create(ErrorSnapshotInvalid,
        'Retained OSV.dev advisory count is inconsistent');
  finally
    Advisories.Free;
  end;
end;

function CanonicalSnapshotBytes(ACheck: TKnownIssueCheck): UTF8String;
var
  Value: TJSONObject;
begin
  Value := nil;
  try
    try
      ValidateSnapshotMatches(ACheck);
      Value := ACheck.ToJSON;
      Result := SerializeJSONUTF8(Value, AsCompressedJSON, 0, False);
    except
      on E: EOutOfMemory do
        raise;
      on E: Exception do
        raise ESecurityFindingsError.Create(ErrorSnapshotInvalid,
          'Retained OSV.dev snapshot is malformed or exceeds limits');
    end;
  finally
    Value.Free;
  end;
end;

procedure AddOwnedObject(AParent: TJSONObject; const AName: string;
  out AChild: TJSONObject); overload;
begin
  AChild := TJSONObject.Create;
  try
    AParent.Add(AName, AChild);
  except
    AChild.Free;
    AChild := nil;
    raise;
  end;
end;

procedure AddOwnedObject(AParent: TJSONArray;
  out AChild: TJSONObject); overload;
begin
  AChild := TJSONObject.Create;
  try
    AParent.Add(AChild);
  except
    AChild.Free;
    AChild := nil;
    raise;
  end;
end;

procedure AddOwnedArray(AParent: TJSONObject; const AName: string;
  out AChild: TJSONArray);
begin
  AChild := TJSONArray.Create;
  try
    AParent.Add(AName, AChild);
  except
    AChild.Free;
    AChild := nil;
    raise;
  end;
end;

function GenerateSecurityFindings(ATask: TScanTask): UTF8String;
var
  Check: TKnownIssueCheck;
  SnapshotBytes: UTF8String;
  Root, SourceValue, SummaryValue, ClaimValue, PrivacyValue,
    MatchValue: TJSONObject;
  MatchValues, Limitations: TJSONArray;
  I: Integer;
begin
  RequireEligibleTask(ATask);
  Check := ATask.KnownIssueCheck;
  SnapshotBytes := CanonicalSnapshotBytes(Check);

  Root := TJSONObject.Create;
  try
    Root.Add('format', SecurityFindingsFormat);
    Root.Add('formatVersion', SecurityFindingsFormatVersion);

    AddOwnedObject(Root, 'source', SourceValue);
    SourceValue.Add('taskId', LowerCase(ATask.ID));
    SourceValue.Add('managedSbomSha256',
      LowerCase(ATask.GeneratedSBOMSHA256));
    SourceValue.Add('knownIssueSnapshotSha256',
      SHA256String(RawByteString(SnapshotBytes)));
    SourceValue.Add('provider', KnownIssueSource);
    SourceValue.Add('checkedUtc', Check.CheckedUTC);
    SourceValue.Add('outcome', Check.OutcomeCode);
    AddOwnedObject(Root, 'summary', SummaryValue);
    SummaryValue.Add('eligibleCandidateCount', Check.EligibleCandidateCount);
    SummaryValue.Add('advisoryCount', Check.AdvisoryCount);
    SummaryValue.Add('matchCount', Check.MatchCount);
    AddOwnedObject(Root, 'claim', ClaimValue);
    ClaimValue.Add('kind', 'advisory-matches');
    ClaimValue.Add('confirmedVulnerabilities', False);
    ClaimValue.Add('text', AdvisoryClaim);
    AddOwnedObject(Root, 'privacy', PrivacyValue);
    PrivacyValue.Add('pathsIncluded', False);
    PrivacyValue.Add('contactsIncluded', False);
    PrivacyValue.Add('diagnosticsIncluded', False);
    AddOwnedArray(Root, 'matches', MatchValues);
    for I := 0 to Check.MatchCount - 1 do
    begin
      AddOwnedObject(MatchValues, MatchValue);
      MatchValue.Add('packageUrl', Check.Matches[I].PackageURL);
      MatchValue.Add('advisoryId', Check.Matches[I].AdvisoryID);
      MatchValue.Add('recordModified', Check.Matches[I].Modified);
    end;

    AddOwnedArray(Root, 'limitations', Limitations);
    Limitations.Add(ReachabilityLimitation);
    Limitations.Add(CoverageLimitation);
    Result := SerializeJSONUTF8(Root, [], 2, True);
  finally
    Root.Free;
  end;
end;

end.
