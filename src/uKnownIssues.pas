(**
  PurpleRay SBOM Analyzer persisted known-issue results.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  The model retains only bounded lookup outcomes and deduplicated advisory
  matches. It deliberately excludes consent, request bodies, raw responses,
  pagination tokens, rejected coordinates, and transport implementation data.
*)
unit uKnownIssues;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, fpjson, uOSVCore;

const
  KnownIssueSource = 'OSV.dev';
  MaximumKnownIssueMatches = OSVMaximumMatches;
  MaximumKnownIssueAdvisories = OSVMaximumAdvisoryIDs;
  MaximumKnownIssueDiagnosticBytes = 1024;
  { Leaves at least 56 MiB of the 64 MiB history-reader budget for the task's
    inventory fields. The estimate below assumes worst-case JSON escaping. }
  MaximumKnownIssueSerializedBytes = 8 * 1024 * 1024;

type
  {** One canonical package/advisory association returned by OSV.dev. *}
  TKnownIssueMatch = class
  public
    PackageURL: string;
    AdvisoryID: string;
    Modified: string;
    function Clone: TKnownIssueMatch;
  end;

  {** Bounded, owned state for one explicit per-scan known-issue check. *}
  TKnownIssueCheck = class
  private
    FAdvisoryIDs: TStringList;
    FEstimatedSerializedBytes: Int64;
    FMatchKeys: TStringList;
    FMatches: TObjectList;
    function GetMatch(AIndex: Integer): TKnownIssueMatch;
  public
    Requested: Boolean;
    CheckedUTC: string;
    OutcomeCode: string;
    Diagnostic: string;
    HTTPStatus: Integer;
    RequestCount: Integer;
    AggregateResponseBytes: Int64;
    EligibleCandidateCount: Integer;
    RejectedCandidateCount: Integer;
    DuplicateCandidateCount: Integer;
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    procedure Assign(ASource: TKnownIssueCheck);
    function Clone: TKnownIssueCheck;
    function AddMatch(AMatch: TKnownIssueMatch): Boolean;
    procedure AssignOSVResult(AResult: TOSVLookupResult;
      const ACheckedUTC: string);
    procedure MarkUnavailable(const ACheckedUTC, AOutcomeCode,
      ADiagnostic: string);
    function AdvisoryCount: Integer;
    function MatchCount: Integer;
    function MatchCountForPackageURL(const APackageURL: string): Integer;
    function IsPartial: Boolean;
    function ToJSON: TJSONObject;
    class function FromJSON(AObject: TJSONObject): TKnownIssueCheck; static;
    property Matches[AIndex: Integer]: TKnownIssueMatch read GetMatch;
  end;

implementation

uses
  uJSONUtils;

function NewOrdinalStringList: TStringList;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.CaseSensitive := True;
  Result.UseLocale := False;
  Result.Duplicates := dupIgnore;
end;

function IsVisibleASCII(const AValue: string; AMaximumBytes: Integer;
  AAllowEmpty: Boolean = False): Boolean;
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

function IsCompactVisibleASCII(const AValue: string;
  AMaximumBytes: Integer): Boolean;
var
  I: Integer;
begin
  Result := (AValue <> '') and (Length(AValue) <= AMaximumBytes);
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Byte(AValue[I]) < 33) or (Byte(AValue[I]) > 126) then
      Exit(False);
end;

function MatchIsValid(AMatch: TKnownIssueMatch): Boolean;
var
  CanonicalPURL: string;
  Reason: TOSVCandidateRejectionReason;
begin
  CanonicalPURL := '';
  Result := (AMatch <> nil) and
    TryCanonicalOSVPackageURL(AMatch.PackageURL, CanonicalPURL, Reason) and
    (CanonicalPURL = AMatch.PackageURL) and
    IsCompactVisibleASCII(AMatch.AdvisoryID, 256) and
    IsCompactVisibleASCII(AMatch.Modified, 128);
end;

function IsKnownOutcomeCode(const AValue: string): Boolean;
var
  Outcome: TOSVOutcome;
begin
  Result := (AValue = 'transport-unavailable') or
    (AValue = 'lookup-failed');
  if Result then
    Exit;
  for Outcome := Low(TOSVOutcome) to High(TOSVOutcome) do
    if AValue = OSVOutcomeCode(Outcome) then
      Exit(True);
end;

function MatchEstimatedJSONBytes(AMatch: TKnownIssueMatch): Int64; forward;

function ScalarFieldsAreValid(ACheck: TKnownIssueCheck): Boolean;
var
  CandidateTotal: Int64;
  EstimatedBytes: Int64;
  I: Integer;
begin
  Result := (ACheck <> nil) and ACheck.Requested and
    IsVisibleASCII(ACheck.CheckedUTC, 64) and
    IsVisibleASCII(ACheck.OutcomeCode, 128) and
    IsKnownOutcomeCode(ACheck.OutcomeCode) and
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
    (ACheck.MatchCount <= MaximumKnownIssueMatches) and
    (ACheck.AdvisoryCount <= MaximumKnownIssueAdvisories);
  if not Result then
    Exit;
  CandidateTotal := Int64(ACheck.EligibleCandidateCount) +
    ACheck.RejectedCandidateCount + ACheck.DuplicateCandidateCount;
  if CandidateTotal > OSVMaximumCandidates then
    Exit(False);
  EstimatedBytes := 2048;
  for I := 0 to ACheck.MatchCount - 1 do
  begin
    if not MatchIsValid(ACheck.Matches[I]) then
      Exit(False);
    { Visible ASCII needs at most two JSON bytes per source byte. The fixed
      allowance covers member names, punctuation, indentation, and line ends. }
    Inc(EstimatedBytes, MatchEstimatedJSONBytes(ACheck.Matches[I]));
    if EstimatedBytes > MaximumKnownIssueSerializedBytes then
      Exit(False);
  end;
end;

function MatchKey(AMatch: TKnownIssueMatch): string;
begin
  Result := AMatch.PackageURL + #1 + AMatch.AdvisoryID;
end;

function MatchEstimatedJSONBytes(AMatch: TKnownIssueMatch): Int64;
begin
  if AMatch = nil then
    Exit(0);
  Result := 128 + (2 * Int64(Length(AMatch.PackageURL))) +
    (2 * Int64(Length(AMatch.AdvisoryID))) +
    (2 * Int64(Length(AMatch.Modified)));
end;

function TKnownIssueMatch.Clone: TKnownIssueMatch;
begin
  Result := TKnownIssueMatch.Create;
  try
    Result.PackageURL := PackageURL;
    Result.AdvisoryID := AdvisoryID;
    Result.Modified := Modified;
  except
    Result.Free;
    raise;
  end;
end;

constructor TKnownIssueCheck.Create;
begin
  inherited Create;
  FAdvisoryIDs := NewOrdinalStringList;
  FEstimatedSerializedBytes := 2048;
  FMatchKeys := NewOrdinalStringList;
  FMatches := TObjectList.Create(True);
end;

destructor TKnownIssueCheck.Destroy;
begin
  FMatches.Free;
  FMatchKeys.Free;
  FAdvisoryIDs.Free;
  inherited Destroy;
end;

procedure TKnownIssueCheck.Clear;
begin
  Requested := False;
  CheckedUTC := '';
  OutcomeCode := '';
  Diagnostic := '';
  HTTPStatus := 0;
  RequestCount := 0;
  AggregateResponseBytes := 0;
  EligibleCandidateCount := 0;
  RejectedCandidateCount := 0;
  DuplicateCandidateCount := 0;
  FMatches.Clear;
  FEstimatedSerializedBytes := 2048;
  FMatchKeys.Clear;
  FAdvisoryIDs.Clear;
end;

function TKnownIssueCheck.GetMatch(AIndex: Integer): TKnownIssueMatch;
begin
  Result := TKnownIssueMatch(FMatches[AIndex]);
end;

function TKnownIssueCheck.AddMatch(AMatch: TKnownIssueMatch): Boolean;
var
  AdvisoryIndex, MatchIndex: Integer;
  AdvisoryAdded, KeyAdded, NewAdvisory: Boolean;
  Key: string;
begin
  Result := False;
  if AMatch = nil then
    Exit;
  try
    if not MatchIsValid(AMatch) then
      Exit;
    if FEstimatedSerializedBytes + MatchEstimatedJSONBytes(AMatch) >
      MaximumKnownIssueSerializedBytes then
      Exit;
    Key := MatchKey(AMatch);
    if FMatchKeys.Find(Key, MatchIndex) then
      Exit;
    if FMatches.Count >= MaximumKnownIssueMatches then
      Exit;
    NewAdvisory := FAdvisoryIDs.IndexOf(AMatch.AdvisoryID) < 0;
    if NewAdvisory and
      (FAdvisoryIDs.Count >= MaximumKnownIssueAdvisories) then
      Exit;
    AdvisoryAdded := False;
    KeyAdded := False;
    AdvisoryIndex := -1;
    try
      if NewAdvisory then
      begin
        AdvisoryIndex := FAdvisoryIDs.Add(AMatch.AdvisoryID);
        AdvisoryAdded := True;
      end;
      MatchIndex := FMatchKeys.Add(Key);
      KeyAdded := True;
      FMatches.Insert(MatchIndex, AMatch);
      Inc(FEstimatedSerializedBytes, MatchEstimatedJSONBytes(AMatch));
      AMatch := nil;
      Result := True;
    except
      if KeyAdded then
        FMatchKeys.Delete(MatchIndex);
      if AdvisoryAdded then
        FAdvisoryIDs.Delete(AdvisoryIndex);
      raise;
    end;
  finally
    AMatch.Free;
  end;
end;

procedure TKnownIssueCheck.Assign(ASource: TKnownIssueCheck);
var
  I: Integer;
begin
  Clear;
  if ASource = nil then
    Exit;
  Requested := ASource.Requested;
  CheckedUTC := ASource.CheckedUTC;
  OutcomeCode := ASource.OutcomeCode;
  Diagnostic := ASource.Diagnostic;
  HTTPStatus := ASource.HTTPStatus;
  RequestCount := ASource.RequestCount;
  AggregateResponseBytes := ASource.AggregateResponseBytes;
  EligibleCandidateCount := ASource.EligibleCandidateCount;
  RejectedCandidateCount := ASource.RejectedCandidateCount;
  DuplicateCandidateCount := ASource.DuplicateCandidateCount;
  for I := 0 to ASource.MatchCount - 1 do
    if not AddMatch(ASource.Matches[I].Clone) then
      raise EInvalidOperation.Create('Unable to clone known-issue match');
end;

function TKnownIssueCheck.Clone: TKnownIssueCheck;
begin
  Result := TKnownIssueCheck.Create;
  try
    Result.Assign(Self);
  except
    Result.Free;
    raise;
  end;
end;

procedure TKnownIssueCheck.AssignOSVResult(AResult: TOSVLookupResult;
  const ACheckedUTC: string);
var
  I: Integer;
  MatchToAdd, MatchValue: TKnownIssueMatch;
  SourceMatch: TOSVMatch;
begin
  if AResult = nil then
    raise EArgumentNilException.Create('OSV lookup result is nil');
  if not IsVisibleASCII(ACheckedUTC, 64) then
    raise EArgumentException.Create('Known-issue check time is invalid');
  if not IsVisibleASCII(AResult.DiagnosticCode, 128) or
    not IsKnownOutcomeCode(AResult.DiagnosticCode) or
    not IsVisibleASCII(AResult.Diagnostic,
      MaximumKnownIssueDiagnosticBytes, True) then
    raise EArgumentException.Create('OSV result diagnostic is invalid');
  Clear;
  Requested := True;
  CheckedUTC := ACheckedUTC;
  OutcomeCode := AResult.DiagnosticCode;
  Diagnostic := AResult.Diagnostic;
  HTTPStatus := AResult.HTTPStatus;
  RequestCount := AResult.RequestCount;
  AggregateResponseBytes := AResult.AggregateResponseBytes;
  EligibleCandidateCount := AResult.EligibleCandidates.Count;
  RejectedCandidateCount := AResult.RejectedCandidates.Count;
  DuplicateCandidateCount := AResult.DuplicateCandidateCount;
  for I := 0 to AResult.Matches.Count - 1 do
  begin
    SourceMatch := TOSVMatch(AResult.Matches[I]);
    MatchValue := TKnownIssueMatch.Create;
    try
      MatchValue.PackageURL := SourceMatch.PackageURL;
      MatchValue.AdvisoryID := SourceMatch.AdvisoryID;
      MatchValue.Modified := SourceMatch.Modified;
      MatchToAdd := MatchValue;
      MatchValue := nil;
      if not AddMatch(MatchToAdd) then
        raise EInvalidOperation.Create(
          'OSV result contains an invalid or over-budget match');
    finally
      MatchValue.Free;
    end;
  end;
  if not ScalarFieldsAreValid(Self) then
    raise EInvalidOperation.Create('OSV result exceeds persisted limits');
end;

procedure TKnownIssueCheck.MarkUnavailable(const ACheckedUTC, AOutcomeCode,
  ADiagnostic: string);
begin
  if not IsVisibleASCII(ACheckedUTC, 64) or
    not IsVisibleASCII(AOutcomeCode, 128) or
    not IsKnownOutcomeCode(AOutcomeCode) or
    not IsVisibleASCII(ADiagnostic, MaximumKnownIssueDiagnosticBytes) then
    raise EArgumentException.Create('Invalid known-issue diagnostic');
  Clear;
  Requested := True;
  CheckedUTC := ACheckedUTC;
  OutcomeCode := AOutcomeCode;
  Diagnostic := ADiagnostic;
end;

function TKnownIssueCheck.AdvisoryCount: Integer;
begin
  Result := FAdvisoryIDs.Count;
end;

function TKnownIssueCheck.MatchCount: Integer;
begin
  Result := FMatches.Count;
end;

function TKnownIssueCheck.MatchCountForPackageURL(
  const APackageURL: string): Integer;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to FMatches.Count - 1 do
    if Matches[I].PackageURL = APackageURL then
      Inc(Result);
end;

function TKnownIssueCheck.IsPartial: Boolean;
begin
  Result := (FMatches.Count > 0) and
    (OutcomeCode <> OSVOutcomeCode(osoSucceeded));
end;

function TKnownIssueCheck.ToJSON: TJSONObject;
var
  I: Integer;
  MatchObject: TJSONObject;
  MatchValues: TJSONArray;
begin
  if not ScalarFieldsAreValid(Self) then
    raise EInvalidOperation.Create('Known-issue result is incomplete');
  Result := TJSONObject.Create;
  try
    Result.Add('requested', Requested);
    Result.Add('source', KnownIssueSource);
    Result.Add('checked_utc', CheckedUTC);
    Result.Add('outcome', OutcomeCode);
    if Diagnostic <> '' then
      Result.Add('diagnostic', Diagnostic);
    Result.Add('http_status', HTTPStatus);
    Result.Add('request_count', RequestCount);
    Result.Add('aggregate_response_bytes', AggregateResponseBytes);
    Result.Add('eligible_candidate_count', EligibleCandidateCount);
    Result.Add('rejected_candidate_count', RejectedCandidateCount);
    Result.Add('duplicate_candidate_count', DuplicateCandidateCount);
    MatchValues := TJSONArray.Create;
    Result.Add('matches', MatchValues);
    for I := 0 to FMatches.Count - 1 do
    begin
      MatchObject := TJSONObject.Create;
      try
        MatchObject.Add('package_url', Matches[I].PackageURL);
        MatchObject.Add('advisory_id', Matches[I].AdvisoryID);
        MatchObject.Add('modified', Matches[I].Modified);
        MatchValues.Add(MatchObject);
        MatchObject := nil;
      finally
        MatchObject.Free;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TKnownIssueCheck.FromJSON(
  AObject: TJSONObject): TKnownIssueCheck;
var
  Data: TJSONData;
  I: Integer;
  MatchObject: TJSONObject;
  MatchToAdd: TKnownIssueMatch;
  MatchValue: TKnownIssueMatch;
  MatchValues: TJSONArray;
  RequestedData: TJSONData;

  function BoundedInteger(const AName: string; AMinimum,
    AMaximum: Int64): Int64;
  var
    IntegerData: TJSONData;
  begin
    IntegerData := AObject.Find(AName);
    if (IntegerData = nil) or (IntegerData.JSONType <> jtNumber) then
      raise EJSON.CreateFmt('known-issue "%s" must be an integer',
        [AName]);
    try
      Result := IntegerData.AsInt64;
      if IntegerData.AsJSON <> IntToStr(Result) then
        raise EJSON.CreateFmt('known-issue "%s" must be an integer',
          [AName]);
    except
      on EJSON do
        raise;
      on Exception do
        raise EJSON.CreateFmt('known-issue "%s" must be an integer',
          [AName]);
    end;
    if (Result < AMinimum) or (Result > AMaximum) then
      raise EJSON.CreateFmt('known-issue "%s" is outside its limit',
        [AName]);
  end;

  function RequiredString(const AName: string;
    AAllowMissing: Boolean = False): string;
  var
    StringData: TJSONData;
  begin
    StringData := AObject.Find(AName);
    if StringData = nil then
    begin
      if AAllowMissing then
        Exit('');
      raise EJSON.CreateFmt('known-issue "%s" must be a string', [AName]);
    end;
    if StringData.JSONType <> jtString then
      raise EJSON.CreateFmt('known-issue "%s" must be a string', [AName]);
    Result := StringData.AsString;
  end;

  function RequiredMatchString(AMatchObject: TJSONObject;
    const AName: string): string;
  var
    StringData: TJSONData;
  begin
    StringData := AMatchObject.Find(AName);
    if (StringData = nil) or (StringData.JSONType <> jtString) then
      raise EJSON.CreateFmt('known-issue match "%s" must be a string',
        [AName]);
    Result := StringData.AsString;
  end;

begin
  if AObject = nil then
    raise EArgumentNilException.Create('Known-issue JSON object is nil');
  Result := TKnownIssueCheck.Create;
  try
    RequestedData := AObject.Find('requested');
    if (RequestedData = nil) or (RequestedData.JSONType <> jtBoolean) then
      raise EJSON.Create('known-issue "requested" must be a Boolean');
    Result.Requested := RequestedData.AsBoolean;
    if not Result.Requested then
      raise EJSON.Create('persisted known-issue result was not requested');
    if RequiredString('source') <> KnownIssueSource then
      raise EJSON.Create('known-issue source is unsupported');
    Result.CheckedUTC := RequiredString('checked_utc');
    Result.OutcomeCode := RequiredString('outcome');
    Result.Diagnostic := RequiredString('diagnostic', True);
    if not IsVisibleASCII(Result.CheckedUTC, 64) or
      not IsVisibleASCII(Result.OutcomeCode, 128) or
      not IsKnownOutcomeCode(Result.OutcomeCode) or
      not IsVisibleASCII(Result.Diagnostic,
        MaximumKnownIssueDiagnosticBytes, True) then
      raise EJSON.Create('known-issue fields are invalid or exceed limits');
    Result.HTTPStatus := Integer(BoundedInteger('http_status', 0, 599));
    Result.RequestCount := Integer(BoundedInteger('request_count', 0,
      OSVMaximumRequests));
    Result.AggregateResponseBytes := BoundedInteger(
      'aggregate_response_bytes', 0, OSVMaximumAggregateResponseBytes);
    Result.EligibleCandidateCount := Integer(BoundedInteger(
      'eligible_candidate_count', 0, OSVMaximumCandidates));
    Result.RejectedCandidateCount := Integer(BoundedInteger(
      'rejected_candidate_count', 0, OSVMaximumCandidates));
    Result.DuplicateCandidateCount := Integer(BoundedInteger(
      'duplicate_candidate_count', 0, OSVMaximumCandidates));
    Data := AObject.Find('matches');
    if (Data = nil) or (Data.JSONType <> jtArray) then
      raise EJSON.Create('known-issue "matches" must be an array');
    MatchValues := TJSONArray(Data);
    if MatchValues.Count > MaximumKnownIssueMatches then
      raise EJSON.Create('known-issue match limit exceeded');
    for I := 0 to MatchValues.Count - 1 do
    begin
      if MatchValues.Items[I].JSONType <> jtObject then
        raise EJSON.Create('known-issue match must be an object');
      MatchObject := TJSONObject(MatchValues.Items[I]);
      MatchValue := TKnownIssueMatch.Create;
      try
        MatchValue.PackageURL := RequiredMatchString(MatchObject,
          'package_url');
        MatchValue.AdvisoryID := RequiredMatchString(MatchObject,
          'advisory_id');
        MatchValue.Modified := RequiredMatchString(MatchObject, 'modified');
        if not MatchIsValid(MatchValue) then
          raise EJSON.Create('known-issue match is invalid');
        { AddMatch always consumes its argument, including rejection paths. }
        MatchToAdd := MatchValue;
        MatchValue := nil;
        if not Result.AddMatch(MatchToAdd) then
          raise EJSON.Create(
            'known-issue match is duplicated or exceeds limits');
      finally
        MatchValue.Free;
      end;
    end;
    if Result.AdvisoryCount > MaximumKnownIssueAdvisories then
      raise EJSON.Create('known-issue advisory limit exceeded');
    if not ScalarFieldsAreValid(Result) then
      raise EJSON.Create('known-issue scalar fields are inconsistent');
  except
    Result.Free;
    raise;
  end;
end;

end.
