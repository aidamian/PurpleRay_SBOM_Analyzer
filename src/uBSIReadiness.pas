(**
  PurpleRay SBOM Analyzer BSI readiness-assessment unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Produces a deterministic field-availability assessment pinned to BSI
  TR-03183-2 v2.1.0. The unit deliberately produces an assessment report, not
  an SBOM and not a statement of conformity. It consumes exact managed
  CycloneDX bytes, verifies their expected SHA-256, and rebuilds a
  privacy-minimal report from a strict whitelist. Source paths, contacts,
  diagnostics, and dynamic security findings are never copied into the report.

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
unit uBSIReadiness;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

const
  { Stable discriminator written to the top-level report format member. }
  BSIReadinessReportFormat = 'purpleray-bsi-tr-03183-2-readiness';
  { Closed report contract version, independent of the target guideline. }
  BSIReadinessReportFormatVersion = 1;
  { Suggested suffix for a readiness artifact derived from an SBOM filename. }
  BSIReadinessSuggestedExtension =
    '.bsi-tr-03183-2-v2.1.0-readiness.json';

type
  { Overall assessment state. A report can require review only when it has no
    deterministic blockers; neither state represents compliance. }
  TBSIReadinessStatus = (brsBlocked, brsReviewRequired);

  { Aggregate counters returned alongside the serialized report. }
  TBSIReadinessSummary = record
    Status: TBSIReadinessStatus;
    ComponentsAssessed: Int64;
    Mapped: Int64;
    Derivable: Int64;
    NotApplicable: Int64;
    NotObserved: Int64;
    Blocked: Int64;
    AdvisoryCount: Int64;
  end;

  { Fail-closed input error with a stable machine-readable Code. }
  EBSIReadinessError = class(Exception)
  private
    FCode: string;
  public
    constructor Create(const ACode, AMessage: string); reintroduce;
    property Code: string read FCode;
  end;

(**
  Returns the stable JSON spelling of an assessment status.

  Parameters
  ----------
  AStatus
    Status value to serialize.

  Returns
  -------
  string
    ``blocked`` or ``review-required``.

  Raises
  ------
  None
*)
function BSIReadinessStatusToString(AStatus: TBSIReadinessStatus): string;

(**
  Generates a deterministic readiness report from exact managed-SBOM bytes.

  Parameters
  ----------
  AManagedSBOMBytes
    Complete managed CycloneDX JSON bytes. No file is opened by this unit.
  AExpectedSHA256
    Persisted 64-character SHA-256 digest for exactly those bytes.
  ATaskID
    Canonical UUID without braces; hexadecimal letters may use either case.
  ASummary
    Receives the same status and aggregate counters serialized into the report.

  Returns
  -------
  UTF8String
    Deterministic pretty-printed JSON conforming to report format version 1.

  Raises
  ------
  EBSIReadinessError
    Raised with a stable Code when the task ID, size, digest, UTF-8, JSON, or
    root shape is invalid. No report is returned after an input failure.
  EOutOfMemory
    May propagate when the bounded assessment cannot be allocated.

  Notes
  -----
  The report is regenerated from a privacy whitelist and never claims BSI
  conformity. It neither mutates nor replaces the managed SBOM, its digest, or
  any scan/cache state.
*)
function GenerateBSIReadinessReport(
  const AManagedSBOMBytes: RawByteString;
  const AExpectedSHA256, ATaskID: string;
  out ASummary: TBSIReadinessSummary): UTF8String;

implementation

uses
  Classes, Contnrs, fpjson, uJSONUtils, uSHA256;

const
  GuidelinePDFSHA256 =
    'dda0ccd9b6148571d1d12241a1618b30027f22bc15e24248fdd21a011e62845c';
  TaxonomyCommit = 'f4c887cae2f46ec284e52ea0a86407bcffaecb91';

  StatusMapped = 'mapped';
  StatusDerivable = 'derivable';
  StatusNotApplicable = 'not-applicable';
  StatusNotObserved = 'not-observed';
  StatusBlocked = 'blocked';

  RequirementMust = 'MUST';
  RequirementMustIfExists = 'MUST_IF_EXISTS';
  RequirementMay = 'MAY';

  ErrorTaskID = 'BSI210-E001-SOURCE-TASK-ID-INVALID';
  ErrorSourceSize = 'BSI210-E002-SOURCE-SIZE-INVALID';
  ErrorExpectedHash = 'BSI210-E003-SOURCE-HASH-MISSING';
  ErrorHashMismatch = 'BSI210-E004-SOURCE-HASH-MISMATCH';
  ErrorJSON = 'BSI210-E005-SOURCE-JSON-INVALID';

  BlockFormat = 'BSI210-D001-FORMAT-NOT-CYCLONEDX-1_6-PLUS';
  BlockVulnerability = 'BSI210-D002-VULNERABILITY-INFORMATION-PRESENT';
  BlockSBOMCreator = 'BSI210-D003-SBOM-CREATOR-CONTACT-NOT-MAPPED';
  BlockTimestamp = 'BSI210-D004-TIMESTAMP-NOT-MAPPED';
  BlockDependencies = 'BSI210-D005-DEPENDENCY-ENUMERATION-INCOMPLETE';
  BlockBuildEvidence = 'BSI210-D006-BUILD-EQUIVALENCE-UNPROVEN';

  BlockKind = 'BSI210-C001-DESCRIPTION-KIND-UNKNOWN';
  BlockLevel = 'BSI210-C002-DESCRIPTION-LEVEL-UNKNOWN';
  BlockCreator = 'BSI210-C003-CREATOR-CONTACT-NOT-MAPPED';
  BlockName = 'BSI210-C004-NAME-NOT-MAPPED';
  BlockVersion = 'BSI210-C005-VERSION-NOT-MAPPED';
  BlockFilename = 'BSI210-C006-FILENAME-NOT-MAPPED';
  BlockComponentDependencies =
    'BSI210-C007-DEPENDENCY-COMPLETENESS-UNPROVEN';
  BlockDistributionLicence =
    'BSI210-C008-DISTRIBUTION-LICENCE-NOT-MAPPED';
  BlockDeployableHash = 'BSI210-C009-DEPLOYABLE-SHA512-NOT-MAPPED';
  BlockExecutable = 'BSI210-C010-EXECUTABLE-CLASSIFICATION-UNKNOWN';
  BlockArchive = 'BSI210-C011-ARCHIVE-CLASSIFICATION-UNKNOWN';
  BlockStructured = 'BSI210-C012-STRUCTURED-CLASSIFICATION-UNKNOWN';
  BlockSourceURI = 'BSI210-C013-SOURCE-URI-EXISTENCE-UNKNOWN';
  BlockDeployableURI = 'BSI210-C014-DEPLOYABLE-URI-EXISTENCE-UNKNOWN';
  BlockIdentifier = 'BSI210-C015-OTHER-IDENTIFIER-EXISTENCE-UNKNOWN';
  BlockOriginalLicence =
    'BSI210-C016-ORIGINAL-LICENCE-EXISTENCE-UNKNOWN';
  BlockSourceHash = 'BSI210-C017-SOURCE-SHA512-NOT-MAPPED';
  BlockEffectiveLicence =
    'BSI210-C018-EFFECTIVE-LICENCE-PROPERTY-INVALID';

type
  TBSIComponentSource = class
  public
    Source: TJSONObject;
    IsPrimary: Boolean;
    Ordinal: Integer;
    RawReference: string;
    ComponentID: string;
    SortKey: string;
  end;

constructor EBSIReadinessError.Create(const ACode, AMessage: string);
begin
  FCode := ACode;
  inherited Create(ACode + ': ' + AMessage);
end;

function BSIReadinessStatusToString(AStatus: TBSIReadinessStatus): string;
begin
  case AStatus of
    brsBlocked: Result := 'blocked';
  else
    Result := 'review-required';
  end;
end;

function StrictString(AObject: TJSONObject; const AName: string): string;
var
  Value: TJSONData;
begin
  Result := '';
  if AObject = nil then
    Exit;
  Value := AObject.Find(AName);
  if (Value <> nil) and (Value.JSONType = jtString) then
    Result := Value.AsString;
end;

function StrictObject(AObject: TJSONObject; const AName: string): TJSONObject;
var
  Value: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Value := AObject.Find(AName);
  if (Value <> nil) and (Value.JSONType = jtObject) then
    Result := TJSONObject(Value);
end;

function StrictArray(AObject: TJSONObject; const AName: string): TJSONArray;
var
  Value: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Value := AObject.Find(AName);
  if (Value <> nil) and (Value.JSONType = jtArray) then
    Result := TJSONArray(Value);
end;

function IsHexDigest(const AValue: string; ALength: Integer): Boolean;
var
  I: Integer;
begin
  Result := Length(AValue) = ALength;
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
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

function IsSafeToken(const AValue: string; AMaximumLength: Integer): Boolean;
var
  I: Integer;
begin
  Result := (AValue <> '') and (Length(AValue) <= AMaximumLength) and
    (AValue = Trim(AValue));
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(False);
end;

function IsEmailValue(const AValue: string): Boolean;
var
  AtPosition, I: Integer;
begin
  Result := False;
  if (AValue = '') or (AValue <> Trim(AValue)) or
    (Length(AValue) > 320) then
    Exit;
  AtPosition := Pos('@', AValue);
  if (AtPosition <= 1) or (AtPosition >= Length(AValue)) or
    (Pos('@', Copy(AValue, AtPosition + 1, MaxInt)) > 0) then
    Exit;
  if (AValue[1] = '.') or (AValue[AtPosition - 1] = '.') or
    (AValue[AtPosition + 1] in ['.', '-']) or
    (AValue[Length(AValue)] in ['.', '-']) then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) <= 32) or (Ord(AValue[I]) = 127) or
      (AValue[I] in ['<', '>', '(', ')', '[', ']', ',', ';']) then
      Exit;
  Result := True;
end;

function IsURIValue(const AValue: string): Boolean;
var
  ColonAt, I: Integer;
begin
  Result := False;
  if (AValue = '') or (AValue <> Trim(AValue)) or
    (Length(AValue) > 4096) then
    Exit;
  ColonAt := Pos(':', AValue);
  if (ColonAt <= 1) or (ColonAt = Length(AValue)) or
    not (AValue[1] in ['A'..'Z', 'a'..'z']) then
    Exit;
  for I := 2 to ColonAt - 1 do
    if not (AValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '+', '-', '.']) then
      Exit;
  for I := ColonAt + 1 to Length(AValue) do
    if (Ord(AValue[I]) <= 32) or (Ord(AValue[I]) = 127) then
      Exit;
  Result := True;
end;

function IsHTTPURL(const AValue: string): Boolean;
begin
  Result := IsURIValue(AValue) and
    ((Pos('https://', LowerCase(AValue)) = 1) or
    (Pos('http://', LowerCase(AValue)) = 1));
end;

function IsLeapYear(AYear: Integer): Boolean;
begin
  Result := ((AYear mod 4) = 0) and
    (((AYear mod 100) <> 0) or ((AYear mod 400) = 0));
end;

function DaysInMonth(AYear, AMonth: Integer): Integer;
const
  Values: array[1..12] of Integer =
    (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
begin
  if (AMonth < 1) or (AMonth > 12) then
    Exit(0);
  Result := Values[AMonth];
  if (AMonth = 2) and IsLeapYear(AYear) then
    Inc(Result);
end;

function ParseDigits(const AValue: string; AStart, ACount: Integer;
  out ANumber: Integer): Boolean;
var
  I: Integer;
begin
  Result := (AStart > 0) and (ACount > 0) and
    (AStart + ACount - 1 <= Length(AValue));
  ANumber := 0;
  if not Result then
    Exit;
  for I := AStart to AStart + ACount - 1 do
  begin
    if not (AValue[I] in ['0'..'9']) then
      Exit(False);
    ANumber := (ANumber * 10) + Ord(AValue[I]) - Ord('0');
  end;
end;

function IsRFC3339Timestamp(const AValue: string): Boolean;
var
  YearValue, MonthValue, DayValue, HourValue, MinuteValue, SecondValue,
    ZoneHour, ZoneMinute, PositionValue: Integer;
begin
  Result := False;
  if (Length(AValue) < 20) or (AValue[5] <> '-') or (AValue[8] <> '-') or
    not (AValue[11] in ['T', 't']) or (AValue[14] <> ':') or
    (AValue[17] <> ':') or
    not ParseDigits(AValue, 1, 4, YearValue) or
    not ParseDigits(AValue, 6, 2, MonthValue) or
    not ParseDigits(AValue, 9, 2, DayValue) or
    not ParseDigits(AValue, 12, 2, HourValue) or
    not ParseDigits(AValue, 15, 2, MinuteValue) or
    not ParseDigits(AValue, 18, 2, SecondValue) then
    Exit;
  if (YearValue < 1) or (MonthValue < 1) or (MonthValue > 12) or
    (DayValue < 1) or (DayValue > DaysInMonth(YearValue, MonthValue)) or
    (HourValue > 23) or (MinuteValue > 59) or (SecondValue > 60) then
    Exit;
  PositionValue := 20;
  if (PositionValue <= Length(AValue)) and (AValue[PositionValue] = '.') then
  begin
    Inc(PositionValue);
    if (PositionValue > Length(AValue)) or
      not (AValue[PositionValue] in ['0'..'9']) then
      Exit;
    while (PositionValue <= Length(AValue)) and
      (AValue[PositionValue] in ['0'..'9']) do
      Inc(PositionValue);
  end;
  if PositionValue > Length(AValue) then
    Exit;
  if AValue[PositionValue] in ['Z', 'z'] then
    Exit(PositionValue = Length(AValue));
  if not (AValue[PositionValue] in ['+', '-']) or
    (PositionValue + 5 <> Length(AValue)) or
    (AValue[PositionValue + 3] <> ':') or
    not ParseDigits(AValue, PositionValue + 1, 2, ZoneHour) or
    not ParseDigits(AValue, PositionValue + 4, 2, ZoneMinute) then
    Exit;
  Result := (ZoneHour <= 23) and (ZoneMinute <= 59);
end;

function HasOrganizationContact(AOrganization: TJSONObject): Boolean;
var
  Contacts, URLs: TJSONArray;
  Contact: TJSONObject;
  I: Integer;
begin
  Result := False;
  if AOrganization = nil then
    Exit;
  Contacts := StrictArray(AOrganization, 'contact');
  if Contacts <> nil then
    for I := 0 to Contacts.Count - 1 do
      if Contacts.Items[I].JSONType = jtObject then
      begin
        Contact := TJSONObject(Contacts.Items[I]);
        if IsEmailValue(StrictString(Contact, 'email')) then
          Exit(True);
      end;
  URLs := StrictArray(AOrganization, 'url');
  if URLs <> nil then
    for I := 0 to URLs.Count - 1 do
      if (URLs.Items[I].JSONType = jtString) and
        IsHTTPURL(URLs.Items[I].AsString) then
        Exit(True);
end;

function HasMappedCreatorContact(AObject: TJSONObject): Boolean;
begin
  Result := HasOrganizationContact(StrictObject(AObject, 'manufacturer'));
end;

function HasAlternativeCreatorContact(AObject: TJSONObject): Boolean;
var
  Authors: TJSONArray;
  Author: TJSONObject;
  Value: string;
  I: Integer;
begin
  Result := False;
  if AObject = nil then
    Exit;
  Value := StrictString(AObject, 'author');
  if IsEmailValue(Value) or IsHTTPURL(Value) then
    Exit(True);
  Value := StrictString(AObject, 'publisher');
  if IsEmailValue(Value) or IsHTTPURL(Value) then
    Exit(True);
  Authors := StrictArray(AObject, 'authors');
  if Authors = nil then
    Exit;
  for I := 0 to Authors.Count - 1 do
    if Authors.Items[I].JSONType = jtObject then
    begin
      Author := TJSONObject(Authors.Items[I]);
      if IsEmailValue(StrictString(Author, 'email')) then
        Exit(True);
    end
    else if (Authors.Items[I].JSONType = jtString) and
      (IsEmailValue(Authors.Items[I].AsString) or
      IsHTTPURL(Authors.Items[I].AsString)) then
      Exit(True);
end;

function CountNamedProperties(AObject: TJSONObject; const AName: string;
  out AFirstValue: string): Integer;
var
  Properties: TJSONArray;
  PropertyValue: TJSONObject;
  I: Integer;
begin
  Result := 0;
  AFirstValue := '';
  Properties := StrictArray(AObject, 'properties');
  if Properties = nil then
    Exit;
  for I := 0 to Properties.Count - 1 do
    if Properties.Items[I].JSONType = jtObject then
    begin
      PropertyValue := TJSONObject(Properties.Items[I]);
      if StrictString(PropertyValue, 'name') = AName then
      begin
        Inc(Result);
        if Result = 1 then
          AFirstValue := StrictString(PropertyValue, 'value');
      end;
    end;
end;

function HasPropertyNameMarker(AProperties: TJSONArray): Boolean;
var
  PropertyValue: TJSONObject;
  NameValue: string;
  I: Integer;
begin
  Result := False;
  if AProperties = nil then
    Exit;
  for I := 0 to AProperties.Count - 1 do
    if AProperties.Items[I].JSONType = jtObject then
    begin
      PropertyValue := TJSONObject(AProperties.Items[I]);
      NameValue := LowerCase(StrictString(PropertyValue, 'name'));
      if (Pos('vulnerab', NameValue) > 0) or
        (Pos('osv:', NameValue) = 1) or (Pos(':osv', NameValue) > 0) or
        (Pos('cve:', NameValue) = 1) or (Pos(':cve', NameValue) > 0) or
        (Pos('ghsa:', NameValue) = 1) or (Pos(':ghsa', NameValue) > 0) then
        Exit(True);
    end;
end;

function ContainsRecognizedSecurityData(AData: TJSONData): Boolean;
var
  ObjectValue, ReferenceValue: TJSONObject;
  ArrayValue: TJSONArray;
  I: Integer;
begin
  Result := False;
  if AData = nil then
    Exit;
  case AData.JSONType of
    jtObject:
      begin
        ObjectValue := TJSONObject(AData);
        if ObjectValue.Find('vulnerabilities') <> nil then
          Exit(True);
        if HasPropertyNameMarker(StrictArray(ObjectValue, 'properties')) then
          Exit(True);
        ArrayValue := StrictArray(ObjectValue, 'externalReferences');
        if ArrayValue <> nil then
          for I := 0 to ArrayValue.Count - 1 do
            if ArrayValue.Items[I].JSONType = jtObject then
            begin
              ReferenceValue := TJSONObject(ArrayValue.Items[I]);
              if SameText(StrictString(ReferenceValue, 'type'), 'advisories') then
                Exit(True);
            end;
        for I := 0 to ObjectValue.Count - 1 do
          if ContainsRecognizedSecurityData(ObjectValue.Items[I]) then
            Exit(True);
      end;
    jtArray:
      begin
        ArrayValue := TJSONArray(AData);
        for I := 0 to ArrayValue.Count - 1 do
          if ContainsRecognizedSecurityData(ArrayValue.Items[I]) then
            Exit(True);
      end;
  end;
end;

function HasAcknowledgedExpression(AComponent: TJSONObject;
  const AAcknowledgement: string): Boolean;
var
  Licenses: TJSONArray;
  Choice: TJSONObject;
  I: Integer;
begin
  Result := False;
  Licenses := StrictArray(AComponent, 'licenses');
  if Licenses = nil then
    Exit;
  for I := 0 to Licenses.Count - 1 do
    if Licenses.Items[I].JSONType = jtObject then
    begin
      Choice := TJSONObject(Licenses.Items[I]);
      if (StrictString(Choice, 'acknowledgement') = AAcknowledgement) and
        IsSafeToken(StrictString(Choice,
        'expression'), 4096) then
        Exit(True);
    end;
end;

function HasExternalReferenceURL(AComponent: TJSONObject;
  const AType: string; ARequireHTTP: Boolean): Boolean;
var
  References: TJSONArray;
  ReferenceValue: TJSONObject;
  URLValue: string;
  I: Integer;
begin
  Result := False;
  References := StrictArray(AComponent, 'externalReferences');
  if References = nil then
    Exit;
  for I := 0 to References.Count - 1 do
    if References.Items[I].JSONType = jtObject then
    begin
      ReferenceValue := TJSONObject(References.Items[I]);
      if StrictString(ReferenceValue, 'type') <> AType then
        Continue;
      URLValue := StrictString(ReferenceValue, 'url');
      if (ARequireHTTP and IsHTTPURL(URLValue)) or
        ((not ARequireHTTP) and IsURIValue(URLValue)) then
        Exit(True);
    end;
end;

function HasExternalReferenceHash(AComponent: TJSONObject;
  const AType, AAlgorithm: string): Boolean;
var
  References, Hashes: TJSONArray;
  ReferenceValue, HashValue: TJSONObject;
  AlgorithmValue, ContentValue: string;
  I, J: Integer;
begin
  Result := False;
  References := StrictArray(AComponent, 'externalReferences');
  if References = nil then
    Exit;
  for I := 0 to References.Count - 1 do
    if References.Items[I].JSONType = jtObject then
    begin
      ReferenceValue := TJSONObject(References.Items[I]);
      if (StrictString(ReferenceValue, 'type') <> AType) or
        not IsURIValue(StrictString(ReferenceValue, 'url')) then
        Continue;
      Hashes := StrictArray(ReferenceValue, 'hashes');
      if Hashes = nil then
        Continue;
      for J := 0 to Hashes.Count - 1 do
        if Hashes.Items[J].JSONType = jtObject then
        begin
          HashValue := TJSONObject(Hashes.Items[J]);
          AlgorithmValue := StrictString(HashValue, 'alg');
          ContentValue := StrictString(HashValue, 'content');
          if (AAlgorithm <> '') and (AlgorithmValue <> AAlgorithm) then
            Continue;
          if AlgorithmValue = 'SHA-512' then
          begin
            if IsHexDigest(ContentValue, 128) then
              Exit(True);
          end
          else if (AAlgorithm = '') and (Length(ContentValue) >= 32) and
            ((Length(ContentValue) mod 2) = 0) and
            IsHexDigest(ContentValue, Length(ContentValue)) then
            Exit(True);
        end;
    end;
end;

function HasExternalReferenceHashEntries(AComponent: TJSONObject;
  const AType: string): Boolean;
var
  References, Hashes: TJSONArray;
  ReferenceValue: TJSONObject;
  I: Integer;
begin
  Result := False;
  References := StrictArray(AComponent, 'externalReferences');
  if References = nil then
    Exit;
  for I := 0 to References.Count - 1 do
    if References.Items[I].JSONType = jtObject then
    begin
      ReferenceValue := TJSONObject(References.Items[I]);
      if StrictString(ReferenceValue, 'type') <> AType then
        Continue;
      Hashes := StrictArray(ReferenceValue, 'hashes');
      if (Hashes <> nil) and (Hashes.Count > 0) then
        Exit(True);
    end;
end;

function HasOtherIdentifier(AComponent: TJSONObject): Boolean;
var
  SWID: TJSONObject;
  Dummy: string;
  CPEPropertyCount: Integer;
begin
  Result := Pos('pkg:', StrictString(AComponent, 'purl')) = 1;
  if Result then
    Exit;
  CPEPropertyCount := CountNamedProperties(AComponent,
    'purpleray-sbom-analyzer:cpe-evidence', Dummy);
  if (CPEPropertyCount = 0) and
    (Pos('cpe:', LowerCase(StrictString(AComponent, 'cpe'))) = 1) then
    Exit(True);
  SWID := StrictObject(AComponent, 'swid');
  Result := (SWID <> nil) and
    IsSafeToken(StrictString(SWID, 'tagId'), 4096);
end;

function ComponentReference(AComponent: TJSONObject): string;
begin
  Result := StrictString(AComponent, 'bom-ref');
  if not IsSafeToken(Result, 4096) then
    Result := '';
end;

function CompareByteStrings(const ALeft, ARight: string): Integer;
var
  I, CommonLength: Integer;
begin
  CommonLength := Length(ALeft);
  if Length(ARight) < CommonLength then
    CommonLength := Length(ARight);
  for I := 1 to CommonLength do
    if Byte(ALeft[I]) <> Byte(ARight[I]) then
    begin
      if Byte(ALeft[I]) < Byte(ARight[I]) then
        Exit(-1)
      else
        Exit(1);
    end;
  if Length(ALeft) < Length(ARight) then
    Result := -1
  else if Length(ALeft) > Length(ARight) then
    Result := 1
  else
    Result := 0;
end;

function CompareComponentSources(Item1, Item2: Pointer): Integer;
var
  Left, Right: TBSIComponentSource;
begin
  Left := TBSIComponentSource(Item1);
  Right := TBSIComponentSource(Item2);
  if Left.IsPrimary <> Right.IsPrimary then
  begin
    if Left.IsPrimary then
      Exit(-1)
    else
      Exit(1);
  end;
  Result := CompareByteStrings(Left.SortKey, Right.SortKey);
  if Result = 0 then
    Result := Left.Ordinal - Right.Ordinal;
end;

procedure AddComponentSource(AList: TObjectList; ASource: TJSONObject;
  AIsPrimary: Boolean; AOrdinal: Integer; const ATaskID: string);
var
  Value: TBSIComponentSource;
  HashInput: RawByteString;
begin
  Value := TBSIComponentSource.Create;
  try
    Value.Source := ASource;
    Value.IsPrimary := AIsPrimary;
    Value.Ordinal := AOrdinal;
    Value.RawReference := ComponentReference(ASource);
    if Value.RawReference <> '' then
    begin
      Value.SortKey := Value.RawReference;
      HashInput := RawByteString(Value.RawReference);
    end
    else
    begin
      Value.SortKey := #255 + Format('%.10d', [AOrdinal]);
      if AIsPrimary then
        HashInput := RawByteString('missing-bom-ref'#0 + LowerCase(ATaskID) +
          #0'primary'#0 + IntToStr(AOrdinal))
      else
        HashInput := RawByteString('missing-bom-ref'#0 + LowerCase(ATaskID) +
          #0'component'#0 + IntToStr(AOrdinal));
    end;
    Value.ComponentID := 'sha256:' + SHA256String(HashInput);
    AList.Add(Value);
  except
    Value.Free;
    raise;
  end;
end;

procedure CountFieldStatus(var ASummary: TBSIReadinessSummary;
  const AStatus: string);
begin
  if AStatus = StatusMapped then
    Inc(ASummary.Mapped)
  else if AStatus = StatusDerivable then
    Inc(ASummary.Derivable)
  else if AStatus = StatusNotApplicable then
    Inc(ASummary.NotApplicable)
  else if AStatus = StatusNotObserved then
    Inc(ASummary.NotObserved);
end;

procedure AddBlocker(ABlockers: TJSONArray; ALocalCodes: TJSONArray;
  var ASummary: TBSIReadinessSummary; const ACode, AScope,
  AComponentID, AField, AReason: string);
var
  Value: TJSONObject;
begin
  Value := TJSONObject.Create;
  try
    Value.Add('code', ACode);
    Value.Add('scope', AScope);
    if AComponentID <> '' then
      Value.Add('componentId', AComponentID);
    Value.Add('field', AField);
    Value.Add('reason', AReason);
    ABlockers.Add(Value);
    Value := nil;
  finally
    Value.Free;
  end;
  if ALocalCodes <> nil then
    ALocalCodes.Add(ACode);
  Inc(ASummary.Blocked);
end;

procedure AddField(AFields, ABlockers, ALocalCodes: TJSONArray;
  var ASummary: TBSIReadinessSummary; const AField, ARequirement,
  AStatus, AEvidence, ABlockerCode, AScope, AComponentID,
  AReason: string; const AMappings: array of string);
var
  Value: TJSONObject;
  Mappings: TJSONArray;
  I: Integer;
begin
  Value := TJSONObject.Create;
  try
    Value.Add('field', AField);
    Value.Add('requirement', ARequirement);
    Value.Add('status', AStatus);
    Mappings := TJSONArray.Create;
    Value.Add('mappings', Mappings);
    for I := Low(AMappings) to High(AMappings) do
      Mappings.Add(AMappings[I]);
    Value.Add('evidence', AEvidence);
    if AStatus = StatusBlocked then
      Value.Add('blockerCode', ABlockerCode);
    AFields.Add(Value);
    Value := nil;
  finally
    Value.Free;
  end;
  if AStatus = StatusBlocked then
    AddBlocker(ABlockers, ALocalCodes, ASummary, ABlockerCode, AScope,
      AComponentID, AField, AReason)
  else
    CountFieldStatus(ASummary, AStatus);
end;

function BuildDependencyReferenceSet(ARoot: TJSONObject): TStringList;
var
  Dependencies: TJSONArray;
  Entry: TJSONObject;
  ReferenceValue: string;
  I: Integer;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.CaseSensitive := True;
  Result.UseLocale := False;
  Result.Duplicates := dupIgnore;
  Dependencies := StrictArray(ARoot, 'dependencies');
  if Dependencies = nil then
    Exit;
  for I := 0 to Dependencies.Count - 1 do
    if Dependencies.Items[I].JSONType = jtObject then
    begin
      Entry := TJSONObject(Dependencies.Items[I]);
      ReferenceValue := StrictString(Entry, 'ref');
      if IsSafeToken(ReferenceValue, 4096) then
        Result.Add(ReferenceValue);
    end;
end;

procedure AddReferenceArray(AReferences: TStringList; AValues: TJSONArray);
var
  I: Integer;
begin
  if AValues = nil then
    Exit;
  for I := 0 to AValues.Count - 1 do
    if (AValues.Items[I].JSONType = jtString) and
      IsSafeToken(AValues.Items[I].AsString, 4096) then
      AReferences.Add(AValues.Items[I].AsString);
end;

function CompositionCoverageComplete(ARoot: TJSONObject;
  AComponents: TObjectList): Boolean;
var
  Compositions: TJSONArray;
  Composition: TJSONObject;
  CoveredReferences: TStringList;
  Source: TBSIComponentSource;
  Index, I: Integer;
begin
  Result := False;
  Compositions := StrictArray(ARoot, 'compositions');
  if (Compositions = nil) or (Compositions.Count = 0) then
    Exit;
  CoveredReferences := TStringList.Create;
  try
    CoveredReferences.Sorted := True;
    CoveredReferences.CaseSensitive := True;
    CoveredReferences.UseLocale := False;
    CoveredReferences.Duplicates := dupIgnore;
    for I := 0 to Compositions.Count - 1 do
    begin
      if Compositions.Items[I].JSONType <> jtObject then
        Exit;
      Composition := TJSONObject(Compositions.Items[I]);
      if StrictString(Composition, 'aggregate') <> 'complete' then
        Exit;
      AddReferenceArray(CoveredReferences,
        StrictArray(Composition, 'dependencies'));
      AddReferenceArray(CoveredReferences,
        StrictArray(Composition, 'assemblies'));
    end;
    if CoveredReferences.Count = 0 then
      Exit;
    for I := 0 to AComponents.Count - 1 do
    begin
      Source := TBSIComponentSource(AComponents[I]);
      if (Source.RawReference = '') or
        not CoveredReferences.Find(Source.RawReference, Index) then
        Exit;
    end;
    Result := True;
  finally
    CoveredReferences.Free;
  end;
end;

function DependencyGraphComplete(ARoot: TJSONObject;
  AComponents: TObjectList; ADependencyReferences: TStringList): Boolean;
var
  Source: TBSIComponentSource;
  SeenReferences: TStringList;
  Index, I: Integer;
begin
  Result := (StrictArray(ARoot, 'dependencies') <> nil) and
    CompositionCoverageComplete(ARoot, AComponents);
  if not Result then
    Exit;
  SeenReferences := TStringList.Create;
  try
    SeenReferences.Sorted := True;
    SeenReferences.CaseSensitive := True;
    SeenReferences.UseLocale := False;
    SeenReferences.Duplicates := dupIgnore;
    for I := 0 to AComponents.Count - 1 do
    begin
      Source := TBSIComponentSource(AComponents[I]);
      if (Source.RawReference = '') or
        SeenReferences.Find(Source.RawReference, Index) or
        not ADependencyReferences.Find(Source.RawReference, Index) then
        Exit(False);
      SeenReferences.Add(Source.RawReference);
    end;
  finally
    SeenReferences.Free;
  end;
end;

procedure AddAdvisory(AAdvisories: TJSONArray;
  var ASummary: TBSIReadinessSummary; const ACode, AMessage: string);
var
  Value: TJSONObject;
begin
  Value := TJSONObject.Create;
  try
    Value.Add('code', ACode);
    Value.Add('message', AMessage);
    AAdvisories.Add(Value);
    Value := nil;
  finally
    Value.Free;
  end;
  Inc(ASummary.AdvisoryCount);
end;

procedure AuditDocument(ASourceRoot: TJSONObject;
  ADocumentFields, ABlockers: TJSONArray;
  var ASummary: TBSIReadinessSummary; AGraphComplete: Boolean);
var
  Metadata: TJSONObject;
  FormatValue, SpecValue, TimestampValue, SerialValue, FieldStatus,
    EvidenceValue: string;
begin
  Metadata := StrictObject(ASourceRoot, 'metadata');
  FormatValue := StrictString(ASourceRoot, 'bomFormat');
  SpecValue := StrictString(ASourceRoot, 'specVersion');
  if (FormatValue = 'CycloneDX') and
    ((SpecValue = '1.6') or (SpecValue = '1.7')) then
    AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.format',
      RequirementMust, StatusMapped, 'cyclonedx-supported', '', 'document',
      '', '', ['bomFormat', 'specVersion'])
  else
    AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.format',
      RequirementMust, StatusBlocked, 'unsupported-or-unrecognized',
      BlockFormat, 'document', '',
      'The source is not recognized as supported CycloneDX 1.6 or 1.7.',
      ['bomFormat', 'specVersion']);

  if ContainsRecognizedSecurityData(ASourceRoot) then
    AddField(ADocumentFields, ABlockers, nil, ASummary,
      'sbom.vulnerabilityInformation', RequirementMust, StatusBlocked,
      'recognized-security-section-present', BlockVulnerability, 'document',
      '', 'Recognized vulnerability or advisory data is present; no values ' +
      'were copied into this report.', ['vulnerabilities',
      'properties', 'externalReferences[type=advisories]'])
  else
    AddField(ADocumentFields, ABlockers, nil, ASummary,
      'sbom.vulnerabilityInformation', RequirementMust, StatusMapped,
      'recognized-security-sections-absent', '', 'document', '', '',
      ['vulnerabilities']);

  if HasMappedCreatorContact(Metadata) then
  begin
    FieldStatus := StatusMapped;
    EvidenceValue := 'manufacturer-contact';
  end
  else if HasAlternativeCreatorContact(Metadata) then
  begin
    FieldStatus := StatusDerivable;
    EvidenceValue := 'author-contact';
  end
  else
  begin
    FieldStatus := StatusBlocked;
    EvidenceValue := 'missing-or-untyped';
  end;
  AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.creator',
    RequirementMust, FieldStatus, EvidenceValue, BlockSBOMCreator,
    'document', '', 'A contactable SBOM creator is not mapped.',
    ['metadata.manufacturer.contact[].email',
    'metadata.manufacturer.url[]', 'metadata.authors[].email',
    'metadata.author', 'metadata.publisher']);

  TimestampValue := StrictString(Metadata, 'timestamp');
  if IsRFC3339Timestamp(TimestampValue) then
    FieldStatus := StatusMapped
  else
    FieldStatus := StatusBlocked;
  AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.timestamp',
    RequirementMust, FieldStatus, 'rfc3339-or-invalid', BlockTimestamp,
    'document', '', 'The SBOM timestamp is missing or not valid RFC 3339.',
    ['metadata.timestamp']);

  SerialValue := StrictString(ASourceRoot, 'serialNumber');
  if IsURIValue(SerialValue) then
  begin
    FieldStatus := StatusMapped;
    EvidenceValue := 'serial-number-uri';
  end
  else
  begin
    FieldStatus := StatusDerivable;
    EvidenceValue := 'task-uuid';
  end;
  AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.uri',
    RequirementMustIfExists, FieldStatus, EvidenceValue, BlockFormat,
    'document', '', 'No valid SBOM URI can be established.', ['serialNumber']);

  if AGraphComplete then
    FieldStatus := StatusMapped
  else
    FieldStatus := StatusBlocked;
  AddField(ADocumentFields, ABlockers, nil, ASummary, 'sbom.dependencies',
    RequirementMust, FieldStatus, 'complete-graph-or-unproven',
    BlockDependencies, 'document', '',
    'Dependency enumeration is absent, incomplete, or not complete for every ' +
    'component.', ['dependencies', 'compositions']);

  AddField(ADocumentFields, ABlockers, nil, ASummary,
    'sbom.buildEquivalence', RequirementMust, StatusBlocked, 'not-proven',
    BlockBuildEvidence, 'document', '',
    'Build-time information or equivalent information is not proven.',
    ['metadata.lifecycles']);
end;

function PropertyStatus(AComponent: TJSONObject; const APropertyName: string;
  const AAllowedOne, AAllowedTwo: string; out AEvidence: string): string;
var
  Count: Integer;
  Value: string;
begin
  Count := CountNamedProperties(AComponent, APropertyName, Value);
  if (Count = 1) and ((Value = AAllowedOne) or (Value = AAllowedTwo)) then
  begin
    AEvidence := 'single-valid-property';
    Result := StatusMapped;
  end
  else
  begin
    AEvidence := 'missing-invalid-or-ambiguous';
    Result := StatusBlocked;
  end;
end;

function HasUnverifiedDeclaredHash(AComponent: TJSONObject): Boolean;
var
  Value: string;
begin
  Result := CountNamedProperties(AComponent,
    'purpleray-sbom-analyzer:declared-hash-provenance', Value) > 0;
end;

procedure AuditComponent(AComponentSource: TBSIComponentSource;
  AComponents, ABlockers: TJSONArray; ADependencyReferences: TStringList;
  var ASummary: TBSIReadinessSummary; AGraphComplete: Boolean);
var
  Source, Value: TJSONObject;
  Fields, LocalBlockers: TJSONArray;
  Prefix, KindValue, FieldStatus, EvidenceValue, PropertyValue: string;
  PropertyCount, DependencyIndex: Integer;
  HasDependencyEntry, HasHash: Boolean;
begin
  Source := AComponentSource.Source;
  Fields := TJSONArray.Create;
  LocalBlockers := TJSONArray.Create;
  Value := TJSONObject.Create;
  try
    Value.Add('componentId', AComponentSource.ComponentID);
    if AComponentSource.IsPrimary then
    begin
      Value.Add('role', 'primary');
      Prefix := 'metadata.component';
    end
    else
    begin
      Value.Add('role', 'component');
      Prefix := 'components[]';
    end;
    if StrictString(Source, 'type') = 'file' then
      KindValue := 'file'
    else
      KindValue := 'unknown';
    Value.Add('kind', KindValue);
    Value.Add('descriptionLevel', 'unknown');

    if KindValue = 'unknown' then
      AddBlocker(ABlockers, LocalBlockers, ASummary, BlockKind, 'component',
        AComponentSource.ComponentID, 'component.descriptionKind',
        'The CycloneDX component type does not prove logical or file status.');
    AddBlocker(ABlockers, LocalBlockers, ASummary, BlockLevel, 'component',
      AComponentSource.ComponentID, 'component.descriptionLevel',
      'Fully described, identified, or referenced status is not established.');

    if HasMappedCreatorContact(Source) then
    begin
      FieldStatus := StatusMapped;
      EvidenceValue := 'manufacturer-contact';
    end
    else if HasAlternativeCreatorContact(Source) then
    begin
      FieldStatus := StatusDerivable;
      EvidenceValue := 'author-or-publisher-contact';
    end
    else
    begin
      FieldStatus := StatusBlocked;
      EvidenceValue := 'missing-or-untyped';
    end;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.creator', RequirementMust, FieldStatus, EvidenceValue,
      BlockCreator, 'component', AComponentSource.ComponentID,
      'A contactable component creator is not mapped.',
      [Prefix + '.manufacturer.contact[].email',
      Prefix + '.manufacturer.url[]', Prefix + '.authors[].email',
      Prefix + '.author', Prefix + '.publisher']);

    if IsSafeToken(StrictString(Source, 'name'), 4096) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary, 'component.name',
      RequirementMust, FieldStatus, 'present-or-missing', BlockName,
      'component', AComponentSource.ComponentID,
      'The component name is missing or invalid.', [Prefix + '.name']);

    if IsSafeToken(StrictString(Source, 'version'), 4096) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary, 'component.version',
      RequirementMust, FieldStatus, 'exact-value-or-missing', BlockVersion,
      'component', AComponentSource.ComponentID,
      'An exact component version is not mapped.', [Prefix + '.version']);

    PropertyCount := CountNamedProperties(Source,
      'bsi:component:filename', PropertyValue);
    if (PropertyCount = 1) and IsSafeToken(PropertyValue, 4096) and
      (Pos('/', PropertyValue) = 0) and (Pos('\', PropertyValue) = 0) and
      (PropertyValue <> '.') and (PropertyValue <> '..') then
    begin
      FieldStatus := StatusMapped;
      EvidenceValue := 'single-filename-property';
    end
    else
    begin
      FieldStatus := StatusBlocked;
      EvidenceValue := 'missing-invalid-or-ambiguous';
    end;
    AddField(Fields, ABlockers, LocalBlockers, ASummary, 'component.filename',
      RequirementMust, FieldStatus, EvidenceValue, BlockFilename,
      'component', AComponentSource.ComponentID,
      'Exactly one basename-only filename is not mapped.',
      [Prefix + '.properties[name=bsi:component:filename].value']);

    HasDependencyEntry := (AComponentSource.RawReference <> '') and
      ADependencyReferences.Find(AComponentSource.RawReference,
      DependencyIndex);
    if AGraphComplete and HasDependencyEntry then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.dependencies', RequirementMust, FieldStatus,
      'dependency-entry-and-complete-graph', BlockComponentDependencies,
      'component', AComponentSource.ComponentID,
      'This component lacks a dependency entry in a proven-complete graph.',
      ['dependencies[ref].dependsOn', 'compositions']);

    if HasAcknowledgedExpression(Source, 'concluded') then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.distributionLicences', RequirementMust, FieldStatus,
      'concluded-expression-or-missing', BlockDistributionLicence,
      'component', AComponentSource.ComponentID,
      'A concluded SPDX expression for distribution is not mapped.',
      [Prefix + '.licenses[].expression[acknowledgement=concluded]']);

    HasHash := HasExternalReferenceHash(Source, 'distribution', 'SHA-512');
    if HasHash and not HasUnverifiedDeclaredHash(Source) then
    begin
      FieldStatus := StatusMapped;
      EvidenceValue := 'distribution-sha512';
    end
    else
    begin
      FieldStatus := StatusBlocked;
      if HasHash then
        EvidenceValue := 'declared-unverified'
      else
        EvidenceValue := 'missing-or-wrong-location';
    end;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.deployableHash', RequirementMust, FieldStatus, EvidenceValue,
      BlockDeployableHash, 'component', AComponentSource.ComponentID,
      'A verified deployable SHA-512 at the BSI mapping is not established.',
      [Prefix +
      '.externalReferences[type=distribution].hashes[alg=SHA-512].content']);

    FieldStatus := PropertyStatus(Source, 'bsi:component:executable',
      'executable', 'non-executable', EvidenceValue);
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.executable', RequirementMust, FieldStatus, EvidenceValue,
      BlockExecutable, 'component', AComponentSource.ComponentID,
      'Executable status is missing, invalid, or ambiguous.',
      [Prefix + '.properties[name=bsi:component:executable].value']);

    FieldStatus := PropertyStatus(Source, 'bsi:component:archive',
      'archive', 'no archive', EvidenceValue);
    AddField(Fields, ABlockers, LocalBlockers, ASummary, 'component.archive',
      RequirementMust, FieldStatus, EvidenceValue, BlockArchive, 'component',
      AComponentSource.ComponentID,
      'Archive status is missing, invalid, or ambiguous.',
      [Prefix + '.properties[name=bsi:component:archive].value']);

    FieldStatus := PropertyStatus(Source, 'bsi:component:structured',
      'structured', 'unstructured', EvidenceValue);
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.structured', RequirementMust, FieldStatus, EvidenceValue,
      BlockStructured, 'component', AComponentSource.ComponentID,
      'Structured status is missing, invalid, or ambiguous.',
      [Prefix + '.properties[name=bsi:component:structured].value']);

    if HasExternalReferenceURL(Source, 'source-distribution', False) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.sourceCodeUri', RequirementMustIfExists, FieldStatus,
      'source-uri-or-existence-unknown', BlockSourceURI, 'component',
      AComponentSource.ComponentID,
      'The existence of a source-code URI cannot be resolved safely.',
      [Prefix + '.externalReferences[type=source-distribution].url']);

    if HasExternalReferenceURL(Source, 'distribution', False) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.deployableUri', RequirementMustIfExists, FieldStatus,
      'distribution-uri-or-existence-unknown', BlockDeployableURI,
      'component', AComponentSource.ComponentID,
      'The existence of a deployable URI cannot be resolved safely.',
      [Prefix + '.externalReferences[type=distribution].url']);

    if HasOtherIdentifier(Source) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.otherIdentifiers', RequirementMustIfExists, FieldStatus,
      'purl-cpe-swid-or-existence-unknown', BlockIdentifier, 'component',
      AComponentSource.ComponentID,
      'No evidence-backed purl, CPE, or SWID is mapped.',
      [Prefix + '.purl', Prefix + '.cpe', Prefix + '.swid.tagId']);

    if HasAcknowledgedExpression(Source, 'declared') then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.originalLicences', RequirementMustIfExists, FieldStatus,
      'declared-expression-or-existence-unknown', BlockOriginalLicence,
      'component', AComponentSource.ComponentID,
      'The existence of an original SPDX licence expression is unresolved.',
      [Prefix + '.licenses[].expression[acknowledgement=declared]']);

    PropertyCount := CountNamedProperties(Source,
      'bsi:component:effectiveLicence', PropertyValue);
    if (PropertyCount = 1) and IsSafeToken(PropertyValue, 4096) then
      FieldStatus := StatusMapped
    else if (PropertyCount = 0) and
      (CountNamedProperties(Source, 'bsi:component:effectiveLicense',
      PropertyValue) = 0) then
      FieldStatus := StatusNotObserved
    else
      FieldStatus := StatusBlocked;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.effectiveLicence', RequirementMay, FieldStatus,
      'registered-property-or-not-observed', BlockEffectiveLicence,
      'component', AComponentSource.ComponentID,
      'The optional effective-licence property is ambiguous or uses the ' +
      'unregistered PDF spelling.',
      [Prefix + '.properties[name=bsi:component:effectiveLicence].value']);

    HasHash := HasExternalReferenceHash(Source, 'source-distribution',
      'SHA-512');
    if HasHash and not HasUnverifiedDeclaredHash(Source) then
    begin
      FieldStatus := StatusMapped;
      EvidenceValue := 'source-sha512';
    end
    else if HasExternalReferenceHashEntries(Source,
      'source-distribution') then
    begin
      FieldStatus := StatusBlocked;
      EvidenceValue := 'source-hash-invalid-or-unverified';
    end
    else
    begin
      FieldStatus := StatusNotObserved;
      EvidenceValue := 'source-hash-not-observed';
    end;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.sourceCodeHash', RequirementMay, FieldStatus,
      EvidenceValue, BlockSourceHash, 'component',
      AComponentSource.ComponentID,
      'A valid, verified source-code SHA-512 at the BSI mapping is not ' +
      'established.',
      [Prefix +
      '.externalReferences[type=source-distribution].hashes[alg=SHA-512].content']);

    if HasExternalReferenceURL(Source, 'rfc-9116', True) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusNotObserved;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.securityTxt', RequirementMay, FieldStatus,
      'rfc9116-url-or-not-observed', '', 'component',
      AComponentSource.ComponentID, '',
      [Prefix + '.externalReferences[type=rfc-9116].url']);

    if HasExternalReferenceURL(Source, 'bom', False) then
      FieldStatus := StatusMapped
    else
      FieldStatus := StatusNotObserved;
    AddField(Fields, ABlockers, LocalBlockers, ASummary,
      'component.referencedBom', RequirementMay, FieldStatus,
      'bom-reference-or-not-observed', '', 'component',
      AComponentSource.ComponentID, '',
      [Prefix + '.externalReferences[type=bom].url']);

    Value.Add('fields', Fields);
    Fields := nil;
    Value.Add('blockers', LocalBlockers);
    LocalBlockers := nil;
    AComponents.Add(Value);
    Value := nil;
    Inc(ASummary.ComponentsAssessed);
  finally
    Value.Free;
    LocalBlockers.Free;
    Fields.Free;
  end;
end;

function GenerateBSIReadinessReport(
  const AManagedSBOMBytes: RawByteString;
  const AExpectedSHA256, ATaskID: string;
  out ASummary: TBSIReadinessSummary): UTF8String;
var
  ActualSHA256, ExpectedSHA256, FormatValue, SpecValue: string;
  Parsed: TJSONData;
  SourceRoot, Metadata, Primary: TJSONObject;
  SourceComponents: TJSONArray;
  ComponentSources: TObjectList;
  DependencyReferences: TStringList;
  DocumentFields, Components, Blockers, Advisories: TJSONArray;
  Root, Target, ClaimValue, SourceValue, PrivacyValue, SummaryValue: TJSONObject;
  I: Integer;
  GraphComplete: Boolean;
begin
  FillChar(ASummary, SizeOf(ASummary), 0);
  ASummary.Status := brsBlocked;
  if not IsCanonicalTaskID(ATaskID) then
    raise EBSIReadinessError.Create(ErrorTaskID,
      'Task identifier must be a canonical UUID without braces');
  if (Length(AManagedSBOMBytes) = 0) or
    (Int64(Length(AManagedSBOMBytes)) > DefaultMaximumJSONBytes) then
    raise EBSIReadinessError.Create(ErrorSourceSize,
      'Managed-SBOM bytes are empty or exceed the accepted size limit');
  ExpectedSHA256 := LowerCase(Trim(AExpectedSHA256));
  if not IsHexDigest(ExpectedSHA256, 64) then
    raise EBSIReadinessError.Create(ErrorExpectedHash,
      'Expected managed-SBOM SHA-256 is missing or invalid');
  ActualSHA256 := SHA256String(AManagedSBOMBytes);
  if ActualSHA256 <> ExpectedSHA256 then
    raise EBSIReadinessError.Create(ErrorHashMismatch,
      'Managed-SBOM bytes do not match the persisted SHA-256');

  Parsed := nil;
  try
    try
      Parsed := ParseStrictUTF8JSON(AManagedSBOMBytes);
    except
      on E: Exception do
        raise EBSIReadinessError.Create(ErrorJSON,
          'Managed-SBOM bytes are not bounded strict UTF-8 JSON');
    end;
    if (Parsed = nil) or (Parsed.JSONType <> jtObject) then
      raise EBSIReadinessError.Create(ErrorJSON,
        'Managed-SBOM JSON root is not an object');
    SourceRoot := TJSONObject(Parsed);

    ComponentSources := TObjectList.Create(True);
    DependencyReferences := nil;
    DocumentFields := TJSONArray.Create;
    Components := TJSONArray.Create;
    Blockers := TJSONArray.Create;
    Advisories := TJSONArray.Create;
    Root := nil;
    try
      Metadata := StrictObject(SourceRoot, 'metadata');
      Primary := StrictObject(Metadata, 'component');
      AddComponentSource(ComponentSources, Primary, True, 0, ATaskID);
      SourceComponents := StrictArray(SourceRoot, 'components');
      if SourceComponents <> nil then
        for I := 0 to SourceComponents.Count - 1 do
          if SourceComponents.Items[I].JSONType = jtObject then
            AddComponentSource(ComponentSources,
              TJSONObject(SourceComponents.Items[I]), False, I + 1, ATaskID)
          else
            AddComponentSource(ComponentSources, nil, False, I + 1, ATaskID);
      ComponentSources.Sort(@CompareComponentSources);
      DependencyReferences := BuildDependencyReferenceSet(SourceRoot);
      GraphComplete := DependencyGraphComplete(SourceRoot, ComponentSources,
        DependencyReferences);

      AuditDocument(SourceRoot, DocumentFields, Blockers, ASummary,
        GraphComplete);
      for I := 0 to ComponentSources.Count - 1 do
        AuditComponent(TBSIComponentSource(ComponentSources[I]), Components,
          Blockers, DependencyReferences, ASummary, GraphComplete);

      AddAdvisory(Advisories, ASummary,
        'BSI210-A001-SOURCE-SCHEMA-NOT-VALIDATED',
        'The runtime assessment performs strict structural checks but does not ' +
        'claim official CycloneDX schema validation.');
      AddAdvisory(Advisories, ASummary,
        'BSI210-A002-EFFECTIVE-LICENCE-SPELLING-CONFLICT',
        'The registered BSI taxonomy uses effectiveLicence; the guideline PDF ' +
        'mapping table prints effectiveLicense. The registered spelling is used.');
      AddAdvisory(Advisories, ASummary,
        'BSI210-A003-TARGET-CURRENTNESS-NOT-ASSERTED',
        'The report is pinned to v2.1.0 and does not assert that it is the ' +
        'currently applicable BSI version.');

      if ASummary.Blocked > 0 then
        ASummary.Status := brsBlocked
      else
        ASummary.Status := brsReviewRequired;

      Root := TJSONObject.Create;
      Root.Add('format', BSIReadinessReportFormat);
      Root.Add('formatVersion', BSIReadinessReportFormatVersion);

      Target := TJSONObject.Create;
      Target.Add('guideline', 'BSI TR-03183-2');
      Target.Add('guidelineVersion', '2.1.0');
      Target.Add('guidelineDate', '2025-08-20');
      Target.Add('guidelinePdfSha256', GuidelinePDFSHA256);
      Target.Add('cycloneDxMinimum', '1.6');
      Target.Add('taxonomyVersion', '0.1.2');
      Target.Add('taxonomyCommit', TaxonomyCommit);
      Root.Add('target', Target);

      ClaimValue := TJSONObject.Create;
      ClaimValue.Add('kind', 'readiness-assessment');
      ClaimValue.Add('complianceClaimed', False);
      ClaimValue.Add('text', 'This is a deterministic field-availability ' +
        'assessment, not a statement of conformity or certification.');
      Root.Add('claim', ClaimValue);

      if StrictString(SourceRoot, 'bomFormat') = 'CycloneDX' then
        FormatValue := 'CycloneDX'
      else
        FormatValue := 'unrecognized';
      SpecValue := StrictString(SourceRoot, 'specVersion');
      if (SpecValue <> '1.6') and (SpecValue <> '1.7') then
        SpecValue := 'unrecognized';
      SourceValue := TJSONObject.Create;
      SourceValue.Add('taskId', LowerCase(ATaskID));
      SourceValue.Add('managedSbomSha256', ExpectedSHA256);
      SourceValue.Add('bomFormat', FormatValue);
      SourceValue.Add('specVersion', SpecValue);
      SourceValue.Add('sourceSchemaValidation', 'not-performed');
      Root.Add('source', SourceValue);

      PrivacyValue := TJSONObject.Create;
      PrivacyValue.Add('profile', 'shareable-minimal');
      PrivacyValue.Add('absolutePathsIncluded', False);
      PrivacyValue.Add('relativePathsIncluded', False);
      PrivacyValue.Add('contactValuesIncluded', False);
      PrivacyValue.Add('diagnosticsIncluded', False);
      PrivacyValue.Add('dynamicSecurityFindingsIncluded', False);
      Root.Add('privacy', PrivacyValue);

      SummaryValue := TJSONObject.Create;
      SummaryValue.Add('status', BSIReadinessStatusToString(ASummary.Status));
      SummaryValue.Add('componentsAssessed', ASummary.ComponentsAssessed);
      SummaryValue.Add('mapped', ASummary.Mapped);
      SummaryValue.Add('derivable', ASummary.Derivable);
      SummaryValue.Add('notApplicable', ASummary.NotApplicable);
      SummaryValue.Add('notObserved', ASummary.NotObserved);
      SummaryValue.Add('blocked', ASummary.Blocked);
      SummaryValue.Add('advisoryCount', ASummary.AdvisoryCount);
      Root.Add('summary', SummaryValue);

      Root.Add('documentFields', DocumentFields);
      DocumentFields := nil;
      Root.Add('components', Components);
      Components := nil;
      Root.Add('blockers', Blockers);
      Blockers := nil;
      Root.Add('advisories', Advisories);
      Advisories := nil;
      Result := SerializeJSONUTF8(Root, [], 2, True);
    finally
      Root.Free;
      Advisories.Free;
      Blockers.Free;
      Components.Free;
      DocumentFields.Free;
      DependencyReferences.Free;
      ComponentSources.Free;
    end;
  finally
    Parsed.Free;
  end;
end;

end.
