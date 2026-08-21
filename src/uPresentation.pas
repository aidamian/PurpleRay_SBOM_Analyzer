(**
  PurpleRay SBOM Analyzer presentation-policy unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Provides deterministic, non-visual formatting rules shared by the native UI
  and regression tests, including status glyphs, local timestamps, message
  counts, and compact digest rendering.

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
unit uPresentation;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

{**
  Formats a persisted UTC timestamp in the current user's local time.

  Parameters
  ----------
  AValue
    ISO-8601 UTC timestamp. Invalid text is returned in a compact fallback
    form rather than raising an exception.

  Returns
  -------
  string
    Local ``yyyy-mm-dd hh:nn:ss`` text or a compact fallback value.

  Raises
  ------
  None
    Timestamp parse failures are converted to fallback display text.
}
function LocalTimestampText(const AValue: string): string;

{**
  Reports whether a completed task needs explicit review attention.

  Parameters
  ----------
  ATask
    Scan task whose warning, error, empty-scan, and known-issue state is
    inspected.

  Returns
  -------
  Boolean
    True when the task completed with warnings, errors, no inspected files, or
    one or more matched known-issue advisories.

  Raises
  ------
  None
}
function TaskNeedsReview(ATask: TScanTask): Boolean;

{**
  Produces a glyph-prefixed task status suitable for history rows.

  Parameters
  ----------
  ATask
    Task whose status and review state should be rendered.

  Returns
  -------
  string
    Theme-independent status text such as ``✓ completed`` or
    ``⚠ completed with warnings``.

  Raises
  ------
  None
}
function TaskStatusDisplayText(ATask: TScanTask): string;

{**
  Adds a success, warning, or failure glyph to an artifact-status spelling.

  Parameters
  ----------
  AStatus
    Artifact status enumeration to render.

  Returns
  -------
  string
    Glyph-prefixed stable artifact status text.

  Raises
  ------
  None
}
function ArtifactStatusDisplayText(AStatus: TArtifactStatus): string;

{**
  Adds a status glyph to a raw component-source status spelling.

  Parameters
  ----------
  AStatus
    Stable artifact-status text associated with a component.

  Returns
  -------
  string
    Glyph-prefixed status text; unknown nonempty values receive a warning
    glyph and blank input remains blank.

  Raises
  ------
  None
}
function StatusDisplayText(const AStatus: string): string;

{**
  Counts diagnostics and artifact notes represented by the Messages tab.

  Parameters
  ----------
  ATask
    Task whose warnings, errors, and artifact messages are counted.

  Returns
  -------
  Integer
    Number of concrete messages, excluding the permanent completeness notice.

  Raises
  ------
  None
}
function TaskMessageCount(ATask: TScanTask): Integer;

{**
  Shortens a digest for table display without changing its stored value.

  Parameters
  ----------
  AValue
    Full digest text.
  ALength
    Maximum displayed character count; non-positive values produce blank text.

  Returns
  -------
  string
    Original text when short enough, otherwise its leading characters.

  Raises
  ------
  None
}
function ShortDigest(const AValue: string; ALength: Integer = 12): string;

implementation

uses
  DateUtils;

const
  SuccessGlyph = #$E2#$9C#$93;
  WarningGlyph = #$E2#$9A#$A0;
  FailureGlyph = #$E2#$9C#$95;
  NeutralGlyph = #$E2#$80#$A2;

{**
  Normalizes malformed or legacy timestamp text without timezone conversion.

  Parameters
  ----------
  AValue
    Timestamp-like text to compact for display.

  Returns
  -------
  string
    Trimmed text with a space separator, no fractional part, and no trailing Z.

  Raises
  ------
  None
}
function CompactTimestampFallback(const AValue: string): string;
var
  FractionAt: SizeInt;
begin
  Result := StringReplace(Trim(AValue), 'T', ' ', []);
  FractionAt := Pos('.', Result);
  if FractionAt > 0 then
    Result := Copy(Result, 1, FractionAt - 1);
  if (Result <> '') and (Result[Length(Result)] = 'Z') then
    Delete(Result, Length(Result), 1);
end;

function LocalTimestampText(const AValue: string): string;
var
  LocalValue: TDateTime;
begin
  if TryISO8601ToDate(AValue, LocalValue, False) then
    Result := FormatDateTime('yyyy"-"mm"-"dd hh":"nn":"ss', LocalValue)
  else
    Result := CompactTimestampFallback(AValue);
end;

function TaskNeedsReview(ATask: TScanTask): Boolean;
begin
  Result := (ATask <> nil) and (ATask.Status = tsCompleted) and
    ((ATask.Warnings.Count > 0) or (ATask.Errors.Count > 0) or
    (ATask.FilesInspected = 0) or
    (ATask.KnownIssueCheck.MatchCount > 0));
end;

function TaskStatusDisplayText(ATask: TScanTask): string;
var
  StatusValue: string;
begin
  if ATask = nil then
    Exit('');
  StatusValue := TaskStatusToString(ATask.Status);
  case ATask.Status of
    tsCompleted:
      if TaskNeedsReview(ATask) then
        Result := WarningGlyph + ' completed with warnings'
      else
        Result := SuccessGlyph + ' ' + StatusValue;
    tsFailed:
      Result := FailureGlyph + ' ' + StatusValue;
    tsCancelled:
      Result := WarningGlyph + ' ' + StatusValue;
  else
    Result := NeutralGlyph + ' ' + StatusValue;
  end;
end;

function ArtifactStatusDisplayText(AStatus: TArtifactStatus): string;
begin
  Result := StatusDisplayText(ArtifactStatusToString(AStatus));
end;

function StatusDisplayText(const AStatus: string): string;
var
  StatusValue: string;
begin
  StatusValue := Trim(AStatus);
  if StatusValue = '' then
    Exit('');
  if SameText(StatusValue, 'parsed') then
    Result := SuccessGlyph + ' ' + StatusValue
  else if SameText(StatusValue, 'failed') then
    Result := FailureGlyph + ' ' + StatusValue
  else if SameText(StatusValue, 'partially parsed') then
    Result := WarningGlyph + ' partial'
  else if SameText(StatusValue, 'detected but unsupported') then
    Result := WarningGlyph + ' unsupported'
  else
    Result := WarningGlyph + ' ' + StatusValue;
end;

function TaskMessageCount(ATask: TScanTask): Integer;
var
  I: Integer;
begin
  Result := 0;
  if ATask = nil then
    Exit;
  Result := ATask.Warnings.Count + ATask.Errors.Count;
  Inc(Result, ATask.KnownIssueCheck.MatchCount);
  for I := 0 to ATask.Artifacts.Count - 1 do
    if Trim(TArtifact(ATask.Artifacts[I]).MessageText) <> '' then
      Inc(Result);
end;

function ShortDigest(const AValue: string; ALength: Integer): string;
begin
  if ALength <= 0 then
    Exit('');
  if Length(AValue) <= ALength then
    Result := AValue
  else
    Result := Copy(AValue, 1, ALength);
end;

end.
