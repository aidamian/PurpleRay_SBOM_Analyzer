(**
  SBOM Analyzer ignore-pattern unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is open source, but the
  author's copyright and attribution rights are retained.

  Description
  -----------
  Normalizes relative paths and evaluates exact-name, wildcard, and relative
  path ignore rules used during recursive scanning.

  Citation requirement
  --------------------
  Derivative works must retain this notice and cite the project as follows:

  @misc{damian2026sbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uIgnoreMatcher;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

{**
  Normalizes separators and removes leading relative-path decoration.

  Parameters
  ----------
  APath
    Relative path in platform or portable notation.

  Returns
  -------
  string
    Slash-separated path without leading ./ or / characters.

  Raises
  ------
  None
}
function NormalizeRelativePath(const APath: string): string;

{**
  Matches a string against a simple asterisk/question-mark wildcard pattern.

  Parameters
  ----------
  APattern
    Pattern containing literal characters, * and ? wildcards.
  AValue
    Candidate value.
  ACaseSensitive
    Controls whether character comparisons preserve case.

  Returns
  -------
  Boolean
    True when the complete value matches the complete pattern.

  Raises
  ------
  None
}
function WildcardMatches(const APattern, AValue: string;
  ACaseSensitive: Boolean = True): Boolean;

{**
  Applies configured ignore rules to a root-relative filesystem entry.

  Parameters
  ----------
  ARelativePath
    Root-relative path to test.
  AIsDirectory
    True when the entry is a directory, enabling directory-name rules.
  APatterns
    Editable exact, wildcard, or relative-path patterns.

  Returns
  -------
  Boolean
    True when any pattern excludes the entry.

  Raises
  ------
  None
}
function ShouldIgnorePath(const ARelativePath: string; AIsDirectory: Boolean;
  APatterns: TStrings): Boolean;

implementation

function NormalizeRelativePath(const APath: string): string;
begin
  Result := StringReplace(Trim(APath), '\', '/', [rfReplaceAll]);
  while Pos('./', Result) = 1 do
    Delete(Result, 1, 2);
  while (Length(Result) > 0) and (Result[1] = '/') do
    Delete(Result, 1, 1);
  while (Length(Result) > 0) and (Result[Length(Result)] = '/') do
    Delete(Result, Length(Result), 1);
end;

function WildcardMatches(const APattern, AValue: string;
  ACaseSensitive: Boolean): Boolean;
var
  PatternValue, InputValue: string;
  PatternIndex, ValueIndex, StarIndex, RetryIndex: Integer;
begin
  if ACaseSensitive then
  begin
    PatternValue := APattern;
    InputValue := AValue;
  end
  else
  begin
    PatternValue := LowerCase(APattern);
    InputValue := LowerCase(AValue);
  end;
  PatternIndex := 1;
  ValueIndex := 1;
  StarIndex := 0;
  RetryIndex := 0;
  while ValueIndex <= Length(InputValue) do
  begin
    if (PatternIndex <= Length(PatternValue)) and
      ((PatternValue[PatternIndex] = '?') or
      (PatternValue[PatternIndex] = InputValue[ValueIndex])) then
    begin
      Inc(PatternIndex);
      Inc(ValueIndex);
    end
    else if (PatternIndex <= Length(PatternValue)) and
      (PatternValue[PatternIndex] = '*') then
    begin
      StarIndex := PatternIndex;
      Inc(PatternIndex);
      RetryIndex := ValueIndex;
    end
    else if StarIndex <> 0 then
    begin
      PatternIndex := StarIndex + 1;
      Inc(RetryIndex);
      ValueIndex := RetryIndex;
    end
    else
      Exit(False);
  end;
  while (PatternIndex <= Length(PatternValue)) and
    (PatternValue[PatternIndex] = '*') do
    Inc(PatternIndex);
  Result := PatternIndex > Length(PatternValue);
end;

function SegmentMatches(const APattern, APath: string;
  ACaseSensitive: Boolean): Boolean;
var
  StartAt, EndAt: Integer;
  Segment: string;
begin
  StartAt := 1;
  repeat
    EndAt := Pos('/', APath, StartAt);
    if EndAt = 0 then
      EndAt := Length(APath) + 1;
    Segment := Copy(APath, StartAt, EndAt - StartAt);
    if WildcardMatches(APattern, Segment, ACaseSensitive) then
      Exit(True);
    StartAt := EndAt + 1;
  until StartAt > Length(APath);
  Result := False;
end;

function ShouldIgnorePath(const ARelativePath: string; AIsDirectory: Boolean;
  APatterns: TStrings): Boolean;
var
  NormalizedPath, PatternValue, Candidate: string;
  I: Integer;
  CaseSensitive: Boolean;
begin
  Result := False;
  if APatterns = nil then
    Exit;
  NormalizedPath := NormalizeRelativePath(ARelativePath);
  {$IFDEF Windows}
  CaseSensitive := False;
  {$ELSE}
  CaseSensitive := True;
  {$ENDIF}
  for I := 0 to APatterns.Count - 1 do
  begin
    PatternValue := NormalizeRelativePath(APatterns[I]);
    if (PatternValue = '') or (PatternValue[1] = '#') then
      Continue;
    if Pos('/', PatternValue) = 0 then
    begin
      if SegmentMatches(PatternValue, NormalizedPath, CaseSensitive) then
        Exit(True);
    end
    else
    begin
      Candidate := NormalizedPath;
      if WildcardMatches(PatternValue, Candidate, CaseSensitive) then
        Exit(True);
      if AIsDirectory and
        WildcardMatches(PatternValue + '/*', Candidate + '/', CaseSensitive) then
        Exit(True);
    end;
  end;
end;

end.
