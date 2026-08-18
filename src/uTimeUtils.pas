(**
  SBOM Analyzer time-and-size formatting unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is open source, but the
  author's copyright and attribution rights are retained.

  Description
  -----------
  Creates UTC timestamps, calculates elapsed milliseconds, and formats elapsed
  time and byte counts for stable persistence and readable UI output.

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
unit uTimeUtils;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

{**
  Produces the current UTC time in millisecond ISO-8601 notation.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Timestamp such as 2026-08-18T14:32:05.123Z.

  Raises
  ------
  None
}
function UTCNowISO8601: string;

{**
  Calculates elapsed milliseconds between two persisted UTC timestamps.

  Parameters
  ----------
  AStartUTC
    ISO-8601 start time.
  AEndUTC
    ISO-8601 end time.

  Returns
  -------
  Int64
    Non-negative elapsed milliseconds, or zero for invalid input.

  Raises
  ------
  None
    Parse failures are converted to zero.
}
function DurationMilliseconds(const AStartUTC, AEndUTC: string): Int64;

{**
  Formats a millisecond duration for compact UI display.

  Parameters
  ----------
  AMilliseconds
    Duration to format.

  Returns
  -------
  string
    Human-readable milliseconds, seconds, or minutes/seconds text.

  Raises
  ------
  None
}
function FormatDuration(AMilliseconds: Int64): string;

{**
  Formats a byte count using binary KiB, MiB, and GiB units.

  Parameters
  ----------
  ABytes
    Byte count to format.

  Returns
  -------
  string
    Compact human-readable size.

  Raises
  ------
  None
}
function FormatByteSize(ABytes: Int64): string;

implementation

uses
  DateUtils;

function UTCNowISO8601: string;
var
  UTCValue: TDateTime;
begin
  UTCValue := LocalTimeToUniversal(Now);
  Result := FormatDateTime('yyyy"-"mm"-"dd"T"hh":"nn":"ss"."zzz"Z"', UTCValue);
end;

function DurationMilliseconds(const AStartUTC, AEndUTC: string): Int64;
var
  StartValue, EndValue: TDateTime;
begin
  Result := 0;
  if (AStartUTC = '') or (AEndUTC = '') then
    Exit;
  try
    StartValue := ISO8601ToDate(AStartUTC, False);
    EndValue := ISO8601ToDate(AEndUTC, False);
    Result := MilliSecondsBetween(EndValue, StartValue);
  except
    Result := 0;
  end;
end;

function FormatDuration(AMilliseconds: Int64): string;
var
  Seconds: Double;
begin
  if AMilliseconds < 0 then
    AMilliseconds := 0;
  Seconds := AMilliseconds / 1000.0;
  if Seconds < 60 then
    Result := FormatFloat('0.0 s', Seconds)
  else
    Result := Format('%d min %.1f s', [AMilliseconds div 60000,
      (AMilliseconds mod 60000) / 1000.0]);
end;

function FormatByteSize(ABytes: Int64): string;
const
  Units: array[0..4] of string = ('B', 'KiB', 'MiB', 'GiB', 'TiB');
var
  Value: Double;
  UnitIndex: Integer;
begin
  Value := ABytes;
  UnitIndex := 0;
  while (Abs(Value) >= 1024.0) and (UnitIndex < High(Units)) do
  begin
    Value := Value / 1024.0;
    Inc(UnitIndex);
  end;
  if UnitIndex = 0 then
    Result := Format('%d %s', [ABytes, Units[UnitIndex]])
  else
    Result := FormatFloat('0.0', Value) + ' ' + Units[UnitIndex];
end;

end.
