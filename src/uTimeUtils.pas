unit uTimeUtils;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

function UTCNowISO8601: string;
function DurationMilliseconds(const AStartUTC, AEndUTC: string): Int64;
function FormatDuration(AMilliseconds: Int64): string;
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
