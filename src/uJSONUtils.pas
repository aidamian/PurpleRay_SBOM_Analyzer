unit uJSONUtils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpjson;

function JSONString(AObject: TJSONObject; const AName: string;
  const ADefault: string = ''): string;
function JSONBoolean(AObject: TJSONObject; const AName: string;
  ADefault: Boolean = False): Boolean;
function JSONInt64(AObject: TJSONObject; const AName: string;
  ADefault: Int64 = 0): Int64;
function JSONObject(AObject: TJSONObject; const AName: string): TJSONObject;
function JSONArray(AObject: TJSONObject; const AName: string): TJSONArray;
function ReadJSONFile(const AFileName: string): TJSONData;
procedure WriteUTF8File(const AFileName: string; const AContent: UTF8String);
function NormalizeJSONLineEndings(const AValue: string): string;

implementation

uses
  jsonparser;

function JSONString(AObject: TJSONObject; const AName: string;
  const ADefault: string): string;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsString;
end;

function JSONBoolean(AObject: TJSONObject; const AName: string;
  ADefault: Boolean): Boolean;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsBoolean;
end;

function JSONInt64(AObject: TJSONObject; const AName: string;
  ADefault: Int64): Int64;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsInt64;
end;

function JSONObject(AObject: TJSONObject; const AName: string): TJSONObject;
var
  Data: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType = jtObject) then
    Result := TJSONObject(Data);
end;

function JSONArray(AObject: TJSONObject; const AName: string): TJSONArray;
var
  Data: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType = jtArray) then
    Result := TJSONArray(Data);
end;

function ReadJSONFile(const AFileName: string): TJSONData;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := GetJSON(Stream);
  finally
    Stream.Free;
  end;
end;

procedure WriteUTF8File(const AFileName: string; const AContent: UTF8String);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(AContent) > 0 then
      Stream.WriteBuffer(AContent[1], Length(AContent));
  finally
    Stream.Free;
  end;
end;

function NormalizeJSONLineEndings(const AValue: string): string;
begin
  Result := StringReplace(AValue, #13#10, #10, [rfReplaceAll]);
  Result := StringReplace(Result, #13, #10, [rfReplaceAll]);
end;

end.
