(**
  PurpleRay SBOM Analyzer JSON utility unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Provides defensive typed JSON accessors and UTF-8 file helpers shared by
  settings, history, manifest parsing, and SBOM generation.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026purpleraysbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{PurpleRay SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uJSONUtils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpjson;

{**
  Reads a string member with type checking and a caller-supplied fallback.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned when the member is absent or not a JSON string.

  Returns
  -------
  string
    Stored value or ADefault.

  Raises
  ------
  None
}
function JSONString(AObject: TJSONObject; const AName: string;
  const ADefault: string = ''): string;

{**
  Reads a Boolean member with type checking.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned for a missing or incompatible member.

  Returns
  -------
  Boolean
    Stored value or ADefault.

  Raises
  ------
  None
}
function JSONBoolean(AObject: TJSONObject; const AName: string;
  ADefault: Boolean = False): Boolean;

{**
  Reads an integer member as Int64 with type checking.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned for a missing or incompatible member.

  Returns
  -------
  Int64
    Stored integer or ADefault.

  Raises
  ------
  None
}
function JSONInt64(AObject: TJSONObject; const AName: string;
  ADefault: Int64 = 0): Int64;

{**
  Returns a named child only when it is a JSON object.

  Parameters
  ----------
  AObject
    Parent object; nil is accepted.
  AName
    Child member name.

  Returns
  -------
  TJSONObject
    Borrowed child reference, or nil when absent or incompatible.

  Raises
  ------
  None
}
function JSONObject(AObject: TJSONObject; const AName: string): TJSONObject;

{**
  Returns a named child only when it is a JSON array.

  Parameters
  ----------
  AObject
    Parent object; nil is accepted.
  AName
    Child member name.

  Returns
  -------
  TJSONArray
    Borrowed child reference, or nil when absent or incompatible.

  Raises
  ------
  None
}
function JSONArray(AObject: TJSONObject; const AName: string): TJSONArray;

{**
  Reads and parses one UTF-8 JSON document from disk.

  Parameters
  ----------
  AFileName
    JSON file to open.

  Returns
  -------
  TJSONData
    Newly allocated JSON tree owned by the caller.

  Raises
  ------
  EFOpenError, EReadError, EJSONParser
    Propagated for file access or malformed JSON.
}
function ReadJSONFile(const AFileName: string): TJSONData;

{**
  Writes exact UTF-8 bytes to a newly created or replaced file.

  Parameters
  ----------
  AFileName
    Destination filename.
  AContent
    UTF-8 bytes to write.

  Returns
  -------
  None

  Raises
  ------
  EFCreateError, EWriteError
    Propagated when the file cannot be created or fully written.
}
procedure WriteUTF8File(const AFileName: string; const AContent: UTF8String);

{**
  Converts CRLF and bare CR sequences to line-feed JSON line endings.

  Parameters
  ----------
  AValue
    Text to normalize.

  Returns
  -------
  string
    Text containing only LF line separators.

  Raises
  ------
  None
}
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
