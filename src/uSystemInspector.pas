(**
  SBOM Analyzer operating-system inspection unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Enriches binary evidence through an explicit allowlist of already available
  OS tools or APIs under strict process, output, and cancellation bounds.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026sbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uSystemInspector;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TSystemInspectionCancelCheck = function: Boolean of object;

  TSystemInspection = class
  public
    ToolName: string;
    ComponentVersion: string;
    Dependencies: TStringList;
    Details: TStringList;
    {**
      Creates sorted, duplicate-free dependency and detail collections.

      Parameters
      ----------
      None

      Returns
      -------
      TSystemInspection
        Newly initialized evidence container.

      Raises
      ------
      EOutOfMemory
        Propagated if the collections cannot be allocated.
    }
    constructor Create;
    destructor Destroy; override;

    {**
      Formats the tool name, linked libraries, and details for artifact messages.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Compact single-line inspection summary.

      Raises
      ------
      None
    }
    function Summary: string;
  end;

{**
  Parses stable readelf dynamic-section and GNU build-ID output.

  Parameters
  ----------
  AOutput
    Combined stdout/stderr captured under the C locale.
  AInspection
    Evidence container that receives dependencies and build identifiers.

  Returns
  -------
  Boolean
    True when at least one recognized evidence item is found.

  Raises
  ------
  None
}
function ParseReadElfOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;

{**
  Applies the approved OS-specific inspection facility for a binary.

  Parameters
  ----------
  AFileName
    Static target file supplied only as tool or API input.
  AFormatName
    Previously detected PE, ELF, or Mach-O format name.
  AInspection
    Receives a newly allocated evidence object on success, otherwise nil.
  ACancelCheck
    Optional callback polled while an approved child process is active.

  Returns
  -------
  Boolean
    True when an applicable facility completed and returned usable status.

  Raises
  ------
  None
    Tool discovery, launch, timeout, output-limit, and API failures return False.
}
function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck = nil): Boolean;

implementation

uses
  Process, uNativeDependencyInspector
  {$IFDEF Windows}, Windows{$ENDIF};

const
  ToolTimeoutMS = 3000;
  MaximumToolOutput = 512 * 1024;

constructor TSystemInspection.Create;
begin
  inherited Create;
  Dependencies := TStringList.Create;
  Dependencies.Sorted := True;
  Dependencies.Duplicates := dupIgnore;
  Details := TStringList.Create;
  Details.Sorted := True;
  Details.Duplicates := dupIgnore;
end;

destructor TSystemInspection.Destroy;
begin
  Details.Free;
  Dependencies.Free;
  inherited Destroy;
end;

function TSystemInspection.Summary: string;
begin
  Result := '';
  if ToolName <> '' then
    Result := 'OS inspection: ' + ToolName;
  if ComponentVersion <> '' then
    Result := Result + '; component version: ' + ComponentVersion;
  if Dependencies.Count > 0 then
    Result := Result + '; linked libraries: ' +
      StringReplace(Dependencies.CommaText, ',', ', ', [rfReplaceAll]);
  if Details.Count > 0 then
    Result := Result + '; ' + StringReplace(Details.Text, LineEnding, '; ',
      [rfReplaceAll]);
  while (Length(Result) >= 2) and
    (Copy(Result, Length(Result) - 1, 2) = '; ') do
    Delete(Result, Length(Result) - 1, 2);
end;

function FindTool(const APreferredPath, AName: string): string;
begin
  if (APreferredPath <> '') and FileExists(APreferredPath) then
    Exit(APreferredPath);
  Result := FileSearch(AName, SysUtils.GetEnvironmentVariable('PATH'));
end;

procedure PrepareToolEnvironment(AProcess: TProcess);
{$IFDEF UNIX}
var
  I: Integer;
{$ENDIF}
begin
  {$IFDEF UNIX}
  for I := 1 to SysUtils.GetEnvironmentVariableCount do
    AProcess.Environment.Add(GetEnvironmentString(I));
  AProcess.Environment.Values['LC_ALL'] := 'C';
  AProcess.Environment.Values['LANG'] := 'C';
  AProcess.Environment.Values['DEBUGINFOD_URLS'] := '';
  {$ENDIF}
end;

{**
  Runs one allowlisted executable directly and captures bounded combined output.

  Parameters
  ----------
  AExecutable
    Resolved executable path; an empty value returns False.
  AParameters
    Argument vector passed without a command shell.
  AOutput
    Receives at most MaximumToolOutput bytes plus a limit diagnostic.
  AExitStatus
    Receives the process exit code, or -1 when launch did not occur.
  ACancelCheck
    Optional callback that terminates the helper cooperatively.

  Returns
  -------
  Boolean
    True when the process ran without scan cancellation; callers still inspect
    AExitStatus where the tool requires a zero exit code.

  Raises
  ------
  None
    Launch errors, timeouts, and cancellation are represented in outputs.
}
function RunBoundedTool(const AExecutable: string; const AParameters: array of string;
  out AOutput: string; out AExitStatus: Integer;
  ACancelCheck: TSystemInspectionCancelCheck): Boolean;
var
  Tool: TProcess;
  Buffer: array[0..8191] of Byte;
  Count, I: Integer;
  Started: QWord;
  Chunk: RawByteString;
  Cancelled: Boolean;
begin
  Result := False;
  AOutput := '';
  AExitStatus := -1;
  Cancelled := False;
  if AExecutable = '' then
    Exit;
  Tool := TProcess.Create(nil);
  try
    Tool.Executable := AExecutable;
    PrepareToolEnvironment(Tool);
    for I := Low(AParameters) to High(AParameters) do
      Tool.Parameters.Add(AParameters[I]);
    Tool.Options := [poUsePipes, poStderrToOutPut];
    try
      Tool.Execute;
    except
      Exit;
    end;
    Started := GetTickCount64;
    while Tool.Running or (Tool.Output.NumBytesAvailable > 0) do
    begin
      while Tool.Output.NumBytesAvailable > 0 do
      begin
        Count := Tool.Output.Read(Buffer, SizeOf(Buffer));
        if Count <= 0 then
          Break;
        SetLength(Chunk, Count);
        Move(Buffer[0], Chunk[1], Count);
        if Length(AOutput) + Count <= MaximumToolOutput then
          AOutput := AOutput + string(Chunk)
        else
        begin
          Tool.Terminate(1);
          AOutput := AOutput + LineEnding +
            '[inspection output exceeded safety limit]';
          Break;
        end;
      end;
      if Tool.Running and (GetTickCount64 - Started >= ToolTimeoutMS) then
      begin
        Tool.Terminate(1);
        AOutput := AOutput + LineEnding + '[inspection timed out]';
      end;
      if Tool.Running and Assigned(ACancelCheck) and ACancelCheck() then
      begin
        Cancelled := True;
        Tool.Terminate(1);
      end;
      if Tool.Running then
        Sleep(10);
    end;
    Tool.WaitOnExit;
    AExitStatus := Tool.ExitStatus;
    Result := not Cancelled;
  finally
    Tool.Free;
  end;
end;

function ParseReadElfOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;
var
  Lines: TStringList;
  I, OpenAt, CloseAt, MarkerAt: Integer;
  LineValue, Value: string;
begin
  Result := False;
  if AInspection = nil then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := AOutput;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      MarkerAt := Pos('(NEEDED)', LineValue);
      if MarkerAt > 0 then
      begin
        OpenAt := Pos('[', LineValue);
        CloseAt := Pos(']', LineValue);
        if (OpenAt > 0) and (CloseAt > OpenAt + 1) then
        begin
          Value := Copy(LineValue, OpenAt + 1, CloseAt - OpenAt - 1);
          AInspection.Dependencies.Add(Value);
          Result := True;
        end;
      end;
      MarkerAt := Pos('(SONAME)', LineValue);
      if MarkerAt > 0 then
      begin
        OpenAt := Pos('[', LineValue);
        CloseAt := Pos(']', LineValue);
        if (OpenAt > 0) and (CloseAt > OpenAt + 1) then
        begin
          Value := Copy(LineValue, OpenAt + 1, CloseAt - OpenAt - 1);
          AInspection.ComponentVersion := NativeDependencyVersion(Value);
          if AInspection.ComponentVersion <> '' then
            Result := True;
        end;
      end;
      MarkerAt := Pos('Build ID:', LineValue);
      if MarkerAt > 0 then
      begin
        Value := Trim(Copy(LineValue, MarkerAt + Length('Build ID:'), MaxInt));
        if Value <> '' then
        begin
          AInspection.Details.Add('build ID: ' + Value);
          Result := True;
        end;
      end;
    end;
  finally
    Lines.Free;
  end;
end;

{**
  Extracts stable identity and signature fields from macOS codesign output.

  Parameters
  ----------
  AOutput
    Combined text emitted by codesign inspection.
  AInspection
    Result object receiving recognized detail lines.

  Returns
  -------
  Boolean
    True when at least one supported signature field is found.

  Raises
  ------
  EOutOfMemory
    Propagated if parsing storage cannot be allocated.
}
function ParseCodeSignOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;
const
  Keys: array[0..5] of string = ('Identifier=', 'TeamIdentifier=',
    'Authority=', 'CDHash=', 'Signature=', 'Runtime Version=');
var
  Lines: TStringList;
  I, J: Integer;
  LineValue: string;
begin
  Result := False;
  Lines := TStringList.Create;
  try
    Lines.Text := AOutput;
    for I := 0 to Lines.Count - 1 do
    begin
      LineValue := Trim(Lines[I]);
      for J := Low(Keys) to High(Keys) do
        if Pos(Keys[J], LineValue) = 1 then
        begin
          AInspection.Details.Add(LineValue);
          Result := True;
          Break;
        end;
    end;
  finally
    Lines.Free;
  end;
end;

{$IFDEF Windows}
{**
  Reads all four fixed-file-version fields through the native Windows API.

  Parameters
  ----------
  AFileName
    PE file whose embedded version resource should be queried.
  AVersion
    Receives major.minor.revision.build on success.

  Returns
  -------
  Boolean
    True only when a structurally valid fixed version resource is available.

  Raises
  ------
  EOutOfMemory
    Propagated when the bounded version-information buffer cannot be allocated.
    Windows API and malformed-resource failures return False.
}
function TryGetWindowsFileVersion(const AFileName: UnicodeString;
  out AVersion: string): Boolean;
var
  IgnoredHandle, InfoSize: DWORD;
  ValueSize: UINT;
  Buffer, FixedBuffer: Pointer;
  FixedInfo: PVSFixedFileInfo;
  RootBlock: UnicodeString;
begin
  Result := False;
  AVersion := '';
  IgnoredHandle := 0;
  InfoSize := GetFileVersionInfoSizeW(PWideChar(AFileName), @IgnoredHandle);
  if InfoSize = 0 then
    Exit;
  GetMem(Buffer, InfoSize);
  try
    if not GetFileVersionInfoW(PWideChar(AFileName), 0, InfoSize, Buffer) then
      Exit;
    RootBlock := '\';
    FixedBuffer := nil;
    ValueSize := 0;
    if not VerQueryValueW(Buffer, PWideChar(RootBlock), FixedBuffer,
      ValueSize) or (FixedBuffer = nil) or
      (ValueSize < SizeOf(TVSFixedFileInfo)) then
      Exit;
    FixedInfo := PVSFixedFileInfo(FixedBuffer);
    if FixedInfo^.dwSignature <> $FEEF04BD then
      Exit;
    AVersion := Format('%d.%d.%d.%d',
      [FixedInfo^.dwFileVersionMS shr 16,
       FixedInfo^.dwFileVersionMS and $FFFF,
       FixedInfo^.dwFileVersionLS shr 16,
       FixedInfo^.dwFileVersionLS and $FFFF]);
    Result := True;
  finally
    FreeMem(Buffer);
  end;
end;
{$ENDIF}

function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck): Boolean;
var
  ExecutableName, OutputText: string;
  ExitStatus: Integer;
  {$IFDEF Windows}
  VersionText: string;
  {$ENDIF}
begin
  Result := False;
  AInspection := TSystemInspection.Create;
  {$IFDEF Linux}
  if SameText(AFormatName, 'ELF') then
  begin
    ExecutableName := FindTool('/usr/bin/readelf', 'readelf');
    if RunBoundedTool(ExecutableName,
      ['--wide', '--dynamic', '--notes', '--', AFileName], OutputText,
      ExitStatus, ACancelCheck) and (ExitStatus = 0) then
    begin
      AInspection.ToolName := 'readelf';
      ParseReadElfOutput(OutputText, AInspection);
      Result := True;
    end;
  end;
  {$ENDIF}
  {$IFDEF Darwin}
  if Pos('Mach-O', AFormatName) = 1 then
  begin
    ExecutableName := FindTool('/usr/bin/codesign', 'codesign');
    if RunBoundedTool(ExecutableName,
      ['--display', '--verbose=4', AFileName], OutputText, ExitStatus,
      ACancelCheck) then
    begin
      AInspection.ToolName := 'codesign';
      ParseCodeSignOutput(OutputText, AInspection);
      Result := True;
    end;
  end;
  {$ENDIF}
  {$IFDEF Windows}
  if SameText(AFormatName, 'PE') then
  begin
    if TryGetWindowsFileVersion(UTF8Decode(AFileName), VersionText) then
    begin
      AInspection.ToolName := 'Windows version-resource API';
      AInspection.ComponentVersion := VersionText;
      AInspection.Details.Add('file version: ' +
        AInspection.ComponentVersion);
      Result := True;
    end;
  end;
  {$ENDIF}
  if not Result then
    FreeAndNil(AInspection);
end;

end.
