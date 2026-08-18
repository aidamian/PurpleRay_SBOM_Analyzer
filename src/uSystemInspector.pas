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
    Dependencies: TStringList;
    Details: TStringList;
    constructor Create;
    destructor Destroy; override;
    function Summary: string;
  end;

function ParseReadElfOutput(const AOutput: string;
  AInspection: TSystemInspection): Boolean;
function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck = nil): Boolean;

implementation

uses
  Process;

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
  Result := FileSearch(AName, GetEnvironmentVariable('PATH'));
end;

procedure PrepareToolEnvironment(AProcess: TProcess);
{$IFDEF UNIX}
var
  I: Integer;
{$ENDIF}
begin
  {$IFDEF UNIX}
  for I := 1 to GetEnvironmentVariableCount do
    AProcess.Environment.Add(GetEnvironmentString(I));
  AProcess.Environment.Values['LC_ALL'] := 'C';
  AProcess.Environment.Values['LANG'] := 'C';
  AProcess.Environment.Values['DEBUGINFOD_URLS'] := '';
  {$ENDIF}
end;

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

function InspectWithSystemTools(const AFileName, AFormatName: string;
  out AInspection: TSystemInspection;
  ACancelCheck: TSystemInspectionCancelCheck): Boolean;
var
  ExecutableName, OutputText: string;
  ExitStatus: Integer;
  {$IFDEF Windows}
  VersionValue: Cardinal;
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
    VersionValue := GetFileVersion(UTF8Decode(AFileName));
    if VersionValue <> $0FFFFFFF then
    begin
      AInspection.ToolName := 'Windows version-resource API';
      AInspection.Details.Add(Format('file version: %d.%d',
        [VersionValue shr 16, VersionValue and $FFFF]));
      Result := True;
    end;
  end;
  {$ENDIF}
  if not Result then
    FreeAndNil(AInspection);
end;

end.
