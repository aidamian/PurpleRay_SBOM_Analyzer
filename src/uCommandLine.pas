(**
  PurpleRay SBOM Analyzer early command-line unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Parses and executes informational and headless scan commands before the LCL
  widgetset initializes, including native redirected output from the Windows
  GUI-subsystem executable.

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
unit uCommandLine;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uModels;

const
  CLIExitSuccess = 0;
  CLIExitFailure = 1;
  CLIExitUsage = 2;
  CLINotHandled = -1;

type
  TCommandLineMode = (clmGUI, clmHelp, clmVersion, clmScan);

  TCommandArgumentArray = array of string;

  TCommandLineOptions = record
    Mode: TCommandLineMode;
    ScanDirectory: string;
    OutputFileName: string;
    SettingsFileName: string;
  end;

{**
  Parses an explicit argument vector without reading process-global state.

  Parameters
  ----------
  AArguments
    Arguments after the executable name, in their original order.
  AOptions
    Receives the selected mode and exact option values on success.
  AError
    Receives a stable usage diagnostic on failure, otherwise an empty string.

  Returns
  -------
  Boolean
    True for a complete GUI, help, version, or headless-scan invocation.

  Raises
  ------
  EOutOfMemory
    May propagate while copying argument values.
}
function ParseCommandLineArguments(const AArguments: array of string;
  out AOptions: TCommandLineOptions; out AError: string): Boolean;

{**
  Loads one explicit JSON settings file without consulting application data.

  Parameters
  ----------
  AFileName
    Path to either a direct scan-settings object or the versioned wrapper
    written by the desktop application.

  Returns
  -------
  TScanSettings
    Newly allocated settings owned by the caller.

  Raises
  ------
  EFOpenError, EReadError, EJSONParser
    Raised for inaccessible, oversized, or malformed input.
  EJSON
    Raised when the root, wrapper, or known setting fields have invalid types.
  EOutOfMemory
    May propagate while parsing or constructing settings.
}
function LoadCommandLineSettings(const AFileName: string): TScanSettings;

{**
  Handles the current process arguments through native standard streams.

  Parameters
  ----------
  None

  Returns
  -------
  Integer
    CLINotHandled for the no-argument GUI path; otherwise a stable process exit
    code suitable for Halt.

  Raises
  ------
  None
    Operational exceptions are converted into stderr diagnostics and a
    nonzero exit code.
}
function HandleCommandLine: Integer;

implementation

uses
  fpjson, uJSONUtils, uPlatform, uScanService, uVersionInfo,
  {$IFDEF Windows}
  Windows, ShellApi;
  {$ELSE}
  BaseUnix, UnixType;
  {$ENDIF}

const
  MaximumSettingsBytes = 1024 * 1024;
  HelpText =
    'PurpleRay SBOM Analyzer' + #10 +
    #10 +
    'Usage:' + #10 +
    '  purpleray-sbom-analyzer' + #10 +
    '  purpleray-sbom-analyzer --help' + #10 +
    '  purpleray-sbom-analyzer --version' + #10 +
    '  purpleray-sbom-analyzer --scan <directory> --output <file>' + #10 +
    '    [--settings <json-file>]' + #10 +
    #10 +
    'Headless scans are offline, do not update task history or saved settings,' + #10 +
    'and use safe scan defaults unless --settings is supplied.' + #10;

{$IFDEF Windows}
type
  TPWideCharArray = array[0..(MaxInt div SizeOf(PWideChar)) - 1] of PWideChar;
  PPWideCharArray = ^TPWideCharArray;

var
  ConsoleAttachmentAttempted: Boolean = False;
{$ENDIF}

{**
  Resets a command-options record to the no-argument GUI mode.

  Parameters
  ----------
  AOptions
    Record to initialize.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure InitializeOptions(out AOptions: TCommandLineOptions);
begin
  AOptions.Mode := clmGUI;
  AOptions.ScanDirectory := '';
  AOptions.OutputFileName := '';
  AOptions.SettingsFileName := '';
end;

{**
  Reports whether an argument token is option-like rather than a value.

  Parameters
  ----------
  AValue
    Token following an option that requires a value.

  Returns
  -------
  Boolean
    True when the token begins with a dash; paths with such names must be
    supplied in qualified form, for example ``./--target``.

  Raises
  ------
  None
}
function IsOptionToken(const AValue: string): Boolean;
begin
  Result := (AValue <> '') and (AValue[1] = '-');
end;

function ParseCommandLineArguments(const AArguments: array of string;
  out AOptions: TCommandLineOptions; out AError: string): Boolean;
var
  Argument, Value: string;
  HasOutput, HasScan, HasSettings: Boolean;
  I: Integer;
begin
  InitializeOptions(AOptions);
  AError := '';
  if Length(AArguments) = 0 then
    Exit(True);
  if Length(AArguments) = 1 then
  begin
    if (AArguments[0] = '--help') or (AArguments[0] = '-h') then
    begin
      AOptions.Mode := clmHelp;
      Exit(True);
    end;
    if AArguments[0] = '--version' then
    begin
      AOptions.Mode := clmVersion;
      Exit(True);
    end;
  end;

  HasScan := False;
  HasOutput := False;
  HasSettings := False;
  I := 0;
  while I < Length(AArguments) do
  begin
    Argument := AArguments[I];
    if (Argument = '--help') or (Argument = '-h') or
      (Argument = '--version') then
    begin
      AError := Argument + ' cannot be combined with other arguments';
      Exit(False);
    end;
    if (Argument <> '--scan') and (Argument <> '--output') and
      (Argument <> '--settings') then
    begin
      AError := 'unknown argument: ' + Argument;
      Exit(False);
    end;
    if I + 1 >= Length(AArguments) then
    begin
      AError := 'missing value for ' + Argument;
      Exit(False);
    end;
    Value := AArguments[I + 1];
    if (Value = '') or IsOptionToken(Value) then
    begin
      AError := 'missing value for ' + Argument;
      Exit(False);
    end;
    if Argument = '--scan' then
    begin
      if HasScan then
      begin
        AError := 'duplicate option: --scan';
        Exit(False);
      end;
      HasScan := True;
      AOptions.ScanDirectory := Value;
    end
    else if Argument = '--output' then
    begin
      if HasOutput then
      begin
        AError := 'duplicate option: --output';
        Exit(False);
      end;
      HasOutput := True;
      AOptions.OutputFileName := Value;
    end
    else
    begin
      if HasSettings then
      begin
        AError := 'duplicate option: --settings';
        Exit(False);
      end;
      HasSettings := True;
      AOptions.SettingsFileName := Value;
    end;
    Inc(I, 2);
  end;

  if not HasScan then
  begin
    AError := 'required option is missing: --scan';
    Exit(False);
  end;
  if not HasOutput then
  begin
    AError := 'required option is missing: --output';
    Exit(False);
  end;
  AOptions.Mode := clmScan;
  Result := True;
end;

{**
  Requires a known settings member to have one exact JSON type when present.

  Parameters
  ----------
  AObject
    Scan-settings object to inspect.
  AName
    Member name.
  AExpectedType
    Only accepted JSON type for a non-null member.

  Returns
  -------
  None

  Raises
  ------
  EJSON
    Raised when the present member has a different type.
}
procedure RequireMemberType(AObject: TJSONObject; const AName: string;
  AExpectedType: TJSONType);
var
  Data: TJSONData;
begin
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) and
    (Data.JSONType <> AExpectedType) then
    raise EJSON.CreateFmt('settings member "%s" has an invalid type', [AName]);
end;

{**
  Validates all known fields in a scan-settings object before conversion.

  Parameters
  ----------
  AObject
    Non-nil JSON settings object.

  Returns
  -------
  None

  Raises
  ------
  EJSON
    Raised for an incompatible known member or ignore-pattern element.
}
procedure ValidateSettingsObject(AObject: TJSONObject);
const
  BooleanNames: array[0..6] of string = (
    'include_absolute_paths', 'follow_symbolic_links', 'allow_outside_root',
    'calculate_sha256', 'remember_privacy_choices', 'use_rescan_cache',
    'refresh_rescan_cache');
  StringNames: array[0..1] of string = (
    'sbom_author_organization', 'sbom_author_email');
var
  Data: TJSONData;
  I: Integer;
begin
  for I := Low(BooleanNames) to High(BooleanNames) do
    RequireMemberType(AObject, BooleanNames[I], jtBoolean);
  for I := Low(StringNames) to High(StringNames) do
    RequireMemberType(AObject, StringNames[I], jtString);
  Data := AObject.Find('ignore_patterns');
  if (Data <> nil) and (Data.JSONType <> jtNull) then
  begin
    if Data.JSONType <> jtArray then
      raise EJSON.Create('settings member "ignore_patterns" has an invalid type');
    for I := 0 to TJSONArray(Data).Count - 1 do
      if TJSONArray(Data).Items[I].JSONType <> jtString then
        raise EJSON.CreateFmt('ignore_patterns item %d is not a string', [I]);
  end;
end;

function LoadCommandLineSettings(const AFileName: string): TScanSettings;
var
  Data: TJSONData;
  Root, SettingsObject: TJSONObject;
begin
  Result := nil;
  Data := ReadJSONFile(ExpandFileName(AFileName), MaximumSettingsBytes);
  try
    if Data.JSONType <> jtObject then
      raise EJSON.Create('settings root is not a JSON object');
    Root := TJSONObject(Data);
    SettingsObject := JSONObject(Root, 'scan_settings');
    if Root.Find('scan_settings') <> nil then
    begin
      if SettingsObject = nil then
        raise EJSON.Create('scan_settings is not a JSON object');
      if (Root.Find('format_version') <> nil) and
        ((Root.Find('format_version').JSONType <> jtNumber) or
        (JSONInt64(Root, 'format_version', 0) <> 1)) then
        raise EJSON.Create('settings format version is unsupported');
    end
    else
      SettingsObject := Root;
    ValidateSettingsObject(SettingsObject);
    Result := TScanSettings.FromJSON(SettingsObject);
  finally
    Data.Free;
  end;
end;

{$IFDEF Windows}
{**
  Obtains a usable inherited or parent-console standard Windows handle.

  Parameters
  ----------
  AStandardHandle
    STD_OUTPUT_HANDLE or STD_ERROR_HANDLE.

  Returns
  -------
  THandle
    Usable native handle, or zero when neither redirection nor a parent console
    is available.

  Raises
  ------
  None
}
function NativeStandardHandle(AStandardHandle: DWORD): THandle;
begin
  Result := GetStdHandle(AStandardHandle);
  if (Result <> 0) and (Result <> INVALID_HANDLE_VALUE) then
    Exit;
  if not ConsoleAttachmentAttempted then
  begin
    ConsoleAttachmentAttempted := True;
    AttachConsole(DWORD(-1));
  end;
  Result := GetStdHandle(AStandardHandle);
  if Result = INVALID_HANDLE_VALUE then
    Result := 0;
end;

{**
  Writes UTF-8 text to a Windows console or redirected native handle.

  Parameters
  ----------
  AStandardHandle
    STD_OUTPUT_HANDLE or STD_ERROR_HANDLE.
  AText
    UTF-8-compatible text to write exactly once, subject to native partial
    write handling.

  Returns
  -------
  None

  Raises
  ------
  None
    Missing or closed standard streams are tolerated for GUI launches.
}
procedure WriteNativeStream(AStandardHandle: DWORD; const AText: string);
var
  Bytes: UTF8String;
  HandleValue: THandle;
  Offset, Remaining: SizeUInt;
  WideText: UnicodeString;
  Written: DWORD;
begin
  HandleValue := NativeStandardHandle(AStandardHandle);
  if (HandleValue = 0) or (AText = '') then
    Exit;
  if GetFileType(HandleValue) = FILE_TYPE_CHAR then
  begin
    WideText := UTF8Decode(UTF8Encode(AText));
    Offset := 1;
    while Offset <= Length(WideText) do
    begin
      Remaining := Length(WideText) - Offset + 1;
      Written := 0;
      if not WriteConsoleW(HandleValue, @WideText[Offset], Remaining,
        Written, nil) or (Written = 0) then
        Exit;
      Inc(Offset, Written);
    end;
    Exit;
  end;
  Bytes := UTF8Encode(AText);
  Offset := 1;
  while Offset <= Length(Bytes) do
  begin
    Remaining := Length(Bytes) - Offset + 1;
    Written := 0;
    if not WriteFile(HandleValue, Bytes[Offset], Remaining, Written, nil) or
      (Written = 0) then
      Exit;
    Inc(Offset, Written);
  end;
end;
{$ELSE}
{**
  Writes text bytes to a Unix standard file descriptor with partial-write and
  interrupted-system-call handling.

  Parameters
  ----------
  AHandle
    Standard output or standard error file descriptor.
  AText
    UTF-8-compatible text to write.

  Returns
  -------
  None

  Raises
  ------
  None
    Closed streams and write failures stop delivery without changing command
    execution status.
}
procedure WriteNativeStream(AHandle: cint; const AText: string);
var
  Bytes: UTF8String;
  Offset: SizeUInt;
  Written: TSsize;
begin
  { Unix RTL strings already carry native UTF-8 path and message bytes. Calling
    UTF8Encode here converts those bytes through the process ANSI code page and
    corrupts non-ASCII output. The explicit UTF8String view preserves the exact
    byte sequence delivered by ParamStr and the scanner. }
  Bytes := UTF8String(AText);
  Offset := 1;
  while Offset <= Length(Bytes) do
  begin
    Written := fpWrite(AHandle, Bytes[Offset], Length(Bytes) - Offset + 1);
    if Written > 0 then
      Inc(Offset, Written)
    else if (Written < 0) and (fpGetErrno = ESysEINTR) then
      Continue
    else
      Exit;
  end;
end;
{$ENDIF}

{**
  Writes one complete message to process standard output.

  Parameters
  ----------
  AText
    Text to emit; callers include any desired trailing newline.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure WriteStandardOutput(const AText: string);
begin
  {$IFDEF Windows}
  WriteNativeStream(STD_OUTPUT_HANDLE, AText);
  {$ELSE}
  WriteNativeStream(StdOutputHandle, AText);
  {$ENDIF}
end;

{**
  Writes one complete message to process standard error.

  Parameters
  ----------
  AText
    Text to emit; callers include any desired trailing newline.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure WriteStandardError(const AText: string);
begin
  {$IFDEF Windows}
  WriteNativeStream(STD_ERROR_HANDLE, AText);
  {$ELSE}
  WriteNativeStream(StdErrorHandle, AText);
  {$ENDIF}
end;

{**
  Expands a scan target while retaining native filesystem-root spelling.

  Parameters
  ----------
  ADirectory
    User-supplied scan directory.

  Returns
  -------
  string
    Absolute path without a redundant trailing delimiter except at a root.

  Raises
  ------
  None
}
function NormalizeScanTarget(const ADirectory: string): string;
var
  RootValue: string;
begin
  Result := ExpandFileName(ADirectory);
  RootValue := IncludeTrailingPathDelimiter(ExtractFileDrive(Result));
  if (RootValue = '') or not SameFileName(Result, RootValue) then
    Result := ExcludeTrailingPathDelimiter(Result);
end;

{**
  Executes a parsed headless scan without loading or saving desktop state.

  Parameters
  ----------
  AOptions
    Complete clmScan command options.

  Returns
  -------
  Integer
    Zero on completed output; one on validation, scan, or output failure.

  Raises
  ------
  None
    Exceptions are rendered to stderr and converted into CLIExitFailure.
}
function RunHeadlessScan(const AOptions: TCommandLineOptions): Integer;
var
  I: Integer;
  OutputPath: string;
  Settings: TScanSettings;
  Target: string;
  Task: TScanTask;
begin
  Result := CLIExitFailure;
  Settings := nil;
  Task := nil;
  try
    try
      Target := NormalizeScanTarget(AOptions.ScanDirectory);
      if not DirectoryExists(NativeFileSystemPath(Target)) then
        raise EInOutError.Create('scan directory does not exist: ' + Target);
      OutputPath := ResolveScanOutputFileName(Target,
        AOptions.OutputFileName);
      if AOptions.SettingsFileName = '' then
        Settings := TScanSettings.Create
      else
        Settings := LoadCommandLineSettings(AOptions.SettingsFileName);
      { Headless scans deliberately have no desktop data-profile dependency.
        Accept shared settings files, but never read or write the GUI cache. }
      Settings.UseRescanCache := False;
      Settings.RefreshRescanCache := False;
      Task := TScanTask.Create;
      Task.TargetDirectory := Target;
      Task.TargetRootName := ExtractFileName(Target);
      if Task.TargetRootName = '' then
        Task.TargetRootName := Target;
      Task.Settings.Assign(Settings);
      if ExecuteScanToFile(Task, OutputPath, nil, nil) then
      begin
        for I := 0 to Task.Warnings.Count - 1 do
          WriteStandardError('Warning: ' + Task.Warnings[I] + #10);
        WriteStandardOutput('SBOM written: ' + Task.GeneratedSBOMPath + #10);
        Result := CLIExitSuccess;
      end
      else
      begin
        for I := 0 to Task.Warnings.Count - 1 do
          WriteStandardError('Warning: ' + Task.Warnings[I] + #10);
        if Task.Errors.Count = 0 then
          WriteStandardError('Error: scan ended with status ' +
            TaskStatusToString(Task.Status) + #10)
        else
          for I := 0 to Task.Errors.Count - 1 do
            WriteStandardError('Error: ' + Task.Errors[I] + #10);
      end;
    except
      on E: Exception do
        WriteStandardError('Error: ' + E.Message + #10);
      else
        WriteStandardError('Error: unexpected non-standard scan failure' + #10);
    end;
  finally
    Task.Free;
    Settings.Free;
  end;
end;

{**
  Collects process arguments with native Unicode fidelity on Windows.

  Parameters
  ----------
  AArguments
    Receives arguments after the executable name as UTF-8 strings.

  Returns
  -------
  None

  Raises
  ------
  EOSError
    Raised when Windows cannot split its native UTF-16 command line.
  EOutOfMemory
    May propagate while allocating or converting argument values.
}
procedure CollectCommandLineArguments(out AArguments: TCommandArgumentArray);
var
  I: Integer;
  {$IFDEF Windows}
  ArgumentCount: LongInt;
  ArgumentVector: pLPWSTR;
  {$ENDIF}
begin
  {$IFDEF Windows}
  ArgumentCount := 0;
  ArgumentVector := CommandLineToArgvW(GetCommandLineW, @ArgumentCount);
  if ArgumentVector = nil then
    RaiseLastOSError;
  try
    if ArgumentCount <= 1 then
      SetLength(AArguments, 0)
    else
    begin
      SetLength(AArguments, ArgumentCount - 1);
      for I := 1 to ArgumentCount - 1 do
        AArguments[I - 1] := UTF8Encode(UnicodeString(
          PPWideCharArray(ArgumentVector)^[I]));
    end;
  finally
    LocalFree(HLOCAL(ArgumentVector));
  end;
  {$ELSE}
  SetLength(AArguments, ParamCount);
  for I := 1 to ParamCount do
    AArguments[I - 1] := ParamStr(I);
  {$ENDIF}
end;

function HandleCommandLine: Integer;
var
  Arguments: TCommandArgumentArray;
  ErrorText: string;
  Options: TCommandLineOptions;
begin
  try
    CollectCommandLineArguments(Arguments);
    if not ParseCommandLineArguments(Arguments, Options, ErrorText) then
    begin
      WriteStandardError('Error: ' + ErrorText + #10 +
        'Run purpleray-sbom-analyzer --help for usage.' + #10);
      Exit(CLIExitUsage);
    end;
    case Options.Mode of
      clmGUI:
        Result := CLINotHandled;
      clmHelp:
        begin
          WriteStandardOutput(HelpText);
          Result := CLIExitSuccess;
        end;
      clmVersion:
        begin
          WriteStandardOutput(AppName + ' ' + DisplayVersion + #10);
          Result := CLIExitSuccess;
        end;
      clmScan:
        Result := RunHeadlessScan(Options);
    else
      Result := CLIExitUsage;
    end;
  except
    on E: Exception do
    begin
      WriteStandardError('Error: unable to process command line: ' +
        E.Message + #10);
      Result := CLIExitFailure;
    end;
    else
    begin
      WriteStandardError('Error: unexpected command-line failure' + #10);
      Result := CLIExitFailure;
    end;
  end;
end;

{**
  Dispatches every argument-bearing process before later LCL units initialize.

  Parameters
  ----------
  None

  Returns
  -------
  None
    Returns only for the no-argument desktop mode; all CLI modes terminate the
    process with their stable exit code.

  Raises
  ------
  None
}
procedure DispatchEarlyCommandLine;
var
  ExitCode: Integer;
begin
  {$IFDEF Windows}
  SetMultiByteConversionCodePage(CP_UTF8);
  SetMultiByteRTLFileSystemCodePage(CP_UTF8);
  {$ENDIF}
  if ParamCount = 0 then
    Exit;
  ExitCode := HandleCommandLine;
  if ExitCode <> CLINotHandled then
    Halt(ExitCode);
end;

initialization
  DispatchEarlyCommandLine;

end.
