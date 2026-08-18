unit uPlatform;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

function ApplicationDataDirectory: string;
function ApplicationDataMigrationWarning: string;
function MigrateApplicationDataDirectory(const ASource, ADestination: string;
  out AWarning: string): Boolean;
function CanonicalPath(const APath: string): string;
function PathIsWithin(const APath, ARoot: string): Boolean;
function IsSymbolicLink(const APath: string): Boolean;
procedure FlushFileStream(AStream: TFileStream);
procedure CopyFileContents(const ASource, ADestination: string);

implementation

{$IFDEF UNIX}
uses
  BaseUnix, Unix;

function CRealPath(PathName, ResolvedName: PChar): PChar; cdecl;
  external 'c' name 'realpath';
{$ENDIF}

{$IFDEF Windows}
uses
  Windows;

function GetFinalPathNameByHandleW(AHandle: THandle; APath: PWideChar;
  APathLength, AFlags: DWORD): DWORD; stdcall;
  external 'kernel32.dll' name 'GetFinalPathNameByHandleW';
{$ENDIF}

var
  CachedApplicationDataDirectory: string = '';
  CachedMigrationWarning: string = '';

function MoveDirectoryContents(const ASource, ADestination: string;
  out AError: string): Boolean;
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
  SourceName, DestinationName: string;
begin
  Result := False;
  AError := '';
  if not ForceDirectories(ADestination) then
  begin
    AError := 'unable to create ' + ADestination;
    Exit;
  end;
  FindResult := FindFirst(IncludeTrailingPathDelimiter(ASource) + '*',
    faAnyFile, SearchRecord);
  try
    while FindResult = 0 do
    begin
      if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
      begin
        SourceName := IncludeTrailingPathDelimiter(ASource) + SearchRecord.Name;
        DestinationName := IncludeTrailingPathDelimiter(ADestination) +
          SearchRecord.Name;
        if (SearchRecord.Attr and faDirectory) <> 0 then
        begin
          if not MoveDirectoryContents(SourceName, DestinationName, AError) then
            Exit;
          if DirectoryExists(SourceName) and not RemoveDir(SourceName) then
          begin
            AError := 'unable to remove migrated directory ' + SourceName;
            Exit;
          end;
        end
        else
        begin
          if FileExists(DestinationName) then
          begin
            AError := 'destination already contains ' + DestinationName;
            Exit;
          end;
          try
            CopyFileContents(SourceName, DestinationName);
          except
            on E: Exception do
            begin
              AError := E.Message;
              Exit;
            end;
          end;
          if not DeleteFile(SourceName) then
          begin
            AError := 'unable to remove migrated file ' + SourceName;
            Exit;
          end;
        end;
      end;
      FindResult := FindNext(SearchRecord);
    end;
  finally
    FindClose(SearchRecord);
  end;
  Result := True;
end;

function MigrateApplicationDataDirectory(const ASource, ADestination: string;
  out AWarning: string): Boolean;
var
  SourceDirectory, DestinationDirectory, ErrorText: string;
begin
  AWarning := '';
  SourceDirectory := ExcludeTrailingPathDelimiter(ExpandFileName(ASource));
  DestinationDirectory := ExcludeTrailingPathDelimiter(
    ExpandFileName(ADestination));
  if SameFileName(SourceDirectory, DestinationDirectory) or
    not DirectoryExists(SourceDirectory) then
    Exit(True);

  if not DirectoryExists(DestinationDirectory) and
    RenameFile(SourceDirectory, DestinationDirectory) then
    Exit(True);

  if not MoveDirectoryContents(SourceDirectory, DestinationDirectory,
    ErrorText) then
  begin
    AWarning := 'Existing application data could not be fully moved from ' +
      SourceDirectory + ' to ' + DestinationDirectory + ': ' + ErrorText;
    Exit(False);
  end;
  if DirectoryExists(SourceDirectory) and not RemoveDir(SourceDirectory) then
  begin
    AWarning := 'Application data was copied, but the old directory could not ' +
      'be removed: ' + SourceDirectory;
    Exit(False);
  end;
  Result := True;
end;

function ApplicationDataDirectory: string;
var
  LegacyDirectory: string;
begin
  if CachedApplicationDataDirectory <> '' then
    Exit(CachedApplicationDataDirectory);
  CachedApplicationDataDirectory := ExcludeTrailingPathDelimiter(
    IncludeTrailingPathDelimiter(GetUserDir) + '.sbom-analyzer');
  LegacyDirectory := ExcludeTrailingPathDelimiter(GetAppConfigDir(False));
  MigrateApplicationDataDirectory(LegacyDirectory,
    CachedApplicationDataDirectory, CachedMigrationWarning);
  if not ForceDirectories(CachedApplicationDataDirectory) and
    (CachedMigrationWarning = '') then
    CachedMigrationWarning := 'Unable to create application data directory: ' +
      CachedApplicationDataDirectory;
  Result := CachedApplicationDataDirectory;
end;

function ApplicationDataMigrationWarning: string;
begin
  ApplicationDataDirectory;
  Result := CachedMigrationWarning;
end;

function CanonicalPath(const APath: string): string;
{$IFDEF UNIX}
var
  Buffer: array[0..4095] of Char;
{$ENDIF}
{$IFDEF Windows}
const
  FileNameNormalized = 0;
var
  Handle: THandle;
  WidePath, ResolvedPath: UnicodeString;
  WideBuffer: array[0..32767] of WideChar;
  PathLength: DWORD;
{$ENDIF}
begin
  {$IFDEF UNIX}
  FillChar(Buffer, SizeOf(Buffer), 0);
  if CRealPath(PChar(APath), @Buffer[0]) <> nil then
    Result := StrPas(@Buffer[0])
  else
    Result := ExpandFileName(APath);
  {$ENDIF}
  {$IFDEF Windows}
  Result := ExpandFileName(APath);
  WidePath := UTF8Decode(Result);
  Handle := CreateFileW(PWideChar(WidePath), 0,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    try
      PathLength := GetFinalPathNameByHandleW(Handle, @WideBuffer[0],
        Length(WideBuffer), FileNameNormalized);
      if (PathLength > 0) and (PathLength < DWORD(Length(WideBuffer))) then
      begin
        SetString(ResolvedPath, PWideChar(@WideBuffer[0]), PathLength);
        if Copy(ResolvedPath, 1, 8) = '\\?\UNC\' then
          ResolvedPath := '\\' + Copy(ResolvedPath, 9, MaxInt)
        else if Copy(ResolvedPath, 1, 4) = '\\?\' then
          Delete(ResolvedPath, 1, 4);
        Result := UTF8Encode(ResolvedPath);
      end;
    finally
      CloseHandle(Handle);
    end;
  end;
  {$ENDIF}
  Result := ExcludeTrailingPathDelimiter(Result);
end;

function PathIsWithin(const APath, ARoot: string): Boolean;
var
  PathValue, RootValue: string;
begin
  PathValue := ExcludeTrailingPathDelimiter(CanonicalPath(APath));
  RootValue := ExcludeTrailingPathDelimiter(CanonicalPath(ARoot));
  {$IFDEF Windows}
  PathValue := LowerCase(PathValue);
  RootValue := LowerCase(RootValue);
  {$ENDIF}
  Result := (PathValue = RootValue) or
    (Pos(IncludeTrailingPathDelimiter(RootValue),
      IncludeTrailingPathDelimiter(PathValue)) = 1);
end;

function IsSymbolicLink(const APath: string): Boolean;
{$IFDEF UNIX}
var
  Info: Stat;
{$ENDIF}
{$IFDEF Windows}
var
  Attributes: DWORD;
  WidePath: UnicodeString;
{$ENDIF}
begin
  {$IFDEF UNIX}
  Result := (fpLStat(PChar(APath), Info) = 0) and FPS_ISLNK(Info.st_mode);
  {$ENDIF}
  {$IFDEF Windows}
  WidePath := UTF8Decode(APath);
  Attributes := GetFileAttributesW(PWideChar(WidePath));
  Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
    ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
  {$ENDIF}
end;

procedure FlushFileStream(AStream: TFileStream);
begin
  if AStream = nil then
    Exit;
  {$IFDEF UNIX}
  if fpFsync(AStream.Handle) <> 0 then
    raise EWriteError.CreateFmt('Unable to flush file stream: %s',
      [SysErrorMessage(fpGetErrNo)]);
  {$ELSE}
  if not FlushFileBuffers(AStream.Handle) then
    RaiseLastOSError;
  {$ENDIF}
end;

procedure CopyFileContents(const ASource, ADestination: string);
var
  SourceStream, DestinationStream: TFileStream;
begin
  SourceStream := TFileStream.Create(ASource, fmOpenRead or fmShareDenyNone);
  try
    DestinationStream := TFileStream.Create(ADestination, fmCreate);
    try
      DestinationStream.CopyFrom(SourceStream, 0);
      FlushFileStream(DestinationStream);
    finally
      DestinationStream.Free;
    end;
  finally
    SourceStream.Free;
  end;
end;

end.
