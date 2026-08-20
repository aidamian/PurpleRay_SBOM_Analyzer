(**
  PurpleRay SBOM Analyzer platform-services unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Supplies the application-data location and migration, canonical path checks,
  symbolic-link detection, durable flushing, and portable file copying.

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
unit uPlatform;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

{**
  Returns the canonical per-user application-data directory, creating it once.

  Parameters
  ----------
  None

  Returns
  -------
  string
    The ~/.purpleray/sbom-analyzer path without a trailing separator.

  Raises
  ------
  None
    Creation or migration problems are retained as a startup warning.
}
function ApplicationDataDirectory: string;

{**
  Returns the cached warning produced while locating or migrating app data.

  Parameters
  ----------
  None

  Returns
  -------
  string
    Empty on success, otherwise a user-facing diagnostic.

  Raises
  ------
  None
}
function ApplicationDataMigrationWarning: string;

{**
  Moves an older application-data tree into the requested destination.

  Parameters
  ----------
  ASource
    Existing legacy directory; a missing directory is treated as success.
  ADestination
    New application-data directory.
  AWarning
    Receives a detailed partial-migration or cleanup warning.

  Returns
  -------
  Boolean
    True when no legacy data remains to be migrated.

  Raises
  ------
  None
    File-operation failures are converted to False and AWarning.
}
function MigrateApplicationDataDirectory(const ASource, ADestination: string;
  out AWarning: string): Boolean;

{**
  Resolves a filesystem path as far as the host OS permits.

  Parameters
  ----------
  APath
    Existing or prospective filesystem path.

  Returns
  -------
  string
    Canonical absolute path, or an expanded fallback when resolution fails.

  Raises
  ------
  None
}
function CanonicalPath(const APath: string): string;

{**
  Tests whether a canonical path is equal to or beneath a canonical root.

  Parameters
  ----------
  APath
    Candidate path.
  ARoot
    Permitted root directory.

  Returns
  -------
  Boolean
    True for the root itself or one of its descendants.

  Raises
  ------
  None
}
function PathIsWithin(const APath, ARoot: string): Boolean;

{**
  Detects Unix symbolic links or Windows reparse points.

  Parameters
  ----------
  APath
    Filesystem entry to inspect without following it.

  Returns
  -------
  Boolean
    True when the entry is link-like on the current platform.

  Raises
  ------
  None
}
function IsSymbolicLink(const APath: string): Boolean;

{**
  Forces buffered file data to stable operating-system storage.

  Parameters
  ----------
  AStream
    Open TFileStream to flush; nil is accepted.

  Returns
  -------
  None

  Raises
  ------
  EWriteError, EOSError
    Raised when fsync or FlushFileBuffers reports failure.
}
procedure FlushFileStream(AStream: TFileStream);

{**
  Copies a file byte-for-byte and flushes the destination before returning.

  Parameters
  ----------
  ASource
    Existing source filename.
  ADestination
    Destination filename to create or replace.

  Returns
  -------
  None

  Raises
  ------
  EFOpenError, EFCreateError, EReadError, EWriteError
    Propagated from source access, copying, destination creation, or flushing.
}
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

{**
  Recursively moves application-data contents without overwriting collisions.

  Parameters
  ----------
  ASource
    Existing directory whose contents should be migrated.
  ADestination
    New application-data directory.
  AError
    Receives a human-readable failure reason.

  Returns
  -------
  Boolean
    True only when every entry is copied and removed from its source.

  Raises
  ------
  None
    Copy and deletion failures are converted into False and AError.
}
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
          { Windows.pas declares a PChar DeleteFile which otherwise shadows
            the cross-platform SysUtils overload on Win64. }
          if not SysUtils.DeleteFile(SourceName) then
          begin
            AError := 'unable to remove migrated file ' + SourceName;
            Exit;
          end;
        end;
      end;
      FindResult := FindNext(SearchRecord);
    end;
  finally
    { Qualify this call because Windows.pas also exports FindClose for search
      handles, with an incompatible parameter type. }
    SysUtils.FindClose(SearchRecord);
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
  LegacyConfigDirectory, PreviousDataDirectory, WarningText: string;

  {**
    Adds one migration diagnostic to the cached startup warning.

    Parameters
    ----------
    AText
      Warning text to append; an empty value is ignored.

    Returns
    -------
    None

    Raises
    ------
    None
  }
  procedure AppendMigrationWarning(const AText: string);
  begin
    if AText = '' then
      Exit;
    if CachedMigrationWarning <> '' then
      CachedMigrationWarning := CachedMigrationWarning + LineEnding;
    CachedMigrationWarning := CachedMigrationWarning + AText;
  end;

begin
  if CachedApplicationDataDirectory <> '' then
    Exit(CachedApplicationDataDirectory);

  CachedApplicationDataDirectory := ExcludeTrailingPathDelimiter(
    IncludeTrailingPathDelimiter(GetUserDir) + '.purpleray' +
    DirectorySeparator + 'sbom-analyzer');

  { PurpleRay releases before this location change stored all persistent data
    directly beneath the user's home directory. Migrate that directory first
    so its newer data wins any collision with the older FPC-specific path. A
    successful migration removes the now-empty source directory. }
  PreviousDataDirectory := ExcludeTrailingPathDelimiter(
    IncludeTrailingPathDelimiter(GetUserDir) + '.sbom-analyzer');
  MigrateApplicationDataDirectory(PreviousDataDirectory,
    CachedApplicationDataDirectory, WarningText);
  AppendMigrationWarning(WarningText);

  { Early builds used FPC's executable-specific configuration directory. Keep
    this migration for users upgrading directly from those builds. }
  LegacyConfigDirectory := ExcludeTrailingPathDelimiter(
    GetAppConfigDir(False));
  MigrateApplicationDataDirectory(LegacyConfigDirectory,
    CachedApplicationDataDirectory, WarningText);
  AppendMigrationWarning(WarningText);

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
