(**
  PurpleRay SBOM Analyzer platform-services unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Supplies the application-data location and migration, canonical path checks,
  symbolic-link detection, durable flushing, atomic file replacement, and
  portable file copying.

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

type
  TFileSystemEntryKind = (
    fsekRegularFile,
    fsekDirectory,
    fsekUnsupported
  );

  {**
    Retains the identity and native handle of one existing directory.

    The pin supports exclusive leaf creation, same-directory atomic rename,
    cleanup, and explicit path-identity checks without redirecting operations
    through a pathname that may have been rebound during a long scan.
  }
  TPinnedDirectory = class
  private
    FDirectoryName: string;
    FPinnedHandle: THandle;
    {$IFDEF UNIX}
    FDevice: QWord;
    FInode: QWord;
    {$ENDIF}
    {$IFDEF Windows}
    FVolumeSerialNumber: Cardinal;
    FFileIndex: QWord;
    FGuardHandles: array of THandle;
    {$ENDIF}
  public
    destructor Destroy; override;
    procedure VerifyCurrentPath;
    {**
      Returns a bounded native identity token without exposing the path.

      The token is stable for the lifetime of the pinned directory and is
      suitable for cache-context invalidation. Unsupported paused targets
      return an empty token so callers fail closed instead of persisting a
      pathname.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Platform-prefixed storage and file identity, or an empty string on an
        unsupported target.

      Raises
      ------
      None
    *}
    function IdentityToken: string;
    function CreateFileExclusive(const AFileName: string): THandle;
    function ReplaceFileAtomically(const ASourceFileName,
      ADestinationFileName: string): Boolean;
    function DeleteFile(const AFileName: string): Boolean;
    property DirectoryName: string read FDirectoryName;
  end;

{**
  Opens and pins the exact existing directory reached by a path.

  Parameters
  ----------
  ADirectory
    Existing directory to pin. Symbolic links and reparse points are resolved
    before the directory identity is captured.

  Returns
  -------
  TPinnedDirectory
    Caller-owned pin whose DirectoryName is the canonical validated path.

  Raises
  ------
  EInOutError
    Raised when the directory cannot be opened, is not a directory, changes
    identity while it is being pinned, or cannot be protected on Windows.
  EOutOfMemory
    May propagate while allocating the pin or Windows ancestor guards.
}
function PinExistingDirectory(const ADirectory: string): TPinnedDirectory;

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
  Converts one path for native filesystem access without changing display
  spelling retained by callers.

  On Windows the result is an absolute UTF-8 ``\\?\`` drive path or
  ``\\?\UNC\`` share path, so wide Win32 and RTL filesystem calls are not
  constrained by the legacy MAX_PATH boundary. Other platforms return the
  input unchanged. The returned value is for immediate filesystem access
  only and must not be persisted or shown to users.

  Parameters
  ----------
  APath
    Ordinary UTF-8 path or search mask.

  Returns
  -------
  string
    Native access spelling for the current platform.

  Raises
  ------
  None
}
function NativeFileSystemPath(const APath: string): string;

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
  Tests whether a filesystem path itself names a regular disk file.

  Parameters
  ----------
  APath
    Filesystem entry to inspect without following symbolic links on Unix.
  AReason
    Receives a stable description when the entry is not a regular file.

  Returns
  -------
  Boolean
    True only for a regular file that is safe to open as scan input.

  Raises
  ------
  None
    Metadata lookup failures are returned as False with AReason populated.
}
function IsRegularFile(const APath: string; out AReason: string): Boolean;

{**
  Classifies metadata captured by an existing directory enumeration.

  Parameters
  ----------
  AAttributes
    Platform attributes copied from the entry's TSearchRec.
  AUnixMode
    Unix mode copied from TSearchRec.Mode, or zero on non-Unix platforms.
  AReason
    Receives a stable description when the entry is not a regular file.

  Returns
  -------
  TFileSystemEntryKind
    Regular file, directory, or unsupported special entry.

  Raises
  ------
  None
}
function ClassifyFileSystemEntry(AAttributes: LongInt; AUnixMode: QWord;
  out AReason: string): TFileSystemEntryKind;

{**
  Determines whether a failed FindFirst call represents an enumeration error.

  Parameters
  ----------
  ADirectory
    Directory passed to the enumeration operation.
  AFindResult
    Nonzero result returned by FindFirst.
  AReason
    Receives the operating-system failure description when Result is True.

  Returns
  -------
  Boolean
    True for an inaccessible or missing directory; False for an empty one.

  Raises
  ------
  None
}
function DirectoryEnumerationFailed(const ADirectory: string;
  AFindResult: Integer; out AReason: string): Boolean;

{**
  Clears the host error state immediately before a directory enumeration call.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure ResetDirectoryEnumerationError;

{**
  Distinguishes normal end-of-directory from a failed continuation call.

  Parameters
  ----------
  AFindResult
    Nonzero result returned by FindNext after enumeration has started.
  AReason
    Receives the operating-system failure description when Result is True.

  Returns
  -------
  Boolean
    True only when enumeration ended because of an error rather than EOF.

  Raises
  ------
  None
}
function DirectoryEnumerationContinuationFailed(AFindResult: Integer;
  out AReason: string): Boolean;

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
  Flushes one already-open native file handle to durable storage.

  Parameters
  ----------
  AHandle
    Valid native file handle owned by the caller.

  Returns
  -------
  None

  Raises
  ------
  EWriteError, EOSError
    Raised when the operating system cannot flush the handle.
}
procedure FlushFileHandle(AHandle: THandle);

{**
  Atomically renames a completed file over an optional existing destination.

  Parameters
  ----------
  ASource
    Existing source file in the destination filesystem.
  ADestination
    Final filename to create or atomically replace.

  Returns
  -------
  Boolean
    True only when the native atomic rename/replace operation succeeds.

  Raises
  ------
  None
    Native failures are returned as False for the persistence caller to report.
}
function ReplaceFileAtomically(const ASource, ADestination: string): Boolean;

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
function COpenAt(ADirectoryHandle: LongInt; APath: PChar; AFlags: LongInt;
  AMode: TMode): LongInt; cdecl; external 'c' name 'openat';
function CRenameAt(ASourceDirectoryHandle: LongInt; ASourcePath: PChar;
  ADestinationDirectoryHandle: LongInt; ADestinationPath: PChar): LongInt;
  cdecl; external 'c' name 'renameat';
function CUnlinkAt(ADirectoryHandle: LongInt; APath: PChar;
  AFlags: LongInt): LongInt; cdecl; external 'c' name 'unlinkat';
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

function ExcludeTrailingDelimiterUnlessRoot(const APath: string): string;
  forward;

{$IFDEF Linux}
{**
  Returns the kernel path currently associated with an open Linux handle.

  Parameters
  ----------
  AHandle
    Open directory descriptor to resolve through procfs.

  Returns
  -------
  string
    Current absolute directory path reported by the kernel.

  Raises
  ------
  EInOutError
    Raised when the descriptor path is unavailable or has been unlinked.
}
function CurrentLinuxPathFromHandle(AHandle: THandle): string;
var
  DescriptorLink: RawByteString;
begin
  DescriptorLink := fpReadLink('/proc/self/fd/' + IntToStr(AHandle));
  Result := ExcludeTrailingDelimiterUnlessRoot(string(DescriptorLink));
  if (Result = '') or ((Length(Result) >= 10) and
    (Copy(Result, Length(Result) - 9, 10) = ' (deleted)')) then
    raise EInOutError.Create('Pinned output directory handle is no longer ' +
      'reachable through its validated path');
end;
{$ENDIF}

{$IFDEF Windows}
{** Builds the wide extended-length spelling accepted by Win32 file APIs. *}
function ExtendedWindowsPath(const APath: string): UnicodeString;
var
  Expanded: UnicodeString;
begin
  Expanded := UTF8Decode(APath);
  if Copy(Expanded, 1, 4) = '\\?\' then
    Exit(Expanded);
  Expanded := UTF8Decode(ExpandFileName(APath));
  if Copy(Expanded, 1, 2) = '\\' then
    Result := '\\?\UNC\' + Copy(Expanded, 3, MaxInt)
  else
    Result := '\\?\' + Expanded;
end;

{**
  Returns the normalized filesystem path reached by an open Windows handle.

  Parameters
  ----------
  AHandle
    Open file or directory handle whose final path is requested.

  Returns
  -------
  string
    UTF-8 drive or UNC path without the Win32 extended-length prefix.

  Raises
  ------
  EInOutError
    Raised when Windows cannot return a bounded final path for the handle.
}
function FinalWindowsPathFromHandle(AHandle: THandle): string;
const
  FileNameNormalized = 0;
var
  ResolvedPath: UnicodeString;
  WideBuffer: array[0..32767] of WideChar;
  PathLength: DWORD;
  ErrorCode: Cardinal;
begin
  PathLength := GetFinalPathNameByHandleW(AHandle, @WideBuffer[0],
    Length(WideBuffer), FileNameNormalized);
  if (PathLength = 0) or (PathLength >= DWORD(Length(WideBuffer))) then
  begin
    ErrorCode := GetLastError;
    raise EInOutError.CreateFmt('Unable to resolve pinned output directory ' +
      'handle: %s', [SysErrorMessage(ErrorCode)]);
  end;
  SetString(ResolvedPath, PWideChar(@WideBuffer[0]), PathLength);
  if Copy(ResolvedPath, 1, 8) = '\\?\UNC\' then
    ResolvedPath := '\\' + Copy(ResolvedPath, 9, MaxInt)
  else if Copy(ResolvedPath, 1, 4) = '\\?\' then
    Delete(ResolvedPath, 1, 4);
  Result := ExcludeTrailingDelimiterUnlessRoot(UTF8Encode(ResolvedPath));
end;

{**
  Finds the immutable drive root or UNC share root for a Windows path.

  Parameters
  ----------
  APath
    Canonical absolute drive or UNC path.

  Returns
  -------
  string
    Drive root such as C:\ or UNC share root such as \\server\share.

  Raises
  ------
  None
}
function WindowsVolumeRoot(const APath: string): string;
var
  CharacterIndex, SeparatorCount: Integer;
begin
  if Copy(APath, 1, 2) <> '\\' then
    Exit(ExcludeTrailingDelimiterUnlessRoot(
      IncludeTrailingPathDelimiter(ExtractFileDrive(APath))));

  SeparatorCount := 0;
  for CharacterIndex := 3 to Length(APath) do
    if APath[CharacterIndex] = '\' then
    begin
      Inc(SeparatorCount);
      if SeparatorCount = 2 then
        Exit(Copy(APath, 1, CharacterIndex - 1));
    end;
  Result := ExcludeTrailingPathDelimiter(APath);
end;
{$ENDIF}

function NativeFileSystemPath(const APath: string): string;
{$IFDEF Windows}
var
  RawPath: RawByteString;
{$ENDIF}
begin
  {$IFDEF Windows}
  if APath = '' then
    Exit('');
  RawPath := RawByteString(UTF8Encode(ExtendedWindowsPath(APath)));
  SetCodePage(RawPath, CP_UTF8, False);
  Result := string(RawPath);
  {$ELSE}
  Result := APath;
  {$ENDIF}
end;

{**
  Rejects path syntax where a pinned-directory operation requires one leaf.

  Parameters
  ----------
  AFileName
    Candidate filename relative to a pinned directory.

  Returns
  -------
  None

  Raises
  ------
  EArgumentException
    Raised for an empty name, dot entry, embedded NUL, path separator, or
    Windows alternate-data-stream delimiter.
}
procedure ValidatePinnedLeafName(const AFileName: string);
begin
  if (AFileName = '') or (AFileName = '.') or (AFileName = '..') or
    (Pos(#0, AFileName) > 0) or
    (ExtractFileName(AFileName) <> AFileName) then
    raise EArgumentException.Create('Pinned file operation requires a ' +
      'single filename: ' + AFileName);
  {$IFDEF Windows}
  if (Pos('/', AFileName) > 0) or (Pos(':', AFileName) > 0) then
    raise EArgumentException.Create('Pinned file operation requires a ' +
      'single filename: ' + AFileName);
  {$ENDIF}
end;

{**
  Releases all operating-system handles retained by a directory pin.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
}
destructor TPinnedDirectory.Destroy;
{$IFDEF Windows}
var
  GuardIndex: Integer;
{$ENDIF}
begin
  if FPinnedHandle <> feInvalidHandle then
  begin
    FileClose(FPinnedHandle);
    FPinnedHandle := feInvalidHandle;
  end;
  {$IFDEF Windows}
  for GuardIndex := High(FGuardHandles) downto Low(FGuardHandles) do
    if FGuardHandles[GuardIndex] <> feInvalidHandle then
      CloseHandle(FGuardHandles[GuardIndex]);
  SetLength(FGuardHandles, 0);
  {$ENDIF}
  inherited Destroy;
end;

{**
  Confirms that the canonical path still reaches the pinned directory object.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  EInOutError
    Raised when the path is missing, rebound, or no longer a directory.
}
procedure TPinnedDirectory.VerifyCurrentPath;
{$IFDEF UNIX}
var
  PathInformation: Stat;
  ErrorCode: Integer;
  {$IFDEF Linux}
  CurrentHandlePath: string;
  {$ENDIF}
{$ENDIF}
{$IFDEF Windows}
var
  CurrentHandle: THandle;
  CurrentInformation: TByHandleFileInformation;
  CurrentIndex: QWord;
  DirectoryWide: UnicodeString;
  ErrorCode: Cardinal;
{$ENDIF}
begin
  {$IFDEF UNIX}
  FillChar(PathInformation, SizeOf(PathInformation), 0);
  if fpStat(PChar(FDirectoryName), PathInformation) <> 0 then
  begin
    ErrorCode := fpGetErrNo;
    raise EInOutError.CreateFmt('Pinned output directory is no longer ' +
      'reachable: %s (%s)', [FDirectoryName, SysErrorMessage(ErrorCode)]);
  end;
  if (not FPS_ISDIR(PathInformation.st_mode)) or
    (QWord(PathInformation.st_dev) <> FDevice) or
    (QWord(PathInformation.st_ino) <> FInode) then
    raise EInOutError.Create('Pinned output directory was replaced or ' +
      'rebound: ' + FDirectoryName);
  {$IFDEF Linux}
  CurrentHandlePath := CurrentLinuxPathFromHandle(FPinnedHandle);
  if not SameFileName(CurrentHandlePath, FDirectoryName) then
    raise EInOutError.Create('Pinned output directory was moved or rebound: ' +
      FDirectoryName);
  {$ENDIF}
  {$ENDIF}
  {$IFDEF Windows}
  FillChar(CurrentInformation, SizeOf(CurrentInformation), 0);
  DirectoryWide := ExtendedWindowsPath(FDirectoryName);
  CurrentHandle := CreateFileW(PWideChar(DirectoryWide), FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE, nil,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
  if CurrentHandle = INVALID_HANDLE_VALUE then
  begin
    ErrorCode := GetLastError;
    raise EInOutError.CreateFmt('Pinned output directory is no longer ' +
      'reachable: %s (%s)', [FDirectoryName, SysErrorMessage(ErrorCode)]);
  end;
  try
    if not GetFileInformationByHandle(CurrentHandle, CurrentInformation) then
    begin
      ErrorCode := GetLastError;
      raise EInOutError.CreateFmt('Unable to verify pinned output directory: ' +
        '%s (%s)', [FDirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    CurrentIndex := (QWord(CurrentInformation.nFileIndexHigh) shl 32) or
      QWord(CurrentInformation.nFileIndexLow);
    if ((CurrentInformation.dwFileAttributes and
      FILE_ATTRIBUTE_DIRECTORY) = 0) or
      (CurrentInformation.dwVolumeSerialNumber <> FVolumeSerialNumber) or
      (CurrentIndex <> FFileIndex) then
      raise EInOutError.Create('Pinned output directory was replaced or ' +
        'rebound: ' + FDirectoryName);
    if not SameFileName(FinalWindowsPathFromHandle(FPinnedHandle),
      FDirectoryName) then
      raise EInOutError.Create('Pinned output directory was moved or ' +
        'rebound: ' + FDirectoryName);
  finally
    CloseHandle(CurrentHandle);
  end;
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  if not DirectoryExists(FDirectoryName) then
    raise EInOutError.Create('Pinned output directory is no longer ' +
      'reachable: ' + FDirectoryName);
  {$ENDIF}
  {$ENDIF}
end;

function TPinnedDirectory.IdentityToken: string;
begin
  {$IFDEF UNIX}
  Result := 'unix:' + LowerCase(IntToHex(FDevice, 16)) + ':' +
    LowerCase(IntToHex(FInode, 16));
  {$ENDIF}
  {$IFDEF Windows}
  Result := 'windows:' + LowerCase(IntToHex(FVolumeSerialNumber, 8)) + ':' +
    LowerCase(IntToHex(FFileIndex, 16));
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := '';
  {$ENDIF}
  {$ENDIF}
end;

{**
  Exclusively creates one regular file inside the pinned directory.

  Parameters
  ----------
  AFileName
    Single relative filename; directory separators are rejected.

  Returns
  -------
  THandle
    Caller-owned writable native handle to the newly created file.

  Raises
  ------
  EArgumentException
    Raised when AFileName is not one leaf name.
  EFCreateError
    Raised when exclusive creation fails.
  EInOutError
    Raised when the pinned path was replaced before creation.
}
function TPinnedDirectory.CreateFileExclusive(const AFileName: string):
  THandle;
var
  ErrorCode: Integer;
  {$IFDEF Windows}
  FileNameWide: UnicodeString;
  {$ENDIF}
begin
  ValidatePinnedLeafName(AFileName);
  VerifyCurrentPath;
  {$IFDEF UNIX}
  repeat
    Result := COpenAt(FPinnedHandle, PChar(AFileName),
      O_WRONLY or O_CREAT or O_EXCL, &600);
  until (Result <> feInvalidHandle) or (fpGetErrNo <> ESysEINTR);
  {$ENDIF}
  {$IFDEF Windows}
  FileNameWide := ExtendedWindowsPath(
    IncludeTrailingPathDelimiter(FDirectoryName) + AFileName);
  Result := CreateFileW(PWideChar(FileNameWide), GENERIC_WRITE, 0, nil,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  if FileExists(IncludeTrailingPathDelimiter(FDirectoryName) + AFileName) then
    Result := feInvalidHandle
  else
    Result := FileCreate(IncludeTrailingPathDelimiter(FDirectoryName) +
      AFileName);
  {$ENDIF}
  {$ENDIF}
  if Result = feInvalidHandle then
  begin
    ErrorCode := GetLastOSError;
    raise EFCreateError.CreateFmt('Unable to create exclusive pinned file: ' +
      '%s (%s)', [AFileName, SysErrorMessage(ErrorCode)]);
  end;
end;

{**
  Atomically renames one pinned-directory leaf over another leaf.

  Parameters
  ----------
  ASourceFileName
    Existing source leaf in the pinned directory.
  ADestinationFileName
    Final destination leaf in the same pinned directory.

  Returns
  -------
  Boolean
    True only when the native directory-relative replacement succeeds.

  Raises
  ------
  EArgumentException
    Raised when either argument is not one leaf name.
  EInOutError
    Raised when the pinned path was replaced before activation.
}
function TPinnedDirectory.ReplaceFileAtomically(const ASourceFileName,
  ADestinationFileName: string): Boolean;
{$IFDEF Windows}
const
  AtomicMoveReplaceExisting = $00000001;
  AtomicMoveWriteThrough = $00000008;
var
  SourceWide, DestinationWide: UnicodeString;
{$ENDIF}
begin
  ValidatePinnedLeafName(ASourceFileName);
  ValidatePinnedLeafName(ADestinationFileName);
  VerifyCurrentPath;
  {$IFDEF UNIX}
  Result := CRenameAt(FPinnedHandle, PChar(ASourceFileName), FPinnedHandle,
    PChar(ADestinationFileName)) = 0;
  {$ENDIF}
  {$IFDEF Windows}
  SourceWide := ExtendedWindowsPath(
    IncludeTrailingPathDelimiter(FDirectoryName) + ASourceFileName);
  DestinationWide := ExtendedWindowsPath(
    IncludeTrailingPathDelimiter(FDirectoryName) + ADestinationFileName);
  Result := MoveFileExW(PWideChar(SourceWide), PWideChar(DestinationWide),
    AtomicMoveReplaceExisting or AtomicMoveWriteThrough);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := uPlatform.ReplaceFileAtomically(
    IncludeTrailingPathDelimiter(FDirectoryName) + ASourceFileName,
    IncludeTrailingPathDelimiter(FDirectoryName) + ADestinationFileName);
  {$ENDIF}
  {$ENDIF}
end;

{**
  Removes one leaf from the pinned directory without following a rebound path.

  Parameters
  ----------
  AFileName
    Single relative filename to remove.

  Returns
  -------
  Boolean
    True when the entry was removed; False on a native deletion failure.

  Raises
  ------
  EArgumentException
    Raised when AFileName is not one leaf name.
}
function TPinnedDirectory.DeleteFile(const AFileName: string): Boolean;
{$IFDEF Windows}
var
  FileNameWide: UnicodeString;
{$ENDIF}
begin
  ValidatePinnedLeafName(AFileName);
  {$IFDEF UNIX}
  Result := CUnlinkAt(FPinnedHandle, PChar(AFileName), 0) = 0;
  {$ENDIF}
  {$IFDEF Windows}
  FileNameWide := ExtendedWindowsPath(
    IncludeTrailingPathDelimiter(FDirectoryName) + AFileName);
  Result := Windows.DeleteFileW(PWideChar(FileNameWide));
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := SysUtils.DeleteFile(IncludeTrailingPathDelimiter(FDirectoryName) +
    AFileName);
  {$ENDIF}
  {$ENDIF}
end;

function PinExistingDirectory(const ADirectory: string): TPinnedDirectory;
var
  DirectoryName: string;
  {$IFDEF UNIX}
  HandleInformation, PathInformation: Stat;
  ErrorCode: Integer;
  {$ENDIF}
  {$IFDEF Windows}
  DirectoryWide, GuardWide: UnicodeString;
  GuardDirectory, ParentDirectory, VolumeRoot: string;
  DirectoryInformation: TByHandleFileInformation;
  GuardHandle: THandle;
  GuardCount: Integer;
  ErrorCode: Cardinal;
  {$ENDIF}
begin
  if Trim(ADirectory) = '' then
    raise EInOutError.Create('Output directory must not be empty');
  DirectoryName := CanonicalPath(ADirectory);
  if not DirectoryExists(NativeFileSystemPath(DirectoryName)) then
    raise EInOutError.Create('Output directory does not exist: ' +
      DirectoryName);

  Result := TPinnedDirectory.Create;
  Result.FPinnedHandle := feInvalidHandle;
  try
    Result.FDirectoryName := DirectoryName;
    {$IFDEF UNIX}
    repeat
      Result.FPinnedHandle := fpOpen(PChar(DirectoryName),
        O_RDONLY or O_DIRECTORY);
    until (Result.FPinnedHandle <> feInvalidHandle) or
      (fpGetErrNo <> ESysEINTR);
    if Result.FPinnedHandle = feInvalidHandle then
    begin
      ErrorCode := fpGetErrNo;
      raise EInOutError.CreateFmt('Unable to pin output directory: %s (%s)',
        [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    { POSIX defines FD_CLOEXEC as bit 1. Do not expose the pinned-directory
      capability to any child process. }
    if fpFcntl(Result.FPinnedHandle, F_SetFd, 1) <> 0 then
    begin
      ErrorCode := fpGetErrNo;
      raise EInOutError.CreateFmt('Unable to protect pinned output-directory ' +
        'handle: %s (%s)', [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    FillChar(HandleInformation, SizeOf(HandleInformation), 0);
    FillChar(PathInformation, SizeOf(PathInformation), 0);
    if fpFStat(Result.FPinnedHandle, HandleInformation) <> 0 then
    begin
      ErrorCode := fpGetErrNo;
      raise EInOutError.CreateFmt('Unable to inspect pinned output ' +
        'directory: %s (%s)', [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    if not FPS_ISDIR(HandleInformation.st_mode) then
      raise EInOutError.Create('Pinned output path is not a directory: ' +
        DirectoryName);
    Result.FDevice := QWord(HandleInformation.st_dev);
    Result.FInode := QWord(HandleInformation.st_ino);
    { Resolve again after opening. If the preflight pathname was swapped to a
      symlink before fpOpen, this captures the directory actually reached by
      the pinned handle rather than retaining the stale outside-root text. }
    {$IFDEF Linux}
    DirectoryName := CurrentLinuxPathFromHandle(Result.FPinnedHandle);
    {$ELSE}
    DirectoryName := CanonicalPath(DirectoryName);
    {$ENDIF}
    Result.FDirectoryName := DirectoryName;
    if fpStat(PChar(DirectoryName), PathInformation) <> 0 then
    begin
      ErrorCode := fpGetErrNo;
      raise EInOutError.CreateFmt('Unable to verify pinned output ' +
        'directory: %s (%s)', [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    if (QWord(PathInformation.st_dev) <> Result.FDevice) or
      (QWord(PathInformation.st_ino) <> Result.FInode) then
      raise EInOutError.Create('Output directory changed while it was being ' +
        'pinned: ' + DirectoryName);
    {$ENDIF}
    {$IFDEF Windows}
    DirectoryWide := ExtendedWindowsPath(DirectoryName);
    Result.FPinnedHandle := CreateFileW(PWideChar(DirectoryWide),
      FILE_READ_ATTRIBUTES, FILE_SHARE_READ or FILE_SHARE_WRITE, nil,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if Result.FPinnedHandle = INVALID_HANDLE_VALUE then
    begin
      ErrorCode := GetLastError;
      raise EInOutError.CreateFmt('Unable to pin output directory: %s (%s)',
        [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    FillChar(DirectoryInformation, SizeOf(DirectoryInformation), 0);
    if not GetFileInformationByHandle(Result.FPinnedHandle,
      DirectoryInformation) then
    begin
      ErrorCode := GetLastError;
      raise EInOutError.CreateFmt('Unable to inspect pinned output ' +
        'directory: %s (%s)', [DirectoryName, SysErrorMessage(ErrorCode)]);
    end;
    if (DirectoryInformation.dwFileAttributes and
      FILE_ATTRIBUTE_DIRECTORY) = 0 then
      raise EInOutError.Create('Pinned output path is not a directory: ' +
        DirectoryName);
    Result.FVolumeSerialNumber := DirectoryInformation.dwVolumeSerialNumber;
    Result.FFileIndex := (QWord(DirectoryInformation.nFileIndexHigh) shl 32) or
      QWord(DirectoryInformation.nFileIndexLow);
    { GetFinalPathNameByHandleW binds containment to the directory actually
      opened even when a junction or reparse point changed after preflight. }
    DirectoryName := FinalWindowsPathFromHandle(Result.FPinnedHandle);
    Result.FDirectoryName := DirectoryName;

    { Keep every mutable ancestor open without delete sharing. Together with
      the final-directory handle this prevents a pathname component from
      being renamed or removed before the pinned operation finishes. }
    VolumeRoot := WindowsVolumeRoot(DirectoryName);
    GuardDirectory := ExtractFileDir(DirectoryName);
    while GuardDirectory <> '' do
    begin
      { Drive roots and UNC share roots cannot be renamed within their own
        volume. ExtractFileDir would otherwise descend from a UNC share to an
        invalid server-only path such as \\server. }
      if SameFileName(GuardDirectory, VolumeRoot) then
        Break;
      ParentDirectory := ExtractFileDir(GuardDirectory);
      if SameFileName(ParentDirectory, GuardDirectory) then
        Break;
      GuardWide := ExtendedWindowsPath(GuardDirectory);
      GuardHandle := CreateFileW(PWideChar(GuardWide), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, 0);
      if GuardHandle = INVALID_HANDLE_VALUE then
      begin
        ErrorCode := GetLastError;
        raise EInOutError.CreateFmt('Unable to protect output-directory ' +
          'ancestor: %s (%s)', [GuardDirectory,
          SysErrorMessage(ErrorCode)]);
      end;
      GuardCount := Length(Result.FGuardHandles);
      SetLength(Result.FGuardHandles, GuardCount + 1);
      Result.FGuardHandles[GuardCount] := GuardHandle;
      GuardDirectory := ParentDirectory;
    end;
    Result.VerifyCurrentPath;
    {$ENDIF}
    {$IFNDEF UNIX}
    {$IFNDEF Windows}
    Result.FPinnedHandle := feInvalidHandle;
    {$ENDIF}
    {$ENDIF}
  except
    Result.Free;
    raise;
  end;
end;

{**
  Removes redundant trailing delimiters without collapsing a filesystem root.

  Parameters
  ----------
  APath
    Absolute or expanded path to normalize.

  Returns
  -------
  string
    Path without a redundant trailing delimiter; Unix, drive, and UNC roots
    retain the delimiter required to identify the root.

  Raises
  ------
  None
}
function ExcludeTrailingDelimiterUnlessRoot(const APath: string): string;
var
  RootValue: string;
begin
  Result := APath;
  if Result = '' then
    Exit;
  RootValue := IncludeTrailingPathDelimiter(ExtractFileDrive(Result));
  if (RootValue <> '') and SameFileName(Result, RootValue) then
    Exit;
  Result := ExcludeTrailingPathDelimiter(Result);
end;

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
  WidePath := ExtendedWindowsPath(Result);
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
  Result := ExcludeTrailingDelimiterUnlessRoot(Result);
end;

function PathIsWithin(const APath, ARoot: string): Boolean;
var
  PathValue, RootValue: string;
begin
  PathValue := ExcludeTrailingDelimiterUnlessRoot(CanonicalPath(APath));
  RootValue := ExcludeTrailingDelimiterUnlessRoot(CanonicalPath(ARoot));
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
  WidePath := ExtendedWindowsPath(APath);
  Attributes := GetFileAttributesW(PWideChar(WidePath));
  Result := (Attributes <> INVALID_FILE_ATTRIBUTES) and
    ((Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0);
  {$ENDIF}
end;

function ClassifyFileSystemEntry(AAttributes: LongInt; AUnixMode: QWord;
  out AReason: string): TFileSystemEntryKind;
begin
  AReason := '';
  {$IFDEF UNIX}
  if FPS_ISREG(TMode(AUnixMode)) then
    Exit(fsekRegularFile);
  if FPS_ISDIR(TMode(AUnixMode)) then
    Exit(fsekDirectory);
  if FPS_ISFIFO(TMode(AUnixMode)) then
    AReason := 'named pipe'
  else if FPS_ISSOCK(TMode(AUnixMode)) then
    AReason := 'socket'
  else if FPS_ISBLK(TMode(AUnixMode)) then
    AReason := 'block device'
  else if FPS_ISCHR(TMode(AUnixMode)) then
    AReason := 'character device'
  else if FPS_ISLNK(TMode(AUnixMode)) then
    AReason := 'symbolic link'
  else
    AReason := 'non-regular file';
  Result := fsekUnsupported;
  {$ENDIF}
  {$IFDEF Windows}
  if (AAttributes and FILE_ATTRIBUTE_DEVICE) <> 0 then
    AReason := 'device'
  else if (AAttributes and FILE_ATTRIBUTE_OFFLINE) <> 0 then
    AReason := 'offline file'
  else if (AAttributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
    Exit(fsekDirectory)
  else
    Exit(fsekRegularFile);
  Result := fsekUnsupported;
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  if (AAttributes and faDirectory) <> 0 then
    Result := fsekDirectory
  else
    Result := fsekRegularFile;
  {$ENDIF}
  {$ENDIF}
end;

function IsRegularFile(const APath: string; out AReason: string): Boolean;
{$IFDEF UNIX}
var
  Info: Stat;
{$ENDIF}
{$IFDEF Windows}
var
  Attributes, ErrorCode: DWORD;
  WidePath: UnicodeString;
{$ENDIF}
begin
  AReason := '';
  {$IFDEF UNIX}
  if fpLStat(PChar(APath), Info) <> 0 then
  begin
    AReason := SysErrorMessage(fpGetErrNo);
    Exit(False);
  end;
  Result := ClassifyFileSystemEntry(0, QWord(Info.st_mode), AReason) =
    fsekRegularFile;
  {$ENDIF}
  {$IFDEF Windows}
  WidePath := ExtendedWindowsPath(APath);
  Attributes := GetFileAttributesW(PWideChar(WidePath));
  if Attributes = INVALID_FILE_ATTRIBUTES then
  begin
    ErrorCode := GetLastError;
    AReason := SysErrorMessage(ErrorCode);
    Exit(False);
  end;
  if (Attributes and FILE_ATTRIBUTE_REPARSE_POINT) <> 0 then
  begin
    AReason := 'reparse point';
    Exit(False);
  end;
  Result := ClassifyFileSystemEntry(LongInt(Attributes), 0, AReason) =
    fsekRegularFile;
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := FileExists(APath);
  if not Result then
    AReason := 'not a regular file';
  {$ENDIF}
  {$ENDIF}
end;

function DirectoryEnumerationFailed(const ADirectory: string;
  AFindResult: Integer; out AReason: string): Boolean;
{$IFDEF UNIX}
var
  EnumerationError, AccessError: Integer;
{$ENDIF}
{$IFDEF Windows}
const
  ErrorFileNotFound = 2;
  ErrorNoMoreFiles = 18;
{$ENDIF}
begin
  {$IFDEF UNIX}
  { Capture errno before any later helper performs another system call. }
  EnumerationError := fpGetErrNo;
  {$ENDIF}
  AReason := '';
  if AFindResult = 0 then
    Exit(False);
  {$IFDEF UNIX}
  if fpAccess(PChar(ADirectory), R_OK or X_OK) <> 0 then
  begin
    AccessError := fpGetErrNo;
    AReason := SysErrorMessage(AccessError);
    Exit(True);
  end;
  if not DirectoryExists(ADirectory) then
  begin
    if EnumerationError <> 0 then
      AReason := SysErrorMessage(EnumerationError)
    else
      AReason := 'directory does not exist';
    Exit(True);
  end;
  if EnumerationError <> 0 then
    AReason := SysErrorMessage(EnumerationError);
  if AReason = '' then
    AReason := 'the operating system rejected directory enumeration';
  Result := True;
  {$ENDIF}
  {$IFDEF Windows}
  if AFindResult in [ErrorFileNotFound, ErrorNoMoreFiles] then
  begin
    if DirectoryExists(NativeFileSystemPath(ADirectory)) then
      Exit(False);
    AReason := SysErrorMessage(AFindResult);
    if AReason = '' then
      AReason := 'directory does not exist';
    Exit(True);
  end;
  AReason := SysErrorMessage(AFindResult);
  if AReason = '' then
    AReason := 'operating-system error ' + IntToStr(AFindResult);
  Result := True;
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := not DirectoryExists(ADirectory);
  if Result then
    AReason := 'directory does not exist';
  {$ENDIF}
  {$ENDIF}
end;

procedure ResetDirectoryEnumerationError;
begin
  {$IFDEF UNIX}
  fpSetErrNo(0);
  {$ENDIF}
end;

function DirectoryEnumerationContinuationFailed(AFindResult: Integer;
  out AReason: string): Boolean;
{$IFDEF UNIX}
var
  EnumerationError: Integer;
{$ENDIF}
{$IFDEF Windows}
const
  ErrorNoMoreFiles = 18;
{$ENDIF}
begin
  AReason := '';
  if AFindResult = 0 then
    Exit(False);
  {$IFDEF UNIX}
  EnumerationError := fpGetErrNo;
  Result := EnumerationError <> 0;
  if Result then
  begin
    AReason := SysErrorMessage(EnumerationError);
    if AReason = '' then
      AReason := 'operating-system error ' + IntToStr(EnumerationError);
  end;
  {$ENDIF}
  {$IFDEF Windows}
  Result := AFindResult <> ErrorNoMoreFiles;
  if Result then
  begin
    AReason := SysErrorMessage(AFindResult);
    if AReason = '' then
      AReason := 'operating-system error ' + IntToStr(AFindResult);
  end;
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := False;
  {$ENDIF}
  {$ENDIF}
end;

procedure FlushFileHandle(AHandle: THandle);
begin
  {$IFDEF UNIX}
  if fpFsync(AHandle) <> 0 then
    raise EWriteError.CreateFmt('Unable to flush file stream: %s',
      [SysErrorMessage(fpGetErrNo)]);
  {$ELSE}
  if not FlushFileBuffers(AHandle) then
    RaiseLastOSError;
  {$ENDIF}
end;

procedure FlushFileStream(AStream: TFileStream);
begin
  if AStream <> nil then
    FlushFileHandle(AStream.Handle);
end;

function ReplaceFileAtomically(const ASource, ADestination: string): Boolean;
{$IFDEF Windows}
const
  AtomicMoveReplaceExisting = $00000001;
  AtomicMoveWriteThrough = $00000008;
var
  DestinationWide, SourceWide: UnicodeString;
{$ENDIF}
begin
  {$IFDEF UNIX}
  Result := fpRename(PChar(ASource), PChar(ADestination)) = 0;
  {$ENDIF}
  {$IFDEF Windows}
  SourceWide := UTF8Decode(ASource);
  DestinationWide := UTF8Decode(ADestination);
  Result := MoveFileExW(PWideChar(SourceWide), PWideChar(DestinationWide),
    AtomicMoveReplaceExisting or AtomicMoveWriteThrough);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  if FileExists(ADestination) and not DeleteFile(ADestination) then
    Exit(False);
  Result := RenameFile(ASource, ADestination);
  {$ENDIF}
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
