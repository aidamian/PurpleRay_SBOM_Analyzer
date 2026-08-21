(**
  PurpleRay SBOM Analyzer verified scan-input unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Pins one regular scan input by native handle, validates its identity and
  containment, and exposes only size-bounded reads to scanner consumers.

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
unit uVerifiedInput;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  EVerifiedInputError = class(EInOutError);

  {**
    Stores the stable native identity observed while a file is enumerated.

    Attributes
    ----------
    Valid
      True when the remaining fields came from an opened regular file.
    StorageID
      Unix device number or Windows volume serial number.
    FileID
      Unix inode or Windows 64-bit file index.
    Size
      Size observed from the native file handle.
    ModifiedSeconds, ModifiedNanoseconds
      Native last-write timestamp used to detect in-place mutation.
    ChangedSeconds, ChangedNanoseconds
      Unix inode-change timestamp, or zero where write sharing is denied.
    LinkCount
      Native hard-link count used as additional Unix mutation evidence.
  *}
  TVerifiedFileIdentity = record
    Valid: Boolean;
    StorageID: QWord;
    FileID: QWord;
    Size: Int64;
    ModifiedSeconds: QWord;
    ModifiedNanoseconds: QWord;
    ChangedSeconds: QWord;
    ChangedNanoseconds: QWord;
    LinkCount: QWord;
  end;

  {**
    Owns one validated regular-file handle for the complete scan pipeline.

    Every NewStream view starts at offset zero and cannot seek or read beyond
    the size captured from the opened object. This object must outlive all of
    its disposable stream views.
  *}
  TVerifiedInput = class
  private
    FOriginalPath: string;
    FFinalPath: string;
    FIdentity: TVerifiedFileIdentity;
    FHandle: THandle;
    FReadLock: TRTLCriticalSection;
    FReadLockInitialized: Boolean;
    function ReadAt(AOffset: Int64; var ABuffer; ACount: LongInt): LongInt;
  public
    {**
      Releases the bounded stream and its owned native handle.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    destructor Destroy; override;

    {**
      Creates a disposable size-bounded view over the pinned input.

      Parameters
      ----------
      None

      Returns
      -------
      TStream
        Caller-owned stream whose destruction does not close the pinned input.

      Raises
      ------
      EOutOfMemory
        Raised if the stream view cannot be allocated.
    *}
    function NewStream: TStream;

    {**
      Returns a safe path-tool input when bounded reopening is supported.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Currently empty because supported path tools cannot enforce frozen size.

      Raises
      ------
      None
    *}
    function ToolPath: string;

    {**
      Confirms that size and last-write metadata still match the open snapshot.

      Parameters
      ----------
      AReason
        Receives a deterministic diagnostic when validation fails.

      Returns
      -------
      Boolean
        True only while the pinned object's identity and metadata are stable.

      Raises
      ------
      None
    *}
    function ValidateStable(out AReason: string): Boolean;

    property OriginalPath: string read FOriginalPath;
    property FinalPath: string read FFinalPath;
    property Identity: TVerifiedFileIdentity read FIdentity;
    property Size: Int64 read FIdentity.Size;
  end;

{**
  Captures a regular file's identity under an explicit final-link policy.

  Parameters
  ----------
  AFileName
    Candidate path reached during directory enumeration.
  AFollowLinks
    True to resolve a final link before capturing the target identity; False
    to reject final symbolic links and reparse points.
  AIdentity
    Receives native storage ID, file ID, size, and last-write metadata.
  AReason
    Receives a deterministic failure explanation.

  Returns
  -------
  Boolean
    True only when a regular file or explicitly followed regular target was
    opened non-blockingly. This compatibility overload performs no root check.

  Raises
  ------
  None
    Native open and metadata errors are returned through AReason.
*}
function TryCaptureVerifiedFileIdentity(const AFileName: string;
  AFollowLinks: Boolean; out AIdentity: TVerifiedFileIdentity;
  out AReason: string): Boolean; overload;

{**
  Captures a regular file's native identity within an already-resolved root.

  Parameters
  ----------
  AFileName
    Candidate path reached during directory enumeration.
  AScanRoot
    Pinned, resolved scan root; an empty value explicitly permits an outside
    target.
  AFollowLinks
    True only when enumeration identified this entry as a link and policy
    permits following it; False rejects a final link or reparse point.
  AIdentity
    Receives native storage ID, file ID, size, and mutation metadata.
  AReason
    Receives a deterministic failure explanation.

  Returns
  -------
  Boolean
    True only when the opened regular object resolves within AScanRoot, when
    one is supplied.

  Raises
  ------
  None
    Native open, metadata, final-path, and containment errors are returned.
*}
function TryCaptureVerifiedFileIdentity(const AFileName, AScanRoot: string;
  AFollowLinks: Boolean; out AIdentity: TVerifiedFileIdentity;
  out AReason: string): Boolean; overload;

{**
  Opens and validates one scan input against enumeration identity and root.

  Parameters
  ----------
  AFileName
    Enumerated input pathname to open under AFollowLinks policy.
  AScanRoot
    Canonical selected scan root; an empty value disables containment checking.
  AFollowLinks
    True to resolve a final link before validating its target; False to reject
    final symbolic links and reparse points.
  AExpectedIdentity
    Valid identity captured during enumeration; invalid records fail closed.
  AInput
    Receives a caller-owned verified input on success, otherwise nil.
  AReason
    Receives a deterministic failure explanation.

  Returns
  -------
  Boolean
    True only for the same regular file within the selected root.

  Raises
  ------
  None
    Native open, metadata, identity, and containment failures are returned.
*}
function TryOpenVerifiedInput(const AFileName, AScanRoot: string;
  AFollowLinks: Boolean; const AExpectedIdentity: TVerifiedFileIdentity;
  out AInput: TVerifiedInput; out AReason: string): Boolean;

implementation

{$IFDEF UNIX}
uses
  BaseUnix;
{$ENDIF}
{$IFDEF Windows}
uses
  Windows;

const
  VerifiedFileFlagOpenReparsePoint = $00200000;

function GetFinalPathNameByHandleW(AHandle: THandle; APath: PWideChar;
  APathLength, AFlags: DWORD): DWORD; stdcall;
  external 'kernel32.dll' name 'GetFinalPathNameByHandleW';
{$ENDIF}

type
  {**
    Read-only stream view capped at the verified initial file size.

    The class does not own the master input or its handle. Seeking outside the
    captured interval and all writes fail rather than exposing later growth.
  *}
  TVerifiedInputStream = class(TStream)
  private
    FOwner: TVerifiedInput;
    FPosition: Int64;
  public
    constructor Create(AOwner: TVerifiedInput);
    function Read(var Buffer; Count: LongInt): LongInt; override;
    function Write(const Buffer; Count: LongInt): LongInt; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

{**
  Combines a Windows FILETIME into one sortable unsigned value.

  Parameters
  ----------
  ATime
    Native Windows timestamp.

  Returns
  -------
  QWord
    High and low timestamp words combined without interpretation.

  Raises
  ------
  None
*}
{$IFDEF Windows}
function FileTimeValue(const ATime: TFileTime): QWord;
begin
  Result := (QWord(ATime.dwHighDateTime) shl 32) or
    QWord(ATime.dwLowDateTime);
end;
{$ENDIF}

{**
  Removes the Win32 extended-path prefix from a final handle pathname.

  Parameters
  ----------
  APath
    Path returned by GetFinalPathNameByHandleW.

  Returns
  -------
  string
    Ordinary UTF-8 drive or UNC pathname.

  Raises
  ------
  None
*}
{$IFDEF Windows}
function NormalizeFinalWindowsPath(const APath: UnicodeString): string;
var
  PathValue: UnicodeString;
begin
  PathValue := APath;
  if Copy(PathValue, 1, 8) = '\\?\UNC\' then
    PathValue := '\\' + Copy(PathValue, 9, MaxInt)
  else if Copy(PathValue, 1, 4) = '\\?\' then
    Delete(PathValue, 1, 4);
  Result := UTF8Encode(PathValue);
end;
{$ENDIF}

{**
  Converts an absolute Windows path to extended-length form for CreateFileW.

  Parameters
  ----------
  AFileName
    UTF-8 input filename.

  Returns
  -------
  UnicodeString
    Absolute extended-length drive or UNC path.

  Raises
  ------
  None
*}
{$IFDEF Windows}
function ExtendedWindowsPath(const AFileName: string): UnicodeString;
var
  Expanded: UnicodeString;
begin
  Expanded := UTF8Decode(ExpandFileName(AFileName));
  if Copy(Expanded, 1, 4) = '\\?\' then
    Exit(Expanded);
  if Copy(Expanded, 1, 2) = '\\' then
    Result := '\\?\UNC\' + Copy(Expanded, 3, MaxInt)
  else
    Result := '\\?\' + Expanded;
end;
{$ENDIF}

{**
  Tests containment between two already-resolved absolute paths.

  Parameters
  ----------
  AResolvedPath
    Final path obtained from the opened input handle.
  AResolvedRoot
    Canonical path held by the pinned scan-root object.

  Returns
  -------
  Boolean
    True for the root itself or a path below its component boundary.

  Raises
  ------
  None

  Notes
  -----
  This comparison performs no filesystem lookup, so a pathname replacement
  cannot redirect containment validation away from the opened handle.
*}
function ResolvedPathIsWithin(const AResolvedPath,
  AResolvedRoot: string): Boolean;
var
  PathValue, RootValue: string;

  {**
    Removes trailing separators without collapsing Unix or Windows roots.

    Parameters
    ----------
    APath
      Already-resolved absolute path.

    Returns
    -------
    string
      Lexically trimmed path with ``/``, drive roots, and UNC roots intact.

    Raises
    ------
    None
  *}
  function ExcludeTrailingUnlessRoot(const APath: string): string;
  begin
    Result := APath;
    while (Length(Result) > 1) and
      (Result[Length(Result)] in ['/', '\']) do
    begin
      {$IFDEF Windows}
      if (Length(Result) = 3) and (Result[2] = ':') then
        Break;
      if Result = '\\' then
        Break;
      {$ENDIF}
      Delete(Result, Length(Result), 1);
    end;
  end;

begin
  PathValue := ExcludeTrailingUnlessRoot(AResolvedPath);
  RootValue := ExcludeTrailingUnlessRoot(AResolvedRoot);
  {$IFDEF Windows}
  PathValue := LowerCase(StringReplace(PathValue, '/', '\', [rfReplaceAll]));
  RootValue := LowerCase(StringReplace(RootValue, '/', '\', [rfReplaceAll]));
  {$ENDIF}
  Result := (PathValue = RootValue) or
    (Pos(IncludeTrailingPathDelimiter(RootValue),
      IncludeTrailingPathDelimiter(PathValue)) = 1);
end;

{**
  Resolves the pathname currently attached to a native file handle.

  Parameters
  ----------
  AHandle
    Open regular-file handle.
  AOriginalPath
    Fallback path on platforms without a handle-path facility.
  AFinalPath
    Receives the resolved path.
  AReason
    Receives a failure explanation.

  Returns
  -------
  Boolean
    True when a usable final path was obtained.

  Raises
  ------
  None
*}
function TryFinalPathFromHandle(AHandle: THandle; const AOriginalPath: string;
  out AFinalPath, AReason: string): Boolean;
{$IFDEF Windows}
const
  FileNameNormalized = 0;
var
  Buffer: array[0..32767] of WideChar;
  PathLength: DWORD;
  PathValue: UnicodeString;
{$ENDIF}
{$IFDEF Linux}
var
  LinkPath, LinkValue: RawByteString;
  DeletedMarker: SizeInt;
{$ENDIF}
begin
  AFinalPath := '';
  AReason := '';
  {$IFDEF Linux}
  LinkPath := '/proc/self/fd/' + IntToStr(AHandle);
  LinkValue := fpReadLink(LinkPath);
  if LinkValue = '' then
  begin
    AReason := 'unable to resolve the opened file handle';
    Exit(False);
  end;
  AFinalPath := string(LinkValue);
  DeletedMarker := Pos(' (deleted)', AFinalPath);
  if (DeletedMarker > 0) and
    (DeletedMarker = Length(AFinalPath) - 9) then
  begin
    AReason := 'the opened file was removed while being verified';
    Exit(False);
  end;
  Exit(True);
  {$ENDIF}
  {$IFDEF Windows}
  FillChar(Buffer, SizeOf(Buffer), 0);
  PathLength := GetFinalPathNameByHandleW(AHandle, @Buffer[0], Length(Buffer),
    FileNameNormalized);
  if (PathLength = 0) or (PathLength >= DWORD(Length(Buffer))) then
  begin
    AReason := 'unable to resolve the opened file handle: ' +
      SysErrorMessage(GetLastError);
    Exit(False);
  end;
  SetString(PathValue, PWideChar(@Buffer[0]), PathLength);
  AFinalPath := NormalizeFinalWindowsPath(PathValue);
  Exit(True);
  {$ENDIF}
  {$IFNDEF Linux}
  {$IFNDEF Windows}
  AReason := 'verified final paths are unsupported on this platform';
  Result := False;
  Exit;
  {$ENDIF}
  {$ENDIF}
end;

{**
  Reads regular-file identity and mutation metadata from an open handle.

  Parameters
  ----------
  AHandle
    Open candidate handle.
  AIdentity
    Receives native metadata.
  AReason
    Receives a deterministic failure explanation.

  Returns
  -------
  Boolean
    True only when the handle denotes a regular disk file of representable size.

  Raises
  ------
  None
*}
function TryIdentityFromHandle(AHandle: THandle;
  out AIdentity: TVerifiedFileIdentity; out AReason: string): Boolean;
{$IFDEF UNIX}
var
  Information: Stat;
{$ENDIF}
{$IFDEF Windows}
var
  Information: TByHandleFileInformation;
  SizeValue: QWord;
{$ENDIF}
begin
  FillChar(AIdentity, SizeOf(AIdentity), 0);
  AReason := '';
  {$IFDEF UNIX}
  FillChar(Information, SizeOf(Information), 0);
  if fpFStat(AHandle, Information) <> 0 then
  begin
    AReason := 'unable to inspect the opened file: ' +
      SysErrorMessage(fpGetErrNo);
    Exit(False);
  end;
  if not FPS_ISREG(Information.st_mode) then
  begin
    AReason := 'opened filesystem entry is not a regular file';
    Exit(False);
  end;
  if Information.st_size < 0 then
  begin
    AReason := 'opened file has an invalid negative size';
    Exit(False);
  end;
  AIdentity.StorageID := QWord(Information.st_dev);
  AIdentity.FileID := QWord(Information.st_ino);
  AIdentity.Size := Information.st_size;
  AIdentity.ModifiedSeconds := QWord(Information.st_mtime);
  AIdentity.ChangedSeconds := QWord(Information.st_ctime);
  AIdentity.LinkCount := QWord(Information.st_nlink);
  {$IFDEF Linux}
  AIdentity.ModifiedNanoseconds := QWord(Information.st_mtime_nsec);
  AIdentity.ChangedNanoseconds := QWord(Information.st_ctime_nsec);
  {$ENDIF}
  {$ENDIF}
  {$IFDEF Windows}
  if GetFileType(AHandle) <> FILE_TYPE_DISK then
  begin
    AReason := 'opened filesystem entry is not a regular disk file';
    Exit(False);
  end;
  FillChar(Information, SizeOf(Information), 0);
  if not GetFileInformationByHandle(AHandle, Information) then
  begin
    AReason := 'unable to inspect the opened file: ' +
      SysErrorMessage(GetLastError);
    Exit(False);
  end;
  if (Information.dwFileAttributes and (FILE_ATTRIBUTE_DIRECTORY or
    FILE_ATTRIBUTE_REPARSE_POINT or FILE_ATTRIBUTE_DEVICE or
    FILE_ATTRIBUTE_OFFLINE)) <> 0 then
  begin
    AReason := 'opened filesystem entry is not a regular non-reparse file';
    Exit(False);
  end;
  SizeValue := (QWord(Information.nFileSizeHigh) shl 32) or
    QWord(Information.nFileSizeLow);
  if SizeValue > QWord(High(Int64)) then
  begin
    AReason := 'opened file is too large to inspect safely';
    Exit(False);
  end;
  AIdentity.StorageID := Information.dwVolumeSerialNumber;
  AIdentity.FileID := (QWord(Information.nFileIndexHigh) shl 32) or
    QWord(Information.nFileIndexLow);
  AIdentity.Size := Int64(SizeValue);
  AIdentity.ModifiedSeconds := FileTimeValue(Information.ftLastWriteTime);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  AReason := 'verified scan inputs are unsupported on this platform';
  Exit(False);
  {$ENDIF}
  {$ENDIF}
  AIdentity.Valid := True;
  Result := True;
end;

{**
  Opens a final path component with explicit link and non-blocking policy.

  Parameters
  ----------
  AFileName
    Candidate input path.
  AFollowLinks
    True to resolve the final link; False to request native no-follow behavior.
  AHandle
    Receives an owned native handle on success.
  AReason
    Receives a native failure explanation.

  Returns
  -------
  Boolean
    True only when the native open succeeds.

  Raises
  ------
  None
*}
function TryOpenNativeInput(const AFileName: string; AFollowLinks: Boolean;
  out AHandle: THandle; out AReason: string): Boolean;
{$IFDEF UNIX}
var
  Flags, ErrorCode: Integer;
{$ENDIF}
{$IFDEF Windows}
var
  WidePath: UnicodeString;
  ErrorCode, OpenFlags: Cardinal;
{$ENDIF}
begin
  AHandle := feInvalidHandle;
  AReason := '';
  {$IFDEF UNIX}
  Flags := O_RDONLY or O_NONBLOCK;
  {$IF declared(O_CLOEXEC)}
  Flags := Flags or O_CLOEXEC;
  {$IFEND}
  {$IF declared(O_NOFOLLOW)}
  if not AFollowLinks then
    Flags := Flags or O_NOFOLLOW;
  {$IFEND}
  repeat
    AHandle := fpOpen(PChar(AFileName), Flags);
  until (AHandle <> feInvalidHandle) or (fpGetErrNo <> ESysEINTR);
  if AHandle = feInvalidHandle then
  begin
    ErrorCode := fpGetErrNo;
    AReason := SysErrorMessage(ErrorCode);
    Exit(False);
  end;
  { FPC 3.2.2 does not expose O_CLOEXEC on every supported Linux target.
    Set the descriptor flag explicitly so only the parent-PID proc path, never
    an inherited descriptor, is available to an allowlisted child tool. }
  if fpFcntl(AHandle, F_SetFd, 1) < 0 then
  begin
    ErrorCode := fpGetErrNo;
    FileClose(AHandle);
    AHandle := feInvalidHandle;
    AReason := 'unable to protect the verified file descriptor: ' +
      SysErrorMessage(ErrorCode);
    Exit(False);
  end;
  Exit(True);
  {$ENDIF}
  {$IFDEF Windows}
  WidePath := ExtendedWindowsPath(AFileName);
  { Denying write and delete sharing keeps the final pathname bound to this
    exact file object while native APIs reopen it for read-only enrichment. }
  OpenFlags := FILE_FLAG_SEQUENTIAL_SCAN;
  if not AFollowLinks then
    OpenFlags := OpenFlags or VerifiedFileFlagOpenReparsePoint;
  AHandle := CreateFileW(PWideChar(WidePath), GENERIC_READ, FILE_SHARE_READ,
    nil, OPEN_EXISTING, OpenFlags, 0);
  if AHandle = INVALID_HANDLE_VALUE then
  begin
    ErrorCode := GetLastError;
    AReason := SysErrorMessage(ErrorCode);
    Exit(False);
  end;
  Exit(True);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  AReason := 'verified scan inputs are unsupported on this platform';
  Result := False;
  {$ENDIF}
  {$ENDIF}
end;

{**
  Creates one logical-position view over a verified input.

  Parameters
  ----------
  AOwner
    Verified input that owns the native handle and frozen bounds.

  Returns
  -------
  TVerifiedInputStream
    Disposable stream view starting at offset zero.

  Raises
  ------
  EArgumentNilException
    Raised when AOwner is nil.
*}
constructor TVerifiedInputStream.Create(AOwner: TVerifiedInput);
begin
  inherited Create;
  if AOwner = nil then
    raise EArgumentNilException.Create('Verified input stream owner is nil');
  FOwner := AOwner;
  FPosition := 0;
end;

{**
  Reads within the owner's frozen size and advances this view only.

  Parameters
  ----------
  Buffer
    Caller-provided destination buffer.
  Count
    Maximum requested byte count.

  Returns
  -------
  LongInt
    Bytes read, zero at the frozen end of input.

  Raises
  ------
  EReadError
    Raised when the native positioned read fails.
*}
function TVerifiedInputStream.Read(var Buffer; Count: LongInt): LongInt;
begin
  Result := FOwner.ReadAt(FPosition, Buffer, Count);
  Inc(FPosition, Result);
end;

{**
  Rejects every attempt to write through a verified input view.

  Parameters
  ----------
  Buffer
    Ignored caller buffer.
  Count
    Ignored requested byte count.

  Returns
  -------
  LongInt
    This function never returns normally.

  Raises
  ------
  EStreamError
    Always raised because verified scan inputs are read-only.
*}
function TVerifiedInputStream.Write(const Buffer; Count: LongInt): LongInt;
begin
  Result := 0;
  raise EStreamError.Create('Verified scan inputs are read-only');
end;

{**
  Changes this view's logical position without moving the master handle.

  Parameters
  ----------
  Offset
    Signed offset interpreted according to Origin.
  Origin
    Beginning, current position, or frozen end of input.

  Returns
  -------
  Int64
    New logical position.

  Raises
  ------
  EStreamError
    Raised for overflow or a target outside the frozen input interval.
*}
function TVerifiedInputStream.Seek(const Offset: Int64;
  Origin: TSeekOrigin): Int64;
var
  BasePosition, TargetPosition: Int64;
begin
  case Origin of
    soBeginning: BasePosition := 0;
    soCurrent: BasePosition := FPosition;
    soEnd: BasePosition := FOwner.Size;
  else
    raise EStreamError.Create('Unsupported verified input seek origin');
  end;
  if ((Offset > 0) and (BasePosition > High(Int64) - Offset)) or
    ((Offset < 0) and (BasePosition < Low(Int64) - Offset)) then
    raise EStreamError.Create('Verified input seek is out of range');
  TargetPosition := BasePosition + Offset;
  if (TargetPosition < 0) or (TargetPosition > FOwner.Size) then
    raise EStreamError.Create('Verified input seek exceeds captured bounds');
  FPosition := TargetPosition;
  Result := FPosition;
end;

{**
  Performs one serialized native read at an explicit frozen-range offset.

  Parameters
  ----------
  AOffset
    Zero-based offset within the captured file size.
  ABuffer
    Caller-provided destination buffer.
  ACount
    Maximum byte count.

  Returns
  -------
  LongInt
    Bytes actually read; zero at end or after an external truncation.

  Raises
  ------
  EReadError
    Raised when seeking or reading the native handle fails.
*}
function TVerifiedInput.ReadAt(AOffset: Int64; var ABuffer;
  ACount: LongInt): LongInt;
var
  Remaining: Int64;
begin
  if (ACount <= 0) or (AOffset >= Size) then
    Exit(0);
  if AOffset < 0 then
    raise EReadError.Create('Verified input read offset is negative');
  Remaining := Size - AOffset;
  if Remaining < ACount then
    ACount := LongInt(Remaining);
  EnterCriticalSection(FReadLock);
  try
    if FileSeek(FHandle, AOffset, 0) <> AOffset then
      raise EReadError.Create('Unable to seek the verified input');
    Result := FileRead(FHandle, ABuffer, ACount);
    if Result < 0 then
      raise EReadError.Create('Unable to read the verified input: ' +
        SysErrorMessage(GetLastOSError));
  finally
    LeaveCriticalSection(FReadLock);
  end;
end;

destructor TVerifiedInput.Destroy;
begin
  if FHandle <> feInvalidHandle then
    FileClose(FHandle);
  if FReadLockInitialized then
    DoneCriticalSection(FReadLock);
  inherited Destroy;
end;

function TVerifiedInput.NewStream: TStream;
begin
  Result := TVerifiedInputStream.Create(Self);
end;

function TVerifiedInput.ToolPath: string;
begin
  { Path-based tools and APIs reopen without this object's frozen-size cap and
    can inspect appended bytes before post-inspection validation. Keep them
    disabled until bounded native T-406 enrichment lands. }
  Result := '';
end;

function TVerifiedInput.ValidateStable(out AReason: string): Boolean;
var
  CurrentIdentity: TVerifiedFileIdentity;
begin
  Result := TryIdentityFromHandle(FHandle, CurrentIdentity, AReason);
  if not Result then
    Exit;
  Result := (CurrentIdentity.StorageID = FIdentity.StorageID) and
    (CurrentIdentity.FileID = FIdentity.FileID);
  if not Result then
  begin
    AReason := 'verified input identity changed during inspection';
    Exit;
  end;
  Result := (CurrentIdentity.Size = FIdentity.Size) and
    (CurrentIdentity.ModifiedSeconds = FIdentity.ModifiedSeconds) and
    (CurrentIdentity.ModifiedNanoseconds = FIdentity.ModifiedNanoseconds) and
    (CurrentIdentity.ChangedSeconds = FIdentity.ChangedSeconds) and
    (CurrentIdentity.ChangedNanoseconds = FIdentity.ChangedNanoseconds) and
    (CurrentIdentity.LinkCount = FIdentity.LinkCount);
  if not Result then
    AReason := 'verified input size or modification time changed during ' +
      'inspection';
end;

function TryCaptureVerifiedFileIdentity(const AFileName, AScanRoot: string;
  AFollowLinks: Boolean; out AIdentity: TVerifiedFileIdentity;
  out AReason: string): Boolean;
var
  HandleValue: THandle;
  FinalPathValue: string;
begin
  FillChar(AIdentity, SizeOf(AIdentity), 0);
  Result := TryOpenNativeInput(AFileName, AFollowLinks, HandleValue, AReason);
  if not Result then
    Exit;
  try
    Result := TryIdentityFromHandle(HandleValue, AIdentity, AReason);
    if not Result then
      Exit;
    Result := TryFinalPathFromHandle(HandleValue, AFileName, FinalPathValue,
      AReason);
    if not Result then
    begin
      FillChar(AIdentity, SizeOf(AIdentity), 0);
      Exit;
    end;
    if (AScanRoot <> '') and not ResolvedPathIsWithin(FinalPathValue,
      AScanRoot) then
    begin
      FillChar(AIdentity, SizeOf(AIdentity), 0);
      AReason := 'opened file resolves outside the selected scan root';
      Exit(False);
    end;
  finally
    FileClose(HandleValue);
  end;
end;

function TryCaptureVerifiedFileIdentity(const AFileName: string;
  AFollowLinks: Boolean; out AIdentity: TVerifiedFileIdentity;
  out AReason: string): Boolean;
begin
  Result := TryCaptureVerifiedFileIdentity(AFileName, '', AFollowLinks,
    AIdentity, AReason);
end;

function TryOpenVerifiedInput(const AFileName, AScanRoot: string;
  AFollowLinks: Boolean; const AExpectedIdentity: TVerifiedFileIdentity;
  out AInput: TVerifiedInput; out AReason: string): Boolean;
var
  HandleValue: THandle;
  IdentityValue: TVerifiedFileIdentity;
  FinalPathValue: string;
begin
  Result := False;
  AInput := nil;
  if not AExpectedIdentity.Valid then
  begin
    AReason := 'enumeration did not provide a verified file identity';
    Exit;
  end;
  if not TryOpenNativeInput(AFileName, AFollowLinks, HandleValue, AReason) then
    Exit;
  try
    if not TryIdentityFromHandle(HandleValue, IdentityValue, AReason) then
      Exit;
    if AExpectedIdentity.Valid and
      ((IdentityValue.StorageID <> AExpectedIdentity.StorageID) or
       (IdentityValue.FileID <> AExpectedIdentity.FileID) or
       (IdentityValue.Size <> AExpectedIdentity.Size) or
       (IdentityValue.ModifiedSeconds <>
         AExpectedIdentity.ModifiedSeconds) or
       (IdentityValue.ModifiedNanoseconds <>
         AExpectedIdentity.ModifiedNanoseconds) or
       (IdentityValue.ChangedSeconds <> AExpectedIdentity.ChangedSeconds) or
       (IdentityValue.ChangedNanoseconds <>
         AExpectedIdentity.ChangedNanoseconds) or
       (IdentityValue.LinkCount <> AExpectedIdentity.LinkCount)) then
    begin
      AReason := 'file identity changed after directory enumeration';
      Exit;
    end;
    if not TryFinalPathFromHandle(HandleValue, AFileName, FinalPathValue,
      AReason) then
      Exit;
    if (AScanRoot <> '') and not ResolvedPathIsWithin(FinalPathValue,
      AScanRoot) then
    begin
      AReason := 'opened file resolves outside the selected scan root';
      Exit;
    end;
    AInput := TVerifiedInput.Create;
    try
      AInput.FHandle := feInvalidHandle;
      AInput.FOriginalPath := ExpandFileName(AFileName);
      AInput.FFinalPath := FinalPathValue;
      AInput.FIdentity := IdentityValue;
      InitCriticalSection(AInput.FReadLock);
      AInput.FReadLockInitialized := True;
      AInput.FHandle := HandleValue;
      HandleValue := feInvalidHandle;
    except
      FreeAndNil(AInput);
      raise;
    end;
    Result := True;
  finally
    if HandleValue <> feInvalidHandle then
      FileClose(HandleValue);
  end;
end;

end.
