(**
  PurpleRay SBOM Analyzer atomic-file persistence unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Writes UTF-8 application data through a flushed temporary file and activates
  it atomically while optionally retaining the previous valid file.

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
unit uAtomicFiles;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uPlatform;

{**
  Durably writes UTF-8 content and atomically activates the completed file.

  Parameters
  ----------
  AFileName
    Final destination filename.
  AContent
    Exact UTF-8 byte content to persist.
  APreserveBackup
    When True, retains the previous destination as a .bak file.

  Returns
  -------
  None

  Raises
  ------
  EFCreateError, EWriteError, EInOutError
    Propagated when a directory, temporary file, flush, backup, or rename
    operation cannot be completed safely.
}
procedure WriteAtomicUTF8(const AFileName: string; const AContent: UTF8String;
  APreserveBackup: Boolean = True);

{**
  Writes UTF-8 bytes through an already pinned destination directory.

  Parameters
  ----------
  APinnedDirectory
    Caller-owned pin acquired and validated before a long-running operation.
  AFileName
    Single destination leaf within the pinned directory.
  AContent
    Exact UTF-8 byte content to persist.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when APinnedDirectory is nil.
  EFCreateError, EWriteError, EInOutError
    Propagated when the pinned path changes or temporary creation, flushing,
    atomic activation, or cleanup cannot be completed safely.
}
procedure WriteAtomicUTF8ToPinnedDirectory(APinnedDirectory: TPinnedDirectory;
  const AFileName: string; const AContent: UTF8String);

implementation

uses
  Classes
  {$IFDEF UNIX}, BaseUnix{$ENDIF}
  {$IFDEF Windows}, Windows{$ENDIF};

type
  TExclusiveHandleStream = class(THandleStream)
  public
    destructor Destroy; override;
  end;

{**
  Closes the exclusively created native handle owned by this stream.

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
destructor TExclusiveHandleStream.Destroy;
begin
  FileClose(Handle);
  inherited Destroy;
end;

{**
  Creates an unpredictable sibling name for one atomic-write attempt.

  Parameters
  ----------
  AFileName
    Final destination used as the sibling-name prefix.

  Returns
  -------
  string
    Destination plus a random GUID suffix.

  Raises
  ------
  Exception
    Raised when the operating system cannot create a random GUID.
}
function NewAtomicTemporaryName(const AFileName: string): string;
var
  Identifier: TGUID;
  Suffix: string;
begin
  if CreateGUID(Identifier) <> 0 then
    raise Exception.Create('Unable to create an atomic-file identifier');
  Suffix := LowerCase(GUIDToString(Identifier));
  if (Length(Suffix) >= 2) and (Suffix[1] = '{') then
    Suffix := Copy(Suffix, 2, Length(Suffix) - 2);
  Result := AFileName + '.tmp-' + Suffix;
end;

{**
  Exclusively creates a regular temporary file without following a symlink.

  Parameters
  ----------
  AFileName
    Unique sibling filename selected for this atomic-write attempt.

  Returns
  -------
  TExclusiveHandleStream
    Newly allocated stream that owns the exclusive native handle.

  Raises
  ------
  EFCreateError
    Raised when the filename already exists or native creation fails.
  EOutOfMemory
    May propagate while allocating the owning stream.
}
function CreateExclusiveTemporaryStream(const AFileName: string):
  TExclusiveHandleStream;
var
  HandleValue: THandle;
  ErrorCode: Integer;
  {$IFDEF Windows}
  FileNameWide: UnicodeString;
  {$ENDIF}
begin
  {$IFDEF UNIX}
  repeat
    HandleValue := fpOpen(PChar(AFileName), O_WRONLY or O_CREAT or O_EXCL,
      &600);
  until (HandleValue <> feInvalidHandle) or (fpGetErrNo <> ESysEINTR);
  {$ENDIF}
  {$IFDEF Windows}
  FileNameWide := UTF8Decode(AFileName);
  HandleValue := CreateFileW(PWideChar(FileNameWide), GENERIC_WRITE, 0, nil,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  if FileExists(AFileName) then
    HandleValue := feInvalidHandle
  else
    HandleValue := FileCreate(AFileName);
  {$ENDIF}
  {$ENDIF}
  if HandleValue = feInvalidHandle then
  begin
    ErrorCode := GetLastOSError;
    raise EFCreateError.CreateFmt('Unable to create exclusive temporary file: ' +
      '%s (%s)', [AFileName, SysErrorMessage(ErrorCode)]);
  end;
  try
    Result := TExclusiveHandleStream.Create(HandleValue);
  except
    FileClose(HandleValue);
    raise;
  end;
end;

{**
  Wraps a newly created pinned-directory file in an owning stream.

  Parameters
  ----------
  APinnedDirectory
    Existing directory pin that performs descriptor-relative creation.
  AFileName
    Unique temporary leaf selected for this attempt.

  Returns
  -------
  TExclusiveHandleStream
    Newly allocated stream that owns the exclusive native handle.

  Raises
  ------
  EFCreateError, EInOutError
    Propagated when the path changed or exclusive creation fails.
  EOutOfMemory
    May propagate while allocating the owning stream.
}
function CreatePinnedTemporaryStream(APinnedDirectory: TPinnedDirectory;
  const AFileName: string): TExclusiveHandleStream;
var
  HandleValue: THandle;
begin
  HandleValue := APinnedDirectory.CreateFileExclusive(AFileName);
  try
    Result := TExclusiveHandleStream.Create(HandleValue);
  except
    FileClose(HandleValue);
    raise;
  end;
end;

procedure WriteAtomicUTF8(const AFileName: string; const AContent: UTF8String;
  APreserveBackup: Boolean);
var
  TemporaryName, BackupName: string;
  Stream: TExclusiveHandleStream;
  MovedOriginal: Boolean;
begin
  if not ForceDirectories(ExtractFileDir(AFileName)) then
    raise EInOutError.CreateFmt('Unable to create directory: %s',
      [ExtractFileDir(AFileName)]);
  TemporaryName := NewAtomicTemporaryName(AFileName);
  BackupName := AFileName + '.bak';
  try
    Stream := CreateExclusiveTemporaryStream(TemporaryName);
    try
      if Length(AContent) > 0 then
        Stream.WriteBuffer(AContent[1], Length(AContent));
      FlushFileHandle(Stream.Handle);
    finally
      Stream.Free;
    end;

    MovedOriginal := False;
    try
      if FileExists(AFileName) then
      begin
        if APreserveBackup then
        begin
          if FileExists(BackupName) and not SysUtils.DeleteFile(BackupName) then
            raise EInOutError.CreateFmt('Unable to replace backup file: %s',
              [BackupName]);
          if not RenameFile(AFileName, BackupName) then
            raise EInOutError.CreateFmt('Unable to preserve previous file: %s',
              [AFileName]);
          MovedOriginal := True;
        end
        else
        begin
          if not ReplaceFileAtomically(TemporaryName, AFileName) then
            raise EInOutError.CreateFmt('Unable to atomically replace file: %s',
              [AFileName]);
          TemporaryName := '';
          Exit;
        end;
      end;
      if not RenameFile(TemporaryName, AFileName) then
        raise EInOutError.CreateFmt('Unable to activate temporary file: %s',
          [AFileName]);
      TemporaryName := '';
    except
      if MovedOriginal and (not FileExists(AFileName)) and
        FileExists(BackupName) then
        RenameFile(BackupName, AFileName);
      raise;
    end;
  finally
    if TemporaryName <> '' then
      SysUtils.DeleteFile(TemporaryName);
  end;
end;

procedure WriteAtomicUTF8ToPinnedDirectory(
  APinnedDirectory: TPinnedDirectory; const AFileName: string;
  const AContent: UTF8String);
var
  Stream: TExclusiveHandleStream;
  TemporaryName: string;
begin
  if APinnedDirectory = nil then
    raise EArgumentNilException.Create('Pinned output directory must not be ' +
      'nil');
  TemporaryName := NewAtomicTemporaryName(AFileName);
  try
    Stream := CreatePinnedTemporaryStream(APinnedDirectory, TemporaryName);
    try
      if Length(AContent) > 0 then
        Stream.WriteBuffer(AContent[1], Length(AContent));
      FlushFileHandle(Stream.Handle);
    finally
      Stream.Free;
    end;

    if not APinnedDirectory.ReplaceFileAtomically(TemporaryName,
      AFileName) then
      raise EInOutError.CreateFmt('Unable to atomically activate pinned ' +
        'output file: %s', [AFileName]);
    TemporaryName := '';
    try
      APinnedDirectory.VerifyCurrentPath;
    except
      { A Unix directory can be renamed while open. Remove the just-written
        leaf through the pin so a detected rebind cannot leave an output in a
        location different from the validated path. Windows prevents this
        condition by retaining non-delete-shared directory guards. }
      APinnedDirectory.DeleteFile(AFileName);
      raise;
    end;
  finally
    if TemporaryName <> '' then
      APinnedDirectory.DeleteFile(TemporaryName);
  end;
end;

end.
