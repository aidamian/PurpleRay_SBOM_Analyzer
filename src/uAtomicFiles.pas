unit uAtomicFiles;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

procedure WriteAtomicUTF8(const AFileName: string; const AContent: UTF8String;
  APreserveBackup: Boolean = True);

implementation

uses
  Classes, uPlatform;

procedure WriteAtomicUTF8(const AFileName: string; const AContent: UTF8String;
  APreserveBackup: Boolean);
var
  TemporaryName, BackupName: string;
  Stream: TFileStream;
  MovedOriginal: Boolean;
begin
  if not ForceDirectories(ExtractFileDir(AFileName)) then
    raise EInOutError.CreateFmt('Unable to create directory: %s',
      [ExtractFileDir(AFileName)]);
  TemporaryName := AFileName + '.tmp';
  BackupName := AFileName + '.bak';
  if FileExists(TemporaryName) and not DeleteFile(TemporaryName) then
    raise EInOutError.CreateFmt('Unable to replace temporary file: %s',
      [TemporaryName]);
  Stream := TFileStream.Create(TemporaryName, fmCreate);
  try
    if Length(AContent) > 0 then
      Stream.WriteBuffer(AContent[1], Length(AContent));
    FlushFileStream(Stream);
  finally
    Stream.Free;
  end;

  MovedOriginal := False;
  try
    if FileExists(AFileName) then
    begin
      if APreserveBackup then
      begin
        if FileExists(BackupName) and not DeleteFile(BackupName) then
          raise EInOutError.CreateFmt('Unable to replace backup file: %s',
            [BackupName]);
        if not RenameFile(AFileName, BackupName) then
          raise EInOutError.CreateFmt('Unable to preserve previous file: %s',
            [AFileName]);
        MovedOriginal := True;
      end
      else if not DeleteFile(AFileName) then
        raise EInOutError.CreateFmt('Unable to replace file: %s', [AFileName]);
    end;
    if not RenameFile(TemporaryName, AFileName) then
      raise EInOutError.CreateFmt('Unable to activate temporary file: %s',
        [AFileName]);
  except
    if MovedOriginal and (not FileExists(AFileName)) and FileExists(BackupName) then
      RenameFile(BackupName, AFileName);
    raise;
  end;
end;

end.
