unit uExportUtils;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

function SafeFileNamePart(const AValue: string): string;
function TaskSBOMExportFileName(ATask: TScanTask): string;
function DatabaseArchiveFileName: string;
procedure ExportDatabaseArchive(const ADataDirectory, ADestination: string);

implementation

uses
  Classes, zipper;

function SafeFileNamePart(const AValue: string): string;
var
  I: Integer;
  Value: Char;
begin
  Result := '';
  for I := 1 to Length(Trim(AValue)) do
  begin
    Value := Trim(AValue)[I];
    if (Ord(Value) < 32) or (Value in ['\', '/', ':', '*', '?', '"', '<',
      '>', '|']) then
      Value := '_';
    if (Value = ' ') and ((Result = '') or (Result[Length(Result)] = '_')) then
      Continue;
    if Value = ' ' then
      Value := '_';
    if (Value = '_') and (Result <> '') and
      (Result[Length(Result)] = '_') then
      Continue;
    Result := Result + Value;
  end;
  while (Result <> '') and (Result[Length(Result)] in ['.', '_']) do
    Delete(Result, Length(Result), 1);
  if Result = '' then
    Result := 'scan';
end;

function TimestampFromISO8601(const AValue: string): string;
var
  Digits: string;
  I: Integer;
begin
  Digits := '';
  for I := 1 to Length(AValue) do
    if AValue[I] in ['0'..'9'] then
      Digits := Digits + AValue[I];
  if Length(Digits) >= 14 then
    Result := Copy(Digits, 1, 8) + '_' + Copy(Digits, 9, 6)
  else
    Result := FormatDateTime('yyyymmdd_hhnnss', Now);
end;

function TaskSBOMExportFileName(ATask: TScanTask): string;
begin
  if ATask = nil then
    Exit('sbom.cdx.json');
  Result := TimestampFromISO8601(ATask.CreatedUTC) + '_' +
    SafeFileNamePart(ATask.TargetRootName) + '_' + ATask.ID + '.cdx.json';
end;

function DatabaseArchiveFileName: string;
begin
  Result := 'sbom-analyzer-database-' +
    FormatDateTime('yyyymmdd_hhnnss', Now) + '.zip';
end;

procedure CollectDatabaseFiles(const ARoot, ADirectory, ASkipFile: string;
  AFiles: TStrings);
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
  DiskName, ArchiveName: string;
begin
  FindResult := FindFirst(IncludeTrailingPathDelimiter(ADirectory) + '*',
    faAnyFile, SearchRecord);
  try
    while FindResult = 0 do
    begin
      if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
      begin
        DiskName := IncludeTrailingPathDelimiter(ADirectory) + SearchRecord.Name;
        if (SearchRecord.Attr and faDirectory) <> 0 then
          CollectDatabaseFiles(ARoot, DiskName, ASkipFile, AFiles)
        else if not SameFileName(ExpandFileName(DiskName), ASkipFile) and
          (LowerCase(ExtractFileExt(DiskName)) <> '.tmp') then
        begin
          ArchiveName := Copy(DiskName,
            Length(IncludeTrailingPathDelimiter(ARoot)) + 1, MaxInt);
          ArchiveName := StringReplace(ArchiveName, '\', '/', [rfReplaceAll]);
          AFiles.Add(ArchiveName + #1 + DiskName);
        end;
      end;
      FindResult := FindNext(SearchRecord);
    end;
  finally
    FindClose(SearchRecord);
  end;
end;

procedure ExportDatabaseArchive(const ADataDirectory, ADestination: string);
var
  Files: TStringList;
  Zipper: TZipper;
  RootDirectory, DestinationName, TemporaryName: string;
  I, SplitAt: Integer;
begin
  RootDirectory := ExcludeTrailingPathDelimiter(ExpandFileName(ADataDirectory));
  DestinationName := ExpandFileName(ADestination);
  if not DirectoryExists(RootDirectory) then
    raise EInOutError.CreateFmt('Application data directory does not exist: %s',
      [RootDirectory]);
  if not ForceDirectories(ExtractFileDir(DestinationName)) then
    raise EInOutError.CreateFmt('Unable to create export directory: %s',
      [ExtractFileDir(DestinationName)]);

  TemporaryName := DestinationName + '.tmp';
  Files := TStringList.Create;
  Zipper := TZipper.Create;
  try
    Files.Sorted := True;
    Files.Duplicates := dupIgnore;
    CollectDatabaseFiles(RootDirectory, RootDirectory, DestinationName, Files);
    if Files.Count = 0 then
      raise EInOutError.Create('There is no saved application data to export');
    if FileExists(TemporaryName) and not DeleteFile(TemporaryName) then
      raise EInOutError.CreateFmt('Unable to replace temporary archive: %s',
        [TemporaryName]);
    Zipper.FileName := TemporaryName;
    for I := 0 to Files.Count - 1 do
    begin
      SplitAt := Pos(#1, Files[I]);
      Zipper.Entries.AddFileEntry(Copy(Files[I], SplitAt + 1, MaxInt),
        'sbom-analyzer/' + Copy(Files[I], 1, SplitAt - 1));
    end;
    Zipper.ZipAllFiles;
    if FileExists(DestinationName) and not DeleteFile(DestinationName) then
      raise EInOutError.CreateFmt('Unable to replace database archive: %s',
        [DestinationName]);
    if not RenameFile(TemporaryName, DestinationName) then
      raise EInOutError.CreateFmt('Unable to activate database archive: %s',
        [DestinationName]);
  finally
    Zipper.Free;
    Files.Free;
    if FileExists(TemporaryName) then
      DeleteFile(TemporaryName);
  end;
end;

end.
