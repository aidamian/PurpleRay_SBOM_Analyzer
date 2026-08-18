unit uTaskHistory;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs;

type
  TTaskHistoryStore = class
  private
    FDataDirectory: string;
    function GetHistoryFileName: string;
    function TryLoadFile(const AFileName: string; ATasks: TObjectList;
      out AError: string): Boolean;
    function PreserveMalformedFile(const AFileName: string): string;
  public
    constructor Create(const ADataDirectory: string = '');
    procedure Save(ATasks: TObjectList);
    function Load(ATasks: TObjectList; out AWarning: string): Boolean;
    property DataDirectory: string read FDataDirectory;
    property HistoryFileName: string read GetHistoryFileName;
  end;

implementation

uses
  fpjson, uJSONUtils, uAtomicFiles, uPlatform, uModels, uTimeUtils;

constructor TTaskHistoryStore.Create(const ADataDirectory: string);
begin
  inherited Create;
  if ADataDirectory <> '' then
    FDataDirectory := ExcludeTrailingPathDelimiter(ExpandFileName(ADataDirectory))
  else
    FDataDirectory := ApplicationDataDirectory;
end;

function TTaskHistoryStore.GetHistoryFileName: string;
begin
  Result := IncludeTrailingPathDelimiter(FDataDirectory) + 'history.json';
end;

procedure TTaskHistoryStore.Save(ATasks: TObjectList);
var
  Root: TJSONObject;
  TasksArray: TJSONArray;
  I: Integer;
  Content: UTF8String;
begin
  Root := TJSONObject.Create;
  try
    Root.Add('format_version', 1);
    TasksArray := TJSONArray.Create;
    for I := 0 to ATasks.Count - 1 do
      TasksArray.Add(TScanTask(ATasks[I]).ToJSON);
    Root.Add('tasks', TasksArray);
    Content := UTF8Encode(NormalizeJSONLineEndings(Root.FormatJSON([], 2)) + #10);
    WriteAtomicUTF8(HistoryFileName, Content, True);
  finally
    Root.Free;
  end;
end;

function TTaskHistoryStore.TryLoadFile(const AFileName: string;
  ATasks: TObjectList; out AError: string): Boolean;
var
  Data: TJSONData;
  Root: TJSONObject;
  TasksArray: TJSONArray;
  Loaded: TObjectList;
  Task: TScanTask;
  I: Integer;
begin
  Result := False;
  AError := '';
  Loaded := TObjectList.Create(True);
  try
    try
      Data := ReadJSONFile(AFileName);
      try
        if Data.JSONType <> jtObject then
          raise Exception.Create('history root is not a JSON object');
        Root := TJSONObject(Data);
        if JSONInt64(Root, 'format_version', 0) <> 1 then
          raise Exception.Create('history format version is unsupported');
        TasksArray := JSONArray(Root, 'tasks');
        if TasksArray = nil then
          raise Exception.Create('history does not contain a task array');
        for I := 0 to TasksArray.Count - 1 do
        begin
          if TasksArray.Items[I].JSONType <> jtObject then
            raise Exception.CreateFmt('task %d is not a JSON object', [I]);
          Task := TScanTask.FromJSON(TJSONObject(TasksArray.Items[I]));
          if Task.ID = '' then
          begin
            Task.Free;
            raise Exception.CreateFmt('task %d has no identifier', [I]);
          end;
          if Task.Status in [tsPending, tsRunning] then
          begin
            Task.Status := tsFailed;
            Task.CompletedUTC := UTCNowISO8601;
            Task.Errors.Add('The application exited before this scan finished.');
          end;
          Loaded.Add(Task);
        end;
      finally
        Data.Free;
      end;
      ATasks.Clear;
      while Loaded.Count > 0 do
        ATasks.Add(Loaded.Extract(Loaded[0]));
      Result := True;
    except
      on E: Exception do
        AError := E.Message;
    end;
  finally
    Loaded.Free;
  end;
end;

function TTaskHistoryStore.PreserveMalformedFile(const AFileName: string): string;
var
  Suffix: string;
begin
  Result := '';
  if not FileExists(AFileName) then
    Exit;
  Suffix := FormatDateTime('yyyymmdd-hhnnss-zzz', Now);
  Result := IncludeTrailingPathDelimiter(FDataDirectory) +
    'history.corrupt-' + Suffix + '.json';
  CopyFileContents(AFileName, Result);
end;

function TTaskHistoryStore.Load(ATasks: TObjectList; out AWarning: string): Boolean;
var
  ErrorText, BackupError, PreservedName: string;
begin
  AWarning := '';
  if not FileExists(HistoryFileName) then
  begin
    ATasks.Clear;
    Exit(True);
  end;
  if TryLoadFile(HistoryFileName, ATasks, ErrorText) then
    Exit(True);

  try
    PreservedName := PreserveMalformedFile(HistoryFileName);
  except
    on E: Exception do
      PreservedName := '(preservation failed: ' + E.Message + ')';
  end;
  if FileExists(HistoryFileName + '.bak') and
    TryLoadFile(HistoryFileName + '.bak', ATasks, BackupError) then
  begin
    AWarning := 'Task history was malformed (' + ErrorText + '). The backup '+
      'was loaded. The malformed file was preserved as ' + PreservedName + '.';
    Exit(True);
  end;
  ATasks.Clear;
  AWarning := 'Task history and its backup could not be loaded. Primary error: '+
    ErrorText;
  if BackupError <> '' then
    AWarning := AWarning + '; backup error: ' + BackupError;
  AWarning := AWarning + '. The malformed file was preserved as ' +
    PreservedName + '.';
  Result := False;
end;

end.
