(**
  PurpleRay SBOM Analyzer task-history persistence unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Persists scan tasks atomically, repairs migrated SBOM paths, recovers from a
  valid backup, and preserves malformed history for diagnosis.

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

    {**
      Validates and reconstructs tasks from one candidate history file.

      Parameters
      ----------
      AFileName
        Active or backup history filename.
      ATasks
        Temporary owned destination list.
      AError
        Receives a concise parse, schema, or reconstruction diagnostic.

      Returns
      -------
      Boolean
        True only when the complete file was valid and loaded.

      Raises
      ------
      EOutOfMemory
        May propagate while allocating reconstructed tasks.
    }
    function TryLoadFile(const AFileName: string; ATasks: TObjectList;
      out AError: string): Boolean;

    {**
      Renames malformed active history to a timestamped diagnostic filename.

      Parameters
      ----------
      AFileName
        Malformed file to preserve.

      Returns
      -------
      string
        Preserved filename, or an empty string when preservation failed.

      Raises
      ------
      None
    }
    function PreserveMalformedFile(const AFileName: string): string;
  public
    {**
      Creates a history store rooted at an explicit or default data directory.

      Parameters
      ----------
      ADataDirectory
        Override directory; an empty value selects ApplicationDataDirectory.

      Returns
      -------
      TTaskHistoryStore
        Newly configured store.

      Raises
      ------
      None
    }
    constructor Create(const ADataDirectory: string = '');

    {**
      Atomically persists the complete owned task list as versioned JSON.

      Parameters
      ----------
      ATasks
        List containing TScanTask instances to serialize.

      Returns
      -------
      None

      Raises
      ------
      EAccessViolation
        Raised when ATasks is nil or contains incompatible objects.
      EFCreateError, EWriteError, EInOutError
        Propagated by JSON serialization and atomic persistence.
    }
    procedure Save(ATasks: TObjectList);

    {**
      Loads history with backup recovery and interrupted-task repair.

      Parameters
      ----------
      ATasks
        Owned destination list cleared and populated only after valid loading.
      AWarning
        Receives backup-recovery, malformed-file, or path-repair information.

      Returns
      -------
      Boolean
        True when active or backup history was loaded; False when no valid
        history could be recovered.

      Raises
      ------
      EAccessViolation
        Raised when ATasks is nil.
      EOutOfMemory
        May propagate while reconstructing task objects.
    }
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
  RelocatedSBOM: string;
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
          if (Task.GeneratedSBOMPath <> '') and
            not FileExists(Task.GeneratedSBOMPath) then
          begin
            RelocatedSBOM := IncludeTrailingPathDelimiter(FDataDirectory) +
              'sboms' + DirectorySeparator + Task.ID + '.cdx.json';
            if FileExists(RelocatedSBOM) then
              Task.GeneratedSBOMPath := RelocatedSBOM;
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
