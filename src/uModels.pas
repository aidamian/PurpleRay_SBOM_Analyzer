(**
  PurpleRay SBOM Analyzer domain-model unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Defines scan settings, artifacts, components, task state, status conversions,
  cloning rules, and their persistent JSON representation.

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
unit uModels;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, fpjson;

type
  TTaskStatus = (tsPending, tsRunning, tsCompleted, tsCancelled, tsFailed);
  TArtifactStatus = (arsParsed, arsPartiallyParsed, arsUnsupported, arsFailed);

  TScanSettings = class
  public
    IncludeAbsolutePaths: Boolean;
    FollowSymbolicLinks: Boolean;
    AllowOutsideRoot: Boolean;
    CalculateSHA256: Boolean;
    IgnorePatterns: TStringList;
    {**
      Creates settings and installs the safe default ignore policy.

      Parameters
      ----------
      None

      Returns
      -------
      TScanSettings
        Newly initialized settings object.

      Raises
      ------
      EOutOfMemory
        Propagated if the ignore-pattern list cannot be allocated.
    }
    constructor Create;
    destructor Destroy; override;

    {**
      Restores all Boolean options and ignore patterns to product defaults.

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
    procedure ResetDefaults;

    {**
      Copies all scan options and ignore patterns from another instance.

      Parameters
      ----------
      ASource
        Settings to copy; nil leaves the receiver unchanged.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure Assign(ASource: TScanSettings);

    {**
      Creates an independent deep copy of these settings.

      Parameters
      ----------
      None

      Returns
      -------
      TScanSettings
        Newly allocated clone owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if the clone cannot be allocated.
    }
    function Clone: TScanSettings;

    {**
      Serializes scan options and ignore patterns.

      Parameters
      ----------
      None

      Returns
      -------
      TJSONObject
        Newly allocated JSON object owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if JSON nodes cannot be allocated.
    }
    function ToJSON: TJSONObject;

    {**
      Constructs settings from JSON while retaining defaults for absent fields.

      Parameters
      ----------
      AObject
        Source JSON object; nil produces default settings.

      Returns
      -------
      TScanSettings
        Newly allocated settings owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if the settings object cannot be allocated.
    }
    class function FromJSON(AObject: TJSONObject): TScanSettings; static;

    {**
      Formats all active settings into one readable summary line.

      Parameters
      ----------
      None

      Returns
      -------
      string
        Human-readable settings summary.

      Raises
      ------
      None
    }
    function AsSummary: string;
  end;

  TArtifact = class
  public
    RelativePath: string;
    AbsolutePath: string;
    ArtifactType: string;
    Ecosystem: string;
    Status: TArtifactStatus;
    ParserName: string;
    FileSize: Int64;
    SHA256: string;
    MessageText: string;
    ComponentCount: Integer;
    {**
      Creates an independent copy of this artifact record.

      Parameters
      ----------
      None

      Returns
      -------
      TArtifact
        Newly allocated clone owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if allocation fails.
    }
    function Clone: TArtifact;

    {**
      Serializes artifact evidence, optionally including its absolute path.

      Parameters
      ----------
      AIncludeAbsolutePath
        Controls whether local absolute-path data is persisted in this object.

      Returns
      -------
      TJSONObject
        Newly allocated JSON object owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if JSON allocation fails.
    }
    function ToJSON(AIncludeAbsolutePath: Boolean): TJSONObject;

    {**
      Constructs an artifact record from persisted JSON.

      Parameters
      ----------
      AObject
        Source JSON object.

      Returns
      -------
      TArtifact
        Newly allocated artifact owned by the caller.

      Raises
      ------
      EAccessViolation
        Raised when AObject is nil; callers must pass a valid object.
    }
    class function FromJSON(AObject: TJSONObject): TArtifact; static;
  end;

  TComponent = class
  public
    ComponentType: string;
    Name: string;
    Version: string;
    Ecosystem: string;
    PackageURL: string;
    SourceArtifact: string;
    SourceParser: string;
    DependencyScope: string;
    SHA256: string;
    EvidencePaths: TStringList;
    {**
      Creates a component with an owned, sorted evidence-path collection.

      Parameters
      ----------
      None

      Returns
      -------
      TComponent
        Newly initialized component.

      Raises
      ------
      EOutOfMemory
        Propagated if allocation fails.
    }
    constructor Create;
    destructor Destroy; override;

    {**
      Creates a deep copy including all evidence paths.

      Parameters
      ----------
      None

      Returns
      -------
      TComponent
        Newly allocated clone owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if allocation fails.
    }
    function Clone: TComponent;

    {**
      Serializes component identity, provenance, scope, and evidence paths.

      Parameters
      ----------
      None

      Returns
      -------
      TJSONObject
        Newly allocated JSON object owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if JSON allocation fails.
    }
    function ToJSON: TJSONObject;

    {**
      Constructs a component and its evidence collection from JSON.

      Parameters
      ----------
      AObject
        Source JSON object.

      Returns
      -------
      TComponent
        Newly allocated component owned by the caller.

      Raises
      ------
      EAccessViolation
        Raised when AObject is nil.
    }
    class function FromJSON(AObject: TJSONObject): TComponent; static;
  end;

  TScanTask = class
  public
    ID: string;
    CreatedUTC: string;
    StartedUTC: string;
    CompletedUTC: string;
    TargetDirectory: string;
    TargetRootName: string;
    Status: TTaskStatus;
    FilesInspected: Int64;
    BytesInspected: Int64;
    ArtifactsDetected: Int64;
    ArtifactsParsed: Int64;
    ArtifactsPartiallyParsed: Int64;
    UnsupportedArtifacts: Int64;
    FailedArtifacts: Int64;
    ComponentsIdentified: Int64;
    DurationMS: Int64;
    Warnings: TStringList;
    Errors: TStringList;
    InspectionTools: TStringList;
    Settings: TScanSettings;
    GeneratedSBOMPath: string;
    GeneratedSBOMSHA256: string;
    ScannerVersion: string;
    ScannerCommit: string;
    Artifacts: TObjectList;
    Components: TObjectList;
    {**
      Creates a pending scan task with a fresh UUID and owned child collections.

      Parameters
      ----------
      None

      Returns
      -------
      TScanTask
        Newly initialized task.

      Raises
      ------
      Exception
        Raised when a unique task identifier cannot be generated.
      EOutOfMemory
        Propagated when child collections cannot be allocated.
    }
    constructor Create;
    destructor Destroy; override;

    {**
      Deep-copies task state, settings, messages, artifacts, and components.

      Parameters
      ----------
      ASource
        Source task; nil leaves the receiver unchanged.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if a child clone cannot be allocated.
    }
    procedure Assign(ASource: TScanTask);

    {**
      Creates an independent deep copy of the complete task.

      Parameters
      ----------
      None

      Returns
      -------
      TScanTask
        Newly allocated clone owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if allocation fails.
    }
    function Clone: TScanTask;

    {**
      Serializes the complete persistent task-history representation.

      Parameters
      ----------
      None

      Returns
      -------
      TJSONObject
        Newly allocated JSON object owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if JSON or child-node allocation fails.
    }
    function ToJSON: TJSONObject;

    {**
      Reconstructs a task and all owned children from persisted JSON.

      Parameters
      ----------
      AObject
        Source task object.

      Returns
      -------
      TScanTask
        Newly allocated task owned by the caller.

      Raises
      ------
      EAccessViolation
        Raised when AObject is nil.
      EOutOfMemory
        Propagated if task or child allocation fails.
    }
    class function FromJSON(AObject: TJSONObject): TScanTask; static;
  end;

{**
  Converts a task-status enumeration to its stable persisted spelling.

  Parameters
  ----------
  AStatus
    Status value to convert.

  Returns
  -------
  string
    Lowercase persisted status name.

  Raises
  ------
  None
}
function TaskStatusToString(AStatus: TTaskStatus): string;

{**
  Parses a persisted task-status spelling, defaulting to pending.

  Parameters
  ----------
  AValue
    Status text.

  Returns
  -------
  TTaskStatus
    Matching status or tsPending for unknown input.

  Raises
  ------
  None
}
function StringToTaskStatus(const AValue: string): TTaskStatus;

{**
  Converts an artifact-status enumeration to its user-facing spelling.

  Parameters
  ----------
  AStatus
    Artifact status to convert.

  Returns
  -------
  string
    Stable human-readable status.

  Raises
  ------
  None
}
function ArtifactStatusToString(AStatus: TArtifactStatus): string;

{**
  Parses artifact-status text, defaulting to unsupported evidence.

  Parameters
  ----------
  AValue
    Status text.

  Returns
  -------
  TArtifactStatus
    Matching status or arsUnsupported for unknown input.

  Raises
  ------
  None
}
function StringToArtifactStatus(const AValue: string): TArtifactStatus;

{**
  Creates a lowercase UUID suitable for task identity and CycloneDX serials.

  Parameters
  ----------
  None

  Returns
  -------
  string
    UUID without surrounding braces.

  Raises
  ------
  Exception
    Raised when the operating system cannot create a GUID.
}
function NewTaskID: string;

implementation

uses
  uJSONUtils, uTimeUtils, uVersionInfo;

procedure StringsToJSON(AStrings: TStrings; AArray: TJSONArray);
var
  I: Integer;
begin
  for I := 0 to AStrings.Count - 1 do
    AArray.Add(AStrings[I]);
end;

procedure JSONToStrings(AArray: TJSONArray; AStrings: TStrings);
var
  I: Integer;
begin
  AStrings.Clear;
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    AStrings.Add(AArray.Strings[I]);
end;

function TaskStatusToString(AStatus: TTaskStatus): string;
begin
  Result := '';
  case AStatus of
    tsPending: Result := 'pending';
    tsRunning: Result := 'running';
    tsCompleted: Result := 'completed';
    tsCancelled: Result := 'cancelled';
    tsFailed: Result := 'failed';
  end;
end;

function StringToTaskStatus(const AValue: string): TTaskStatus;
begin
  case LowerCase(AValue) of
    'running': Result := tsRunning;
    'completed': Result := tsCompleted;
    'cancelled': Result := tsCancelled;
    'failed': Result := tsFailed;
  else
    Result := tsPending;
  end;
end;

function ArtifactStatusToString(AStatus: TArtifactStatus): string;
begin
  Result := '';
  case AStatus of
    arsParsed: Result := 'parsed';
    arsPartiallyParsed: Result := 'partially parsed';
    arsUnsupported: Result := 'detected but unsupported';
    arsFailed: Result := 'failed';
  end;
end;

function StringToArtifactStatus(const AValue: string): TArtifactStatus;
begin
  case LowerCase(AValue) of
    'parsed': Result := arsParsed;
    'partially parsed': Result := arsPartiallyParsed;
    'failed': Result := arsFailed;
  else
    Result := arsUnsupported;
  end;
end;

function NewTaskID: string;
var
  Value: TGuid;
begin
  if CreateGUID(Value) <> 0 then
    raise Exception.Create('Unable to create a task identifier');
  Result := LowerCase(GUIDToString(Value));
  if (Length(Result) >= 2) and (Result[1] = '{') then
    Result := Copy(Result, 2, Length(Result) - 2);
end;

constructor TScanSettings.Create;
begin
  inherited Create;
  IgnorePatterns := TStringList.Create;
  ResetDefaults;
end;

destructor TScanSettings.Destroy;
begin
  IgnorePatterns.Free;
  inherited Destroy;
end;

procedure TScanSettings.ResetDefaults;
const
  Defaults: array[0..9] of string = (
    '.git', '.svn', '.hg', '.idea', '.vscode', '.cache', '__pycache__',
    'node_modules', '.venv', 'venv');
var
  I: Integer;
begin
  IncludeAbsolutePaths := False;
  FollowSymbolicLinks := False;
  AllowOutsideRoot := False;
  CalculateSHA256 := True;
  IgnorePatterns.Clear;
  for I := Low(Defaults) to High(Defaults) do
    IgnorePatterns.Add(Defaults[I]);
end;

procedure TScanSettings.Assign(ASource: TScanSettings);
begin
  if ASource = nil then
    Exit;
  IncludeAbsolutePaths := ASource.IncludeAbsolutePaths;
  FollowSymbolicLinks := ASource.FollowSymbolicLinks;
  AllowOutsideRoot := ASource.AllowOutsideRoot;
  CalculateSHA256 := ASource.CalculateSHA256;
  IgnorePatterns.Assign(ASource.IgnorePatterns);
end;

function TScanSettings.Clone: TScanSettings;
begin
  Result := TScanSettings.Create;
  Result.Assign(Self);
end;

function TScanSettings.ToJSON: TJSONObject;
var
  Patterns: TJSONArray;
begin
  Result := TJSONObject.Create;
  Result.Add('include_absolute_paths', IncludeAbsolutePaths);
  Result.Add('follow_symbolic_links', FollowSymbolicLinks);
  Result.Add('allow_outside_root', AllowOutsideRoot);
  Result.Add('calculate_sha256', CalculateSHA256);
  Patterns := TJSONArray.Create;
  StringsToJSON(IgnorePatterns, Patterns);
  Result.Add('ignore_patterns', Patterns);
end;

class function TScanSettings.FromJSON(AObject: TJSONObject): TScanSettings;
begin
  Result := TScanSettings.Create;
  if AObject = nil then
    Exit;
  Result.IncludeAbsolutePaths := JSONBoolean(AObject, 'include_absolute_paths', False);
  Result.FollowSymbolicLinks := JSONBoolean(AObject, 'follow_symbolic_links', False);
  Result.AllowOutsideRoot := JSONBoolean(AObject, 'allow_outside_root', False);
  Result.CalculateSHA256 := JSONBoolean(AObject, 'calculate_sha256', True);
  if JSONArray(AObject, 'ignore_patterns') <> nil then
    JSONToStrings(JSONArray(AObject, 'ignore_patterns'), Result.IgnorePatterns);
end;

function TScanSettings.AsSummary: string;
begin
  Result := Format('absolute paths: %s; follow symlinks: %s; leave root: %s; '+
    'SHA-256: %s; ignore patterns: %d', [BoolToStr(IncludeAbsolutePaths, True),
    BoolToStr(FollowSymbolicLinks, True), BoolToStr(AllowOutsideRoot, True),
    BoolToStr(CalculateSHA256, True), IgnorePatterns.Count]);
end;

function TArtifact.Clone: TArtifact;
begin
  Result := TArtifact.Create;
  Result.RelativePath := RelativePath;
  Result.AbsolutePath := AbsolutePath;
  Result.ArtifactType := ArtifactType;
  Result.Ecosystem := Ecosystem;
  Result.Status := Status;
  Result.ParserName := ParserName;
  Result.FileSize := FileSize;
  Result.SHA256 := SHA256;
  Result.MessageText := MessageText;
  Result.ComponentCount := ComponentCount;
end;

function TArtifact.ToJSON(AIncludeAbsolutePath: Boolean): TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.Add('relative_path', RelativePath);
  if AIncludeAbsolutePath and (AbsolutePath <> '') then
    Result.Add('absolute_path', AbsolutePath);
  Result.Add('artifact_type', ArtifactType);
  Result.Add('ecosystem', Ecosystem);
  Result.Add('status', ArtifactStatusToString(Status));
  Result.Add('parser', ParserName);
  Result.Add('file_size', FileSize);
  if SHA256 <> '' then
    Result.Add('sha256', SHA256);
  if MessageText <> '' then
    Result.Add('message', MessageText);
  Result.Add('component_count', ComponentCount);
end;

class function TArtifact.FromJSON(AObject: TJSONObject): TArtifact;
begin
  Result := TArtifact.Create;
  Result.RelativePath := JSONString(AObject, 'relative_path');
  Result.AbsolutePath := JSONString(AObject, 'absolute_path');
  Result.ArtifactType := JSONString(AObject, 'artifact_type');
  Result.Ecosystem := JSONString(AObject, 'ecosystem');
  Result.Status := StringToArtifactStatus(JSONString(AObject, 'status'));
  Result.ParserName := JSONString(AObject, 'parser');
  Result.FileSize := JSONInt64(AObject, 'file_size');
  Result.SHA256 := JSONString(AObject, 'sha256');
  Result.MessageText := JSONString(AObject, 'message');
  Result.ComponentCount := JSONInt64(AObject, 'component_count');
end;

constructor TComponent.Create;
begin
  inherited Create;
  ComponentType := 'library';
  EvidencePaths := TStringList.Create;
  EvidencePaths.Sorted := True;
  EvidencePaths.Duplicates := dupIgnore;
end;

destructor TComponent.Destroy;
begin
  EvidencePaths.Free;
  inherited Destroy;
end;

function TComponent.Clone: TComponent;
begin
  Result := TComponent.Create;
  Result.ComponentType := ComponentType;
  Result.Name := Name;
  Result.Version := Version;
  Result.Ecosystem := Ecosystem;
  Result.PackageURL := PackageURL;
  Result.SourceArtifact := SourceArtifact;
  Result.SourceParser := SourceParser;
  Result.DependencyScope := DependencyScope;
  Result.SHA256 := SHA256;
  Result.EvidencePaths.Assign(EvidencePaths);
end;

function TComponent.ToJSON: TJSONObject;
var
  Evidence: TJSONArray;
begin
  Result := TJSONObject.Create;
  Result.Add('component_type', ComponentType);
  Result.Add('name', Name);
  if Version <> '' then
    Result.Add('version', Version);
  Result.Add('ecosystem', Ecosystem);
  if PackageURL <> '' then
    Result.Add('package_url', PackageURL);
  Result.Add('source_artifact', SourceArtifact);
  Result.Add('source_parser', SourceParser);
  if DependencyScope <> '' then
    Result.Add('dependency_scope', DependencyScope);
  if SHA256 <> '' then
    Result.Add('sha256', SHA256);
  Evidence := TJSONArray.Create;
  StringsToJSON(EvidencePaths, Evidence);
  Result.Add('evidence_paths', Evidence);
end;

class function TComponent.FromJSON(AObject: TJSONObject): TComponent;
begin
  Result := TComponent.Create;
  Result.ComponentType := JSONString(AObject, 'component_type', 'library');
  Result.Name := JSONString(AObject, 'name');
  Result.Version := JSONString(AObject, 'version');
  Result.Ecosystem := JSONString(AObject, 'ecosystem');
  Result.PackageURL := JSONString(AObject, 'package_url');
  Result.SourceArtifact := JSONString(AObject, 'source_artifact');
  Result.SourceParser := JSONString(AObject, 'source_parser');
  Result.DependencyScope := JSONString(AObject, 'dependency_scope');
  Result.SHA256 := JSONString(AObject, 'sha256');
  JSONToStrings(JSONArray(AObject, 'evidence_paths'), Result.EvidencePaths);
end;

constructor TScanTask.Create;
begin
  inherited Create;
  ID := NewTaskID;
  CreatedUTC := UTCNowISO8601;
  Status := tsPending;
  Warnings := TStringList.Create;
  Errors := TStringList.Create;
  InspectionTools := TStringList.Create;
  InspectionTools.Sorted := True;
  InspectionTools.Duplicates := dupIgnore;
  Settings := TScanSettings.Create;
  Artifacts := TObjectList.Create(True);
  Components := TObjectList.Create(True);
  ScannerVersion := AppVersion;
  ScannerCommit := AppCommit;
end;

destructor TScanTask.Destroy;
begin
  InspectionTools.Free;
  Components.Free;
  Artifacts.Free;
  Settings.Free;
  Errors.Free;
  Warnings.Free;
  inherited Destroy;
end;

procedure TScanTask.Assign(ASource: TScanTask);
var
  I: Integer;
begin
  if ASource = nil then
    Exit;
  ID := ASource.ID;
  CreatedUTC := ASource.CreatedUTC;
  StartedUTC := ASource.StartedUTC;
  CompletedUTC := ASource.CompletedUTC;
  TargetDirectory := ASource.TargetDirectory;
  TargetRootName := ASource.TargetRootName;
  Status := ASource.Status;
  FilesInspected := ASource.FilesInspected;
  BytesInspected := ASource.BytesInspected;
  ArtifactsDetected := ASource.ArtifactsDetected;
  ArtifactsParsed := ASource.ArtifactsParsed;
  ArtifactsPartiallyParsed := ASource.ArtifactsPartiallyParsed;
  UnsupportedArtifacts := ASource.UnsupportedArtifacts;
  FailedArtifacts := ASource.FailedArtifacts;
  ComponentsIdentified := ASource.ComponentsIdentified;
  DurationMS := ASource.DurationMS;
  Warnings.Assign(ASource.Warnings);
  Errors.Assign(ASource.Errors);
  InspectionTools.Assign(ASource.InspectionTools);
  Settings.Assign(ASource.Settings);
  GeneratedSBOMPath := ASource.GeneratedSBOMPath;
  GeneratedSBOMSHA256 := ASource.GeneratedSBOMSHA256;
  ScannerVersion := ASource.ScannerVersion;
  ScannerCommit := ASource.ScannerCommit;
  Artifacts.Clear;
  for I := 0 to ASource.Artifacts.Count - 1 do
    Artifacts.Add(TArtifact(ASource.Artifacts[I]).Clone);
  Components.Clear;
  for I := 0 to ASource.Components.Count - 1 do
    Components.Add(TComponent(ASource.Components[I]).Clone);
end;

function TScanTask.Clone: TScanTask;
begin
  Result := TScanTask.Create;
  Result.Assign(Self);
end;

function TScanTask.ToJSON: TJSONObject;
var
  ArrayValue: TJSONArray;
  I: Integer;
begin
  Result := TJSONObject.Create;
  Result.Add('id', ID);
  Result.Add('created_utc', CreatedUTC);
  Result.Add('started_utc', StartedUTC);
  Result.Add('completed_utc', CompletedUTC);
  Result.Add('target_directory', TargetDirectory);
  Result.Add('target_root_name', TargetRootName);
  Result.Add('status', TaskStatusToString(Status));
  Result.Add('files_inspected', FilesInspected);
  Result.Add('bytes_inspected', BytesInspected);
  Result.Add('artifacts_detected', ArtifactsDetected);
  Result.Add('artifacts_parsed', ArtifactsParsed);
  Result.Add('artifacts_partially_parsed', ArtifactsPartiallyParsed);
  Result.Add('unsupported_artifacts', UnsupportedArtifacts);
  Result.Add('failed_artifacts', FailedArtifacts);
  Result.Add('components_identified', ComponentsIdentified);
  Result.Add('duration_ms', DurationMS);
  ArrayValue := TJSONArray.Create;
  StringsToJSON(Warnings, ArrayValue);
  Result.Add('warnings', ArrayValue);
  ArrayValue := TJSONArray.Create;
  StringsToJSON(Errors, ArrayValue);
  Result.Add('errors', ArrayValue);
  ArrayValue := TJSONArray.Create;
  StringsToJSON(InspectionTools, ArrayValue);
  Result.Add('inspection_tools', ArrayValue);
  Result.Add('scan_settings', Settings.ToJSON);
  Result.Add('generated_sbom_path', GeneratedSBOMPath);
  Result.Add('generated_sbom_sha256', GeneratedSBOMSHA256);
  Result.Add('scanner_version', ScannerVersion);
  Result.Add('scanner_commit', ScannerCommit);
  ArrayValue := TJSONArray.Create;
  for I := 0 to Artifacts.Count - 1 do
    ArrayValue.Add(TArtifact(Artifacts[I]).ToJSON(True));
  Result.Add('artifacts', ArrayValue);
  ArrayValue := TJSONArray.Create;
  for I := 0 to Components.Count - 1 do
    ArrayValue.Add(TComponent(Components[I]).ToJSON);
  Result.Add('components', ArrayValue);
end;

class function TScanTask.FromJSON(AObject: TJSONObject): TScanTask;
var
  ArrayValue: TJSONArray;
  I: Integer;
begin
  Result := TScanTask.Create;
  Result.ID := JSONString(AObject, 'id', Result.ID);
  Result.CreatedUTC := JSONString(AObject, 'created_utc', Result.CreatedUTC);
  Result.StartedUTC := JSONString(AObject, 'started_utc');
  Result.CompletedUTC := JSONString(AObject, 'completed_utc');
  Result.TargetDirectory := JSONString(AObject, 'target_directory');
  Result.TargetRootName := JSONString(AObject, 'target_root_name');
  Result.Status := StringToTaskStatus(JSONString(AObject, 'status'));
  Result.FilesInspected := JSONInt64(AObject, 'files_inspected');
  Result.BytesInspected := JSONInt64(AObject, 'bytes_inspected');
  Result.ArtifactsDetected := JSONInt64(AObject, 'artifacts_detected');
  Result.ArtifactsParsed := JSONInt64(AObject, 'artifacts_parsed');
  Result.ArtifactsPartiallyParsed := JSONInt64(AObject, 'artifacts_partially_parsed');
  Result.UnsupportedArtifacts := JSONInt64(AObject, 'unsupported_artifacts');
  Result.FailedArtifacts := JSONInt64(AObject, 'failed_artifacts');
  Result.ComponentsIdentified := JSONInt64(AObject, 'components_identified');
  Result.DurationMS := JSONInt64(AObject, 'duration_ms');
  JSONToStrings(JSONArray(AObject, 'warnings'), Result.Warnings);
  JSONToStrings(JSONArray(AObject, 'errors'), Result.Errors);
  JSONToStrings(JSONArray(AObject, 'inspection_tools'), Result.InspectionTools);
  if JSONObject(AObject, 'scan_settings') <> nil then
  begin
    Result.Settings.Free;
    Result.Settings := TScanSettings.FromJSON(JSONObject(AObject, 'scan_settings'));
  end;
  Result.GeneratedSBOMPath := JSONString(AObject, 'generated_sbom_path');
  Result.GeneratedSBOMSHA256 := JSONString(AObject, 'generated_sbom_sha256');
  Result.ScannerVersion := JSONString(AObject, 'scanner_version', AppVersion);
  Result.ScannerCommit := JSONString(AObject, 'scanner_commit', AppCommit);
  ArrayValue := JSONArray(AObject, 'artifacts');
  if ArrayValue <> nil then
    for I := 0 to ArrayValue.Count - 1 do
      if ArrayValue.Items[I].JSONType = jtObject then
        Result.Artifacts.Add(TArtifact.FromJSON(TJSONObject(ArrayValue.Items[I])));
  ArrayValue := JSONArray(AObject, 'components');
  if ArrayValue <> nil then
    for I := 0 to ArrayValue.Count - 1 do
      if ArrayValue.Items[I].JSONType = jtObject then
        Result.Components.Add(TComponent.FromJSON(TJSONObject(ArrayValue.Items[I])));
end;

end.
