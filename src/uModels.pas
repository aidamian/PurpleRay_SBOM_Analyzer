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
  Classes, SysUtils, Contnrs, fpjson, uKnownIssues;

const
  { Lock files may contain many archive alternatives. Keep the model bounded
    independently of the surrounding history/cache document limits. }
  MaximumDeclaredHashesPerComponent = 256;
  MaximumDeclaredHashSubjectLength = 4096;
  MaximumDeclaredHashSourceLength = 4096;

type
  TTaskStatus = (tsPending, tsRunning, tsCompleted, tsCancelled, tsFailed);
  TArtifactStatus = (arsParsed, arsPartiallyParsed, arsUnsupported, arsFailed);

  TScanSettings = class
  public
    IncludeAbsolutePaths: Boolean;
    FollowSymbolicLinks: Boolean;
    AllowOutsideRoot: Boolean;
    CalculateSHA256: Boolean;
    { Reuse remains opt-in. RefreshRescanCache bypasses reads for one scan
      while rebuilding the last-successful profile-local snapshot. }
    UseRescanCache: Boolean;
    RefreshRescanCache: Boolean;
    SBOMAuthorOrganization: string;
    SBOMAuthorEmail: string;
    RememberPrivacyChoices: Boolean;
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
      Restores author identity, Boolean options, and ignore patterns to product
      defaults.

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
      EJSON
        Raised when a present settings member has an incompatible JSON type.
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

  {** One package/archive digest declared by a manifest or lock file. *}
  TDeclaredHash = class
  public
    Algorithm: string;
    Digest: string;
    Subject: string;
    SourceArtifact: string;
    SourceParser: string;
    function Clone: TDeclaredHash;
    function ToJSON: TJSONObject;
    class function FromJSON(AObject: TJSONObject): TDeclaredHash; static;
  end;

  {** Owned, capped, exact-deduplicated declared-hash collection. *}
  TDeclaredHashList = class(TObjectList)
  private
    function GetHash(AIndex: Integer): TDeclaredHash;
  public
    constructor Create;
    function Add(AHash: TDeclaredHash): Integer; reintroduce;
    procedure AddClones(AHashes: TDeclaredHashList);
    function Clone: TDeclaredHashList;
    procedure SortDeterministic;
    property Hashes[AIndex: Integer]: TDeclaredHash read GetHash; default;
  end;

  TComponent = class
  public
    ComponentType: string;
    Name: string;
    Version: string;
    Ecosystem: string;
    PackageURL: string;
    CPE: string;
    CPEEvidence: string;
    CompanyName: string;
    ProductName: string;
    NativeSONAME: string;
    NativeBuildID: string;
    SourceArtifact: string;
    SourceParser: string;
    DependencyScope: string;
    SHA256: string;
    EvidencePaths: TStringList;
    DeclaredLicenses: TStringList;
    DeclaredPublishers: TStringList;
    DeclaredHashes: TDeclaredHashList;
    {**
      Creates a component with owned, sorted evidence and declaration lists.

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
      Creates a deep copy including evidence, licenses, and publishers.

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
      Serializes component identity, provenance, scope, evidence, and explicit
      manifest declarations.

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
      Constructs a component, its evidence collection, and its declared
      license and publisher collections from JSON.

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
    KnownIssueCheck: TKnownIssueCheck;
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

{** Validates canonical declared-hash fields and their explicit size caps. *}
function IsValidDeclaredHash(AHash: TDeclaredHash): Boolean;

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
  UseRescanCache := False;
  RefreshRescanCache := False;
  SBOMAuthorOrganization := '';
  SBOMAuthorEmail := '';
  RememberPrivacyChoices := False;
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
  UseRescanCache := ASource.UseRescanCache;
  RefreshRescanCache := ASource.RefreshRescanCache;
  SBOMAuthorOrganization := ASource.SBOMAuthorOrganization;
  SBOMAuthorEmail := ASource.SBOMAuthorEmail;
  RememberPrivacyChoices := ASource.RememberPrivacyChoices;
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
  Result.Add('use_rescan_cache', UseRescanCache);
  Result.Add('refresh_rescan_cache', RefreshRescanCache);
  if SBOMAuthorOrganization <> '' then
    Result.Add('sbom_author_organization', SBOMAuthorOrganization);
  if SBOMAuthorEmail <> '' then
    Result.Add('sbom_author_email', SBOMAuthorEmail);
  Result.Add('remember_privacy_choices', RememberPrivacyChoices);
  Patterns := TJSONArray.Create;
  StringsToJSON(IgnorePatterns, Patterns);
  Result.Add('ignore_patterns', Patterns);
end;

class function TScanSettings.FromJSON(AObject: TJSONObject): TScanSettings;
const
  BooleanNames: array[0..6] of string = (
    'include_absolute_paths', 'follow_symbolic_links', 'allow_outside_root',
    'calculate_sha256', 'use_rescan_cache', 'refresh_rescan_cache',
    'remember_privacy_choices');
  StringNames: array[0..1] of string = (
    'sbom_author_organization', 'sbom_author_email');
var
  Data: TJSONData;
  I, J: Integer;
begin
  Result := TScanSettings.Create;
  try
    if AObject = nil then
      Exit;
    for I := Low(BooleanNames) to High(BooleanNames) do
    begin
      Data := AObject.Find(BooleanNames[I]);
      if (Data <> nil) and (Data.JSONType <> jtBoolean) then
        raise EJSON.CreateFmt('scan setting "%s" must be a Boolean',
          [BooleanNames[I]]);
    end;
    for I := Low(StringNames) to High(StringNames) do
    begin
      Data := AObject.Find(StringNames[I]);
      if (Data <> nil) and (Data.JSONType <> jtString) then
        raise EJSON.CreateFmt('scan setting "%s" must be a string',
          [StringNames[I]]);
    end;
    Data := AObject.Find('ignore_patterns');
    if (Data <> nil) and (Data.JSONType <> jtArray) then
      raise EJSON.Create('scan setting "ignore_patterns" must be an array');
    if Data <> nil then
      for J := 0 to TJSONArray(Data).Count - 1 do
        if TJSONArray(Data).Items[J].JSONType <> jtString then
          raise EJSON.Create(
            'scan setting "ignore_patterns" entries must be strings');

    Result.IncludeAbsolutePaths := JSONBoolean(AObject,
      'include_absolute_paths', False);
    Result.FollowSymbolicLinks := JSONBoolean(AObject,
      'follow_symbolic_links', False);
    Result.AllowOutsideRoot := JSONBoolean(AObject,
      'allow_outside_root', False);
    Result.CalculateSHA256 := JSONBoolean(AObject, 'calculate_sha256', True);
    Result.UseRescanCache := JSONBoolean(AObject, 'use_rescan_cache', False);
    Result.RefreshRescanCache := JSONBoolean(AObject,
      'refresh_rescan_cache', False);
    Result.SBOMAuthorOrganization := JSONString(AObject,
      'sbom_author_organization');
    Result.SBOMAuthorEmail := JSONString(AObject, 'sbom_author_email');
    Result.RememberPrivacyChoices := JSONBoolean(AObject,
      'remember_privacy_choices', False);
    if Data <> nil then
      JSONToStrings(TJSONArray(Data), Result.IgnorePatterns);
  except
    FreeAndNil(Result);
    raise;
  end;
end;

function TScanSettings.AsSummary: string;
begin
  Result := Format('absolute paths: %s; follow symlinks: %s; leave root: %s; '+
    'SHA-256: %s; rescan cache: %s; full cache refresh: %s; ' +
    'ignore patterns: %d; SBOM author configured: %s; ' +
    'remember privacy choices: %s', [BoolToStr(IncludeAbsolutePaths, True),
    BoolToStr(FollowSymbolicLinks, True), BoolToStr(AllowOutsideRoot, True),
    BoolToStr(CalculateSHA256, True), BoolToStr(UseRescanCache, True),
    BoolToStr(RefreshRescanCache, True), IgnorePatterns.Count,
    BoolToStr((Trim(SBOMAuthorOrganization) <> '') or
      (Trim(SBOMAuthorEmail) <> ''), True),
    BoolToStr(RememberPrivacyChoices, True)]);
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

function DeclaredHashFieldIsBounded(const AValue: string;
  AMaximumLength: Integer): Boolean;
var
  I: Integer;
begin
  Result := (AValue <> '') and (Length(AValue) <= AMaximumLength);
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(False);
end;

function IsValidDeclaredHash(AHash: TDeclaredHash): Boolean;
var
  ExpectedLength, I: Integer;
begin
  Result := False;
  if AHash = nil then
    Exit;
  case AHash.Algorithm of
    'SHA-1': ExpectedLength := 40;
    'SHA-256': ExpectedLength := 64;
    'SHA-384': ExpectedLength := 96;
    'SHA-512': ExpectedLength := 128;
  else
    Exit;
  end;
  if Length(AHash.Digest) <> ExpectedLength then
    Exit;
  for I := 1 to Length(AHash.Digest) do
    if not (AHash.Digest[I] in ['0'..'9', 'a'..'f']) then
      Exit;
  Result := DeclaredHashFieldIsBounded(AHash.Subject,
      MaximumDeclaredHashSubjectLength) and
    DeclaredHashFieldIsBounded(AHash.SourceArtifact,
      MaximumDeclaredHashSourceLength) and
    DeclaredHashFieldIsBounded(AHash.SourceParser,
      MaximumDeclaredHashSourceLength);
end;

function CompareDeclaredHashes(ALeft, ARight: TDeclaredHash): Integer;
begin
  Result := CompareStr(ALeft.Algorithm, ARight.Algorithm);
  if Result = 0 then
    Result := CompareStr(ALeft.Digest, ARight.Digest);
  if Result = 0 then
    Result := CompareStr(ALeft.Subject, ARight.Subject);
  if Result = 0 then
    Result := CompareStr(ALeft.SourceArtifact, ARight.SourceArtifact);
  if Result = 0 then
    Result := CompareStr(ALeft.SourceParser, ARight.SourceParser);
end;

function CompareDeclaredHashItems(AItem1, AItem2: Pointer): Integer;
begin
  Result := CompareDeclaredHashes(TDeclaredHash(AItem1),
    TDeclaredHash(AItem2));
end;

function TDeclaredHash.Clone: TDeclaredHash;
begin
  Result := TDeclaredHash.Create;
  try
    Result.Algorithm := Algorithm;
    Result.Digest := Digest;
    Result.Subject := Subject;
    Result.SourceArtifact := SourceArtifact;
    Result.SourceParser := SourceParser;
  except
    Result.Free;
    raise;
  end;
end;

function TDeclaredHash.ToJSON: TJSONObject;
begin
  if not IsValidDeclaredHash(Self) then
    raise EArgumentException.Create('Invalid declared-hash model');
  Result := TJSONObject.Create;
  try
    Result.Add('algorithm', Algorithm);
    Result.Add('digest', Digest);
    Result.Add('subject', Subject);
    Result.Add('source_artifact', SourceArtifact);
    Result.Add('source_parser', SourceParser);
  except
    Result.Free;
    raise;
  end;
end;

class function TDeclaredHash.FromJSON(AObject: TJSONObject): TDeclaredHash;
const
  RequiredFields: array[0..4] of string = (
    'algorithm', 'digest', 'subject', 'source_artifact', 'source_parser');
var
  I: Integer;
  Data: TJSONData;
begin
  if AObject = nil then
    raise EArgumentNilException.Create('Declared-hash JSON object is nil');
  for I := Low(RequiredFields) to High(RequiredFields) do
  begin
    Data := AObject.Find(RequiredFields[I]);
    if (Data = nil) or (Data.JSONType <> jtString) then
      raise EJSON.CreateFmt('declared hash "%s" must be a string',
        [RequiredFields[I]]);
  end;
  Result := TDeclaredHash.Create;
  try
    Result.Algorithm := JSONString(AObject, 'algorithm');
    Result.Digest := JSONString(AObject, 'digest');
    Result.Subject := JSONString(AObject, 'subject');
    Result.SourceArtifact := JSONString(AObject, 'source_artifact');
    Result.SourceParser := JSONString(AObject, 'source_parser');
    if not IsValidDeclaredHash(Result) then
      raise EJSON.Create('declared hash fields are invalid or exceed limits');
  except
    Result.Free;
    raise;
  end;
end;

constructor TDeclaredHashList.Create;
begin
  inherited Create(True);
end;

function TDeclaredHashList.GetHash(AIndex: Integer): TDeclaredHash;
begin
  Result := TDeclaredHash(inherited Items[AIndex]);
end;

function TDeclaredHashList.Add(AHash: TDeclaredHash): Integer;
var
  I: Integer;
begin
  Result := -1;
  if AHash = nil then
    Exit;
  if not IsValidDeclaredHash(AHash) or
    (Count >= MaximumDeclaredHashesPerComponent) then
  begin
    AHash.Free;
    Exit;
  end;
  for I := 0 to Count - 1 do
    if CompareDeclaredHashes(Hashes[I], AHash) = 0 then
    begin
      AHash.Free;
      Exit(I);
    end;
  try
    Result := inherited Add(AHash);
  except
    { Preserve the public ownership contract even when the backing list cannot
      grow. Once inherited Add succeeds, the owned list releases the value. }
    AHash.Free;
    raise;
  end;
  SortDeterministic;
  Result := IndexOf(AHash);
end;

procedure TDeclaredHashList.AddClones(AHashes: TDeclaredHashList);
var
  I: Integer;
begin
  if AHashes = nil then
    Exit;
  for I := 0 to AHashes.Count - 1 do
    Add(AHashes[I].Clone);
end;

function TDeclaredHashList.Clone: TDeclaredHashList;
begin
  Result := TDeclaredHashList.Create;
  try
    Result.AddClones(Self);
  except
    Result.Free;
    raise;
  end;
end;

procedure TDeclaredHashList.SortDeterministic;
begin
  Sort(@CompareDeclaredHashItems);
end;

constructor TComponent.Create;
begin
  inherited Create;
  ComponentType := 'library';
  DeclaredHashes := TDeclaredHashList.Create;
  EvidencePaths := TStringList.Create;
  EvidencePaths.Sorted := True;
  EvidencePaths.CaseSensitive := True;
  EvidencePaths.UseLocale := False;
  EvidencePaths.Duplicates := dupIgnore;
  DeclaredLicenses := TStringList.Create;
  DeclaredLicenses.Sorted := True;
  DeclaredLicenses.Duplicates := dupIgnore;
  DeclaredPublishers := TStringList.Create;
  DeclaredPublishers.Sorted := True;
  DeclaredPublishers.Duplicates := dupIgnore;
end;

destructor TComponent.Destroy;
begin
  DeclaredHashes.Free;
  DeclaredPublishers.Free;
  DeclaredLicenses.Free;
  EvidencePaths.Free;
  inherited Destroy;
end;

function TComponent.Clone: TComponent;
begin
  Result := TComponent.Create;
  try
    Result.ComponentType := ComponentType;
    Result.Name := Name;
    Result.Version := Version;
    Result.Ecosystem := Ecosystem;
    Result.PackageURL := PackageURL;
    Result.CPE := CPE;
    Result.CPEEvidence := CPEEvidence;
    Result.CompanyName := CompanyName;
    Result.ProductName := ProductName;
    Result.NativeSONAME := NativeSONAME;
    Result.NativeBuildID := NativeBuildID;
    Result.SourceArtifact := SourceArtifact;
    Result.SourceParser := SourceParser;
    Result.DependencyScope := DependencyScope;
    Result.SHA256 := SHA256;
    Result.EvidencePaths.Assign(EvidencePaths);
    Result.DeclaredLicenses.Assign(DeclaredLicenses);
    Result.DeclaredPublishers.Assign(DeclaredPublishers);
    Result.DeclaredHashes.AddClones(DeclaredHashes);
  except
    Result.Free;
    raise;
  end;
end;

function TComponent.ToJSON: TJSONObject;
var
  Evidence, Values, HashValues: TJSONArray;
  HashObject: TJSONObject;
  I: Integer;
begin
  Result := TJSONObject.Create;
  try
    Result.Add('component_type', ComponentType);
    Result.Add('name', Name);
    if Version <> '' then
      Result.Add('version', Version);
    Result.Add('ecosystem', Ecosystem);
    if PackageURL <> '' then
      Result.Add('package_url', PackageURL);
    if CPE <> '' then
      Result.Add('cpe', CPE);
    if CPEEvidence <> '' then
      Result.Add('cpe_evidence', CPEEvidence);
    if CompanyName <> '' then
      Result.Add('company_name', CompanyName);
    if ProductName <> '' then
      Result.Add('product_name', ProductName);
    if NativeSONAME <> '' then
      Result.Add('native_soname', NativeSONAME);
    if NativeBuildID <> '' then
      Result.Add('native_build_id', NativeBuildID);
    Result.Add('source_artifact', SourceArtifact);
    Result.Add('source_parser', SourceParser);
    if DependencyScope <> '' then
      Result.Add('dependency_scope', DependencyScope);
    if SHA256 <> '' then
      Result.Add('sha256', SHA256);
    Evidence := TJSONArray.Create;
    Result.Add('evidence_paths', Evidence);
    StringsToJSON(EvidencePaths, Evidence);
    if DeclaredLicenses.Count > 0 then
    begin
      Values := TJSONArray.Create;
      Result.Add('declared_licenses', Values);
      StringsToJSON(DeclaredLicenses, Values);
    end;
    if DeclaredPublishers.Count > 0 then
    begin
      Values := TJSONArray.Create;
      Result.Add('declared_publishers', Values);
      StringsToJSON(DeclaredPublishers, Values);
    end;
    if DeclaredHashes.Count > 0 then
    begin
      HashValues := TJSONArray.Create;
      Result.Add('declared_hashes', HashValues);
      for I := 0 to DeclaredHashes.Count - 1 do
      begin
        HashObject := DeclaredHashes[I].ToJSON;
        try
          HashValues.Add(HashObject);
          HashObject := nil;
        finally
          HashObject.Free;
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TComponent.FromJSON(AObject: TJSONObject): TComponent;
var
  HashValues: TJSONArray;
  HashValue: TDeclaredHash;
  Data: TJSONData;
  I: Integer;
begin
  if AObject = nil then
    raise EArgumentNilException.Create('Component JSON object is nil');
  Result := TComponent.Create;
  try
    Result.ComponentType := JSONString(AObject, 'component_type', 'library');
    Result.Name := JSONString(AObject, 'name');
    Result.Version := JSONString(AObject, 'version');
    Result.Ecosystem := JSONString(AObject, 'ecosystem');
    Result.PackageURL := JSONString(AObject, 'package_url');
    Result.CPE := JSONString(AObject, 'cpe');
    Result.CPEEvidence := JSONString(AObject, 'cpe_evidence');
    Result.CompanyName := JSONString(AObject, 'company_name');
    Result.ProductName := JSONString(AObject, 'product_name');
    Result.NativeSONAME := JSONString(AObject, 'native_soname');
    Result.NativeBuildID := JSONString(AObject, 'native_build_id');
    Result.SourceArtifact := JSONString(AObject, 'source_artifact');
    Result.SourceParser := JSONString(AObject, 'source_parser');
    Result.DependencyScope := JSONString(AObject, 'dependency_scope');
    Result.SHA256 := JSONString(AObject, 'sha256');
    JSONToStrings(JSONArray(AObject, 'evidence_paths'), Result.EvidencePaths);
    JSONToStrings(JSONArray(AObject, 'declared_licenses'),
      Result.DeclaredLicenses);
    JSONToStrings(JSONArray(AObject, 'declared_publishers'),
      Result.DeclaredPublishers);
    Data := AObject.Find('declared_hashes');
    if (Data <> nil) and (Data.JSONType <> jtArray) then
      raise EJSON.Create('component "declared_hashes" must be an array');
    HashValues := JSONArray(AObject, 'declared_hashes');
    if (HashValues <> nil) and
      (HashValues.Count > MaximumDeclaredHashesPerComponent) then
      raise EJSON.Create('component declared-hash limit exceeded');
    if HashValues <> nil then
      for I := 0 to HashValues.Count - 1 do
      begin
        if HashValues.Items[I].JSONType <> jtObject then
          raise EJSON.Create('component declared hash must be an object');
        HashValue := TDeclaredHash.FromJSON(
          TJSONObject(HashValues.Items[I]));
        Result.DeclaredHashes.Add(HashValue);
      end;
  except
    Result.Free;
    raise;
  end;
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
  KnownIssueCheck := TKnownIssueCheck.Create;
  ScannerVersion := AppVersion;
  ScannerCommit := AppCommit;
end;

destructor TScanTask.Destroy;
begin
  KnownIssueCheck.Free;
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
  KnownIssueCheck.Assign(ASource.KnownIssueCheck);
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
  try
    Result.Assign(Self);
  except
    Result.Free;
    raise;
  end;
end;

function TScanTask.ToJSON: TJSONObject;
var
  ArrayValue: TJSONArray;
  I: Integer;
begin
  Result := TJSONObject.Create;
  try
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
    if KnownIssueCheck.Requested then
      Result.Add('known_issue_check', KnownIssueCheck.ToJSON);
    ArrayValue := TJSONArray.Create;
    for I := 0 to Artifacts.Count - 1 do
      ArrayValue.Add(TArtifact(Artifacts[I]).ToJSON(True));
    Result.Add('artifacts', ArrayValue);
    ArrayValue := TJSONArray.Create;
    for I := 0 to Components.Count - 1 do
      ArrayValue.Add(TComponent(Components[I]).ToJSON);
    Result.Add('components', ArrayValue);
  except
    Result.Free;
    raise;
  end;
end;

class function TScanTask.FromJSON(AObject: TJSONObject): TScanTask;
var
  ArrayValue: TJSONArray;
  Data: TJSONData;
  I: Integer;
  ParsedCheck: TKnownIssueCheck;
  ParsedSettings: TScanSettings;
begin
  Result := TScanTask.Create;
  try
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
    Result.ArtifactsPartiallyParsed :=
      JSONInt64(AObject, 'artifacts_partially_parsed');
    Result.UnsupportedArtifacts :=
      JSONInt64(AObject, 'unsupported_artifacts');
    Result.FailedArtifacts := JSONInt64(AObject, 'failed_artifacts');
    Result.ComponentsIdentified :=
      JSONInt64(AObject, 'components_identified');
    Result.DurationMS := JSONInt64(AObject, 'duration_ms');
    JSONToStrings(JSONArray(AObject, 'warnings'), Result.Warnings);
    JSONToStrings(JSONArray(AObject, 'errors'), Result.Errors);
    JSONToStrings(JSONArray(AObject, 'inspection_tools'),
      Result.InspectionTools);
    if JSONObject(AObject, 'scan_settings') <> nil then
    begin
      ParsedSettings := TScanSettings.FromJSON(
        JSONObject(AObject, 'scan_settings'));
      Result.Settings.Free;
      Result.Settings := ParsedSettings;
    end;
    Result.GeneratedSBOMPath := JSONString(AObject, 'generated_sbom_path');
    Result.GeneratedSBOMSHA256 :=
      JSONString(AObject, 'generated_sbom_sha256');
    Result.ScannerVersion :=
      JSONString(AObject, 'scanner_version', AppVersion);
    Result.ScannerCommit := JSONString(AObject, 'scanner_commit', AppCommit);
    Data := AObject.Find('known_issue_check');
    if (Data <> nil) and (Data.JSONType <> jtObject) then
      raise EJSON.Create('task "known_issue_check" must be an object');
    if Data <> nil then
    begin
      ParsedCheck := TKnownIssueCheck.FromJSON(TJSONObject(Data));
      Result.KnownIssueCheck.Free;
      Result.KnownIssueCheck := ParsedCheck;
    end;
    ArrayValue := JSONArray(AObject, 'artifacts');
    if ArrayValue <> nil then
      for I := 0 to ArrayValue.Count - 1 do
        if ArrayValue.Items[I].JSONType = jtObject then
          Result.Artifacts.Add(TArtifact.FromJSON(
            TJSONObject(ArrayValue.Items[I])));
    ArrayValue := JSONArray(AObject, 'components');
    if ArrayValue <> nil then
      for I := 0 to ArrayValue.Count - 1 do
        if ArrayValue.Items[I].JSONType = jtObject then
          Result.Components.Add(TComponent.FromJSON(
            TJSONObject(ArrayValue.Items[I])));
  except
    Result.Free;
    raise;
  end;
end;

end.
