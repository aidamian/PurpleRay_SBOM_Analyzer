(**
  PurpleRay SBOM Analyzer deterministic regression-test program.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Exercises non-visual parsing, hashing, persistence, migration, export,
  dependency inspection, normalization, traversal, and cancellation behavior.

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
program test_runner;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, BaseUnix,{$ENDIF}
  {$IFDEF Windows}Windows,{$ENDIF}
  Classes, SysUtils, Contnrs, fpjson, jsonparser, zipper,
  uModels, uSHA256, uBinaryInspector, uManifestParsers, uArtifactIdentifier,
  uTaskHistory, uJSONUtils, uComponentNormalizer, uCycloneDX, uIgnoreMatcher,
  uScanEngine, uPlatform, uSystemInspector, uNativeDependencyInspector,
  uExportUtils, uVersionInfo, uScanWorker;

type
  TTestMethod = procedure;

  { Signals that a registered test is not applicable to this runtime. }
  ETestSkipped = class(Exception);

  TCancelController = class
  private
    FChecks: Integer;
    FLimit: Integer;
  public
    constructor Create(ALimit: Integer);
    function Check: Boolean;
  end;

  { Captures a queued scan-worker completion for exception-path assertions. }
  TCompletionObserver = class
  public
    Count: Integer;
    Status: TTaskStatus;
    ErrorText: string;
    CompletedUTC: string;
    procedure Complete(Sender: TObject; AResult: TScanTask);
  end;

  { Injects a deterministic failure through the worker's protected test seam. }
  TFailingScanWorker = class(TScanWorker)
  protected
    procedure PerformScan; override;
  end;

  {$IFDEF UNIX}
  { Supplies one byte to a FIFO if a regressed scanner attempts to open it. }
  TFIFOWriter = class(TThread)
  private
    FPath: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const APath: string);
  end;
  {$ENDIF}

var
  TestCount: Integer = 0;
  PassCount: Integer = 0;
  FailureCount: Integer = 0;
  SkipCount: Integer = 0;
  ProjectRoot: string;
  TemporaryRoot: string;

constructor TCancelController.Create(ALimit: Integer);
begin
  inherited Create;
  FLimit := ALimit;
end;

function TCancelController.Check: Boolean;
begin
  Inc(FChecks);
  Result := FChecks >= FLimit;
end;

{**
  Records one worker completion without retaining the worker-owned task.

  Parameters
  ----------
  Sender
    Worker that queued the completion; unused by the observer.
  AResult
    Worker-owned task whose stable scalar state is copied for assertions.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure TCompletionObserver.Complete(Sender: TObject; AResult: TScanTask);
begin
  Inc(Count);
  Status := AResult.Status;
  ErrorText := AResult.Errors.Text;
  CompletedUTC := AResult.CompletedUTC;
end;

{**
  Raises a known exception to exercise the worker's last-resort boundary.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Always raised with a stable regression-test diagnostic.
}
procedure TFailingScanWorker.PerformScan;
begin
  raise Exception.Create('intentional worker regression failure');
end;

{$IFDEF UNIX}
{**
  Creates a suspended bounded FIFO writer for the special-file regression.

  Parameters
  ----------
  APath
    FIFO path that may be opened by a regressed scanner.

  Returns
  -------
  TFIFOWriter
    Suspended writer owned by the caller.

  Raises
  ------
  EOutOfMemory
    Propagated if thread allocation fails.
}
constructor TFIFOWriter.Create(const APath: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FPath := APath;
end;

{**
  Non-blockingly connects to a FIFO reader and supplies a finite payload.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
    Connection failures are retried for at most five seconds.
}
procedure TFIFOWriter.Execute;
var
  Deadline: QWord;
  FileHandle: cint;
  Payload: Byte;
begin
  Deadline := GetTickCount64 + 5000;
  repeat
    if Terminated then
      Exit;
    FileHandle := fpOpen(PChar(FPath), O_WRONLY or O_NONBLOCK);
    if FileHandle >= 0 then
    begin
      try
        Payload := Ord('x');
        fpWrite(FileHandle, Payload, 1);
      finally
        fpClose(FileHandle);
      end;
      Exit;
    end;
    Sleep(1);
  until GetTickCount64 >= Deadline;
end;
{$ENDIF}

procedure Fail(const AMessage: string);
begin
  raise Exception.Create(AMessage);
end;

{**
  Marks the current registered test as inapplicable on this runtime.

  Parameters
  ----------
  AReason
    Concise explanation written beside the explicit SKIP result.

  Returns
  -------
  None

  Raises
  ------
  ETestSkipped
    Always raised so RunTest can account for the skipped case separately.
}
procedure SkipTest(const AReason: string);
begin
  raise ETestSkipped.Create(AReason);
end;

procedure AssertTrue(AValue: Boolean; const AMessage: string);
begin
  if not AValue then
    Fail(AMessage);
end;

procedure AssertEqual(const AExpected, AActual: string; const AMessage: string);
begin
  if AExpected <> AActual then
    Fail(AMessage + Format(' (expected "%s", got "%s")',
      [AExpected, AActual]));
end;

procedure AssertEqual(AExpected, AActual: Int64; const AMessage: string);
begin
  if AExpected <> AActual then
    Fail(AMessage + Format(' (expected %d, got %d)', [AExpected, AActual]));
end;

function Fixture(const AName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(ProjectRoot) + 'tests' +
    DirectorySeparator + 'fixtures' + DirectorySeparator + AName;
end;

function NewTemporaryDirectory(const AName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(TemporaryRoot) + AName;
  if not ForceDirectories(Result) then
    Fail('Unable to create temporary test directory: ' + Result);
end;

{**
  Independently identifies link-like entries during test cleanup.

  Parameters
  ----------
  APath
    Exact test-owned entry to inspect without following it.

  Returns
  -------
  Boolean
    True for a Unix symbolic link or Windows reparse point.

  Raises
  ------
  None
    Metadata lookup failures are treated as non-links for best-effort cleanup.
}
function CleanupEntryIsLink(const APath: string): Boolean;
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
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  Result := False;
  {$ENDIF}
  {$ENDIF}
end;

{**
  Best-effort removes a test-owned directory without following symlinks.

  Parameters
  ----------
  ADirectory
    Exact temporary directory tree owned by this test process.

  Returns
  -------
  None

  Raises
  ------
  None
    Cleanup failures are ignored so they cannot hide the actual test result.
}
procedure RemoveTemporaryTree(const ADirectory: string);
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
  EntryPath: string;
begin
  if not DirectoryExists(ADirectory) then
    Exit;
  FindResult := FindFirst(IncludeTrailingPathDelimiter(ADirectory) + '*',
    faAnyFile, SearchRecord);
  if FindResult = 0 then
  begin
    try
      while FindResult = 0 do
      begin
        if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
        begin
          EntryPath := IncludeTrailingPathDelimiter(ADirectory) +
            SearchRecord.Name;
          if ((SearchRecord.Attr and faDirectory) <> 0) and
            not CleanupEntryIsLink(EntryPath) then
            RemoveTemporaryTree(EntryPath)
          else
            SysUtils.DeleteFile(EntryPath);
        end;
        FindResult := FindNext(SearchRecord);
      end;
    finally
      FindClose(SearchRecord);
    end;
  end;
  RemoveDir(ADirectory);
end;

procedure WriteText(const AFileName, AContent: RawByteString);
var
  Stream: TFileStream;
begin
  ForceDirectories(ExtractFileDir(AFileName));
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(AContent) > 0 then
      Stream.WriteBuffer(AContent[1], Length(AContent));
  finally
    Stream.Free;
  end;
end;

procedure WriteBytes(const AFileName: string; const ABytes: array of Byte);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(ABytes) > 0 then
      Stream.WriteBuffer(ABytes[0], Length(ABytes));
  finally
    Stream.Free;
  end;
end;

procedure SetUInt16LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: Word);
begin
  ABuffer[AOffset] := Byte(AValue);
  ABuffer[AOffset + 1] := Byte(AValue shr 8);
end;

procedure SetUInt32LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: UInt32);
begin
  ABuffer[AOffset] := Byte(AValue);
  ABuffer[AOffset + 1] := Byte(AValue shr 8);
  ABuffer[AOffset + 2] := Byte(AValue shr 16);
  ABuffer[AOffset + 3] := Byte(AValue shr 24);
end;

procedure SetUInt64LE(var ABuffer: array of Byte; AOffset: Integer;
  AValue: QWord);
begin
  SetUInt32LE(ABuffer, AOffset, UInt32(AValue));
  SetUInt32LE(ABuffer, AOffset + 4, UInt32(AValue shr 32));
end;

procedure SetBufferString(var ABuffer: array of Byte; AOffset: Integer;
  const AValue: RawByteString);
var
  I: Integer;
begin
  for I := 1 to Length(AValue) do
    ABuffer[AOffset + I - 1] := Byte(AValue[I]);
  ABuffer[AOffset + Length(AValue)] := 0;
end;

function FindComponent(AComponents: TObjectList; const AName: string):
  uModels.TComponent;
var
  I: Integer;
begin
  for I := 0 to AComponents.Count - 1 do
    if SameText(uModels.TComponent(AComponents[I]).Name, AName) then
      Exit(uModels.TComponent(AComponents[I]));
  Result := nil;
end;

{**
  Finds one artifact by its exact root-relative evidence path.

  Parameters
  ----------
  AArtifacts
    Artifact collection produced by the scan engine.
  ARelativePath
    Case-sensitive root-relative path to locate.

  Returns
  -------
  TArtifact
    Matching borrowed artifact, or nil when no exact path exists.

  Raises
  ------
  None
}
function FindArtifact(AArtifacts: TObjectList; const ARelativePath: string):
  TArtifact;
var
  I: Integer;
begin
  for I := 0 to AArtifacts.Count - 1 do
    if TArtifact(AArtifacts[I]).RelativePath = ARelativePath then
      Exit(TArtifact(AArtifacts[I]));
  Result := nil;
end;

{**
  Finds an object in a JSON array by one exact string member.

  Parameters
  ----------
  AArray
    Array whose object elements are searched; nil is accepted.
  AField
    Required string-member name.
  AValue
    Exact case-sensitive member value to match.

  Returns
  -------
  TJSONObject
    Borrowed matching object, or nil when no element matches.

  Raises
  ------
  None
}
function FindJSONObjectByString(AArray: TJSONArray; const AField,
  AValue: string): TJSONObject;
var
  I: Integer;
  Candidate: TJSONObject;
begin
  Result := nil;
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if AArray.Items[I].JSONType = jtObject then
    begin
      Candidate := TJSONObject(AArray.Items[I]);
      if JSONString(Candidate, AField) = AValue then
        Exit(Candidate);
    end;
end;

{**
  Tests whether a JSON array contains one exact string value.

  Parameters
  ----------
  AArray
    Array whose scalar strings are searched; nil is accepted.
  AValue
    Exact case-sensitive value to find.

  Returns
  -------
  Boolean
    True when AValue occurs as a string array element.

  Raises
  ------
  None
}
function JSONArrayContainsString(AArray: TJSONArray; const AValue: string):
  Boolean;
var
  I: Integer;
begin
  Result := False;
  if AArray = nil then
    Exit;
  for I := 0 to AArray.Count - 1 do
    if (AArray.Items[I].JSONType = jtString) and
      (AArray.Items[I].AsString = AValue) then
      Exit(True);
end;

{**
  Looks up one named CycloneDX property on a component object.

  Parameters
  ----------
  AComponent
    Component object containing an optional properties array.
  AName
    Exact property name.
  AValue
    Receives the property value when present.

  Returns
  -------
  Boolean
    True when the requested property exists.

  Raises
  ------
  None
}
function FindCycloneProperty(AComponent: TJSONObject; const AName: string;
  out AValue: string): Boolean;
var
  Item: TJSONObject;
begin
  AValue := '';
  Item := FindJSONObjectByString(JSONArray(AComponent, 'properties'), 'name',
    AName);
  Result := Item <> nil;
  if Result then
    AValue := JSONString(Item, 'value');
end;

{**
  Adds a fully described component to a synthetic scan task.

  Parameters
  ----------
  ATask
    Task that takes ownership of the component.
  AName, AVersion, AEcosystem, APURL
    Component identity and optional Package URL.
  ASourceArtifact, ASourceParser, AScope
    Root-relative provenance and dependency-scope evidence.
  AComponentType
    CycloneDX component type.

  Returns
  -------
  TComponent
    Borrowed component reference for additional test-specific setup.

  Raises
  ------
  EOutOfMemory
    Propagated when the component or evidence list cannot be allocated.
}
function AddFixtureComponent(ATask: TScanTask; const AName, AVersion,
  AEcosystem, APURL, ASourceArtifact, ASourceParser, AScope,
  AComponentType: string): uModels.TComponent;
begin
  Result := uModels.TComponent.Create;
  Result.Name := AName;
  Result.Version := AVersion;
  Result.Ecosystem := AEcosystem;
  Result.PackageURL := APURL;
  Result.SourceArtifact := ASourceArtifact;
  Result.SourceParser := ASourceParser;
  Result.DependencyScope := AScope;
  Result.ComponentType := AComponentType;
  if ASourceArtifact <> '' then
    Result.EvidencePaths.Add(ASourceArtifact);
  ATask.Components.Add(Result);
end;

{**
  Searches a string collection for a case-insensitive diagnostic fragment.

  Parameters
  ----------
  AStrings
    Collection of warnings or errors to search.
  AText
    Required diagnostic fragment.

  Returns
  -------
  Boolean
    True when any entry contains AText, ignoring ASCII letter case.

  Raises
  ------
  None
}
function StringListContainsText(AStrings: TStrings; const AText: string):
  Boolean;
var
  I: Integer;
  SearchText: string;
begin
  Result := False;
  SearchText := LowerCase(AText);
  for I := 0 to AStrings.Count - 1 do
    if Pos(SearchText, LowerCase(AStrings[I])) > 0 then
      Exit(True);
end;

{**
  Parses one named fixture through the production manifest dispatcher.

  Parameters
  ----------
  AName
    Fixture filename relative to the test fixture directory.
  AKind
    Parser kind to exercise.
  AComponents
    Owned list receiving parsed components.
  AArtifact
    Newly allocated artifact record returned to the caller.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated when the artifact cannot be allocated.
}
procedure ParseFixture(const AName: string; AKind: TParserKind;
  AComponents: TObjectList; out AArtifact: TArtifact);
begin
  AArtifact := TArtifact.Create;
  ParseArtifact(Fixture(AName), AName, AKind, AArtifact, AComponents);
end;

procedure TestSHA256;
begin
  AssertEqual('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    SHA256String(''), 'SHA-256 empty vector differs');
  AssertEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    SHA256String('abc'), 'SHA-256 abc vector differs');
end;

{**
  Verifies that the UI exposes the exact embedded product version.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when VERSION, the compiled UI value, Lazarus file/product resource
    metadata, or the operator-only CI generation order diverges.
}
procedure TestDisplayedVersion;
var
  VersionLines, VersionParts, ProjectLines, WorkflowLines: TStringList;
  VersionValue, ProjectText, WorkflowText: string;
  PartIndex, CharacterIndex, PartValue, CheckPosition, WritePosition: Integer;
begin
  VersionLines := TStringList.Create;
  VersionParts := TStringList.Create;
  ProjectLines := TStringList.Create;
  WorkflowLines := TStringList.Create;
  try
    VersionLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'VERSION');
    AssertEqual(1, VersionLines.Count,
      'VERSION should contain exactly one line');
    VersionValue := VersionLines[0];
    AssertEqual(Trim(VersionValue), VersionValue,
      'VERSION should not contain surrounding whitespace');
    AssertEqual(VersionValue, AppVersion,
      'compiled product version differs from VERSION');
    AssertEqual(AppVersion, DisplayVersion,
      'displayed version differs from the embedded product version');

    VersionParts.Delimiter := '.';
    VersionParts.StrictDelimiter := True;
    VersionParts.DelimitedText := VersionValue;
    AssertEqual(3, VersionParts.Count,
      'VERSION should contain three numeric components');
    for PartIndex := 0 to VersionParts.Count - 1 do
    begin
      AssertTrue(VersionParts[PartIndex] <> '',
        'VERSION components should not be empty');
      AssertTrue((Length(VersionParts[PartIndex]) = 1) or
        (VersionParts[PartIndex][1] <> '0'),
        'VERSION components should not contain leading zeros');
      for CharacterIndex := 1 to Length(VersionParts[PartIndex]) do
        AssertTrue(VersionParts[PartIndex][CharacterIndex] in ['0'..'9'],
          'VERSION components should contain decimal digits only');
      AssertTrue(TryStrToInt(VersionParts[PartIndex], PartValue),
        'VERSION component should fit a native integer');
      AssertTrue(PartValue <= 65535,
        'VERSION component exceeds the Windows resource range');
    end;
    ProjectLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpi');
    ProjectText := ProjectLines.Text;
    AssertTrue(Pos('<UseVersionInfo Value="True"/>', ProjectText) > 0,
      'Lazarus version resources should be enabled');
    AssertTrue(Pos('<MajorVersionNr Value="' + VersionParts[0] + '"/>',
      ProjectText) > 0, 'Lazarus major file version differs from VERSION');
    AssertTrue(Pos('<MinorVersionNr Value="' + VersionParts[1] + '"/>',
      ProjectText) > 0, 'Lazarus minor file version differs from VERSION');
    AssertTrue(Pos('<RevisionNr Value="' + VersionParts[2] + '"/>',
      ProjectText) > 0, 'Lazarus revision file version differs from VERSION');
    AssertTrue(Pos('<BuildNr Value="0"/>', ProjectText) > 0,
      'Lazarus file-version build number should be zero');
    AssertTrue(Pos('FileVersion="' + VersionValue + '.0"', ProjectText) > 0,
      'Lazarus string file version differs from VERSION');
    AssertTrue(Pos('ProductVersion="' + VersionValue + '"', ProjectText) > 0,
      'Lazarus product version differs from VERSION');
    WorkflowLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      '.github' + DirectorySeparator + 'workflows' + DirectorySeparator +
      'build-release.yml');
    WorkflowText := WorkflowLines.Text;
    CheckPosition := Pos('scripts/check-version.sh', WorkflowText);
    WritePosition := Pos('scripts/write-version.sh', WorkflowText);
    AssertTrue((CheckPosition = 0) or (CheckPosition > WritePosition),
      'CI must not require synchronized fallbacks before generation');
    AssertTrue(WritePosition > 0,
      'CI version generation step is missing');
    AssertTrue(WritePosition < Pos('scripts/run-tests.sh', WorkflowText),
      'CI must generate version metadata before compiling tests');
  finally
    WorkflowLines.Free;
    ProjectLines.Free;
    VersionParts.Free;
    VersionLines.Free;
  end;
end;

{**
  Verifies the compile-time feature shell and Analyzer frame ownership split.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when the shell regains scan-domain responsibilities, the frame is
    auto-created, a placeholder feature is exposed, or either LFM/LPI resource
    declaration diverges from the intended ownership model.
}
procedure TestApplicationShellStructure;
var
  ShellSourceLines, ShellResourceLines, AnalyzerSourceLines,
    AnalyzerResourceLines, ProjectLines, ProgramLines: TStringList;
  ShellSource, ShellResource, AnalyzerSource, AnalyzerResource, ProjectText,
    ProgramText: string;
  LineIndex, PageCount: Integer;
begin
  ShellSourceLines := TStringList.Create;
  ShellResourceLines := TStringList.Create;
  AnalyzerSourceLines := TStringList.Create;
  AnalyzerResourceLines := TStringList.Create;
  ProjectLines := TStringList.Create;
  ProgramLines := TStringList.Create;
  try
    ShellSourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uMainForm.pas');
    ShellResourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uMainForm.lfm');
    AnalyzerSourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uSBOMAnalyzerFrame.pas');
    AnalyzerResourceLines.LoadFromFile(
      IncludeTrailingPathDelimiter(ProjectRoot) + 'src' + DirectorySeparator +
      'uSBOMAnalyzerFrame.lfm');
    ProjectLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpi');
    ProgramLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'purpleray_sbom_analyzer.lpr');
    ShellSource := ShellSourceLines.Text;
    ShellResource := ShellResourceLines.Text;
    AnalyzerSource := AnalyzerSourceLines.Text;
    AnalyzerResource := AnalyzerResourceLines.Text;
    ProjectText := ProjectLines.Text;
    ProgramText := ProgramLines.Text;

    AssertTrue(Pos('TMainForm = class(TForm)', ShellSource) > 0,
      'the application shell is not the main form');
    AssertTrue(Pos('uSBOMAnalyzerFrame', ShellSource) > 0,
      'the shell does not import the Analyzer feature frame');
    AssertTrue(Pos('TSBOMAnalyzerFrame.Create(AnalyzerPage)', ShellSource) > 0,
      'the shell does not create the Analyzer frame inside its page');
    AssertTrue(Pos('FAnalyzerFrame.Parent := AnalyzerPage', ShellSource) > 0,
      'the Analyzer frame is not parented to its notebook page');
    AssertTrue(Pos('uModels', ShellSource) = 0,
      'the shell imports task-model responsibilities');
    AssertTrue(Pos('uTaskHistory', ShellSource) = 0,
      'the shell imports task-history responsibilities');
    AssertTrue(Pos('uSettingsStore', ShellSource) = 0,
      'the shell imports settings-store responsibilities');
    AssertTrue(Pos('uScanWorker', ShellSource) = 0,
      'the shell imports scan-worker responsibilities');
    AssertTrue(Pos('uScanEngine', ShellSource) = 0,
      'the shell imports scan-engine responsibilities');
    AssertTrue(Pos('uExportUtils', ShellSource) = 0,
      'the shell imports export responsibilities');

    AssertTrue(Pos('object MainForm: TMainForm', ShellResource) > 0,
      'the main-form resource root differs');
    AssertTrue(Pos('AllowDropFiles = True', ShellResource) > 0,
      'the shell no longer accepts folder drops');
    AssertTrue(Pos('KeyPreview = True', ShellResource) > 0,
      'the shell no longer receives application shortcuts');
    AssertTrue(Pos('object FeatureSelector: TComboBox', ShellResource) > 0,
      'the feature selector is missing');
    AssertTrue(Pos('Style = csDropDownList', ShellResource) > 0,
      'the feature selector should not accept arbitrary text');
    AssertTrue(Pos('object WorkspaceNotebook: TNotebook', ShellResource) > 0,
      'the tabless workspace notebook is missing');
    AssertTrue(Pos('object AnalyzerPage: TPage', ShellResource) > 0,
      'the Analyzer workspace page is missing');
    AssertTrue(Pos('Compare', ShellResource) = 0,
      'an unfinished comparison placeholder is exposed');
    PageCount := 0;
    for LineIndex := 0 to ShellResourceLines.Count - 1 do
      if Pos(': TPage', ShellResourceLines[LineIndex]) > 0 then
        Inc(PageCount);
    AssertEqual(1, PageCount,
      'the shell should expose exactly one completed feature page');

    AssertTrue(Pos('TSBOMAnalyzerFrame = class(TFrame)', AnalyzerSource) > 0,
      'the Analyzer workspace is not an LCL frame');
    AssertTrue(Pos('procedure ShowPendingWarnings;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing startup-warning delivery');
    AssertTrue(Pos('procedure HandleDroppedFiles(', AnalyzerSource) > 0,
      'the Analyzer shell API is missing drop handling');
    AssertTrue(Pos('function HandleShortcut(', AnalyzerSource) > 0,
      'the Analyzer shell API is missing shortcut handling');
    AssertTrue(Pos('function PrepareForClose: Boolean;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing safe shutdown');
    AssertTrue(Pos('procedure Activate;', AnalyzerSource) > 0,
      'the Analyzer shell API is missing feature activation');
    AssertTrue(Pos('property ScanActive: Boolean', AnalyzerSource) > 0,
      'the Analyzer shell API is missing activity state');
    AssertTrue(Pos('property OnActivityChanged:', AnalyzerSource) > 0,
      'the Analyzer shell API is missing activity notifications');
    AssertTrue(Pos('uMainForm', AnalyzerSource) = 0,
      'the Analyzer frame depends back on its shell');
    AssertTrue(Pos('FindTask(FWorker.ResultTask.ID)', AnalyzerSource) > 0,
      'shutdown does not recover the worker result independently');
    AssertTrue(Pos('FClosePrepared: Boolean;', AnalyzerSource) > 0,
      'shutdown lacks a separate successful-completion guard');
    AssertTrue(Pos('if FClosePrepared then', AnalyzerSource) > 0,
      'completed shutdown is not idempotent');
    AssertTrue(Pos('FClosePrepared := True;', AnalyzerSource) > 0,
      'shutdown never records successful completion');
    AssertTrue(Pos('FreeAndNil(FWorker)', AnalyzerSource) > 0,
      'shutdown does not remove worker-owned queued events');

    AssertTrue(Pos('object SBOMAnalyzerFrame: TSBOMAnalyzerFrame',
      AnalyzerResource) > 0, 'the Analyzer frame resource root differs');
    AssertTrue(Pos('AllowDropFiles =', AnalyzerResource) = 0,
      'the frame retained a form-only drop property');
    AssertTrue(Pos('OnCloseQuery =', AnalyzerResource) = 0,
      'the frame retained a form-only close event');
    AssertTrue(Pos('OnDropFiles =', AnalyzerResource) = 0,
      'the frame retained a form-only drop event');
    AssertTrue(Pos(LineEnding + '  OnKeyDown =', AnalyzerResource) = 0,
      'the frame retained a form-only key event');
    AssertTrue(Pos('OnShow =', AnalyzerResource) = 0,
      'the frame retained a form-only show event');
    AssertTrue(Pos('Position =', AnalyzerResource) = 0,
      'the frame retained a form-only position property');

    AssertTrue(Pos('<Units Count="4">', ProjectText) > 0,
      'the Lazarus project unit count does not include the feature frame');
    AssertTrue(Pos('<Filename Value="uSBOMAnalyzerFrame.pas"/>',
      ProjectText) > 0, 'the Lazarus project does not list the feature frame');
    AssertTrue(Pos('<ComponentName Value="SBOMAnalyzerFrame"/>',
      ProjectText) > 0, 'the Lazarus frame component name differs');
    AssertTrue(Pos('<HasResources Value="True"/>', ProjectText) > 0,
      'the Lazarus project does not register the frame resource');
    AssertTrue(Pos('<ResourceBaseClass Value="Frame"/>', ProjectText) > 0,
      'the Lazarus project does not register a Frame resource');
    AssertTrue(Pos('Application.CreateForm(TMainForm, MainForm);',
      ProgramText) > 0, 'the application no longer auto-creates its shell');
    AssertTrue(Pos('CreateForm(TSBOMAnalyzerFrame', ProgramText) = 0,
      'the feature frame must be created by the shell, not the program');
  finally
    ProgramLines.Free;
    ProjectLines.Free;
    AnalyzerResourceLines.Free;
    AnalyzerSourceLines.Free;
    ShellResourceLines.Free;
    ShellSourceLines.Free;
  end;
end;

{**
  Verifies the settings dialog keeps its GTK3 DPI-safe top-label layout.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when the LFM restores top border spacing on the first aligned label
    or removes the fixed spacer that supplies the equivalent visual margin.
}
procedure TestScanSettingsDialogDPIStableLayout;
var
  SourceLines, ResourceLines: TStringList;
  SourceText, ResourceText: string;
  DescriptionIndex, LineIndex: Integer;
begin
  SourceLines := TStringList.Create;
  ResourceLines := TStringList.Create;
  try
    SourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanSettingsDialog.pas');
    ResourceLines.LoadFromFile(IncludeTrailingPathDelimiter(ProjectRoot) +
      'src' + DirectorySeparator + 'uScanSettingsDialog.lfm');
    SourceText := SourceLines.Text;
    ResourceText := ResourceLines.Text;

    AssertTrue(Pos('DescriptionTopSpacer: TPanel;', SourceText) > 0,
      'the DPI-safe settings-dialog spacer is not LFM-backed');
    AssertTrue(Pos('object DescriptionTopSpacer: TPanel', ResourceText) > 0,
      'the settings dialog lacks its fixed top spacer');
    AssertTrue(Pos('object DescriptionTopSpacer: TPanel', ResourceText) <
      Pos('object DescriptionLabel: TLabel', ResourceText),
      'the settings-dialog spacer must precede the first aligned label');

    DescriptionIndex := -1;
    for LineIndex := 0 to ResourceLines.Count - 1 do
      if Pos('object DescriptionLabel: TLabel',
        ResourceLines[LineIndex]) > 0 then
      begin
        DescriptionIndex := LineIndex;
        Break;
      end;
    AssertTrue(DescriptionIndex >= 0,
      'the settings-dialog description label is missing');
    for LineIndex := DescriptionIndex + 1 to ResourceLines.Count - 1 do
    begin
      if Trim(ResourceLines[LineIndex]) = 'end' then
        Break;
      AssertTrue(Pos('BorderSpacing.Top', ResourceLines[LineIndex]) = 0,
        'top spacing on the first aligned label reintroduces the GTK3 DPI loop');
      AssertTrue(Pos('BorderSpacing.Around', ResourceLines[LineIndex]) = 0,
        'around spacing on the first aligned label reintroduces the GTK3 DPI loop');
    end;
  finally
    ResourceLines.Free;
    SourceLines.Free;
  end;
end;

procedure TestRequirementsParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('requirements.txt', pkRequirements, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'requirements should parse');
      AssertEqual(3, Components.Count, 'requirements component count differs');
      Component := FindComponent(Components, 'requests');
      AssertTrue(Component <> nil, 'requests component is missing');
      AssertEqual('2.32.3', Component.Version, 'requests version differs');
      AssertEqual('pkg:pypi/requests@2.32.3', Component.PackageURL,
        'requests purl differs');
      Component := FindComponent(Components, 'urllib3');
      AssertEqual('>=2.2', Component.Version, 'constraint should be retained');
      AssertEqual('', Component.PackageURL,
        'constraint must not be converted to an exact purl');
      Component := FindComponent(Components, 'Typing_Extensions');
      AssertTrue(Component <> nil,
        'the display spelling of the Python package is missing');
      AssertEqual('4.12.2', Component.Version,
        'Python exact version differs');
      AssertEqual('pkg:pypi/typing-extensions@4.12.2',
        Component.PackageURL, 'PEP-503 normalized PyPI purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies ecosystem-specific Package URL canonicalization and rejection.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a supported ecosystem produces a noncanonical purl or an
    unresolved version/name is assigned a misleading purl.
}
procedure TestPackageURLNormalization;
begin
  AssertEqual('pkg:pypi/flask@3.0.3',
    BuildPackageURL('PyPI', 'Flask', '3.0.3'),
    'PyPI purl must be lowercase');
  AssertEqual('pkg:pypi/typing-extensions@4.12.2',
    BuildPackageURL('PyPI', 'typing_extensions', '4.12.2'),
    'PyPI separator runs must follow PEP 503');
  AssertEqual('pkg:pypi/friendly-bard@1.0',
    BuildPackageURL('PyPI', 'FrIeNdLy-._.-bArD', '1.0'),
    'PyPI mixed separator normalization differs');
  AssertEqual('pkg:npm/lodash@4.17.21',
    BuildPackageURL('npm', 'LoDash', '4.17.21'),
    'npm purl name must be lowercase');
  AssertEqual('pkg:npm/%40scope/tool@3.4.5',
    BuildPackageURL('npm', '@Scope/Tool', '3.4.5'),
    'scoped npm purl normalization differs');
  AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
    BuildPackageURL('Gradle', 'org.example:demo-core', '2.1.0'),
    'Gradle module must use a Maven purl');
  AssertEqual('pkg:conda/numpy@2.1.0',
    BuildPackageURL('Conda', 'numpy', '2.1.0'),
    'Conda purl differs');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '^4.17.21'),
    'a range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', 'latest'),
    'an npm tag must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '1'),
    'an npm one-segment X-range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', '1.2'),
    'an npm two-segment X-range must not produce a purl');
  AssertEqual('', BuildPackageURL('npm', 'lodash', 'canary'),
    'an arbitrary npm dist-tag must not produce a purl');
  AssertEqual('pkg:npm/lodash@1.2.3-beta.1%2Bbuild.4',
    BuildPackageURL('npm', 'lodash', '1.2.3-beta.1+build.4'),
    'an exact npm prerelease/build version was rejected');
  AssertEqual('', BuildPackageURL('Gradle', 'org.example:demo-core', '1.+'),
    'a Gradle dynamic selector must not produce a purl');
  AssertTrue(not IsVersionRange('file:/home/alice/private/pkg'),
    'a private local path must not be classified as a requested range');
  AssertEqual('', BuildPackageURL('npm', '@scope/', '1.0.0'),
    'an incomplete npm scope must not produce a purl');
  AssertEqual('', BuildPackageURL('Gradle', 'org.example:', '1.0.0'),
    'an incomplete Gradle coordinate must not produce a purl');
end;

{**
  Verifies that conservative Gradle and Conda parsers assign resolved purls.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when production parser dispatch loses an exact module identity or
    emits an ecosystem-incompatible Package URL.
}
procedure TestGradleAndCondaPURLs;
var
  DirectoryName, FileName: string;
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  DirectoryName := NewTemporaryDirectory('gradle-conda-purls');
  Components := TObjectList.Create(True);
  try
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'gradle.lockfile';
    WriteText(FileName, 'org.example:demo-core:2.1.0=runtimeClasspath' +
      LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'gradle.lockfile', pkGradleLock, Artifact,
        Components);
      Component := FindComponent(Components, 'org.example:demo-core');
      AssertTrue(Component <> nil, 'Gradle component is missing');
      AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
        Component.PackageURL, 'parsed Gradle purl differs');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) +
      'environment.yml';
    WriteText(FileName, 'name: fixture' + LineEnding + 'dependencies:' +
      LineEnding + '  - numpy=2.1.0=py312_0' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'environment.yml', pkEnvironmentYAML, Artifact,
        Components);
      Component := FindComponent(Components, 'numpy');
      AssertTrue(Component <> nil, 'Conda component is missing');
      AssertEqual('pkg:conda/numpy@2.1.0', Component.PackageURL,
        'parsed Conda purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies production manifest parsing and honest CycloneDX version/scope use.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when Cargo requirements, npm paths/tags/partials, or Maven scopes
    are represented as resolved versions or mapped to an incorrect spec scope.
}
procedure TestDeclaredVersionAndScopeSemantics;
var
  DirectoryName, FileName, PropertyValue: string;
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  Task: TScanTask;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, ComponentJSON: TJSONObject;
  ComponentArray: TJSONArray;
  I: Integer;
begin
  DirectoryName := NewTemporaryDirectory('declared-version-scope');
  Components := TObjectList.Create(True);
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := DirectoryName;
    Task.TargetRootName := 'declared-version-scope';
    Task.ScannerVersion := AppVersion;

    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'Cargo.toml';
    WriteText(FileName, '[dependencies]' + LineEnding +
      'serde = "1.0.0"' + LineEnding + '[dev-dependencies]' + LineEnding +
      'insta = "1.2"' + LineEnding + '[build-dependencies]' + LineEnding +
      'cc = "1.0.99"' + LineEnding);
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'Cargo.toml', pkCargoTOML, Artifact, Components);
      AssertTrue(Artifact.Status in [arsParsed, arsPartiallyParsed],
        'Cargo.toml should parse conservatively');
    finally
      Artifact.Free;
    end;
    Component := FindComponent(Components, 'serde');
    AssertTrue(Component <> nil, 'Cargo runtime dependency is missing');
    AssertEqual('runtime', Component.DependencyScope,
      'Cargo runtime scope differs');
    AssertEqual('', Component.PackageURL,
      'Cargo manifest requirement must not produce a resolved purl');
    AssertEqual('development', FindComponent(Components,
      'insta').DependencyScope, 'Cargo dev scope differs');
    AssertEqual('build', FindComponent(Components, 'cc').DependencyScope,
      'Cargo build scope differs');
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'serde');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil),
        'Cargo manifest requirement became a resolved identity');
      AssertTrue(FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'Cargo shorthand requested range is missing');
      AssertEqual('1.0.0', PropertyValue,
        'Cargo shorthand requested range differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'insta');
      AssertEqual('excluded', JSONString(ComponentJSON, 'scope'),
        'Cargo development dependency must be excluded');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name', 'cc');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Cargo build dependency must retain the required default');
    finally
      Data.Free;
    end;

    Components.Clear;
    Task.Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'package.json';
    WriteText(FileName, '{"dependencies":{' +
      '"local-secret":"file:/home/alice/private/pkg",' +
      '"partial":"1.2","tagged":"canary","exact":"1.2.3"}}');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'package.json', pkPackageJSON, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed, 'package.json should parse');
    finally
      Artifact.Free;
    end;
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    AssertTrue(Pos('/home/alice/private/pkg', string(SBOM)) = 0,
      'default SBOM leaked a local dependency path');
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'partial');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil),
        'npm partial X-range became a resolved identity');
      AssertTrue(FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'npm partial requested range is missing');
      AssertEqual('1.2', PropertyValue, 'npm partial range differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'tagged');
      AssertTrue((ComponentJSON.Find('version') = nil) and
        (ComponentJSON.Find('purl') = nil) and
        not FindCycloneProperty(ComponentJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'npm dist-tag was mislabeled as a resolved version or range');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'exact');
      AssertEqual('1.2.3', JSONString(ComponentJSON, 'version'),
        'exact npm version was lost');
      AssertEqual('pkg:npm/exact@1.2.3', JSONString(ComponentJSON, 'purl'),
        'exact npm purl differs');
    finally
      Data.Free;
    end;

    Components.Clear;
    Task.Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'pom.xml';
    WriteText(FileName, '<?xml version="1.0"?><project><dependencies>' +
      '<dependency><groupId>org.example</groupId><artifactId>compile-dep' +
      '</artifactId><version>1.0.0</version></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>test-dep' +
      '</artifactId><version>1.0.0</version><scope>test</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>provided-dep' +
      '</artifactId><version>1.0.0</version><scope>provided</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>system-dep' +
      '</artifactId><version>1.0.0</version><scope>system</scope></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>optional-dep' +
      '</artifactId><version>1.0.0</version><optional>true</optional></dependency>' +
      '<dependency><groupId>org.example</groupId><artifactId>imported-bom' +
      '</artifactId><version>1.0.0</version><scope>import</scope></dependency>' +
      '</dependencies></project>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
      AssertTrue(Artifact.Status = arsParsed, 'scope POM should parse');
    finally
      Artifact.Free;
    end;
    AssertEqual('runtime', FindComponent(Components,
      'compile-dep').DependencyScope, 'Maven compile scope differs');
    AssertEqual('development', FindComponent(Components,
      'test-dep').DependencyScope, 'Maven test scope differs');
    AssertEqual('provided', FindComponent(Components,
      'provided-dep').DependencyScope, 'Maven provided scope was not retained');
    AssertEqual('system', FindComponent(Components,
      'system-dep').DependencyScope, 'Maven system scope was not retained');
    AssertEqual('optional', FindComponent(Components,
      'optional-dep').DependencyScope, 'Maven optional flag differs');
    AssertTrue(FindComponent(Components, 'imported-bom') = nil,
      'Maven dependency-management import became a runtime component');
    for I := 0 to Components.Count - 1 do
      Task.Components.Add(uModels.TComponent(Components[I]).Clone);
    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      ComponentArray := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'test-dep');
      AssertEqual('excluded', JSONString(ComponentJSON, 'scope'),
        'Maven test dependency must be excluded');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'optional-dep');
      AssertEqual('optional', JSONString(ComponentJSON, 'scope'),
        'Maven optional dependency scope differs');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'provided-dep');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Maven provided dependency must remain required');
      ComponentJSON := FindJSONObjectByString(ComponentArray, 'name',
        'system-dep');
      AssertTrue(ComponentJSON.Find('scope') = nil,
        'Maven system dependency must remain required');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
    Components.Free;
  end;
end;

procedure TestPackageJSONParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('package.json', pkPackageJSON, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'package.json should parse');
      AssertEqual(3, Components.Count, 'package.json component count differs');
      Component := FindComponent(Components, 'fixture-app');
      AssertTrue(Component <> nil, 'package root component is missing');
      AssertEqual('application', Component.ComponentType,
        'package root type differs');
      Component := FindComponent(Components, 'lodash');
      AssertEqual('pkg:npm/lodash@4.17.21', Component.PackageURL,
        'npm dependency purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

procedure TestPackageLockParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('package-lock.json', pkPackageLockJSON, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'package lock should parse');
      AssertEqual(3, Components.Count, 'package lock component count differs');
      Component := FindComponent(Components, '@scope/tool');
      AssertTrue(Component <> nil, 'scoped npm package is missing');
      AssertEqual('pkg:npm/%40scope/tool@3.4.5', Component.PackageURL,
        'scoped npm purl differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

procedure TestXMLParsers;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('pom.xml', pkMavenPOM, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed, 'pom.xml should parse');
      Component := FindComponent(Components, 'demo-core');
      AssertTrue(Component <> nil, 'Maven dependency is missing');
      AssertEqual('pkg:maven/org.example/demo-core@2.1.0',
        Component.PackageURL, 'Maven purl differs');
    finally
      Artifact.Free;
    end;
    Components.Clear;
    ParseFixture('project.csproj', pkMSBuildProject, Components, Artifact);
    try
      Component := FindComponent(Components, 'Example.Core');
      AssertTrue(Component <> nil, 'MSBuild PackageReference is missing');
      AssertEqual('5.4.3', Component.Version, 'MSBuild version differs');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies current and legacy-compatible Lazarus package-name extraction.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when a current-format `.lpi` requirement is
    not represented as build-scope Free Pascal component evidence.
}
procedure TestLazarusProjectParser;
var
  Components: TObjectList;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  DirectoryName, FileName: string;
begin
  Components := TObjectList.Create(True);
  try
    ParseFixture('lazarus-current.lpi', pkLazarusXML, Components, Artifact);
    try
      AssertTrue(Artifact.Status = arsParsed,
        'current Lazarus project should parse');
      AssertEqual(1, Artifact.ComponentCount,
        'current Lazarus artifact component count differs');
      AssertEqual(1, Components.Count,
        'current Lazarus requirement count differs');
      Component := FindComponent(Components, 'LCL');
      AssertTrue(Component <> nil, 'LCL requirement is missing');
      AssertEqual('', Component.Version,
        'Lazarus requirement should not invent a version');
      AssertEqual('FreePascal', Component.Ecosystem,
        'Lazarus requirement ecosystem differs');
      AssertEqual('library', Component.ComponentType,
        'Lazarus requirement component type differs');
      AssertEqual('lazarus-current.lpi', Component.SourceArtifact,
        'Lazarus requirement source artifact differs');
      AssertEqual('lazarus-project-xml', Component.SourceParser,
        'Lazarus requirement parser evidence differs');
      AssertEqual('build', Component.DependencyScope,
        'Lazarus requirement scope differs');
      AssertEqual('', Component.PackageURL,
        'Lazarus requirement should not invent a package URL');
      AssertEqual(1, Component.EvidencePaths.Count,
        'Lazarus requirement evidence count differs');
      AssertEqual('lazarus-current.lpi', Component.EvidencePaths[0],
        'Lazarus requirement evidence path differs');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    DirectoryName := NewTemporaryDirectory('lazarus-parser-compatibility');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'legacy.lpk';
    WriteText(FileName, '<?xml version="1.0"?><CONFIG><RequiredPackages>' +
      '<Item1><Name Value="LegacyAttr"/></Item1>' +
      '<Item2><Name>LegacyText</Name></Item2>' +
      '</RequiredPackages></CONFIG>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'legacy.lpk', pkLazarusXML, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'legacy Lazarus package should parse');
      AssertEqual(2, Artifact.ComponentCount,
        'legacy Lazarus package-name variants differ');
      AssertTrue(FindComponent(Components, 'LegacyAttr') <> nil,
        'legacy Lazarus Name Value requirement is missing');
      AssertTrue(FindComponent(Components, 'LegacyText') <> nil,
        'legacy Lazarus Name text requirement is missing');
    finally
      Artifact.Free;
    end;

    Components.Clear;
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'empty.lpi';
    WriteText(FileName, '<?xml version="1.0"?><CONFIG><ProjectOptions>' +
      '<RequiredPackages Count="0"/></ProjectOptions></CONFIG>');
    Artifact := TArtifact.Create;
    try
      ParseArtifact(FileName, 'empty.lpi', pkLazarusXML, Artifact,
        Components);
      AssertTrue(Artifact.Status = arsParsed,
        'empty valid Lazarus project should still parse');
      AssertEqual(0, Artifact.ComponentCount,
        'empty Lazarus project should have no components');
      AssertTrue(Pos('No dependency components were identified.',
        Artifact.MessageText) > 0,
        'zero-component Lazarus parse should be visibly annotated');
    finally
      Artifact.Free;
    end;
  finally
    Components.Free;
  end;
end;

{**
  Verifies deterministic parser-kind size policies and an oversized rejection.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a parser is unbounded or an over-limit manifest is opened,
    parsed, hashed, or omitted instead of becoming a failed artifact.
}
procedure TestManifestSizeLimits;
var
  ParserKind: TParserKind;
  RootName, FileName, ExpectedMessage: string;
  Stream: TFileStream;
  Task: TScanTask;
  Engine: TScanEngine;
  Artifact: TArtifact;
  LimitValue: Int64;
begin
  AssertEqual(0, ManifestSizeLimit(pkNone),
    'unsupported artifacts should not receive a parser size limit');
  for ParserKind := Low(TParserKind) to High(TParserKind) do
    if ParserKind <> pkNone then
      AssertTrue(ManifestSizeLimit(ParserKind) > 0,
        'recognized parser kind has no bounded size policy');
  AssertEqual(8 * 1024 * 1024, ManifestSizeLimit(pkPackageJSON),
    'ordinary manifest size limit differs');
  AssertEqual(32 * 1024 * 1024, ManifestSizeLimit(pkPackageLockJSON),
    'JSON lockfile size limit differs');
  AssertEqual(64 * 1024 * 1024, ManifestSizeLimit(pkCargoLock),
    'line-oriented lockfile size limit differs');

  RootName := NewTemporaryDirectory('manifest-size-limit');
  FileName := IncludeTrailingPathDelimiter(RootName) + 'package.json';
  LimitValue := ManifestSizeLimit(pkPackageJSON);
  Stream := TFileStream.Create(FileName, fmCreate);
  try
    Stream.Size := LimitValue + 1;
  finally
    Stream.Free;
  end;
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'manifest-size-limit';
    Task.Settings.CalculateSHA256 := True;
    AssertTrue(Engine.Scan(Task),
      'over-limit manifest should not fail the containing scan');
    AssertEqual(1, Task.Artifacts.Count,
      'over-limit manifest artifact is missing');
    Artifact := TArtifact(Task.Artifacts[0]);
    ExpectedMessage := 'Manifest exceeds the size limit for package-json: ' +
      IntToStr(LimitValue + 1) + ' bytes (maximum ' + IntToStr(LimitValue) +
      ' bytes).';
    AssertTrue(Artifact.Status = arsFailed,
      'over-limit manifest should be a failed artifact');
    AssertEqual(ExpectedMessage, Artifact.MessageText,
      'over-limit manifest diagnostic differs');
    AssertEqual(0, Artifact.ComponentCount,
      'over-limit manifest should produce no components');
    AssertEqual(1, Task.FailedArtifacts,
      'over-limit manifest failed-artifact count differs');
    AssertEqual(0, Task.ArtifactsParsed,
      'over-limit manifest should not be counted as parsed');
    AssertEqual(0, Task.ComponentsIdentified,
      'over-limit manifest should not identify components');
    AssertEqual('', Artifact.SHA256,
      'over-limit manifest should be rejected before hashing');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure TestXMLDocumentTypeRejection;
var
  DirectoryName, FileName: string;
  Components: TObjectList;
  Artifact: TArtifact;
begin
  DirectoryName := NewTemporaryDirectory('xml-doctype');
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'pom.xml';
  WriteText(FileName, '<!DOCTYPE project [<!ENTITY local SYSTEM ' +
    '"file:///etc/passwd">]><project><dependencies><dependency>' +
    '<artifactId>&local;</artifactId></dependency></dependencies></project>');
  Components := TObjectList.Create(True);
  Artifact := TArtifact.Create;
  try
    ParseArtifact(FileName, 'pom.xml', pkMavenPOM, Artifact, Components);
    AssertTrue(Artifact.Status = arsFailed,
      'XML with a document type must be rejected');
    AssertEqual(0, Components.Count,
      'rejected XML must not produce components');
    AssertTrue(Pos('document type declarations are not allowed',
      LowerCase(Artifact.MessageText)) > 0,
      'XML rejection message is unclear');
  finally
    Artifact.Free;
    Components.Free;
  end;
end;

procedure TestHistoryRoundTrip;
var
  DirectoryName, RelocatedSBOM: string;
  Store: TTaskHistoryStore;
  Tasks, Loaded: TObjectList;
  Task: TScanTask;
  WarningText: string;
begin
  DirectoryName := NewTemporaryDirectory('history-roundtrip');
  Store := TTaskHistoryStore.Create(DirectoryName);
  Tasks := TObjectList.Create(True);
  Loaded := TObjectList.Create(True);
  try
    Task := TScanTask.Create;
    Task.TargetDirectory := '/tmp/example';
    Task.TargetRootName := 'example';
    Task.Status := tsCompleted;
    Task.FilesInspected := 42;
    Task.Warnings.Add('fixture warning');
    Task.InspectionTools.Add('readelf');
    Task.GeneratedSBOMPath := '/old/location/' + Task.ID + '.cdx.json';
    RelocatedSBOM := IncludeTrailingPathDelimiter(DirectoryName) + 'sboms' +
      DirectorySeparator + Task.ID + '.cdx.json';
    WriteText(RelocatedSBOM, '{}');
    Tasks.Add(Task);
    Store.Save(Tasks);
    AssertTrue(Store.Load(Loaded, WarningText), 'history should load');
    AssertEqual('', WarningText, 'valid history produced a warning');
    AssertEqual(1, Loaded.Count, 'loaded task count differs');
    AssertEqual(42, TScanTask(Loaded[0]).FilesInspected,
      'loaded file count differs');
    AssertEqual('fixture warning', TScanTask(Loaded[0]).Warnings[0],
      'loaded warning differs');
    AssertEqual('readelf', TScanTask(Loaded[0]).InspectionTools[0],
      'inspection tool was not persisted');
    AssertEqual(RelocatedSBOM, TScanTask(Loaded[0]).GeneratedSBOMPath,
      'SBOM path was not relocated with the application data');
  finally
    Loaded.Free;
    Tasks.Free;
    Store.Free;
  end;
end;

procedure TestApplicationDataMigration;
var
  SourceDirectory, DestinationDirectory, WarningText: string;
begin
  SourceDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
    '.sbom-analyzer';
  DestinationDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
    '.purpleray' + DirectorySeparator + 'sbom-analyzer';
  ForceDirectories(SourceDirectory);
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'history.json',
    '{"format_version":1,"tasks":[]}');
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'sboms' +
    DirectorySeparator + 'fixture.cdx.json', '{}');
  AssertTrue(MigrateApplicationDataDirectory(SourceDirectory,
    DestinationDirectory, WarningText), 'application data migration failed');
  AssertEqual('', WarningText, 'successful migration produced a warning');
  AssertTrue(not DirectoryExists(SourceDirectory),
    '~/.sbom-analyzer was retained after successful migration');
  AssertTrue(DirectoryExists(DestinationDirectory),
    '~/.purpleray/sbom-analyzer was not created');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(DestinationDirectory) +
    'history.json'), 'history was not migrated');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(DestinationDirectory) +
    'sboms' + DirectorySeparator + 'fixture.cdx.json'),
    'saved SBOM was not migrated');

  { A later partial migration must preserve the legacy directory when a file
    would overwrite data already present at the destination. }
  ForceDirectories(SourceDirectory);
  WriteText(IncludeTrailingPathDelimiter(SourceDirectory) + 'history.json',
    '{"format_version":1,"tasks":[{"legacy":true}]}');
  AssertTrue(not MigrateApplicationDataDirectory(SourceDirectory,
    DestinationDirectory, WarningText),
    'colliding application data migration unexpectedly succeeded');
  AssertTrue(WarningText <> '',
    'colliding application data migration produced no warning');
  AssertTrue(DirectoryExists(SourceDirectory),
    'legacy directory was removed after a partial migration');
  AssertTrue(FileExists(IncludeTrailingPathDelimiter(SourceDirectory) +
    'history.json'), 'unmigrated legacy data was deleted');
end;

procedure TestExportNaming;
var
  Task: TScanTask;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.TargetRootName := 'Demo: Folder';
    AssertEqual('20250102_030405_Demo_Folder_' + Task.ID + '.cdx.json',
      TaskSBOMExportFileName(Task), 'SBOM export filename differs');
  finally
    Task.Free;
  end;
end;

function ArchiveContains(AEntries: TFullZipFileEntries;
  const AName: string): Boolean;
var
  I: Integer;
begin
  for I := 0 to AEntries.Count - 1 do
    if AEntries[I].ArchiveFileName = AName then
      Exit(True);
  Result := False;
end;

procedure TestDatabaseArchive;
var
  DataDirectory, ArchiveName: string;
  UnZipper: TUnZipper;
begin
  DataDirectory := NewTemporaryDirectory('database-archive');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'history.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'settings.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'sboms' +
    DirectorySeparator + 'fixture.cdx.json', '{}');
  WriteText(IncludeTrailingPathDelimiter(DataDirectory) + 'ignored.tmp',
    'temporary');
  ArchiveName := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'database-export.zip';
  ExportDatabaseArchive(DataDirectory, ArchiveName);
  AssertTrue(FileExists(ArchiveName), 'database archive was not created');
  UnZipper := TUnZipper.Create;
  try
    UnZipper.FileName := ArchiveName;
    UnZipper.Examine;
    AssertEqual(3, UnZipper.Entries.Count,
      'database archive entry count differs');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/history.json'), 'database archive omits history');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/settings.json'), 'database archive omits settings');
    AssertTrue(ArchiveContains(UnZipper.Entries,
      'purpleray-sbom-analyzer/sboms/fixture.cdx.json'),
      'database archive omits saved SBOMs');
  finally
    UnZipper.Free;
  end;
end;

procedure TestReadElfParsing;
var
  Inspection: TSystemInspection;
begin
  Inspection := TSystemInspection.Create;
  try
    AssertTrue(ParseReadElfOutput(
      ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]' + LineEnding +
      ' 0x0000000000000001 (NEEDED) Shared library: [libz.so.1]' + LineEnding +
      ' 0x000000000000000e (SONAME) Library soname: [libdemo.so.4.2]' + LineEnding +
      ' Build ID: 0123456789abcdef', Inspection),
      'readelf evidence was not recognized');
    AssertEqual(2, Inspection.Dependencies.Count,
      'readelf dependency count differs');
    AssertEqual('libc.so.6', Inspection.Dependencies[0],
      'first readelf dependency differs');
    AssertEqual('libz.so.1', Inspection.Dependencies[1],
      'second readelf dependency differs');
    AssertEqual('4.2', Inspection.ComponentVersion,
      'readelf SONAME version differs');
    AssertEqual('build ID: 0123456789abcdef', Inspection.Details[0],
      'readelf build ID differs');
  finally
    Inspection.Free;
  end;
end;

procedure TestNativeDependencyVersions;
begin
  AssertEqual('', NativeDependencyVersion('libc.so.6'),
    'ELF SONAME ABI major must not become a product version');
  AssertEqual('', NativeDependencyVersion('libgtk-3.so.0'),
    'a bare ELF ABI suffix must not become a product version');
  AssertEqual('1.2.3', NativeDependencyVersion('/opt/lib/libdemo.so.1.2.3'),
    'ELF SONAME dotted version differs');
  AssertEqual('3', NativeDependencyVersion('/usr/lib/libcrypto.3.dylib'),
    'Mach-O install-name version differs');
  AssertEqual('', NativeDependencyVersion('kernel32.dll'),
    'unversioned PE import must not invent a version');
  AssertEqual('', NativeDependencyVersion('api-ms-win-core-file-l1-1-0.dll'),
    'Windows API-set tokens must not become a version');
  AssertEqual('', NativeDependencyVersion('libSystem.B.dylib'),
    'non-numeric Mach-O suffix must not become a version');
end;

procedure TestNativeVersionScanAndSBOM;
var
  DirectoryName, FileName: string;
  Buffer: array[0..63] of Byte;
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
  SBOM: UTF8String;
begin
  DirectoryName := NewTemporaryDirectory('native-version-scan');
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'libdemo.so.4.2';
  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
  Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
  SetUInt16LE(Buffer, 16, 3);
  SetUInt16LE(Buffer, 18, 62);
  WriteBytes(FileName, Buffer);
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'libc.so.6';
  WriteBytes(FileName, Buffer);

  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := DirectoryName;
    Task.TargetRootName := 'native-version-scan';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'native version fixture scan failed');
    Component := FindComponent(Task.Components, 'libdemo.so.4.2');
    AssertTrue(Component <> nil, 'versioned native component is missing');
    AssertEqual('4.2', Component.Version,
      'versioned native component lost filename evidence');
    Component := FindComponent(Task.Components, 'libc.so.6');
    AssertTrue(Component <> nil, 'bare-ABI native component is missing');
    AssertEqual('', Component.Version,
      'bare ELF ABI suffix leaked into the component version');
    SBOM := GenerateCycloneDX(Task);
    AssertTrue(Pos('"version" : "4.2"', string(SBOM)) > 0,
      'native version evidence is missing from CycloneDX output');
    AssertTrue(Pos('purpleray-sbom-analyzer:soname-abi-version',
      string(SBOM)) > 0,
      'bare ELF ABI evidence is missing from CycloneDX properties');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure TestNativeDependencyTables;
var
  DirectoryName, FileName: string;
  Buffer: array[0..511] of Byte;
  Dependencies: TStringList;
begin
  DirectoryName := NewTemporaryDirectory('native-dependencies');
  Dependencies := TStringList.Create;
  try
    Dependencies.Sorted := True;
    Dependencies.Duplicates := dupIgnore;

    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
    Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
    SetUInt64LE(Buffer, 32, 64);
    SetUInt16LE(Buffer, 54, 56);
    SetUInt16LE(Buffer, 56, 2);
    SetUInt32LE(Buffer, 64, 1);
    SetUInt64LE(Buffer, 72, 0);
    SetUInt64LE(Buffer, 80, $400000);
    SetUInt64LE(Buffer, 96, SizeOf(Buffer));
    SetUInt32LE(Buffer, 120, 2);
    SetUInt64LE(Buffer, 128, 256);
    SetUInt64LE(Buffer, 136, $400100);
    SetUInt64LE(Buffer, 152, 64);
    SetUInt64LE(Buffer, 256, 5);
    SetUInt64LE(Buffer, 264, $400180);
    SetUInt64LE(Buffer, 272, 10);
    SetUInt64LE(Buffer, 280, 32);
    SetUInt64LE(Buffer, 288, 1);
    SetBufferString(Buffer, 384, 'libfixture.so');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.elf';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'ELF', Dependencies),
      'ELF dependency table was not parsed');
    AssertEqual(1, Dependencies.Count, 'ELF dependency count differs');
    AssertEqual('libfixture.so', Dependencies[0],
      'ELF dependency name differs');

    Dependencies.Clear;
    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := Ord('M'); Buffer[1] := Ord('Z');
    SetUInt32LE(Buffer, $3C, 64);
    Buffer[64] := Ord('P'); Buffer[65] := Ord('E');
    SetUInt16LE(Buffer, 70, 1);
    SetUInt16LE(Buffer, 84, 224);
    SetUInt16LE(Buffer, 88, $010B);
    SetUInt32LE(Buffer, 116, $400000);
    SetUInt32LE(Buffer, 148, 400);
    SetUInt32LE(Buffer, 180, 16);
    SetUInt32LE(Buffer, 192, $1000);
    SetUInt32LE(Buffer, 196, 40);
    SetUInt32LE(Buffer, 320, $100);
    SetUInt32LE(Buffer, 324, $1000);
    SetUInt32LE(Buffer, 328, $70);
    SetUInt32LE(Buffer, 332, 400);
    SetUInt32LE(Buffer, 400, $1060);
    SetUInt32LE(Buffer, 412, $1050);
    SetBufferString(Buffer, 480, 'KERNEL32.dll');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.exe';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'PE', Dependencies),
      'PE import table was not parsed');
    AssertEqual(1, Dependencies.Count, 'PE dependency count differs');
    AssertEqual('KERNEL32.dll', Dependencies[0],
      'PE dependency name differs');

    Dependencies.Clear;
    FillChar(Buffer, SizeOf(Buffer), 0);
    Buffer[0] := $CF; Buffer[1] := $FA; Buffer[2] := $ED; Buffer[3] := $FE;
    SetUInt32LE(Buffer, 4, $01000007);
    SetUInt32LE(Buffer, 12, 2);
    SetUInt32LE(Buffer, 16, 1);
    SetUInt32LE(Buffer, 20, 64);
    SetUInt32LE(Buffer, 32, $0C);
    SetUInt32LE(Buffer, 36, 64);
    SetUInt32LE(Buffer, 40, 24);
    SetBufferString(Buffer, 56, '@rpath/libFixture.dylib');
    FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'fixture.macho';
    WriteBytes(FileName, Buffer);
    AssertTrue(InspectNativeDependencies(FileName, 'Mach-O', Dependencies),
      'Mach-O load commands were not parsed');
    AssertEqual(1, Dependencies.Count, 'Mach-O dependency count differs');
    AssertEqual('@rpath/libFixture.dylib', Dependencies[0],
      'Mach-O dependency name differs');
  finally
    Dependencies.Free;
  end;
end;

procedure TestAtomicHistoryRecovery;
var
  DirectoryName: string;
  Store: TTaskHistoryStore;
  Tasks, Loaded: TObjectList;
  FirstTask, SecondTask: TScanTask;
  WarningText: string;
  SearchRecord: TSearchRec;
begin
  DirectoryName := NewTemporaryDirectory('history-recovery');
  Store := TTaskHistoryStore.Create(DirectoryName);
  Tasks := TObjectList.Create(True);
  Loaded := TObjectList.Create(True);
  try
    FirstTask := TScanTask.Create;
    FirstTask.TargetRootName := 'first';
    FirstTask.Status := tsCompleted;
    Tasks.Add(FirstTask);
    Store.Save(Tasks);
    SecondTask := TScanTask.Create;
    SecondTask.TargetRootName := 'second';
    SecondTask.Status := tsCompleted;
    Tasks.Add(SecondTask);
    Store.Save(Tasks);
    WriteText(Store.HistoryFileName, '{invalid json');
    AssertTrue(Store.Load(Loaded, WarningText), 'backup history should recover');
    AssertEqual(1, Loaded.Count, 'backup should contain prior task set');
    AssertEqual('first', TScanTask(Loaded[0]).TargetRootName,
      'wrong task recovered from backup');
    AssertTrue(Pos('backup was loaded', WarningText) > 0,
      'recovery warning is unclear');
    AssertTrue(FindFirst(IncludeTrailingPathDelimiter(DirectoryName) +
      'history.corrupt-*.json', faAnyFile, SearchRecord) = 0,
      'malformed history was not preserved');
    FindClose(SearchRecord);
  finally
    Loaded.Free;
    Tasks.Free;
    Store.Free;
  end;
end;

procedure TestBinaryInspection;
var
  DirectoryName, FileName: string;
  Buffer: array[0..127] of Byte;
  Info: TBinaryInfo;
begin
  DirectoryName := NewTemporaryDirectory('binary-headers');
  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := Ord('M'); Buffer[1] := Ord('Z'); Buffer[$3C] := $40;
  Buffer[$40] := Ord('P'); Buffer[$41] := Ord('E');
  Buffer[$44] := $64; Buffer[$45] := $86;
  Buffer[$56] := $00; Buffer[$57] := $20;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample.dll';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'PE header was not detected');
  AssertEqual('PE', Info.FormatName, 'PE format differs');
  AssertEqual('x86_64', Info.Architecture, 'PE architecture differs');
  AssertEqual('library', Info.Classification, 'PE classification differs');

  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $7F; Buffer[1] := Ord('E'); Buffer[2] := Ord('L');
  Buffer[3] := Ord('F'); Buffer[4] := 2; Buffer[5] := 1;
  Buffer[16] := 2; Buffer[18] := 62;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample-elf';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'ELF header was not detected');
  AssertEqual('x86_64', Info.Architecture, 'ELF architecture differs');

  FillChar(Buffer, SizeOf(Buffer), 0);
  Buffer[0] := $CF; Buffer[1] := $FA; Buffer[2] := $ED; Buffer[3] := $FE;
  Buffer[4] := $07; Buffer[7] := $01;
  Buffer[12] := 2;
  FileName := IncludeTrailingPathDelimiter(DirectoryName) + 'sample-macho';
  WriteBytes(FileName, Buffer);
  AssertTrue(InspectBinary(FileName, Info), 'Mach-O header was not detected');
  AssertEqual('Mach-O', Info.FormatName, 'Mach-O format differs');
  AssertEqual('x86_64', Info.Architecture, 'Mach-O architecture differs');
end;

{**
  Verifies deterministic merging of duplicate component evidence and scopes.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when normalization loses evidence or cannot
    merge two non-empty dependency scopes.
}
procedure TestComponentDeduplication;
var
  Input, Output: TObjectList;
  First, Second, Merged: uModels.TComponent;
begin
  Input := TObjectList.Create(True);
  Output := TObjectList.Create(True);
  try
    First := uModels.TComponent.Create;
    First.Name := 'demo'; First.Version := '1.0.0'; First.Ecosystem := 'npm';
    First.PackageURL := 'pkg:npm/demo@1.0.0';
    First.SourceArtifact := 'a/package.json';
    First.DependencyScope := ' runtime, development ';
    First.EvidencePaths.Add('a/package.json');
    Input.Add(First);
    Second := uModels.TComponent.Create;
    Second.Name := 'demo'; Second.Version := '1.0.0'; Second.Ecosystem := 'npm';
    Second.PackageURL := 'pkg:npm/demo@1.0.0';
    Second.SourceArtifact := 'b/package-lock.json';
    Second.DependencyScope := 'optional, runtime';
    Second.EvidencePaths.Add('b/package-lock.json');
    Input.Add(Second);
    NormalizeComponents(Input, Output);
    AssertEqual(1, Output.Count, 'duplicate components were not merged');
    Merged := uModels.TComponent(Output[0]);
    AssertEqual(2, Merged.EvidencePaths.Count,
      'duplicate evidence paths were not merged');
    AssertEqual('development, optional, runtime', Merged.DependencyScope,
      'duplicate dependency scopes were not merged deterministically');
  finally
    Output.Free;
    Input.Free;
  end;
end;

{**
  Verifies that an escaped scan exception still completes exactly once.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised by assertion helpers when worker containment, diagnostics, timing,
    or queued completion delivery regresses.
}
procedure TestWorkerExceptionContainment;
var
  SourceTask: TScanTask;
  Worker: TFailingScanWorker;
  Observer: TCompletionObserver;
  Deadline: QWord;
begin
  SourceTask := TScanTask.Create;
  SourceTask.StartedUTC := SourceTask.CreatedUTC;
  Observer := TCompletionObserver.Create;
  Worker := TFailingScanWorker.Create(SourceTask, TemporaryRoot);
  try
    Worker.OnComplete := @Observer.Complete;
    Worker.Start;
    Deadline := GetTickCount64 + 5000;
    repeat
      CheckSynchronize(10);
      Sleep(1);
    until (Observer.Count > 0) or (GetTickCount64 >= Deadline);
    Worker.WaitFor;
    CheckSynchronize(10);
    AssertEqual(1, Observer.Count,
      'failed worker completion was not delivered exactly once');
    AssertTrue(Observer.Status = tsFailed,
      'escaped worker exception did not fail the task');
    AssertTrue(Pos('intentional worker regression failure',
      Observer.ErrorText) > 0,
      'escaped worker diagnostic was not retained');
    AssertTrue(Observer.CompletedUTC <> '',
      'failed worker task has no completion timestamp');
  finally
    Worker.Free;
    Observer.Free;
    SourceTask.Free;
  end;
end;

{**
  Scans manifest, lockfile, and Lazarus fixtures through the production engine.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when scoped evidence does not merge or production artifact
    identification/serialization omits the parsed project or current-format
    Lazarus requirement.
}
procedure TestManifestLockScan;
var
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
  Artifact: TArtifact;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, ComponentJSON, RootDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  RootReference, ComponentReferenceValue: string;
begin
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := Fixture('');
    Task.TargetRootName := 'fixtures';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task),
      'manifest-plus-lockfile directory scan failed');
    Component := FindComponent(Task.Components, 'lodash');
    AssertTrue(Component <> nil,
      'manifest-plus-lockfile scan omitted lodash');
    AssertEqual('resolved, runtime', Component.DependencyScope,
      'manifest and lockfile scopes were not merged');

    Component := FindComponent(Task.Components, 'LCL');
    AssertTrue(Component <> nil,
      'production scan omitted the current-format Lazarus requirement');
    AssertEqual('lazarus-current.lpi', Component.SourceArtifact,
      'production Lazarus component evidence path differs');
    Artifact := FindArtifact(Task.Artifacts, 'lazarus-current.lpi');
    AssertTrue(Artifact <> nil,
      'production artifact identification omitted lazarus-current.lpi');
    AssertTrue(Artifact.Status = arsParsed,
      'production Lazarus artifact should parse');
    AssertEqual('lazarus-project-xml', Artifact.ParserName,
      'production Lazarus parser identification differs');
    AssertEqual(1, Artifact.ComponentCount,
      'production Lazarus artifact component count differs');

    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('fixtures', JSONString(Primary, 'name'),
        'production root folder name differs');
      AssertEqual('pkg:npm/fixture-app@1.2.3', JSONString(Primary, 'purl'),
        'parsed project component was not promoted');
      RootReference := JSONString(Primary, 'bom-ref');
      Components := JSONArray(Root, 'components');
      AssertTrue(FindJSONObjectByString(Components, 'name',
        'fixture-app') = nil, 'parsed project remains duplicated');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'lodash');
      AssertTrue(ComponentJSON <> nil,
        'production CycloneDX components omitted lodash');
      ComponentReferenceValue := JSONString(ComponentJSON, 'bom-ref');
      Dependencies := JSONArray(Root, 'dependencies');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        RootReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertTrue(JSONArrayContainsString(DependsOn,
        ComponentReferenceValue),
        'production manifest edge to lodash is missing');
    finally
      Data.Free;
    end;
  finally
    Engine.Free;
    Task.Free;
  end;
end;

{**
  Verifies stable synthetic roots and conservative multi-project handling.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when task IDs affect root identity, filesystem roots leak as names,
    or ambiguous projects are promoted instead of remaining explicit.
}
procedure TestCycloneDXSyntheticRoot;
var
  Task: TScanTask;
  Content: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, RootDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  FirstReference, SecondReference: string;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '11111111-2222-3333-4444-555555555555';
    Task.TargetDirectory := '/first/location/repeated-name';
    Task.ScannerVersion := AppVersion;
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      FirstReference := JSONString(Primary, 'bom-ref');
      AssertTrue(FirstReference <> '', 'synthetic root reference is missing');
    finally
      Data.Free;
    end;

    Task.ID := 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      SecondReference := JSONString(Primary, 'bom-ref');
      AssertEqual(FirstReference, SecondReference,
        'synthetic root reference changed with the task ID');
    finally
      Data.Free;
    end;

    AddFixtureComponent(Task, 'project-one', '1.0.0', 'npm',
      'pkg:npm/project-one@1.0.0', 'one/package.json', 'package-json',
      'project', 'application');
    AddFixtureComponent(Task, 'project-two', '2.0.0', 'npm',
      'pkg:npm/project-two@2.0.0', 'two/package.json', 'package-json',
      'project', 'application');
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual(FirstReference, JSONString(Primary, 'bom-ref'),
        'ambiguous projects replaced the synthetic root');
      Components := JSONArray(Root, 'components');
      AssertEqual(2, Components.Count,
        'ambiguous project components should remain explicit');
      Dependencies := JSONArray(Root, 'dependencies');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        FirstReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertEqual(2, DependsOn.Count,
        'ambiguous projects should remain root dependencies');
    finally
      Data.Free;
    end;

    Task.TargetDirectory := '/';
    Task.TargetRootName := '/';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('scanned-project', JSONString(Primary, 'name'),
        'Unix filesystem root leaked as the primary component name');
    finally
      Data.Free;
    end;

    Task.TargetDirectory := 'C:\';
    Task.TargetRootName := 'C:\';
    Content := GenerateCycloneDX(Task);
    Data := GetJSON(string(Content));
    try
      Root := TJSONObject(Data);
      Metadata := JSONObject(Root, 'metadata');
      Primary := JSONObject(Metadata, 'component');
      AssertEqual('scanned-project', JSONString(Primary, 'name'),
        'Windows filesystem root leaked as the primary component name');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
  end;
end;

{**
  Verifies CycloneDX subject promotion, honest fields, scopes, and graph edges.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when either supported schema version loses subject identity,
    component semantics, retained evidence, or a directly observed graph edge.
  EFCreateError, EWriteError
    Propagated when the optional CI schema fixtures cannot be written.
}
procedure TestCycloneDXStructure;
var
  Task: TScanTask;
  ProjectComponent, SharedComponent: uModels.TComponent;
  Artifact: TArtifact;
  SBOM16, SBOM17: UTF8String;
  Data: TJSONData;
  Root, Metadata, Primary, ComponentJSON, RuntimeJSON, RangeJSON,
    OptionalJSON, PeerJSON, ResolvedJSON, MergedJSON, BuildJSON, BinaryJSON,
    SecondBinaryJSON, LibcJSON, DottedJSON, SharedJSON, RootDependency, BinaryDependency,
    SecondBinaryDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  RootReference, RuntimeReference, RangeReference, OptionalReference,
    PeerReference, ResolvedReference, MergedReference, BinaryReference,
    SecondBinaryReference, LibcReference,
    DottedReference, SharedReference, SystemReference, PropertyValue,
    FixtureDirectory: string;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := '/private/acme/fixture-root/';
    Task.TargetRootName := 'stale-root-name';
    Task.ScannerVersion := AppVersion;

    ProjectComponent := AddFixtureComponent(Task, 'fixture-app', '1.2.3',
      'npm', 'pkg:npm/fixture-app@1.2.3', 'package.json', 'package-json',
      'project', 'application');
    ProjectComponent.SHA256 := SHA256String('fixture-project');
    AddFixtureComponent(Task, 'lodash', '4.17.21', 'npm',
      'pkg:npm/lodash@4.17.21', 'package.json', 'package-json', 'runtime',
      'library');
    AddFixtureComponent(Task, 'vitest', '^2.0.0', 'npm', '', 'package.json',
      'package-json', 'development', 'library');
    AddFixtureComponent(Task, 'optional-tool', '1.1.0', 'npm',
      'pkg:npm/optional-tool@1.1.0', 'package.json', 'package-json',
      'optional', 'library');
    AddFixtureComponent(Task, 'peer-tool', '1.0.0', 'npm',
      'pkg:npm/peer-tool@1.0.0', 'package.json', 'package-json', 'peer',
      'library');
    AddFixtureComponent(Task, 'locked-tool', '3.0.0', 'npm',
      'pkg:npm/locked-tool@3.0.0', 'package-lock.json',
      'package-lock-json', 'resolved', 'library');
    AddFixtureComponent(Task, 'merged-tool', '2.0.0', 'npm',
      'pkg:npm/merged-tool@2.0.0', 'package.json', 'package-json',
      'development, runtime', 'library');

    AddFixtureComponent(Task, 'demo-tool', '', 'native', '', 'bin/demo-tool',
      'binary-header', '', 'application');
    AddFixtureComponent(Task, 'libc.so.6', '6', 'native', '', 'bin/demo-tool',
      'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(Task, 'libdemo.so.1.2.3', '1.2.3', 'native', '',
      'bin/demo-tool', 'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(Task, 'libsystem.so.2', '', 'native', '',
      'bin/demo-tool', 'readelf', 'runtime', 'library');
    AddFixtureComponent(Task, 'libbuild.so.1', '', 'native', '',
      'bin/demo-tool', 'binary-dependency-table', 'build', 'library');
    AddFixtureComponent(Task, 'libother.so.1', '', 'native', '',
      'bin/other-tool', 'binary-dependency-table', 'runtime', 'library');
    SharedComponent := AddFixtureComponent(Task, 'libshared.so.7', '',
      'native', '', 'bin/demo-tool', 'binary-dependency-table', 'runtime',
      'library');
    SharedComponent.EvidencePaths.Add('bin/demo-copy');
    AddFixtureComponent(Task, 'demo-copy', '', 'native', '', 'bin/demo-copy',
      'binary-header', '', 'application');

    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'bin/demo-tool';
    Artifact.ArtifactType := 'ELF executable';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);

    SBOM16 := GenerateCycloneDX(Task, cdxSpec16);
    SBOM17 := GenerateCycloneDX(Task);
    FixtureDirectory := GetEnvironmentVariable(
      'PURPLERAY_CYCLONEDX_FIXTURE_DIR');
    if FixtureDirectory <> '' then
    begin
      if not ForceDirectories(FixtureDirectory) then
        Fail('Unable to create CycloneDX schema-fixture directory: ' +
          FixtureDirectory);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'fixture-1.6.cdx.json', SBOM16);
      WriteUTF8File(IncludeTrailingPathDelimiter(FixtureDirectory) +
        'fixture-1.7.cdx.json', SBOM17);
    end;

    Data := GetJSON(string(SBOM16));
    try
      AssertTrue(Data.JSONType = jtObject,
        'CycloneDX 1.6 output root is not an object');
      Root := TJSONObject(Data);
      AssertEqual('1.6', JSONString(Root, 'specVersion'),
        'explicit CycloneDX compatibility version differs');
      AssertEqual('https://cyclonedx.org/schema/bom-1.6.schema.json',
        JSONString(Root, '$schema'), 'CycloneDX 1.6 schema URL differs');
    finally
      Data.Free;
    end;

    Data := GetJSON(string(SBOM17));
    try
      AssertTrue(Data.JSONType = jtObject,
        'CycloneDX 1.7 output root is not an object');
      Root := TJSONObject(Data);
      AssertEqual('1.7', JSONString(Root, 'specVersion'),
        'default CycloneDX version differs');
      AssertEqual('https://cyclonedx.org/schema/bom-1.7.schema.json',
        JSONString(Root, '$schema'), 'CycloneDX 1.7 schema URL differs');

      Metadata := JSONObject(Root, 'metadata');
      AssertTrue(Metadata <> nil, 'CycloneDX metadata is missing');
      Primary := JSONObject(Metadata, 'component');
      AssertTrue(Primary <> nil, 'metadata.component is missing');
      AssertEqual('application', JSONString(Primary, 'type'),
        'primary component type differs');
      AssertEqual('fixture-root', JSONString(Primary, 'name'),
        'primary component must use the target-folder basename');
      AssertEqual('1.2.3', JSONString(Primary, 'version'),
        'project version was not promoted');
      AssertEqual('pkg:npm/fixture-app@1.2.3', JSONString(Primary, 'purl'),
        'project purl was not promoted');
      RootReference := JSONString(Primary, 'bom-ref');
      AssertEqual('pkg:npm/fixture-app@1.2.3', RootReference,
        'promoted project reference differs');
      AssertTrue(Primary.Find('scope') = nil,
        'project scope must use the required default');

      Components := JSONArray(Root, 'components');
      AssertTrue(Components <> nil, 'CycloneDX components are missing');
      AssertEqual(14, Components.Count,
        'promoted project component was not removed exactly once');
      AssertTrue(FindJSONObjectByString(Components, 'name', 'fixture-app') = nil,
        'promoted project remains duplicated in components');

      RuntimeJSON := FindJSONObjectByString(Components, 'name', 'lodash');
      RangeJSON := FindJSONObjectByString(Components, 'name', 'vitest');
      OptionalJSON := FindJSONObjectByString(Components, 'name',
        'optional-tool');
      PeerJSON := FindJSONObjectByString(Components, 'name', 'peer-tool');
      ResolvedJSON := FindJSONObjectByString(Components, 'name',
        'locked-tool');
      MergedJSON := FindJSONObjectByString(Components, 'name', 'merged-tool');
      BuildJSON := FindJSONObjectByString(Components, 'name', 'libbuild.so.1');
      BinaryJSON := FindJSONObjectByString(Components, 'name', 'demo-tool');
      SecondBinaryJSON := FindJSONObjectByString(Components, 'name',
        'demo-copy');
      LibcJSON := FindJSONObjectByString(Components, 'name', 'libc.so.6');
      DottedJSON := FindJSONObjectByString(Components, 'name',
        'libdemo.so.1.2.3');
      SharedJSON := FindJSONObjectByString(Components, 'name',
        'libshared.so.7');
      ComponentJSON := FindJSONObjectByString(Components, 'name',
        'libsystem.so.2');
      AssertTrue((RuntimeJSON <> nil) and (RangeJSON <> nil) and
        (OptionalJSON <> nil) and (PeerJSON <> nil) and
        (ResolvedJSON <> nil) and (MergedJSON <> nil) and
        (BuildJSON <> nil) and (BinaryJSON <> nil) and
        (SecondBinaryJSON <> nil) and (LibcJSON <> nil) and
        (DottedJSON <> nil) and (SharedJSON <> nil) and
        (ComponentJSON <> nil), 'CycloneDX fixture components are incomplete');

      AssertTrue(RangeJSON.Find('version') = nil,
        'requested range leaked into the CycloneDX version field');
      AssertEqual('excluded', JSONString(RangeJSON, 'scope'),
        'development dependency scope differs');
      AssertTrue(FindCycloneProperty(RangeJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'requested-range property is missing');
      AssertEqual('^2.0.0', PropertyValue,
        'requested-range property value differs');
      AssertTrue(FindCycloneProperty(RangeJSON,
        'purpleray-sbom-analyzer:dependency-scope', PropertyValue),
        'custom dependency-scope property was lost');
      AssertEqual('development', PropertyValue,
        'custom development scope differs');
      AssertEqual('optional', JSONString(OptionalJSON, 'scope'),
        'optional dependency scope differs');
      AssertEqual('optional', JSONString(PeerJSON, 'scope'),
        'peer dependency must map to optional');
      AssertTrue(ResolvedJSON.Find('scope') = nil,
        'resolved dependency must use the required default');
      AssertTrue(MergedJSON.Find('scope') = nil,
        'runtime plus development must remain required');
      AssertTrue(RuntimeJSON.Find('scope') = nil,
        'runtime must use the required default');
      AssertTrue(BuildJSON.Find('scope') = nil,
        'build dependency must use the required default');

      AssertTrue(LibcJSON.Find('version') = nil,
        'bare SONAME ABI leaked into version');
      AssertTrue(FindCycloneProperty(LibcJSON,
        'purpleray-sbom-analyzer:soname-abi-version', PropertyValue),
        'SONAME ABI property is missing');
      AssertEqual('6', PropertyValue, 'SONAME ABI property differs');
      AssertTrue(not FindCycloneProperty(LibcJSON,
        'purpleray-sbom-analyzer:requested-range', PropertyValue),
        'persisted SONAME ABI was mislabeled as a requested range');
      AssertEqual('1.2.3', JSONString(DottedJSON, 'version'),
        'dotted native product version was lost');

      RuntimeReference := JSONString(RuntimeJSON, 'bom-ref');
      RangeReference := JSONString(RangeJSON, 'bom-ref');
      OptionalReference := JSONString(OptionalJSON, 'bom-ref');
      PeerReference := JSONString(PeerJSON, 'bom-ref');
      ResolvedReference := JSONString(ResolvedJSON, 'bom-ref');
      MergedReference := JSONString(MergedJSON, 'bom-ref');
      BinaryReference := JSONString(BinaryJSON, 'bom-ref');
      SecondBinaryReference := JSONString(SecondBinaryJSON, 'bom-ref');
      LibcReference := JSONString(LibcJSON, 'bom-ref');
      DottedReference := JSONString(DottedJSON, 'bom-ref');
      SharedReference := JSONString(SharedJSON, 'bom-ref');
      SystemReference := JSONString(ComponentJSON, 'bom-ref');

      Dependencies := JSONArray(Root, 'dependencies');
      AssertTrue(Dependencies <> nil, 'CycloneDX dependency graph is missing');
      AssertEqual(3, Dependencies.Count,
        'dependency graph must contain root and two binary owners');
      AssertEqual(RootReference,
        JSONString(TJSONObject(Dependencies.Items[0]), 'ref'),
        'metadata root must be the first dependency entry');
      RootDependency := FindJSONObjectByString(Dependencies, 'ref',
        RootReference);
      DependsOn := JSONArray(RootDependency, 'dependsOn');
      AssertEqual(6, DependsOn.Count,
        'root direct-manifest dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, RuntimeReference) and
        JSONArrayContainsString(DependsOn, RangeReference) and
        JSONArrayContainsString(DependsOn, OptionalReference) and
        JSONArrayContainsString(DependsOn, PeerReference) and
        JSONArrayContainsString(DependsOn, ResolvedReference) and
        JSONArrayContainsString(DependsOn, MergedReference),
        'root manifest dependency edges are incomplete');
      AssertTrue(not JSONArrayContainsString(DependsOn, BinaryReference) and
        not JSONArrayContainsString(DependsOn, LibcReference),
        'root graph inferred unsupported native edges');

      BinaryDependency := FindJSONObjectByString(Dependencies, 'ref',
        BinaryReference);
      DependsOn := JSONArray(BinaryDependency, 'dependsOn');
      AssertEqual(4, DependsOn.Count,
        'first binary direct-dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, LibcReference) and
        JSONArrayContainsString(DependsOn, DottedReference) and
        JSONArrayContainsString(DependsOn, SharedReference) and
        JSONArrayContainsString(DependsOn, SystemReference),
        'first binary dependency-table edges are incomplete');
      SecondBinaryDependency := FindJSONObjectByString(Dependencies, 'ref',
        SecondBinaryReference);
      DependsOn := JSONArray(SecondBinaryDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'second binary must have only the merged shared dependency');
      AssertTrue(JSONArrayContainsString(DependsOn, SharedReference),
        'merged cross-artifact evidence lost the second binary edge');
      AssertTrue(FindJSONObjectByString(Dependencies, 'ref', LibcReference) = nil,
        'leaf dependency received an inferred transitive graph entry');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
  end;
end;

{**
  Verifies binary graph edges survive production component normalization.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a scanned library header merged with another binary's direct
    dependency evidence loses its owner edge or creates a transitive edge.
}
procedure TestCycloneDXNormalizedBinaryGraph;
var
  RawTask, Task: TScanTask;
  Artifact: TArtifact;
  Component: uModels.TComponent;
  SBOM: UTF8String;
  Data: TJSONData;
  Root, ComponentJSON, AppDependency, LibraryDependency: TJSONObject;
  Components, Dependencies, DependsOn: TJSONArray;
  AppReference, LibraryReference, LibcReference: string;
begin
  RawTask := TScanTask.Create;
  Task := TScanTask.Create;
  try
    Task.TargetDirectory := '/private/normalized-binary-graph';
    Task.TargetRootName := 'normalized-binary-graph';
    Task.ScannerVersion := AppVersion;

    AddFixtureComponent(RawTask, 'app', '', 'native', '', 'bin/app',
      'binary-header', '', 'application');
    AddFixtureComponent(RawTask, 'libfoo.so.1.2.3', '1.2.3', 'native', '',
      'bin/app', 'binary-dependency-table', 'runtime', 'library');
    AddFixtureComponent(RawTask, 'libfoo.so.1.2.3', '1.2.3', 'native', '',
      'lib/libfoo.so.1.2.3', 'binary-header', '', 'library');
    AddFixtureComponent(RawTask, 'libc.so.6', '', 'native', '',
      'lib/libfoo.so.1.2.3', 'binary-dependency-table', 'runtime', 'library');
    NormalizeComponents(RawTask.Components, Task.Components);
    AssertEqual(3, Task.Components.Count,
      'binary normalization fixture did not merge exactly one identity');
    Component := FindComponent(Task.Components, 'libfoo.so.1.2.3');
    AssertTrue(Component <> nil, 'normalized library component is missing');
    AssertEqual('binary-dependency-table', Component.SourceParser,
      'regression fixture did not collapse the binary-header parser pair');
    AssertEqual(2, Component.EvidencePaths.Count,
      'normalized library did not retain both binary evidence paths');

    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'bin/app';
    Artifact.ArtifactType := 'ELF executable';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);
    Artifact := TArtifact.Create;
    Artifact.RelativePath := 'lib/libfoo.so.1.2.3';
    Artifact.ArtifactType := 'ELF library';
    Artifact.ParserName := 'binary-header';
    Artifact.Status := arsParsed;
    Task.Artifacts.Add(Artifact);

    SBOM := GenerateCycloneDX(Task);
    Data := GetJSON(string(SBOM));
    try
      Root := TJSONObject(Data);
      Components := JSONArray(Root, 'components');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'app');
      AssertTrue(ComponentJSON <> nil, 'binary application node is missing');
      AppReference := JSONString(ComponentJSON, 'bom-ref');
      ComponentJSON := FindJSONObjectByString(Components, 'name',
        'libfoo.so.1.2.3');
      AssertTrue(ComponentJSON <> nil, 'binary library owner node is missing');
      LibraryReference := JSONString(ComponentJSON, 'bom-ref');
      ComponentJSON := FindJSONObjectByString(Components, 'name', 'libc.so.6');
      AssertTrue(ComponentJSON <> nil, 'normalized leaf library is missing');
      LibcReference := JSONString(ComponentJSON, 'bom-ref');

      Dependencies := JSONArray(Root, 'dependencies');
      AssertEqual(3, Dependencies.Count,
        'normalized graph must contain root and two binary owners');
      AppDependency := FindJSONObjectByString(Dependencies, 'ref',
        AppReference);
      AssertTrue(AppDependency <> nil,
        'application dependency entry is missing');
      DependsOn := JSONArray(AppDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'application received a lost or inferred dependency edge');
      AssertTrue(JSONArrayContainsString(DependsOn, LibraryReference),
        'application-to-library direct edge was lost during normalization');
      AssertTrue(not JSONArrayContainsString(DependsOn, LibcReference),
        'application received an inferred transitive libc edge');

      LibraryDependency := FindJSONObjectByString(Dependencies, 'ref',
        LibraryReference);
      AssertTrue(LibraryDependency <> nil,
        'scanned library dependency entry is missing after normalization');
      DependsOn := JSONArray(LibraryDependency, 'dependsOn');
      AssertEqual(1, DependsOn.Count,
        'scanned library direct-dependency count differs');
      AssertTrue(JSONArrayContainsString(DependsOn, LibcReference),
        'library-to-libc direct edge was lost during normalization');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
    RawTask.Free;
  end;
end;

procedure TestDeterministicCycloneDX;
var
  Task: TScanTask;
  Component: uModels.TComponent;
  First, Second: UTF8String;
begin
  Task := TScanTask.Create;
  try
    Task.ID := '00112233-4455-6677-8899-aabbccddeeff';
    Task.CreatedUTC := '2025-01-02T03:04:05.000Z';
    Task.StartedUTC := Task.CreatedUTC;
    Task.TargetDirectory := '/secret/work';
    Task.ScannerVersion := '1.2.3';
    Component := uModels.TComponent.Create;
    Component.Name := 'demo'; Component.Version := '1.0.0';
    Component.Ecosystem := 'npm'; Component.PackageURL := 'pkg:npm/demo@1.0.0';
    Component.SourceArtifact := 'src/package.json';
    Component.SourceParser := 'package-json';
    Component.EvidencePaths.Add('src/package.json');
    Task.Components.Add(Component);
    First := GenerateCycloneDX(Task);
    Second := GenerateCycloneDX(Task);
    AssertEqual(string(First), string(Second),
      'CycloneDX generation is not deterministic');
    AssertTrue(Pos('/secret/work', string(First)) = 0,
      'default CycloneDX output leaked the absolute target path');
    AssertTrue(Pos('"specVersion" : "1.7"', string(First)) > 0,
      'CycloneDX version is missing');
    AssertTrue(Pos('"name" : "PurpleRay SBOM Analyzer"', string(First)) > 0,
      'renamed scanner identity is missing from CycloneDX output');
    AssertTrue(Pos('purpleray-sbom-analyzer:inspection-method',
      string(First)) > 0,
      'renamed scanner property namespace is missing from CycloneDX output');
    AssertTrue(Pos('"version" : "1.0.0"', string(First)) > 0,
      'known component version is missing from CycloneDX output');
  finally
    Task.Free;
  end;
end;

procedure TestIgnoreMatching;
var
  Settings: TScanSettings;
begin
  Settings := TScanSettings.Create;
  try
    AssertTrue(ShouldIgnorePath('src/node_modules', True,
      Settings.IgnorePatterns), 'node_modules default ignore is missing');
    AssertTrue(ShouldIgnorePath('deep/.git/config', False,
      Settings.IgnorePatterns), '.git contents should be ignored');
    AssertTrue(not ShouldIgnorePath('dist/output', True,
      Settings.IgnorePatterns), 'dist must not be ignored by default');
    Settings.IgnorePatterns.Add('generated/*/cache');
    AssertTrue(ShouldIgnorePath('generated/x/cache', True,
      Settings.IgnorePatterns), 'relative wildcard did not match');
    AssertTrue(WildcardMatches('requirements*.txt', 'requirements-dev.txt'),
      'simple wildcard did not match');
  finally
    Settings.Free;
  end;
end;

{**
  Verifies that a named pipe is warned about and never opened by the scanner.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when FIFO creation fails or scanner counters/warnings show that the
    special entry reached file processing.
}
procedure TestSpecialFileSkip;
{$IFDEF UNIX}
var
  RootName, FifoName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Writer: TFIFOWriter;
begin
  RootName := NewTemporaryDirectory('special-file-skip');
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'ordinary.txt', 'safe');
  FifoName := IncludeTrailingPathDelimiter(RootName) + 'events.pipe';
  if fpMkFifo(PChar(FifoName), 384) <> 0 then
    Fail('Unable to create FIFO fixture: ' + SysErrorMessage(fpGetErrNo));
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  Writer := TFIFOWriter.Create(FifoName);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'special-file-skip';
    Task.Settings.CalculateSHA256 := False;
    Writer.Start;
    AssertTrue(Engine.Scan(Task), 'scan containing a FIFO should finish');
    AssertEqual(1, Task.FilesInspected,
      'FIFO should not be counted as an inspected file');
    AssertTrue(StringListContainsText(Task.Warnings, 'events.pipe') and
      StringListContainsText(Task.Warnings, 'non-regular'),
      'FIFO skip warning should name the non-regular entry');
  finally
    Writer.Terminate;
    Writer.WaitFor;
    Writer.Free;
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix named-pipe support');
end;
{$ENDIF}

{**
  Verifies Windows device and offline attributes are rejected before opening.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when captured Windows attributes are classified as regular inputs.
}
procedure TestWindowsSpecialAttributeClassification;
{$IFDEF Windows}
var
  Reason: string;
begin
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_DEVICE, 0, Reason) =
    fsekUnsupported, 'Windows device attribute should be unsupported');
  AssertEqual('device', Reason,
    'Windows device classification reason differs');
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_OFFLINE, 0, Reason) =
    fsekUnsupported, 'Windows offline attribute should be unsupported');
  AssertEqual('offline file', Reason,
    'Windows offline classification reason differs');
  AssertTrue(ClassifyFileSystemEntry(FILE_ATTRIBUTE_DIRECTORY, 0, Reason) =
    fsekDirectory, 'Windows directory attribute classification differs');
  AssertTrue(ClassifyFileSystemEntry(0, 0, Reason) = fsekRegularFile,
    'ordinary Windows file classification differs');
end;
{$ELSE}
begin
  SkipTest('requires Windows file-attribute constants');
end;
{$ENDIF}

{**
  Verifies platform-specific end-of-directory and enumeration-error handling.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when normal enumeration exhaustion is reported as a failure or a
    real continuation error is silently accepted.
}
procedure TestDirectoryEnumerationErrors;
var
  Reason: string;
{$IFDEF Windows}
  RootName, MissingName: string;
{$ENDIF}
begin
  ResetDirectoryEnumerationError;
  {$IFDEF UNIX}
  AssertTrue(not DirectoryEnumerationContinuationFailed(-1, Reason),
    'Unix end-of-directory sentinel should not be an enumeration failure');
  AssertEqual('', Reason,
    'Unix normal end-of-directory should have no diagnostic');
  try
    fpSetErrNo(ESysEIO);
    AssertTrue(DirectoryEnumerationContinuationFailed(-1, Reason),
      'Unix FindNext I/O error should be reported');
    AssertTrue(Reason <> '',
      'Unix FindNext I/O error should retain a diagnostic');
  finally
    ResetDirectoryEnumerationError;
  end;
  {$ENDIF}
  {$IFDEF Windows}
  AssertTrue(not DirectoryEnumerationContinuationFailed(
    ERROR_NO_MORE_FILES, Reason),
    'Windows end-of-directory code should not be an enumeration failure');
  AssertEqual('', Reason,
    'Windows normal end-of-directory should have no diagnostic');
  AssertTrue(DirectoryEnumerationContinuationFailed(
    ERROR_ACCESS_DENIED, Reason),
    'Windows FindNext access denial should be reported');
  AssertTrue(Reason <> '',
    'Windows FindNext access denial should retain a diagnostic');

  RootName := NewTemporaryDirectory('windows-directory-errors');
  AssertTrue(not DirectoryEnumerationFailed(RootName,
    ERROR_FILE_NOT_FOUND, Reason),
    'Windows empty existing directory should not be an enumeration failure');
  AssertEqual('', Reason,
    'Windows empty existing directory should have no diagnostic');
  MissingName := IncludeTrailingPathDelimiter(RootName) + 'missing';
  AssertTrue(DirectoryEnumerationFailed(MissingName,
    ERROR_PATH_NOT_FOUND, Reason),
    'Windows missing directory should be an enumeration failure');
  AssertTrue(Reason <> '',
    'Windows missing directory should retain a diagnostic');
  {$ENDIF}
  {$IFNDEF UNIX}
  {$IFNDEF Windows}
  SkipTest('requires Unix or Windows enumeration semantics');
  {$ENDIF}
  {$ENDIF}
end;

{**
  Verifies case-preserving Linux enumeration and ordinal artifact ordering.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when either case-variant is dropped, receives incorrect metadata,
    or is emitted outside ordinal path order.
}
procedure TestCasePreservingEnumeration;
{$IFDEF LINUX}
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Artifact: TArtifact;
  UpperContent, LowerContent: RawByteString;
begin
  RootName := NewTemporaryDirectory('case-preserving-enumeration');
  LowerContent := 'lower-package==2.0.0' + LineEnding;
  UpperContent := 'upper-package==1.0.0' + LineEnding;
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirements.txt',
    LowerContent);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'Requirements.txt',
    UpperContent);
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'case-preserving-enumeration';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'case-variant scan should finish');
    AssertEqual(2, Task.FilesInspected,
      'case-variant filename was silently dropped');
    AssertEqual(Length(UpperContent) + Length(LowerContent),
      Task.BytesInspected,
      'case-variant file sizes were not retained');
    AssertEqual(2, Task.Artifacts.Count,
      'case-variant requirements artifacts were not both retained');
    Artifact := FindArtifact(Task.Artifacts, 'Requirements.txt');
    AssertTrue(Artifact <> nil,
      'uppercase requirements artifact is missing');
    AssertEqual(Length(UpperContent), Artifact.FileSize,
      'uppercase requirements artifact size differs');
    Artifact := FindArtifact(Task.Artifacts, 'requirements.txt');
    AssertTrue(Artifact <> nil,
      'lowercase requirements artifact is missing');
    AssertEqual(Length(LowerContent), Artifact.FileSize,
      'lowercase requirements artifact size differs');
    AssertEqual('Requirements.txt',
      TArtifact(Task.Artifacts[0]).RelativePath,
      'case-variant artifacts are not in ordinal order');
    AssertEqual('requirements.txt',
      TArtifact(Task.Artifacts[1]).RelativePath,
      'case-variant artifact ordinal order differs');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires a case-sensitive Linux filesystem');
end;
{$ENDIF}

{**
  Verifies literal wildcard characters cannot redirect artifact metadata.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a literal question-mark artifact is lost, assigned another
    entry's size, or emitted outside ordinal path order.
}
procedure TestGlobMetacharacterEnumeration;
{$IFDEF UNIX}
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  LiteralArtifact, AlternateArtifact: TArtifact;
  LiteralContent, AlternateContent: RawByteString;
begin
  RootName := NewTemporaryDirectory('glob-metachar-enumeration');
  AlternateContent := 'alternate-package==22.0.0' + LineEnding;
  LiteralContent := 'literal-package==1.0.0' + LineEnding;
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirementsA.txt',
    AlternateContent);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'requirements?.txt',
    LiteralContent);
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'glob-metachar-enumeration';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task), 'glob-metacharacter scan should finish');
    AssertEqual(2, Task.FilesInspected,
      'glob-metacharacter filename was not independently processed');
    AssertEqual(2, Task.Artifacts.Count,
      'glob-metacharacter requirements artifacts were not both retained');
    LiteralArtifact := FindArtifact(Task.Artifacts, 'requirements?.txt');
    AlternateArtifact := FindArtifact(Task.Artifacts, 'requirementsA.txt');
    AssertTrue(LiteralArtifact <> nil,
      'literal question-mark artifact is missing');
    AssertTrue(AlternateArtifact <> nil,
      'alternate wildcard-match artifact is missing');
    AssertEqual(Length(LiteralContent), LiteralArtifact.FileSize,
      'literal question-mark artifact received another entry''s size');
    AssertEqual(Length(AlternateContent), AlternateArtifact.FileSize,
      'alternate wildcard-match artifact size differs');
    AssertEqual('requirements?.txt',
      TArtifact(Task.Artifacts[0]).RelativePath,
      'glob-metacharacter artifacts are not in ordinal order');
    AssertEqual('requirementsA.txt',
      TArtifact(Task.Artifacts[1]).RelativePath,
      'glob-metacharacter artifact ordinal order differs');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix support for a literal question mark in a filename');
end;
{$ENDIF}

{**
  Verifies unreadable directories are reported instead of silently omitted.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  Exception
    Raised when a permission-denied subtree or target root produces no warning.
}
procedure TestUnreadableDirectoryWarning;
{$IFDEF UNIX}
var
  RootName, RestrictedName: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  if fpGetUID = 0 then
    SkipTest('chmod 000 is not an effective denial fixture for UID 0');
  RootName := NewTemporaryDirectory('unreadable-directory');
  RestrictedName := IncludeTrailingPathDelimiter(RootName) + 'restricted';
  ForceDirectories(RestrictedName);
  WriteText(IncludeTrailingPathDelimiter(RootName) + 'visible.txt', 'v');
  WriteText(IncludeTrailingPathDelimiter(RestrictedName) + 'hidden.txt', 'x');
  if fpChmod(PChar(RestrictedName), 0) <> 0 then
    Fail('Unable to restrict directory fixture: ' +
      SysErrorMessage(fpGetErrNo));
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'unreadable-directory';
    Task.Settings.CalculateSHA256 := False;
    AssertTrue(Engine.Scan(Task),
      'scan with an unreadable subtree should retain partial results');
    AssertEqual(1, Task.FilesInspected,
      'unreadable subtree contents should not be reported as inspected');
    AssertTrue(StringListContainsText(Task.Warnings, 'restricted') and
      StringListContainsText(Task.Warnings, 'unable to enumerate'),
      'unreadable subtree warning should name the omitted directory');

    Task.TargetDirectory := RestrictedName;
    Task.TargetRootName := 'restricted';
    AssertTrue(Engine.Scan(Task),
      'unreadable target root should complete with an explicit warning');
    AssertEqual(0, Task.FilesInspected,
      'unreadable target root should not report inspected files');
    AssertTrue(StringListContainsText(Task.Warnings, 'unable to enumerate'),
      'unreadable target root was presented as a clean empty scan');
  finally
    fpChmod(PChar(RestrictedName), 448);
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix permission semantics');
end;
{$ENDIF}

procedure TestSymlinkLoopPrevention;
{$IFDEF UNIX}
var
  RootName, PackageName, LinkName: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  RootName := NewTemporaryDirectory('symlink-loop');
  ForceDirectories(IncludeTrailingPathDelimiter(RootName) + 'a');
  PackageName := IncludeTrailingPathDelimiter(RootName) + 'a/package.json';
  WriteText(PackageName, '{"name":"loop-fixture","version":"1.0.0"}');
  LinkName := IncludeTrailingPathDelimiter(RootName) + 'a/loop';
  if fpSymlink(PChar(IncludeTrailingPathDelimiter(RootName) + 'a'),
    PChar(LinkName)) <> 0 then
    Fail('Unable to create symlink-loop fixture');
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'symlink-loop';
    Task.Settings.FollowSymbolicLinks := True;
    AssertTrue(Engine.Scan(Task), 'scan with symlink loop should finish');
    AssertEqual(1, Task.FilesInspected,
      'symlink loop caused a file to be scanned repeatedly');
    AssertTrue(Task.Warnings.Count > 0, 'symlink loop should produce a warning');
  finally
    Engine.Free;
    Task.Free;
  end;
end;
{$ELSE}
begin
  SkipTest('requires Unix symbolic-link support');
end;
{$ENDIF}

procedure TestScanCancellation;
var
  RootName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Controller: TCancelController;
  I: Integer;
begin
  RootName := NewTemporaryDirectory('cancellation');
  for I := 1 to 30 do
    WriteText(IncludeTrailingPathDelimiter(RootName) + Format('file-%.2d.txt', [I]),
      'ordinary content');
  Task := TScanTask.Create;
  Controller := TCancelController.Create(8);
  Engine := TScanEngine.Create(@Controller.Check, nil);
  try
    Task.TargetDirectory := RootName;
    Task.TargetRootName := 'cancellation';
    AssertTrue(not Engine.Scan(Task), 'cancelled scan reported success');
    AssertTrue(Task.Status = tsCancelled, 'cancelled scan status differs');
    AssertTrue(Task.FilesInspected < 30,
      'cancellation did not stop directory traversal');
  finally
    Engine.Free;
    Controller.Free;
    Task.Free;
  end;
end;

{**
  Executes one test case and records a pass or failure without aborting the run.

  Parameters
  ----------
  AName
    Human-readable test name written to the console.
  AMethod
    Test procedure to invoke.

  Returns
  -------
  None

  Raises
  ------
  None
    Test exceptions are counted as failures; ETestSkipped is counted and
    reported separately.
}
procedure RunTest(const AName: string; AMethod: TTestMethod);
begin
  Inc(TestCount);
  try
    AMethod();
    Inc(PassCount);
    WriteLn('[PASS] ', AName);
  except
    on E: ETestSkipped do
    begin
      Inc(SkipCount);
      WriteLn('[SKIP] ', AName, ': ', E.Message);
    end;
    on E: Exception do
    begin
      Inc(FailureCount);
      WriteLn(StdErr, '[FAIL] ', AName, ': ', E.Message);
    end;
  end;
end;

begin
  ProjectRoot := ExpandFileName(ExtractFilePath(ParamStr(0)) + '..' +
    DirectorySeparator + '..');
  TemporaryRoot := IncludeTrailingPathDelimiter(GetTempDir(False)) +
    'purpleray-sbom-analyzer-tests-' + NewTaskID;
  ForceDirectories(TemporaryRoot);
  RunTest('SHA-256 vectors', @TestSHA256);
  RunTest('displayed product version', @TestDisplayedVersion);
  RunTest('application shell structure', @TestApplicationShellStructure);
  RunTest('settings dialog DPI-stable layout',
    @TestScanSettingsDialogDPIStableLayout);
  RunTest('requirements parser', @TestRequirementsParser);
  RunTest('Package URL normalization', @TestPackageURLNormalization);
  RunTest('Gradle and Conda purls', @TestGradleAndCondaPURLs);
  RunTest('declared version and scope semantics',
    @TestDeclaredVersionAndScopeSemantics);
  RunTest('package.json parser', @TestPackageJSONParser);
  RunTest('package-lock.json parser', @TestPackageLockParser);
  RunTest('XML dependency parsers', @TestXMLParsers);
  RunTest('Lazarus project parser', @TestLazarusProjectParser);
  RunTest('manifest size limits', @TestManifestSizeLimits);
  RunTest('XML document type rejection', @TestXMLDocumentTypeRejection);
  RunTest('task-history round trip', @TestHistoryRoundTrip);
  RunTest('atomic-history recovery', @TestAtomicHistoryRecovery);
  RunTest('application-data migration', @TestApplicationDataMigration);
  RunTest('SBOM export naming', @TestExportNaming);
  RunTest('database archive export', @TestDatabaseArchive);
  RunTest('readelf output parsing', @TestReadElfParsing);
  RunTest('native dependency versions', @TestNativeDependencyVersions);
  RunTest('native version scan and SBOM', @TestNativeVersionScanAndSBOM);
  RunTest('native dependency tables', @TestNativeDependencyTables);
  RunTest('PE/ELF/Mach-O inspection', @TestBinaryInspection);
  RunTest('component deduplication', @TestComponentDeduplication);
  RunTest('worker exception containment', @TestWorkerExceptionContainment);
  RunTest('manifest and lockfile scan', @TestManifestLockScan);
  RunTest('CycloneDX synthetic root', @TestCycloneDXSyntheticRoot);
  RunTest('CycloneDX structure and semantics', @TestCycloneDXStructure);
  RunTest('CycloneDX normalized binary graph',
    @TestCycloneDXNormalizedBinaryGraph);
  RunTest('deterministic CycloneDX', @TestDeterministicCycloneDX);
  RunTest('ignore and wildcard matching', @TestIgnoreMatching);
  RunTest('special-file skip', @TestSpecialFileSkip);
  RunTest('Windows special attributes',
    @TestWindowsSpecialAttributeClassification);
  RunTest('filesystem enumeration errors',
    @TestDirectoryEnumerationErrors);
  RunTest('case-preserving enumeration', @TestCasePreservingEnumeration);
  RunTest('glob-metacharacter enumeration', @TestGlobMetacharacterEnumeration);
  RunTest('unreadable-directory warnings', @TestUnreadableDirectoryWarning);
  RunTest('symbolic-link loop prevention', @TestSymlinkLoopPrevention);
  RunTest('scan cancellation', @TestScanCancellation);
  WriteLn(Format('%d tests: %d passed, %d failed, %d skipped',
    [TestCount, PassCount, FailureCount, SkipCount]));
  RemoveTemporaryTree(TemporaryRoot);
  if FailureCount <> 0 then
    Halt(1);
end.
