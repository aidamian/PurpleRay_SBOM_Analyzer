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
  Classes, SysUtils, Contnrs, fpjson, zipper,
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
    Raised when VERSION, the compiled UI value, or Lazarus file/product
    resource metadata diverge.
}
procedure TestDisplayedVersion;
var
  VersionLines, VersionParts, ProjectLines: TStringList;
  VersionValue, ProjectText: string;
  PartIndex, CharacterIndex, PartValue: Integer;
begin
  VersionLines := TStringList.Create;
  VersionParts := TStringList.Create;
  ProjectLines := TStringList.Create;
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
  finally
    ProjectLines.Free;
    VersionParts.Free;
    VersionLines.Free;
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
    finally
      Artifact.Free;
    end;
  finally
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
  AssertEqual('6', NativeDependencyVersion('libc.so.6'),
    'ELF SONAME major version differs');
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
    SBOM := GenerateCycloneDX(Task);
    AssertTrue(Pos('"version" : "4.2"', string(SBOM)) > 0,
      'native version evidence is missing from CycloneDX output');
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
    identification omits the current-format Lazarus project.
}
procedure TestManifestLockScan;
var
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
  Artifact: TArtifact;
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
  finally
    Engine.Free;
    Task.Free;
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
    AssertTrue(Pos('"specVersion" : "1.6"', string(First)) > 0,
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
  RunTest('requirements parser', @TestRequirementsParser);
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
