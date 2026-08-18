program test_runner;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads, BaseUnix,{$ENDIF}
  Classes, SysUtils, Contnrs, fpjson,
  uModels, uSHA256, uBinaryInspector, uManifestParsers, uArtifactIdentifier,
  uTaskHistory, uJSONUtils, uComponentNormalizer, uCycloneDX, uIgnoreMatcher,
  uScanEngine;

type
  TTestMethod = procedure;

  TCancelController = class
  private
    FChecks: Integer;
    FLimit: Integer;
  public
    constructor Create(ALimit: Integer);
    function Check: Boolean;
  end;

var
  TestCount: Integer = 0;
  FailureCount: Integer = 0;
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

procedure Fail(const AMessage: string);
begin
  raise Exception.Create(AMessage);
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
  DirectoryName: string;
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
    Tasks.Add(Task);
    Store.Save(Tasks);
    AssertTrue(Store.Load(Loaded, WarningText), 'history should load');
    AssertEqual('', WarningText, 'valid history produced a warning');
    AssertEqual(1, Loaded.Count, 'loaded task count differs');
    AssertEqual(42, TScanTask(Loaded[0]).FilesInspected,
      'loaded file count differs');
    AssertEqual('fixture warning', TScanTask(Loaded[0]).Warnings[0],
      'loaded warning differs');
  finally
    Loaded.Free;
    Tasks.Free;
    Store.Free;
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
    First.EvidencePaths.Add('a/package.json');
    Input.Add(First);
    Second := uModels.TComponent.Create;
    Second.Name := 'demo'; Second.Version := '1.0.0'; Second.Ecosystem := 'npm';
    Second.PackageURL := 'pkg:npm/demo@1.0.0';
    Second.SourceArtifact := 'b/package-lock.json';
    Second.EvidencePaths.Add('b/package-lock.json');
    Input.Add(Second);
    NormalizeComponents(Input, Output);
    AssertEqual(1, Output.Count, 'duplicate components were not merged');
    Merged := uModels.TComponent(Output[0]);
    AssertEqual(2, Merged.EvidencePaths.Count,
      'duplicate evidence paths were not merged');
  finally
    Output.Free;
    Input.Free;
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

procedure RunTest(const AName: string; AMethod: TTestMethod);
begin
  Inc(TestCount);
  try
    AMethod();
    WriteLn('[PASS] ', AName);
  except
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
    'sbom-analyzer-tests-' + NewTaskID;
  ForceDirectories(TemporaryRoot);
  RunTest('SHA-256 vectors', @TestSHA256);
  RunTest('requirements parser', @TestRequirementsParser);
  RunTest('package.json parser', @TestPackageJSONParser);
  RunTest('package-lock.json parser', @TestPackageLockParser);
  RunTest('XML dependency parsers', @TestXMLParsers);
  RunTest('XML document type rejection', @TestXMLDocumentTypeRejection);
  RunTest('task-history round trip', @TestHistoryRoundTrip);
  RunTest('atomic-history recovery', @TestAtomicHistoryRecovery);
  RunTest('PE/ELF/Mach-O inspection', @TestBinaryInspection);
  RunTest('component deduplication', @TestComponentDeduplication);
  RunTest('deterministic CycloneDX', @TestDeterministicCycloneDX);
  RunTest('ignore and wildcard matching', @TestIgnoreMatching);
  RunTest('symbolic-link loop prevention', @TestSymlinkLoopPrevention);
  RunTest('scan cancellation', @TestScanCancellation);
  WriteLn(Format('%d tests, %d failures', [TestCount, FailureCount]));
  if FailureCount <> 0 then
    Halt(1);
end.
