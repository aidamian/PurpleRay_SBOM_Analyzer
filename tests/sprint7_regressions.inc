{ Sprint 7 verified-input, installed-tree, archive, native-evidence, bounded
  analysis-pool, cache, strict-JSON/Unicode, and settings-recovery regressions.
  This file is included after RunTest is declared. }

type
  TS7MutationMode = (
    s7mmNone,
    s7mmReplaceBeforeOpen,
    s7mmLinkBeforeOpen,
    s7mmAppendBeforeCommit,
    s7mmRewriteBeforeCommit,
    s7mmTruncateBeforeCommit,
    s7mmRebindRootBeforeOpen
  );

  TS7MutationScanEngine = class(TScanEngine)
  protected
    procedure BeforeVerifiedInputOpen(const AFileName,
      ARelativePath: string;
      const AExpectedIdentity: TVerifiedFileIdentity); override;
    procedure BeforeVerifiedInputCommit(const AFileName,
      ARelativePath: string; AInput: TVerifiedInput); override;
  public
    Mode: TS7MutationMode;
    Triggered: Boolean;
    MutationSucceeded: Boolean;
    MutationError: string;
    MovedPath: string;
  end;

  TS7AlwaysCancel = class
  public
    function Check: Boolean;
  end;

  TS7ShortReadMemoryStream = class(TMemoryStream)
  private
    FReadableBytes: Int64;
  public
    constructor Create(AReadableBytes: Int64);
    function Read(var Buffer; Count: LongInt): LongInt; override;
  end;

  TS7ProgressObserver = class
  private
    FSeen: Boolean;
  public
    ExpectedOldest: string;
    SawExpectedOldest: Boolean;
    SawWrongUncommittedPath: Boolean;
    Monotonic: Boolean;
    LastProgress: TScanProgress;
    constructor Create;
    procedure Progress(const AProgress: TScanProgress);
  end;

  TS7ProgressCancellation = class
  public
    Armed: Boolean;
    ExpectedOldest: string;
    function Check: Boolean;
    procedure Progress(const AProgress: TScanProgress);
  end;

{$IFDEF Windows}
function GetProcessHandleCount(AProcess: THandle;
  out AHandleCount: DWORD): BOOL; stdcall;
  external 'kernel32.dll' name 'GetProcessHandleCount';
{$ENDIF}

const
  S7OriginalManifest = '{"name":"original-x","version":"1.0.0"}';
  S7ReplacementManifest = '{"name":"replaced-x","version":"1.0.0"}';

function TS7AlwaysCancel.Check: Boolean;
begin
  Result := True;
end;

constructor TS7ShortReadMemoryStream.Create(AReadableBytes: Int64);
begin
  inherited Create;
  FReadableBytes := AReadableBytes;
end;

function TS7ShortReadMemoryStream.Read(var Buffer; Count: LongInt): LongInt;
begin
  if Position >= FReadableBytes then
    Exit(0);
  if Count > FReadableBytes - Position then
    Count := FReadableBytes - Position;
  Result := inherited Read(Buffer, Count);
end;

procedure TS7MutationScanEngine.BeforeVerifiedInputOpen(const AFileName,
  ARelativePath: string; const AExpectedIdentity: TVerifiedFileIdentity);
var
  RootPath: string;
begin
  if Triggered or (ARelativePath <> 'package.json') or
    not (Mode in [s7mmReplaceBeforeOpen, s7mmLinkBeforeOpen,
      s7mmRebindRootBeforeOpen]) then
    Exit;
  Triggered := True;
  try
    if Mode in [s7mmReplaceBeforeOpen, s7mmLinkBeforeOpen] then
    begin
      MovedPath := AFileName + '.captured';
      if not RenameFile(AFileName, MovedPath) then
        raise EInOutError.Create('unable to move captured input');
      if Mode = s7mmReplaceBeforeOpen then
        WriteText(AFileName, S7ReplacementManifest)
      {$IFDEF UNIX}
      else if fpSymlink(PChar(MovedPath), PChar(AFileName)) <> 0 then
        raise EInOutError.Create('unable to install replacement symlink');
      {$ELSE}
      else
        raise EInOutError.Create('link replacement fixture is Unix-only');
      {$ENDIF}
    end
    else
    begin
      RootPath := ExtractFileDir(AFileName);
      MovedPath := RootPath + '-captured';
      if not RenameFile(RootPath, MovedPath) then
        raise EInOutError.Create('unable to move pinned scan root');
      if not ForceDirectories(RootPath) then
        raise EInOutError.Create('unable to recreate scan-root pathname');
    end;
    MutationSucceeded := True;
  except
    on E: Exception do
      MutationError := E.Message;
  end;
end;

procedure TS7MutationScanEngine.BeforeVerifiedInputCommit(const AFileName,
  ARelativePath: string; AInput: TVerifiedInput);
var
  Stream: TFileStream;
  Value: RawByteString;
begin
  if Triggered or (ARelativePath <> 'package.json') or
    not (Mode in [s7mmAppendBeforeCommit, s7mmRewriteBeforeCommit,
      s7mmTruncateBeforeCommit]) then
    Exit;
  Triggered := True;
  Stream := nil;
  try
    Stream := TFileStream.Create(AFileName, fmOpenWrite or fmShareDenyNone);
    case Mode of
      s7mmAppendBeforeCommit:
        begin
          Stream.Position := Stream.Size;
          Value := LineEnding + ' ';
          Stream.WriteBuffer(Value[1], Length(Value));
        end;
      s7mmRewriteBeforeCommit:
        begin
          AssertEqual(Length(S7OriginalManifest),
            Length(S7ReplacementManifest),
            'same-size verified-input fixtures differ');
          Stream.Position := 0;
          Value := S7ReplacementManifest;
          Stream.WriteBuffer(Value[1], Length(Value));
        end;
      s7mmTruncateBeforeCommit:
        Stream.Size := 2;
    end;
    MutationSucceeded := True;
  except
    on E: Exception do
      MutationError := E.Message;
  end;
  Stream.Free;
end;

constructor TS7ProgressObserver.Create;
begin
  inherited Create;
  Monotonic := True;
end;

procedure TS7ProgressObserver.Progress(const AProgress: TScanProgress);
begin
  if FSeen and ((AProgress.FilesInspected < LastProgress.FilesInspected) or
    (AProgress.BytesInspected < LastProgress.BytesInspected) or
    (AProgress.ArtifactsDetected < LastProgress.ArtifactsDetected) or
    (AProgress.ComponentsIdentified < LastProgress.ComponentsIdentified) or
    (AProgress.ElapsedMS < LastProgress.ElapsedMS)) then
    Monotonic := False;
  if AProgress.FilesInspected = 0 then
  begin
    if AProgress.CurrentRelativePath = ExpectedOldest then
      SawExpectedOldest := True
    else if AProgress.CurrentRelativePath <> '' then
      SawWrongUncommittedPath := True;
  end;
  LastProgress := AProgress;
  FSeen := True;
end;

function TS7ProgressCancellation.Check: Boolean;
begin
  Result := Armed;
end;

procedure TS7ProgressCancellation.Progress(const AProgress: TScanProgress);
begin
  if (AProgress.FilesInspected = 0) and
    (AProgress.CurrentRelativePath = ExpectedOldest) then
    Armed := True;
end;

procedure S7ConfigureTask(ATask: TScanTask; const ARoot: string);
begin
  ATask.TargetDirectory := ARoot;
  ATask.TargetRootName := ExtractFileName(ARoot);
  ATask.Settings.CalculateSHA256 := True;
end;

function S7OpenVerified(const AFileName, ARoot: string): TVerifiedInput;
var
  Identity: TVerifiedFileIdentity;
  Reason: string;
begin
  Result := nil;
  AssertTrue(TryCaptureVerifiedFileIdentity(AFileName, ARoot, False,
    Identity, Reason), 'verified identity capture failed: ' + Reason);
  AssertTrue(TryOpenVerifiedInput(AFileName, ARoot, False, Identity,
    Result, Reason), 'verified open failed: ' + Reason);
end;

function S7OpenHandleCount: Int64;
{$IFDEF UNIX}
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
{$ENDIF}
{$IFDEF Windows}
var
  Count: DWORD;
{$ENDIF}
begin
  {$IFDEF UNIX}
  Result := 0;
  FindResult := FindFirst('/proc/self/fd/*', faAnyFile, SearchRecord);
  if FindResult <> 0 then
    SkipTest('native handle counting requires /proc/self/fd');
  try
    while FindResult = 0 do
    begin
      if (SearchRecord.Name <> '.') and (SearchRecord.Name <> '..') then
        Inc(Result);
      FindResult := FindNext(SearchRecord);
    end;
  finally
    FindClose(SearchRecord);
  end;
  {$ENDIF}
  {$IFDEF Windows}
  Count := 0;
  if not GetProcessHandleCount(GetCurrentProcess, Count) then
    Fail('GetProcessHandleCount failed');
  Result := Count;
  {$ENDIF}
end;

procedure TestSprint7VerifiedInputCore;
var
  RootPath, FileName, Reason, Digest: string;
  Identity, InvalidIdentity: TVerifiedFileIdentity;
  Input, RejectedInput: TVerifiedInput;
  FirstView, SecondView: TStream;
  Buffer: array[0..2] of AnsiChar;
  BufferText: RawByteString;
  SeekFailed: Boolean;
  {$IFDEF UNIX}
  FIFOName: string;
  GrowthValue: RawByteString;
  GrowthBuffer: array[0..31] of Byte;
  GrowthView: TStream;
  GrowthWriter: TFileStream;
  Started: QWord;
  {$ENDIF}
begin
  RootPath := NewTemporaryDirectory('sprint7-verified-core');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'payload.bin';
  WriteText(FileName, 'abcdefghij');
  AssertTrue(TryCaptureVerifiedFileIdentity(FileName,
    CanonicalPath(RootPath), False, Identity, Reason),
    'regular identity capture failed: ' + Reason);
  AssertTrue(TryOpenVerifiedInput(FileName, CanonicalPath(RootPath), False,
    Identity, Input, Reason), 'verified input open failed: ' + Reason);
  try
    AssertEqual(10, Input.Size, 'verified input size differs');
    AssertEqual('', Input.ToolPath, 'unsafe pathname tool bridge is enabled');
    FirstView := Input.NewStream;
    SecondView := Input.NewStream;
    try
      AssertEqual(SizeOf(Buffer), FirstView.Read(Buffer, SizeOf(Buffer)),
        'first bounded view returned a short read');
      SetString(BufferText, PAnsiChar(@Buffer[0]), SizeOf(Buffer));
      AssertEqual('abc', string(BufferText), 'first bounded view bytes differ');
      AssertEqual(SizeOf(Buffer), SecondView.Read(Buffer, SizeOf(Buffer)),
        'second bounded view did not begin at offset zero');
      SetString(BufferText, PAnsiChar(@Buffer[0]), SizeOf(Buffer));
      AssertEqual('abc', string(BufferText),
        'second bounded view bytes differ');
      SeekFailed := False;
      try
        SecondView.Seek(1, soEnd);
      except
        on E: EStreamError do
          SeekFailed := True;
      end;
      AssertTrue(SeekFailed, 'bounded stream accepted a past-end seek');
      SecondView.Position := 0;
      AssertTrue(SHA256Stream(SecondView, Digest, nil, nil),
        'bounded stream hash was cancelled');
      AssertEqual(SHA256String('abcdefghij'), Digest,
        'bounded stream digest differs');
    finally
      SecondView.Free;
      FirstView.Free;
    end;
    AssertTrue(Input.ValidateStable(Reason),
      'unchanged verified input became unstable: ' + Reason);
    {$IFDEF UNIX}
    GrowthWriter := TFileStream.Create(FileName,
      fmOpenWrite or fmShareDenyNone);
    try
      GrowthWriter.Position := GrowthWriter.Size;
      GrowthValue := 'later-growth';
      GrowthWriter.WriteBuffer(GrowthValue[1], Length(GrowthValue));
    finally
      GrowthWriter.Free;
    end;
    GrowthView := Input.NewStream;
    try
      AssertEqual(10, GrowthView.Read(GrowthBuffer, SizeOf(GrowthBuffer)),
        'bounded view exposed bytes appended after verified open');
      AssertEqual(0, GrowthView.Read(GrowthBuffer, SizeOf(GrowthBuffer)),
        'bounded view read beyond its frozen size');
    finally
      GrowthView.Free;
    end;
    AssertTrue(not Input.ValidateStable(Reason),
      'post-open growth was not detected');
    {$ENDIF}
  finally
    Input.Free;
  end;

  FillChar(InvalidIdentity, SizeOf(InvalidIdentity), 0);
  RejectedInput := nil;
  AssertTrue(not TryOpenVerifiedInput(FileName, CanonicalPath(RootPath),
    False, InvalidIdentity, RejectedInput, Reason),
    'invalid enumeration identity was accepted');
  AssertTrue(RejectedInput = nil,
    'invalid enumeration identity returned an input object');

  {$IFDEF UNIX}
  FIFOName := IncludeTrailingPathDelimiter(RootPath) + 'events.pipe';
  AssertTrue(fpMkFifo(PChar(FIFOName), 384) = 0,
    'unable to create FIFO fixture');
  Started := GetTickCount64;
  AssertTrue(not TryCaptureVerifiedFileIdentity(FIFOName, False,
    Identity, Reason), 'FIFO was accepted as a regular input');
  AssertTrue(GetTickCount64 - Started < 2000,
    'FIFO identity capture blocked');
  {$ENDIF}
end;

procedure S7AssertCommitMutation(const ALabel: string;
  AMode: TS7MutationMode);
var
  RootPath, FileName: string;
  Engine: TS7MutationScanEngine;
  Task: TScanTask;
  Artifact: TArtifact;
begin
  RootPath := NewTemporaryDirectory(ALabel);
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'package.json';
  WriteText(FileName, S7OriginalManifest);
  Engine := TS7MutationScanEngine.Create(nil, nil);
  Task := TScanTask.Create;
  try
    Engine.Mode := AMode;
    S7ConfigureTask(Task, RootPath);
    AssertTrue(Engine.Scan(Task), ALabel + ' scan did not complete');
    AssertTrue(Engine.Triggered, ALabel + ' mutation hook did not run');
    AssertEqual(1, Task.Artifacts.Count,
      ALabel + ' did not retain one artifact');
    Artifact := TArtifact(Task.Artifacts[0]);
    {$IFDEF UNIX}
    AssertTrue(Engine.MutationSucceeded,
      ALabel + ' mutation failed: ' + Engine.MutationError);
    AssertTrue(Artifact.Status = arsFailed,
      ALabel + ' artifact was not failed');
    AssertEqual('', Artifact.SHA256,
      ALabel + ' leaked a hash from unstable content');
    AssertEqual(0, Artifact.ComponentCount,
      ALabel + ' retained staged component counts');
    AssertEqual(0, Task.Components.Count,
      ALabel + ' published staged components');
    AssertTrue(Pos('changed during bounded inspection',
      LowerCase(Artifact.MessageText)) > 0,
      ALabel + ' omitted its instability diagnostic');
    {$ENDIF}
    {$IFDEF Windows}
    AssertTrue(not Engine.MutationSucceeded,
      ALabel + ' bypassed the Windows deny-write handle');
    AssertTrue(Engine.MutationError <> '',
      ALabel + ' sharing denial had no diagnostic');
    AssertTrue(Artifact.Status = arsParsed,
      ALabel + ' stable Windows artifact was not parsed');
    AssertEqual(1, Task.Components.Count,
      ALabel + ' stable Windows component was not published');
    {$ENDIF}
  finally
    Task.Free;
    Engine.Free;
  end;
end;

procedure TestSprint7VerifiedInputRaces;
var
  RootPath, FileName: string;
  Engine: TS7MutationScanEngine;
  Task: TScanTask;
  ScanCompleted: Boolean;
  {$IFDEF UNIX}
  OutsidePath, TargetName, LinkName, OutsideName, EscapeLink, Reason: string;
  Identity: TVerifiedFileIdentity;
  Input: TVerifiedInput;
  {$ENDIF}
begin
  RootPath := NewTemporaryDirectory('sprint7-replace-before-open');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'package.json';
  WriteText(FileName, S7OriginalManifest);
  Engine := TS7MutationScanEngine.Create(nil, nil);
  Task := TScanTask.Create;
  try
    Engine.Mode := s7mmReplaceBeforeOpen;
    S7ConfigureTask(Task, RootPath);
    AssertTrue(Engine.Scan(Task), 'replacement scan did not finish');
    AssertTrue(Engine.Triggered and Engine.MutationSucceeded,
      'replacement fixture did not run: ' + Engine.MutationError);
    AssertEqual(0, Task.FilesInspected,
      'replacement input was reported as inspected');
    AssertEqual(0, Task.Artifacts.Count,
      'replacement input produced an artifact');
    AssertEqual(0, Task.Components.Count,
      'replacement input produced a component');
    AssertTrue(StringListContainsText(Task.Warnings, 'identity changed'),
      'replacement skip omitted its identity diagnostic');
  finally
    Task.Free;
    Engine.Free;
  end;

  {$IFDEF UNIX}
  RootPath := NewTemporaryDirectory('sprint7-regular-to-link');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'package.json';
  WriteText(FileName, S7OriginalManifest);
  Engine := TS7MutationScanEngine.Create(nil, nil);
  Task := TScanTask.Create;
  try
    Engine.Mode := s7mmLinkBeforeOpen;
    S7ConfigureTask(Task, RootPath);
    Task.Settings.FollowSymbolicLinks := True;
    AssertTrue(Engine.Scan(Task), 'regular-to-link scan did not finish');
    AssertTrue(Engine.Triggered and Engine.MutationSucceeded,
      'regular-to-link fixture did not run: ' + Engine.MutationError);
    AssertEqual(0, Task.Artifacts.Count,
      'replacement link produced an artifact');
    AssertTrue(StringListContainsText(Task.Warnings, 'could not be verified'),
      'replacement link omitted its verification diagnostic');
  finally
    Task.Free;
    Engine.Free;
  end;

  RootPath := NewTemporaryDirectory('sprint7-link-containment');
  OutsidePath := NewTemporaryDirectory('sprint7-link-outside');
  TargetName := IncludeTrailingPathDelimiter(RootPath) + 'target.json';
  LinkName := IncludeTrailingPathDelimiter(RootPath) + 'inside.json';
  OutsideName := IncludeTrailingPathDelimiter(OutsidePath) + 'outside.json';
  EscapeLink := IncludeTrailingPathDelimiter(RootPath) + 'escape.json';
  WriteText(TargetName, S7OriginalManifest);
  WriteText(OutsideName, S7ReplacementManifest);
  AssertTrue(fpSymlink(PChar(TargetName), PChar(LinkName)) = 0,
    'unable to create inside-link fixture');
  AssertTrue(fpSymlink(PChar(OutsideName), PChar(EscapeLink)) = 0,
    'unable to create outside-link fixture');
  AssertTrue(not TryCaptureVerifiedFileIdentity(LinkName, False,
    Identity, Reason), 'no-follow capture accepted a symbolic link');
  AssertTrue(TryCaptureVerifiedFileIdentity(LinkName, True,
    Identity, Reason), 'follow capture rejected inside link: ' + Reason);
  AssertTrue(TryOpenVerifiedInput(LinkName, CanonicalPath(RootPath), True,
    Identity, Input, Reason), 'inside link failed containment: ' + Reason);
  Input.Free;
  AssertTrue(TryCaptureVerifiedFileIdentity(EscapeLink, True,
    Identity, Reason), 'outside link target capture failed: ' + Reason);
  Input := nil;
  AssertTrue(not TryOpenVerifiedInput(EscapeLink, CanonicalPath(RootPath),
    True, Identity, Input, Reason),
    'outside-root link target was accepted');
  AssertTrue(Input = nil, 'outside-root link returned an input object');
  {$ENDIF}

  S7AssertCommitMutation('sprint7-append-before-commit',
    s7mmAppendBeforeCommit);
  S7AssertCommitMutation('sprint7-rewrite-before-commit',
    s7mmRewriteBeforeCommit);
  S7AssertCommitMutation('sprint7-truncate-before-commit',
    s7mmTruncateBeforeCommit);

  RootPath := NewTemporaryDirectory('sprint7-root-rebind');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'package.json';
  WriteText(FileName, S7OriginalManifest);
  Engine := TS7MutationScanEngine.Create(nil, nil);
  Task := TScanTask.Create;
  try
    Engine.Mode := s7mmRebindRootBeforeOpen;
    S7ConfigureTask(Task, RootPath);
    ScanCompleted := Engine.Scan(Task);
    AssertTrue(Engine.Triggered, 'root-rebind hook did not run');
    if Engine.MutationSucceeded then
    begin
      AssertTrue(not ScanCompleted,
        'rebound root was reported as a successful scan');
      AssertTrue(Task.Status = tsFailed,
        'rebound root did not fail the task');
      AssertEqual(0, Task.Artifacts.Count,
        'rebound root published an artifact');
      AssertEqual(0, Task.Components.Count,
        'rebound root published a component');
      AssertEqual(1, Task.Errors.Count,
        'rebound root did not produce one bounded task error');
      AssertEqual('The scan failed because the selected folder''s identity ' +
        'could not be verified safely.', Task.Errors[0],
        'rebound root exposed a raw filesystem diagnostic');
      AssertTrue((Pos(RootPath, Task.Errors[0]) = 0) and
        (Pos(Engine.MovedPath, Task.Errors[0]) = 0),
        'rebound-root error exposed an absolute path');
    end
    else
    begin
      {$IFDEF UNIX}
      Fail('Unix root-rebind fixture failed: ' + Engine.MutationError);
      {$ENDIF}
      {$IFDEF Windows}
      AssertTrue(ScanCompleted,
        'rename-denied Windows scan did not remain stable');
      AssertTrue(Engine.MutationError <> '',
        'Windows root rename denial had no diagnostic');
      {$ENDIF}
    end;
  finally
    Task.Free;
    Engine.Free;
  end;
end;

procedure S7ParseText(const AText, ARelativePath: string;
  AKind: TParserKind; AArtifact: TArtifact; AComponents: TObjectList);
var
  Stream: TStringStream;
begin
  Stream := TStringStream.Create(AText);
  try
    ParseArtifact(Stream, ARelativePath, AKind, AArtifact, AComponents);
  finally
    Stream.Free;
  end;
end;

procedure TestSprint7InstalledTrees;
var
  Definition: TArtifactDefinition;
  Artifact: TArtifact;
  Components, Raw, Normalized: TObjectList;
  Component: uModels.TComponent;
  RootPath: string;
  Task: TScanTask;
  Engine: TScanEngine;
begin
  AssertTrue(IdentifyArtifact('package.json',
    'node_modules/example/package.json', Definition) and
    (Definition.ParserKind = pkInstalledPackageJSON),
    'node_modules package.json did not select installed parsing');
  {$IFDEF UNIX}
  AssertTrue(IdentifyArtifact('package.json',
    'Node_Modules/example/package.json', Definition) and
    (Definition.ParserKind = pkPackageJSON),
    'Unix installed-tree segment matching lost exact case');
  {$ENDIF}
  AssertTrue(IdentifyArtifact('METADATA',
    'site/demo-1.2.3.dist-info/METADATA', Definition) and
    (Definition.ParserKind = pkPythonDistInfoMetadata),
    'dist-info METADATA was not recognized');
  AssertTrue(not IdentifyArtifact('METADATA',
    'site/demo-1.2.3.dist-info/nested/METADATA', Definition),
    'nested dist-info METADATA was recognized');

  Artifact := TArtifact.Create;
  Components := TObjectList.Create(True);
  try
    S7ParseText('{"name":"@Scope/Thing","version":"1.2.3-ALPHA",' +
      '"dependencies":{"noise":"^9"},' +
      '"devDependencies":{"noise-dev":"1.0.0"}}',
      'node_modules/@Scope/Thing/package.json', pkInstalledPackageJSON,
      Artifact, Components);
    AssertTrue(Artifact.Status = arsParsed,
      'valid installed npm identity did not parse');
    AssertEqual(1, Components.Count,
      'installed npm parser emitted dependency declarations');
    Component := uModels.TComponent(Components[0]);
    AssertEqual('@Scope/Thing', Component.Name,
      'installed npm name differs');
    AssertEqual('1.2.3-ALPHA', Component.Version,
      'installed npm version case was changed');
    AssertEqual('pkg:npm/%40scope/thing@1.2.3-ALPHA', Component.PackageURL,
      'installed npm purl differs');
    AssertEqual('resolved', Component.DependencyScope,
      'installed npm scope differs');
  finally
    Components.Free;
    Artifact.Free;
  end;

  Artifact := TArtifact.Create;
  Components := TObjectList.Create(True);
  try
    S7ParseText('Metadata-Version: 2.4' + LineEnding +
      'Name: Demo_Package' + LineEnding + 'Version: 2.3.4rc1' + LineEnding +
      'Requires-Dist: ignored (>=9)' + LineEnding + LineEnding +
      'Name: body-must-not-win' + LineEnding,
      'site/Demo_Package-2.3.4rc1.dist-info/METADATA',
      pkPythonDistInfoMetadata, Artifact, Components);
    AssertTrue(Artifact.Status = arsParsed,
      'valid dist-info identity did not parse');
    AssertEqual(1, Components.Count,
      'dist-info parser emitted dependency or body declarations');
    Component := uModels.TComponent(Components[0]);
    AssertEqual('Demo_Package', Component.Name,
      'dist-info name differs');
    AssertEqual('2.3.4rc1', Component.Version,
      'dist-info version differs');
    AssertEqual('pkg:pypi/demo-package@2.3.4rc1', Component.PackageURL,
      'dist-info purl differs');
  finally
    Components.Free;
    Artifact.Free;
  end;

  Artifact := TArtifact.Create;
  Components := TObjectList.Create(True);
  try
    S7ParseText('Name: duplicate' + LineEnding + 'Name: second' +
      LineEnding + 'Version: 1.0.0' + LineEnding + LineEnding,
      'duplicate.dist-info/METADATA', pkPythonDistInfoMetadata,
      Artifact, Components);
    AssertTrue(Artifact.Status = arsFailed,
      'duplicate dist-info identity header was accepted');
    AssertEqual(0, Components.Count,
      'failed dist-info metadata emitted a component');
  finally
    Components.Free;
    Artifact.Free;
  end;

  Raw := TObjectList.Create(True);
  Normalized := TObjectList.Create(True);
  try
    Artifact := TArtifact.Create;
    try
      S7ParseText('{"name":"example","version":"1.0.0-ALPHA"}',
        'node_modules/a/package.json', pkInstalledPackageJSON,
        Artifact, Raw);
    finally
      Artifact.Free;
    end;
    Artifact := TArtifact.Create;
    try
      S7ParseText('{"name":"example","version":"1.0.0-alpha"}',
        'node_modules/b/package.json', pkInstalledPackageJSON,
        Artifact, Raw);
    finally
      Artifact.Free;
    end;
    AssertEqual(2, Raw.Count,
      'installed purl case fixtures did not parse');
    AssertEqual('pkg:npm/example@1.0.0-ALPHA',
      uModels.TComponent(Raw[0]).PackageURL,
      'installed parser changed uppercase purl version bytes');
    AssertEqual('pkg:npm/example@1.0.0-alpha',
      uModels.TComponent(Raw[1]).PackageURL,
      'installed parser changed lowercase purl version bytes');
    AssertTrue(ComponentNormalizationKey(uModels.TComponent(Raw[0])) <>
      ComponentNormalizationKey(uModels.TComponent(Raw[1])),
      'normalization keys folded exact purl case');
    NormalizeComponents(Raw, Normalized);
    AssertEqual(2, Normalized.Count,
      'case-distinct canonical purls were merged');
  finally
    Normalized.Free;
    Raw.Free;
  end;

  RootPath := NewTemporaryDirectory('sprint7-ignored-roots');
  WriteText(IncludeTrailingPathDelimiter(RootPath) +
    'node_modules/a/package.json', '{"name":"ignored","version":"1.0.0"}');
  WriteText(IncludeTrailingPathDelimiter(RootPath) +
    '.git/package.json', '{"name":"ignored-git","version":"1.0.0"}');
  WriteText(IncludeTrailingPathDelimiter(RootPath) + 'package.json',
    '{"name":"visible","version":"1.0.0"}');
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    S7ConfigureTask(Task, RootPath);
    AssertTrue(Engine.Scan(Task), 'ignored-root scan did not complete');
    AssertEqual(1, Task.Components.Count,
      'default ignored trees contributed components');
    AssertTrue(StringListContainsText(Task.Warnings,
      'Skipped 2 directory roots due to ignore rules'),
      'ignored-root deterministic summary differs');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure S7AddZIPEntry(AZipper: TZipper; AStreams: TObjectList;
  const AName: string; const AData: RawByteString);
var
  Stream: TStringStream;
  Entry: TZipFileEntry;
begin
  Stream := TStringStream.Create(string(AData));
  AStreams.Add(Stream);
  Entry := AZipper.Entries.AddFileEntry(Stream, AName);
  Entry.DateTime := EncodeDate(2026, 1, 1);
end;

procedure S7WriteZIP(const AFileName: string; ANames, AData: TStrings);
var
  ZipperObject: TZipper;
  Streams: TObjectList;
  I: Integer;
begin
  AssertTrue((ANames <> nil) and (AData <> nil) and
    (ANames.Count = AData.Count), 'invalid ZIP fixture lists');
  ZipperObject := TZipper.Create;
  Streams := TObjectList.Create(True);
  try
    for I := 0 to ANames.Count - 1 do
      S7AddZIPEntry(ZipperObject, Streams, ANames[I],
        RawByteString(AData[I]));
    ZipperObject.SaveToFile(AFileName);
  finally
    Streams.Free;
    ZipperObject.Free;
  end;
end;

procedure S7SwapFirstTwoCentralOffsets(const AFileName: string);
const
  EndHeaderBytes = 22;
  CentralHeaderBytes = 46;
var
  Stream: TFileStream;
  EndHeader: array[0..EndHeaderBytes - 1] of Byte;
  FirstHeader, SecondHeader: array[0..CentralHeaderBytes - 1] of Byte;
  CentralOffset, FirstHeaderOffset, SecondHeaderOffset: LongWord;
  FirstRecordPosition, SecondRecordPosition: Int64;

  function ReadWord(const AHeader: array of Byte; AOffset: Integer): Word;
  begin
    Result := Word(AHeader[AOffset]) or
      (Word(AHeader[AOffset + 1]) shl 8);
  end;

  function ReadDWord(const AHeader: array of Byte;
    AOffset: Integer): LongWord;
  begin
    Result := LongWord(AHeader[AOffset]) or
      (LongWord(AHeader[AOffset + 1]) shl 8) or
      (LongWord(AHeader[AOffset + 2]) shl 16) or
      (LongWord(AHeader[AOffset + 3]) shl 24);
  end;

  procedure WriteDWord(AValue: LongWord);
  var
    Bytes: array[0..3] of Byte;
  begin
    Bytes[0] := Byte(AValue);
    Bytes[1] := Byte(AValue shr 8);
    Bytes[2] := Byte(AValue shr 16);
    Bytes[3] := Byte(AValue shr 24);
    Stream.WriteBuffer(Bytes, SizeOf(Bytes));
  end;

begin
  Stream := TFileStream.Create(AFileName, fmOpenReadWrite);
  try
    AssertTrue(Stream.Size >= EndHeaderBytes + (2 * CentralHeaderBytes),
      'ZIP swap fixture is too small');
    Stream.Position := Stream.Size - EndHeaderBytes;
    Stream.ReadBuffer(EndHeader, SizeOf(EndHeader));
    AssertTrue(ReadDWord(EndHeader, 0) = $06054B50,
      'ZIP swap fixture has no standard EOCD');
    AssertEqual(2, ReadWord(EndHeader, 10),
      'ZIP swap fixture entry count differs');
    CentralOffset := ReadDWord(EndHeader, 16);
    FirstRecordPosition := CentralOffset;
    Stream.Position := FirstRecordPosition;
    Stream.ReadBuffer(FirstHeader, SizeOf(FirstHeader));
    AssertTrue(ReadDWord(FirstHeader, 0) = $02014B50,
      'first ZIP central header is invalid');
    SecondRecordPosition := FirstRecordPosition + CentralHeaderBytes +
      ReadWord(FirstHeader, 28) + ReadWord(FirstHeader, 30) +
      ReadWord(FirstHeader, 32);
    Stream.Position := SecondRecordPosition;
    Stream.ReadBuffer(SecondHeader, SizeOf(SecondHeader));
    AssertTrue(ReadDWord(SecondHeader, 0) = $02014B50,
      'second ZIP central header is invalid');
    FirstHeaderOffset := ReadDWord(FirstHeader, 42);
    SecondHeaderOffset := ReadDWord(SecondHeader, 42);
    Stream.Position := FirstRecordPosition + 42;
    WriteDWord(SecondHeaderOffset);
    Stream.Position := SecondRecordPosition + 42;
    WriteDWord(FirstHeaderOffset);
  finally
    Stream.Free;
  end;
end;

function S7RunJavaArchive(const AFileName: string; AKind: TJavaArchiveKind;
  out AArtifact: TArtifact; out AComponents: TObjectList;
  ACancelCheck: TCancelCheck = nil): TArchiveInspectionResult;
var
  Input: TVerifiedInput;
begin
  AArtifact := TArtifact.Create;
  AComponents := TObjectList.Create(True);
  Input := nil;
  try
    Input := S7OpenVerified(AFileName,
      CanonicalPath(ExtractFileDir(AFileName)));
    Result := InspectJavaArchive(Input, AKind, ExtractFileName(AFileName),
      'outer-sha256', AArtifact, AComponents, ACancelCheck);
  except
    Input.Free;
    FreeAndNil(AComponents);
    FreeAndNil(AArtifact);
    raise;
  end;
  Input.Free;
end;

procedure TestSprint7Archives;
var
  RootPath, FileName: string;
  Names, Data: TStringList;
  Artifact: TArtifact;
  Components: TObjectList;
  Component: uModels.TComponent;
  Input: TVerifiedInput;
  CancelSource: TS7AlwaysCancel;
  Kind: TJavaArchiveKind;
begin
  AssertTrue(TryJavaArchiveKind('demo.JAR', Kind) and (Kind = jakJAR),
    'JAR recognition differs');
  AssertTrue(TryJavaArchiveKind('demo.war', Kind) and (Kind = jakWAR),
    'WAR recognition differs');
  AssertTrue(TryJavaArchiveKind('demo.Ear', Kind) and (Kind = jakEAR),
    'EAR recognition differs');
  AssertTrue(not TryJavaArchiveKind('demo.zip', Kind),
    'plain ZIP was recognized as a Java archive');
  AssertTrue(IsStaticLibraryFileName('native.LIB'),
    'static .lib recognition differs');
  AssertTrue(not IsStaticLibraryFileName('native.dll'),
    'dynamic library was recognized as static');
  AssertEqual('pkg:maven/org.example/demo@1.2.3',
    BuildMavenPackageURL('org.example', 'demo', '1.2.3'),
    'exact Maven purl differs');
  AssertEqual('', BuildMavenPackageURL('org.example', 'demo', '${revision}'),
    'placeholder Maven version was accepted');
  AssertEqual('', BuildMavenPackageURL('org.example', 'de' + #127 + 'mo',
    '1.2.3'), 'DEL-bearing Maven coordinate was accepted');

  RootPath := NewTemporaryDirectory('sprint7-archives');
  Names := TStringList.Create;
  Data := TStringList.Create;
  try
    Names.Add('META-INF/MANIFEST.MF');
    Data.Add('Manifest-Version: 1.0'#10 +
      'Implementation-Title: demo'#10 +
      'Implementation-Version: 1.2.3'#10#10);
    Names.Add('META-INF/maven/org.example/demo/pom.properties');
    Data.Add('groupId=org.example'#10 + 'artifactId=demo'#10 +
      'version=1.2.3'#10);
    FileName := IncludeTrailingPathDelimiter(RootPath) + 'demo.jar';
    S7WriteZIP(FileName, Names, Data);
    AssertTrue(S7RunJavaArchive(FileName, jakJAR, Artifact, Components) =
      airCompleted, 'valid JAR inspection was cancelled');
    try
      AssertTrue(Artifact.Status = arsParsed,
        'valid Maven JAR was not parsed');
      AssertEqual(1, Components.Count,
        'single-coordinate JAR component count differs');
      Component := uModels.TComponent(Components[0]);
      AssertEqual('demo', Component.Name, 'Maven archive name differs');
      AssertEqual('1.2.3', Component.Version,
        'Maven archive version differs');
      AssertEqual('pkg:maven/org.example/demo@1.2.3',
        Component.PackageURL, 'Maven archive purl differs');
      AssertEqual('outer-sha256', Component.SHA256,
        'outer archive hash was not retained');
    finally
      Components.Free;
      Artifact.Free;
    end;

    Names.Clear;
    Data.Clear;
    Names.Add('META-INF/MANIFEST.MF');
    Data.Add(StringOfChar('A', MaximumManifestBytes + 1));
    FileName := IncludeTrailingPathDelimiter(RootPath) + 'over-cap.jar';
    S7WriteZIP(FileName, Names, Data);
    S7RunJavaArchive(FileName, jakJAR, Artifact, Components);
    try
      AssertTrue(Artifact.Status = arsFailed,
        'over-cap archive metadata was not rejected');
      AssertEqual(0, Components.Count,
        'over-cap archive retained components');
    finally
      Components.Free;
      Artifact.Free;
    end;

    Names.Clear;
    Data.Clear;
    Names.Add('META-INF/MANIFEST.MF');
    Data.Add('Manifest-Version: 1.0'#10 +
      'Implementation-Title: swapped'#10#10);
    Names.Add('META-INF/maven/org.example/swapped/pom.properties');
    Data.Add('groupId=org.example'#10 + 'artifactId=swapped'#10 +
      'version=1.0.0'#10);
    FileName := IncludeTrailingPathDelimiter(RootPath) +
      'swapped-offsets.jar';
    S7WriteZIP(FileName, Names, Data);
    S7SwapFirstTwoCentralOffsets(FileName);
    S7RunJavaArchive(FileName, jakJAR, Artifact, Components);
    try
      AssertTrue(Artifact.Status = arsFailed,
        'swapped local/central selected entries were accepted');
      AssertEqual(0, Components.Count,
        'swapped local/central entries produced components');
    finally
      Components.Free;
      Artifact.Free;
    end;

    FileName := IncludeTrailingPathDelimiter(RootPath) + 'valid.a';
    WriteText(FileName, '!<arch>'#10'fixture-member-data');
    Artifact := TArtifact.Create;
    Components := TObjectList.Create(True);
    Input := S7OpenVerified(FileName, CanonicalPath(RootPath));
    try
      AssertTrue(InspectStaticLibrary(Input, 'native/valid.a', 'ar-sha256',
        Artifact, Components) = airCompleted,
        'static-library inspection was cancelled');
      AssertTrue((Artifact.Status = arsParsed) and (Components.Count = 1),
        'exact ar signature was not recognized');
      AssertEqual('valid.a', uModels.TComponent(Components[0]).Name,
        'static-library basename differs');
      AssertEqual('ar-sha256', uModels.TComponent(Components[0]).SHA256,
        'static-library hash evidence differs');
    finally
      Input.Free;
      Components.Free;
      Artifact.Free;
    end;

    FileName := IncludeTrailingPathDelimiter(RootPath) + 'invalid.lib';
    WriteText(FileName, 'not-arch');
    Artifact := TArtifact.Create;
    Components := TObjectList.Create(True);
    Input := S7OpenVerified(FileName, CanonicalPath(RootPath));
    try
      InspectStaticLibrary(Input, 'invalid.lib', '', Artifact, Components);
      AssertTrue((Artifact.Status = arsFailed) and (Components.Count = 0),
        'invalid ar candidate was accepted');
    finally
      Input.Free;
      Components.Free;
      Artifact.Free;
    end;

    CancelSource := TS7AlwaysCancel.Create;
    try
      AssertTrue(S7RunJavaArchive(IncludeTrailingPathDelimiter(RootPath) +
        'demo.jar', jakJAR, Artifact, Components, @CancelSource.Check) =
        airCancelled, 'archive cancellation result differs');
      try
        AssertEqual(0, Components.Count,
          'cancelled archive retained components');
      finally
        Components.Free;
        Artifact.Free;
      end;
    finally
      CancelSource.Free;
    end;
  finally
    Data.Free;
    Names.Free;
  end;
end;

procedure S7Put16(var AData: TBytes; AOffset: Integer; AValue: Word);
begin
  AData[AOffset] := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
end;

procedure S7Put32(var AData: TBytes; AOffset: Integer; AValue: UInt32);
begin
  AData[AOffset] := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
  AData[AOffset + 2] := Byte(AValue shr 16);
  AData[AOffset + 3] := Byte(AValue shr 24);
end;

procedure S7Put64(var AData: TBytes; AOffset: Integer; AValue: QWord);
begin
  S7Put32(AData, AOffset, UInt32(AValue));
  S7Put32(AData, AOffset + 4, UInt32(AValue shr 32));
end;

function S7StreamFromBytes(const AData: TBytes): TMemoryStream;
begin
  Result := TMemoryStream.Create;
  if Length(AData) > 0 then
    Result.WriteBuffer(AData[0], Length(AData));
  Result.Position := 0;
end;

function S7BuildELFImage(AProgramType: UInt32;
  AValidInterpreter: Boolean): TBytes;
const
  InterpreterOffset = 160;
var
  I: Integer;
  PathValue: RawByteString;
begin
  Result := nil;
  SetLength(Result, 192);
  FillByte(Result[0], Length(Result), 0);
  Result[0] := $7F;
  Result[1] := Ord('E');
  Result[2] := Ord('L');
  Result[3] := Ord('F');
  Result[4] := 2;
  Result[5] := 1;
  S7Put16(Result, 16, 3);
  S7Put16(Result, 18, 62);
  S7Put64(Result, 32, 64);
  S7Put16(Result, 54, 56);
  S7Put16(Result, 56, 1);
  S7Put32(Result, 64, AProgramType);
  if AProgramType = 3 then
  begin
    S7Put64(Result, 72, InterpreterOffset);
    S7Put64(Result, 96, 8);
    if AValidInterpreter then
      PathValue := '/ld.so'#0#0
    else
      PathValue := '12345678';
    for I := 1 to 8 do
      Result[InterpreterOffset + I - 1] := Byte(PathValue[I]);
  end;
end;

function S7BuildELFNoteImage(AValidOwner: Boolean): TBytes;
const
  NoteOffset = 128;
begin
  Result := S7BuildELFImage(4, False);
  S7Put64(Result, 72, NoteOffset);
  S7Put64(Result, 96, 20);
  S7Put32(Result, NoteOffset, 4);
  S7Put32(Result, NoteOffset + 4, 4);
  S7Put32(Result, NoteOffset + 8, 3);
  Result[NoteOffset + 12] := Ord('G');
  Result[NoteOffset + 13] := Ord('N');
  Result[NoteOffset + 14] := Ord('U');
  if AValidOwner then
    Result[NoteOffset + 15] := 0
  else
    Result[NoteOffset + 15] := Ord('X');
  Result[NoteOffset + 16] := 1;
  Result[NoteOffset + 17] := 2;
  Result[NoteOffset + 18] := 3;
  Result[NoteOffset + 19] := 4;
end;

function S7BuildShortOptionalPEDelayTrap(AIs64Bit: Boolean): TBytes;
const
  PEOffset = $80;
  OptionalOffset = PEOffset + 24;
  DelayDescriptorOffset = $200;
  DependencyNameOffset = $240;
var
  DataDirectoryOffset, I, OptionalSize: Integer;
  DependencyName: RawByteString;
begin
  Result := nil;
  SetLength(Result, 1024);
  FillByte(Result[0], Length(Result), 0);
  Result[0] := Ord('M');
  Result[1] := Ord('Z');
  S7Put32(Result, $3C, PEOffset);
  Result[PEOffset] := Ord('P');
  Result[PEOffset + 1] := Ord('E');
  S7Put16(Result, PEOffset + 4, $8664);
  S7Put16(Result, PEOffset + 6, 1);
  if AIs64Bit then
  begin
    OptionalSize := 128;
    DataDirectoryOffset := OptionalOffset + 112;
    S7Put16(Result, OptionalOffset, $020B);
    S7Put32(Result, OptionalOffset + 108, 14);
  end
  else
  begin
    OptionalSize := 112;
    DataDirectoryOffset := OptionalOffset + 96;
    S7Put16(Result, OptionalOffset, $010B);
    S7Put32(Result, OptionalOffset + 92, 14);
  end;
  S7Put16(Result, PEOffset + 20, OptionalSize);
  S7Put32(Result, OptionalOffset + 60, $300);
  S7Put32(Result, DataDirectoryOffset + 13 * 8, DelayDescriptorOffset);
  S7Put32(Result, DataDirectoryOffset + 13 * 8 + 4, 32);
  S7Put32(Result, DelayDescriptorOffset, 1);
  S7Put32(Result, DelayDescriptorOffset + 4, DependencyNameOffset);
  DependencyName := 'outside-header.dll'#0;
  for I := 1 to Length(DependencyName) do
    Result[DependencyNameOffset + I - 1] := Byte(DependencyName[I]);
end;

procedure S7Append16(var AData: TBytes; AValue: Word);
var
  Offset: Integer;
begin
  Offset := Length(AData);
  SetLength(AData, Offset + 2);
  S7Put16(AData, Offset, AValue);
end;

procedure S7Append32(var AData: TBytes; AValue: UInt32);
var
  Offset: Integer;
begin
  Offset := Length(AData);
  SetLength(AData, Offset + 4);
  S7Put32(AData, Offset, AValue);
end;

procedure S7AlignResource(var AData: TBytes);
begin
  while (Length(AData) and 3) <> 0 do
  begin
    SetLength(AData, Length(AData) + 1);
    AData[High(AData)] := 0;
  end;
end;

procedure S7AppendUTF16(var AData: TBytes; const AValue: string);
var
  I: Integer;
begin
  for I := 1 to Length(AValue) do
    S7Append16(AData, Ord(AValue[I]));
  S7Append16(AData, 0);
end;

function S7BeginResourceBlock(var AData: TBytes; AValueLength,
  AValueType: Word; const AKey: string): Integer;
begin
  Result := Length(AData);
  S7Append16(AData, 0);
  S7Append16(AData, AValueLength);
  S7Append16(AData, AValueType);
  S7AppendUTF16(AData, AKey);
  S7AlignResource(AData);
end;

procedure S7EndResourceBlock(var AData: TBytes; ABlockStart: Integer);
begin
  S7Put16(AData, ABlockStart, Length(AData) - ABlockStart);
end;

procedure S7AppendVersionString(var AData: TBytes;
  const AKey, AValue: string);
var
  BlockStart: Integer;
begin
  BlockStart := S7BeginResourceBlock(AData, Length(AValue) + 1, 1, AKey);
  S7AppendUTF16(AData, AValue);
  S7AlignResource(AData);
  S7EndResourceBlock(AData, BlockStart);
  S7AlignResource(AData);
end;

procedure S7AppendStringTable(var AData: TBytes; const AKey, ACompanyName,
  AProductName: string);
var
  BlockStart: Integer;
begin
  BlockStart := S7BeginResourceBlock(AData, 0, 1, AKey);
  if ACompanyName <> '' then
    S7AppendVersionString(AData, 'CompanyName', ACompanyName);
  if AProductName <> '' then
    S7AppendVersionString(AData, 'ProductName', AProductName);
  S7EndResourceBlock(AData, BlockStart);
  S7AlignResource(AData);
end;

function S7BuildVersionResource(const AFirstKey, AFirstCompany,
  AFirstProduct, ASecondKey, ASecondCompany,
  ASecondProduct: string): TBytes;
var
  RootStart, FileInfoStart: Integer;
begin
  Result := nil;
  SetLength(Result, 0);
  RootStart := S7BeginResourceBlock(Result, 52, 0, 'VS_VERSION_INFO');
  S7Append32(Result, $FEEF04BD);
  S7Append32(Result, $00010000);
  S7Append32(Result, $00010002);
  S7Append32(Result, $00030004);
  S7Append32(Result, $00010002);
  S7Append32(Result, $00030004);
  while Length(Result) < RootStart + 6 +
    (Length('VS_VERSION_INFO') + 1) * 2 do
    SetLength(Result, Length(Result) + 1);
  while Length(Result) < 92 do
    S7Append32(Result, 0);
  S7AlignResource(Result);
  FileInfoStart := S7BeginResourceBlock(Result, 0, 1, 'StringFileInfo');
  S7AppendStringTable(Result, AFirstKey, AFirstCompany, AFirstProduct);
  S7AppendStringTable(Result, ASecondKey, ASecondCompany, ASecondProduct);
  S7EndResourceBlock(Result, FileInfoStart);
  S7AlignResource(Result);
  S7EndResourceBlock(Result, RootStart);
end;

function S7BuildPEVersionImage(const AVersionData: TBytes;
  AShallowLeaf: Boolean): TBytes;
const
  PEOffset = $80;
  OptionalOffset = PEOffset + 24;
  SectionOffset = OptionalOffset + 240;
  ResourceOffset = $200;
  VersionOffset = $300;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, 2048);
  FillByte(Result[0], Length(Result), 0);
  Result[0] := Ord('M');
  Result[1] := Ord('Z');
  S7Put32(Result, $3C, PEOffset);
  Result[PEOffset] := Ord('P');
  Result[PEOffset + 1] := Ord('E');
  S7Put16(Result, PEOffset + 4, $8664);
  S7Put16(Result, PEOffset + 6, 1);
  S7Put16(Result, PEOffset + 20, 240);
  S7Put16(Result, PEOffset + 22, $0002);
  S7Put16(Result, OptionalOffset, $020B);
  S7Put32(Result, OptionalOffset + 60, $200);
  S7Put32(Result, OptionalOffset + 108, 16);
  S7Put32(Result, OptionalOffset + 128, $1000);
  S7Put32(Result, OptionalOffset + 132, $600);
  S7Put32(Result, SectionOffset + 8, $600);
  S7Put32(Result, SectionOffset + 12, $1000);
  S7Put32(Result, SectionOffset + 16, $600);
  S7Put32(Result, SectionOffset + 20, ResourceOffset);
  S7Put16(Result, ResourceOffset + 14, 1);
  S7Put32(Result, ResourceOffset + 16, 16);
  S7Put32(Result, ResourceOffset + 20, $80000020);
  S7Put16(Result, ResourceOffset + $20 + 14, 1);
  S7Put32(Result, ResourceOffset + $20 + 16, 1);
  if AShallowLeaf then
    S7Put32(Result, ResourceOffset + $20 + 20, $60)
  else
    S7Put32(Result, ResourceOffset + $20 + 20, $80000040);
  S7Put16(Result, ResourceOffset + $40 + 14, 1);
  S7Put32(Result, ResourceOffset + $40 + 16, $0409);
  S7Put32(Result, ResourceOffset + $40 + 20, $60);
  S7Put32(Result, ResourceOffset + $60, $1100);
  S7Put32(Result, ResourceOffset + $64, Length(AVersionData));
  AssertTrue(Length(AVersionData) <= Length(Result) - VersionOffset,
    'VERSIONINFO fixture exceeds PE image');
  for I := 0 to High(AVersionData) do
    Result[VersionOffset + I] := AVersionData[I];
end;

procedure TestSprint7NativeStructure;
var
  Data, VersionData: TBytes;
  Stream: TMemoryStream;
  ShortStream: TS7ShortReadMemoryStream;
  Reader: TBoundedBinaryReader;
  Dummy: Byte;
  TextValue: string;
  Info: TBinaryInfo;
  Dependencies: TStringList;
  Metadata: TNativeBinaryMetadata;
  Inspection: TSystemInspection;
  Evidence: TPEVersionInfoEvidence;
  Is64Bit: Boolean;
  RootPath, FileName: string;
  Task: TScanTask;
  Engine: TScanEngine;
  Component: uModels.TComponent;
begin
  SetLength(Data, 4);
  Data[0] := Ord('a');
  Data[1] := Ord('b');
  Data[2] := Ord('c');
  Data[3] := 0;
  Stream := S7StreamFromBytes(Data);
  try
    Reader := TBoundedBinaryReader.Create(Stream);
    try
      AssertTrue(Reader.ContainsRange(4, 0),
        'zero range at stream end was rejected');
      AssertTrue(Reader.ReadBuffer(4, Dummy, 0),
        'zero-byte bounded read was rejected');
      AssertTrue(not Reader.ContainsRange(3, 2),
        'past-end bounded range was accepted');
      AssertTrue(not Reader.ContainsRange(High(QWord), 1),
        'overflowing bounded range was accepted');
      AssertTrue(Reader.ReadCString(0, 4, TextValue) and
        (TextValue = 'abc'), 'bounded C string differs');
    finally
      Reader.Free;
    end;
  finally
    Stream.Free;
  end;
  Data[1] := $7F;
  Stream := S7StreamFromBytes(Data);
  try
    Reader := TBoundedBinaryReader.Create(Stream);
    try
      AssertTrue(not Reader.ReadCString(0, 4, TextValue),
        'DEL-bearing native string was accepted');
    finally
      Reader.Free;
    end;
  finally
    Stream.Free;
  end;
  ShortStream := TS7ShortReadMemoryStream.Create(2);
  try
    ShortStream.WriteBuffer(Data[0], Length(Data));
    ShortStream.Position := 0;
    Reader := TBoundedBinaryReader.Create(ShortStream);
    try
      AssertTrue(not Reader.ReadBuffer(0, Data[0], Length(Data)),
        'early EOF satisfied an exact native read');
    finally
      Reader.Free;
    end;
  finally
    ShortStream.Free;
  end;

  SetLength(Data, 8300);
  FillByte(Data[0], Length(Data), 0);
  Data[0] := Ord('M');
  Data[1] := Ord('Z');
  S7Put32(Data, $3C, 8192);
  Data[8192] := Ord('P');
  Data[8193] := Ord('E');
  S7Put16(Data, 8196, $8664);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'far-header.exe', Info) and
      (Info.FormatName = 'PE') and (Info.Architecture = 'x86_64') and
      (Info.Classification = 'executable') and (Info.Diagnostic = ''),
      'targeted PE header beyond 4096 bytes was not recognized');
  finally
    Stream.Free;
  end;
  SetLength(Data, 64);
  FillByte(Data[0], Length(Data), 0);
  Data[0] := Ord('M');
  Data[1] := Ord('Z');
  S7Put32(Data, $3C, 16 * 1024 * 1024 + 1);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'over-cap.exe', Info) and
      (Info.Classification = 'binary') and (Info.Diagnostic <> ''),
      'over-cap PE candidate was silently ignored');
  finally
    Stream.Free;
  end;

  Data := S7BuildELFImage(3, True);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'pie', Info) and
      (Info.Classification = 'executable') and (Info.Diagnostic = ''),
      'valid ELF PT_INTERP was not classified executable');
  finally
    Stream.Free;
  end;
  Data := S7BuildELFImage(1, False);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'plugin.node', Info) and
      (Info.Classification = 'library') and (Info.Diagnostic = ''),
      'valid ET_DYN without PT_INTERP was not classified library');
  finally
    Stream.Free;
  end;
  Data := S7BuildELFImage(3, False);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'malformed', Info) and
      (Info.Classification = 'binary') and (Info.Diagnostic <> ''),
      'malformed PT_INTERP was mislabeled');
  finally
    Stream.Free;
  end;
  Data := S7BuildELFImage(1, False);
  S7Put16(Data, 56, 0);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'missing-table', Info) and
      (Info.Classification = 'binary') and (Info.Diagnostic <> ''),
      'ET_DYN without a program-header table was trusted');
  finally
    Stream.Free;
  end;

  SetLength(Data, 4);
  Data[0] := $CA;
  Data[1] := $FE;
  Data[2] := $BA;
  Data[3] := $BE;
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(not InspectBinary(Stream, 'fat-magic-only', Info),
      'magic-only Mach-O fat candidate was accepted');
  finally
    Stream.Free;
  end;
  SetLength(Data, 8);
  FillByte(Data[0], Length(Data), 0);
  Data[0] := $CA;
  Data[1] := $FE;
  Data[2] := $BA;
  Data[3] := $BE;
  Data[7] := 1;
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(not InspectBinary(Stream, 'fat-truncated', Info),
      'truncated Mach-O fat architecture table was accepted');
  finally
    Stream.Free;
  end;
  SetLength(Data, 28);
  FillByte(Data[0], Length(Data), 0);
  Data[0] := $CA;
  Data[1] := $FE;
  Data[2] := $BA;
  Data[3] := $BE;
  Data[7] := 1;
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectBinary(Stream, 'fat-valid', Info) and
      (Info.FormatName = 'Mach-O universal'),
      'complete Mach-O fat table was rejected');
  finally
    Stream.Free;
  end;

  for Is64Bit := False to True do
  begin
    Data := S7BuildShortOptionalPEDelayTrap(Is64Bit);
    Stream := S7StreamFromBytes(Data);
    Dependencies := TStringList.Create;
    try
      AssertTrue(not InspectNativeDependencies(Stream, 'PE', Dependencies)
        and (Dependencies.Count = 0),
        'delay-import bytes beyond the PE optional header were trusted');
    finally
      Dependencies.Free;
      Stream.Free;
    end;
  end;

  Data := S7BuildELFNoteImage(True);
  Stream := S7StreamFromBytes(Data);
  Dependencies := TStringList.Create;
  try
    AssertTrue(InspectNativeEvidence(Stream, 'ELF', Dependencies, Metadata)
      and (Metadata.BuildID = '01020304'),
      'valid GNU build ID was not parsed');
    Stream.Position := 0;
    Inspection := nil;
    AssertTrue(InspectBinarySystemEvidence(Stream, 'ELF', Inspection) and
      (Inspection <> nil) and (Inspection.BuildID = '01020304'),
      'common native inspection lost the GNU build ID');
    Inspection.Free;
  finally
    Dependencies.Free;
    Stream.Free;
  end;
  Data := S7BuildELFNoteImage(False);
  Stream := S7StreamFromBytes(Data);
  Dependencies := TStringList.Create;
  try
    AssertTrue(not InspectNativeEvidence(Stream, 'ELF', Dependencies,
      Metadata) and (Metadata.BuildID = ''),
      'nonterminated GNU note owner was trusted');
  finally
    Dependencies.Free;
    Stream.Free;
  end;

  VersionData := S7BuildVersionResource('040904E4', 'Company A', '',
    '041104E4', '', 'Product B');
  AssertTrue(ParsePEVersionInfoResource(VersionData, Evidence) and
    (Evidence.CompanyName = '') and (Evidence.ProductName = ''),
    'PE VERSIONINFO mixed fields from separate string tables');
  VersionData := S7BuildVersionResource('041104E4', 'Company B', 'Product B',
    '040904E4', 'Company A', 'Product A');
  AssertTrue(ParsePEVersionInfoResource(VersionData, Evidence) and
    (Evidence.FixedProductVersion = '1.2.3.4') and
    (Evidence.CompanyName = 'Company A') and
    (Evidence.ProductName = 'Product A'),
    'PE VERSIONINFO deterministic table selection differs');
  Data := S7BuildPEVersionImage(VersionData, False);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(InspectPEVersionInfo(Stream, Evidence) and
      (Evidence.CompanyName = 'Company A') and
      (Evidence.ProductName = 'Product A'),
      'canonical PE resource tree did not expose VERSIONINFO');
  finally
    Stream.Free;
  end;
  Data := S7BuildPEVersionImage(VersionData, True);
  Stream := S7StreamFromBytes(Data);
  try
    AssertTrue(not InspectPEVersionInfo(Stream, Evidence),
      'shallow PE VERSIONINFO leaf bypassed resource depth');
  finally
    Stream.Free;
  end;

  AssertTrue(IsExactBinaryVersion('1.2.3.4'),
    'fixed binary version was rejected');
  AssertTrue(not IsExactBinaryVersion('0.0.0.0'),
    'all-zero binary version was accepted');
  AssertEqual('pkg:generic/demo.exe@1.2.3.4?checksum=sha256:' +
    StringOfChar('a', 64), BuildGenericBinaryPackageURL('demo.exe',
    '1.2.3.4', StringOfChar('a', 64)),
    'generic binary purl differs');
  AssertEqual('', BuildGenericBinaryPackageURL('demo.exe', '',
    StringOfChar('a', 64)),
    'missing binary version produced a generic purl');
  AssertEqual('', BuildGenericBinaryPackageURL('demo.exe', '1.2.3.4',
    'abcd'), 'short binary hash produced a generic purl');
  AssertTrue(Pos('cpe:2.3:a:company_a:product_a:1.2.3.4:',
    BuildEvidenceCPE('Company A', 'Product A', '1.2.3.4')) = 1,
    'complete PE evidence did not produce a candidate CPE');
  AssertEqual('', BuildEvidenceCPE('', 'Product A', '1.2.3.4'),
    'missing company evidence produced a CPE');

  RootPath := NewTemporaryDirectory('sprint7-native-scan');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'demo.exe';
  VersionData := S7BuildVersionResource('040904E4', 'Company A', 'Product A',
    '041104E4', 'Company B', 'Product B');
  Data := S7BuildPEVersionImage(VersionData, False);
  WriteBytes(FileName, Data);
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(nil, nil);
  try
    S7ConfigureTask(Task, RootPath);
    AssertTrue(Engine.Scan(Task), 'native PE scan did not complete');
    AssertEqual(1, Task.Artifacts.Count,
      'native PE scan artifact count differs');
    AssertEqual(1, Task.Components.Count,
      'native PE scan component count differs');
    Component := uModels.TComponent(Task.Components[0]);
    AssertEqual('Company A', Component.CompanyName,
      'native scan lost PE company evidence');
    AssertEqual('Product A', Component.ProductName,
      'native scan lost PE product evidence');
    AssertEqual('1.2.3.4', Component.Version,
      'native scan lost fixed product version');
    AssertTrue(Pos('pkg:generic/demo.exe@1.2.3.4?checksum=sha256:',
      Component.PackageURL) = 1,
      'native scan did not derive a checksum-qualified purl');
    AssertTrue(Pos('cpe:2.3:a:company_a:product_a:1.2.3.4:',
      Component.CPE) = 1,
      'native scan did not derive an evidence CPE');
  finally
    Engine.Free;
    Task.Free;
  end;
end;

procedure TestSprint7NativeModelAndCycloneDX;
var
  Component, Clone, Restored: uModels.TComponent;
  JSON: TJSONObject;
  Task: TScanTask;
  SBOM: UTF8String;
begin
  Component := uModels.TComponent.Create;
  try
    Component.ComponentType := 'application';
    Component.Name := 'demo.exe';
    Component.Version := '1.2.3.4';
    Component.Ecosystem := 'native';
    Component.SHA256 := StringOfChar('b', 64);
    Component.PackageURL := BuildGenericBinaryPackageURL(Component.Name,
      Component.Version, Component.SHA256);
    Component.CompanyName := 'Example Company';
    Component.ProductName := 'Demo Product';
    Component.CPE := BuildEvidenceCPE(Component.CompanyName,
      Component.ProductName, Component.Version);
    Component.CPEEvidence :=
      'PE VERSIONINFO CompanyName + ProductName; inventory candidate only';
    Component.NativeSONAME := 'libdemo.so.1';
    Component.NativeBuildID := '01020304';
    Component.SourceArtifact := 'bin/demo.exe';
    Component.SourceParser := 'binary-header';
    Component.EvidencePaths.Add(Component.SourceArtifact);
    Clone := Component.Clone;
    try
      AssertEqual(Component.CPE, Clone.CPE,
        'clone lost native CPE evidence');
      AssertEqual(Component.CPEEvidence, Clone.CPEEvidence,
        'clone lost native CPE provenance');
      AssertEqual(Component.NativeBuildID, Clone.NativeBuildID,
        'clone lost native build ID');
    finally
      Clone.Free;
    end;
    JSON := Component.ToJSON;
    try
      Restored := uModels.TComponent.FromJSON(JSON);
      try
        AssertEqual(Component.CPE, Restored.CPE,
          'JSON round trip lost native CPE');
        AssertEqual(Component.CompanyName, Restored.CompanyName,
          'JSON round trip lost PE company');
        AssertEqual(Component.ProductName, Restored.ProductName,
          'JSON round trip lost PE product');
        AssertEqual(Component.NativeSONAME, Restored.NativeSONAME,
          'JSON round trip lost ELF SONAME');
        AssertEqual(Component.NativeBuildID, Restored.NativeBuildID,
          'JSON round trip lost ELF build ID');
      finally
        Restored.Free;
      end;
    finally
      JSON.Free;
    end;
    Task := TScanTask.Create;
    try
      Task.TargetDirectory := IncludeTrailingPathDelimiter(TemporaryRoot) +
        'isolated-native-model';
      Task.TargetRootName := 'native-model';
      Task.CreatedUTC := '2026-08-21T00:00:00.000Z';
      Task.Components.Add(Component.Clone);
      SBOM := GenerateCycloneDX(Task);
      AssertTrue(Pos('"cpe"', string(SBOM)) > 0,
        'CycloneDX omitted the standard CPE field');
      AssertTrue(Pos('purpleray-sbom-analyzer:cpe-evidence',
        string(SBOM)) > 0, 'CycloneDX omitted CPE provenance');
      AssertTrue(Pos('purpleray-sbom-analyzer:pe-company-name',
        string(SBOM)) > 0, 'CycloneDX omitted PE company evidence');
      AssertTrue(Pos('purpleray-sbom-analyzer:elf-soname',
        string(SBOM)) > 0, 'CycloneDX omitted ELF SONAME evidence');
      AssertTrue(Pos('purpleray-sbom-analyzer:elf-build-id',
        string(SBOM)) > 0, 'CycloneDX omitted ELF build-ID evidence');
      AssertTrue(Pos('binary-package-url-evidence', string(SBOM)) > 0,
        'CycloneDX omitted generic-purl evidence');
    finally
      Task.Free;
    end;
  finally
    Component.Free;
  end;
end;

procedure S7PopulatePoolCorpus(const ARoot: string);
begin
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'a/package.json',
    '{"name":"alpha","version":"1.2.3",' +
    '"dependencies":{"left-pad":"1.3.0"}}');
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'b/requirements.txt',
    'requests==2.32.3' + LineEnding + 'urllib3==2.5.0' + LineEnding);
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'c/pom.xml',
    '<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>' +
    '<groupId>org.example</groupId><artifactId>demo</artifactId>' +
    '<version>4.5.6</version><dependencies><dependency>' +
    '<groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId>' +
    '<version>2.0.17</version></dependency></dependencies></project>');
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'd/Cargo.lock',
    'version = 3' + LineEnding + LineEnding + '[[package]]' + LineEnding +
    'name = "serde"' + LineEnding + 'version = "1.0.219"' + LineEnding);
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'e/ordinary.txt',
    'not an artifact');
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'f/package.json',
    '{"name":"case-version","version":"1.0A"}');
  WriteText(IncludeTrailingPathDelimiter(ARoot) + 'g/package.json',
    '{"name":"case-version","version":"1.0a"}');
end;

function S7ScanPoolCorpus(const ARoot: string; AWorkerCount: Integer;
  ADelayFirst: Boolean; AObserver: TS7ProgressObserver): TScanTask;
var
  Options: TScanExecutionOptions;
  Engine: TScanEngine;
begin
  Options := DefaultScanExecutionOptions;
  Options.WorkerCount := AWorkerCount;
  if ADelayFirst then
  begin
    SetLength(Options.OrdinalDelays, 1);
    Options.OrdinalDelays[0].Ordinal := 0;
    Options.OrdinalDelays[0].Milliseconds := 300;
  end;
  Result := TScanTask.Create;
  Result.TargetDirectory := ARoot;
  Result.TargetRootName := 'sprint7-pool-corpus';
  Result.ID := '00000000-0000-4000-8000-000000000007';
  Engine := TScanEngine.Create(nil, @AObserver.Progress, Options);
  try
    AssertTrue(Engine.Scan(Result), 'pool corpus scan did not complete');
  finally
    Engine.Free;
  end;
end;

procedure S7StabilizeTaskMetadata(ATask: TScanTask);
begin
  ATask.ID := '00000000-0000-4000-8000-000000000007';
  ATask.CreatedUTC := '2026-08-21T00:00:00.000Z';
  ATask.StartedUTC := '2026-08-21T00:00:00.000Z';
  ATask.CompletedUTC := '2026-08-21T00:00:01.000Z';
  ATask.DurationMS := 1000;
end;

function S7TaskEvidenceSignature(ATask: TScanTask): string;
var
  I: Integer;
  Data: TJSONObject;
begin
  Result := Format('%d|%d|%d|%d|%d|%d', [ATask.FilesInspected,
    ATask.BytesInspected, ATask.ArtifactsDetected, ATask.ArtifactsParsed,
    ATask.FailedArtifacts, ATask.ComponentsIdentified]);
  for I := 0 to ATask.Artifacts.Count - 1 do
  begin
    Data := TArtifact(ATask.Artifacts[I]).ToJSON(False);
    try
      Result := Result + LineEnding + 'artifact|' + Data.AsJSON;
    finally
      Data.Free;
    end;
  end;
  for I := 0 to ATask.Components.Count - 1 do
  begin
    Data := uModels.TComponent(ATask.Components[I]).ToJSON;
    try
      Result := Result + LineEnding + 'component|' + Data.AsJSON;
    finally
      Data.Free;
    end;
  end;
  for I := 0 to ATask.Warnings.Count - 1 do
    Result := Result + LineEnding + 'warning|' + ATask.Warnings[I];
  for I := 0 to ATask.InspectionTools.Count - 1 do
    Result := Result + LineEnding + 'inspection|' +
      ATask.InspectionTools[I];
end;

procedure S7AssertFinalProgress(ATask: TScanTask;
  AObserver: TS7ProgressObserver; AWorkerCount: Integer);
begin
  AssertTrue(AObserver.Monotonic,
    'worker ' + IntToStr(AWorkerCount) + ' progress regressed');
  AssertEqual(ATask.FilesInspected, AObserver.LastProgress.FilesInspected,
    'final progress file count differs');
  AssertEqual(ATask.BytesInspected, AObserver.LastProgress.BytesInspected,
    'final progress byte count differs');
  AssertEqual(ATask.ArtifactsDetected,
    AObserver.LastProgress.ArtifactsDetected,
    'final progress artifact count differs');
  AssertEqual(ATask.Components.Count,
    AObserver.LastProgress.ComponentsIdentified,
    'final progress component count differs');
  AssertEqual('', AObserver.LastProgress.CurrentRelativePath,
    'final progress retained an input path');
end;

procedure TestSprint7PoolWorkerCounts;
var
  RootPath, BaselineSignature, CurrentSignature: string;
  BaselineDocument, CurrentDocument: UTF8String;
  BaselineTask, CurrentTask: TScanTask;
  Observer: TS7ProgressObserver;
  WorkerCount: Integer;
begin
  RootPath := NewTemporaryDirectory('sprint7-pool-corpus');
  S7PopulatePoolCorpus(RootPath);
  BaselineTask := nil;
  Observer := TS7ProgressObserver.Create;
  try
    Observer.ExpectedOldest := 'a/package.json';
    BaselineTask := S7ScanPoolCorpus(RootPath, 1, False, Observer);
    S7AssertFinalProgress(BaselineTask, Observer, 1);
    BaselineSignature := S7TaskEvidenceSignature(BaselineTask);
    S7StabilizeTaskMetadata(BaselineTask);
    BaselineDocument := GenerateCycloneDX(BaselineTask);
  finally
    Observer.Free;
  end;
  try
    for WorkerCount := 2 to 4 do
    begin
      Observer := TS7ProgressObserver.Create;
      CurrentTask := nil;
      try
        Observer.ExpectedOldest := 'a/package.json';
        CurrentTask := S7ScanPoolCorpus(RootPath, WorkerCount, True,
          Observer);
        S7AssertFinalProgress(CurrentTask, Observer, WorkerCount);
        AssertTrue(Observer.SawExpectedOldest,
          'parallel progress never reported the oldest uncommitted path');
        AssertTrue(not Observer.SawWrongUncommittedPath,
          'parallel progress reported a newer uncommitted path');
        CurrentSignature := S7TaskEvidenceSignature(CurrentTask);
        AssertEqual(BaselineSignature, CurrentSignature,
          'worker-count evidence model differs for ' +
          IntToStr(WorkerCount) + ' workers');
        S7StabilizeTaskMetadata(CurrentTask);
        CurrentDocument := GenerateCycloneDX(CurrentTask);
        AssertEqual(string(BaselineDocument), string(CurrentDocument),
          'CycloneDX bytes differ for ' + IntToStr(WorkerCount) +
          ' workers');
      finally
        CurrentTask.Free;
        Observer.Free;
      end;
    end;
  finally
    BaselineTask.Free;
  end;
end;

procedure TestSprint7PoolOrderingAndBounds;
const
  JobCount = 9;
var
  RootPath, RootCanonical, FileName: string;
  Pool, InvalidPool: TScanAnalysisPool;
  Job: TScanAnalysisJob;
  AnalysisResult: TScanAnalysisResult;
  Input: TVerifiedInput;
  I: Integer;
  Deadline: QWord;
  BaselineHandles, FinalHandles: Int64;
  Rejected: Boolean;
begin
  InvalidPool := nil;
  Rejected := False;
  try
    InvalidPool := TScanAnalysisPool.Create(0);
  except
    on E: EArgumentOutOfRangeException do
      Rejected := True;
  end;
  InvalidPool.Free;
  AssertTrue(Rejected, 'zero-worker pool was accepted');
  InvalidPool := nil;
  Rejected := False;
  try
    InvalidPool := TScanAnalysisPool.Create(5);
  except
    on E: EArgumentOutOfRangeException do
      Rejected := True;
  end;
  InvalidPool.Free;
  AssertTrue(Rejected, 'over-cap worker pool was accepted');

  BaselineHandles := S7OpenHandleCount;
  RootPath := NewTemporaryDirectory('sprint7-pool-bound');
  RootCanonical := CanonicalPath(RootPath);
  Pool := TScanAnalysisPool.Create(4);
  try
    for I := 0 to JobCount - 1 do
    begin
      FileName := IncludeTrailingPathDelimiter(RootPath) + 'job-' +
        IntToStr(I) + DirectorySeparator + 'package.json';
      WriteText(FileName, '{"name":"job-' + IntToStr(I) +
        '","version":"1.0.' + IntToStr(I) + '"}');
      Input := S7OpenVerified(FileName, RootCanonical);
      Job := TScanAnalysisJob.Create(I, FileName,
        'job-' + IntToStr(I) + '/package.json', Input, True,
        Ord(I = 0) * 1500);
      Input := nil;
      if I < Pool.MaximumInFlight then
      begin
        AssertTrue(Pool.Submit(Job),
          'bounded pool rejected an in-cap job');
        Job := nil;
      end
      else
        AssertTrue(not Pool.Submit(Job),
          'bounded pool accepted a ninth verified input');
      Job.Free;
      Input.Free;
    end;
    AssertEqual(Pool.MaximumInFlight, Pool.InFlight,
      'pool in-flight count differs from its bound');
    AssertEqual(8, Pool.MaximumInFlight,
      'pool maximum in-flight value is not 2*N');
    AssertEqual(Pool.MaximumInFlight, Pool.PeakInFlight,
      'pool did not record its exact in-flight peak');

    Deadline := GetTickCount64 + 1000;
    while (GetTickCount64 < Deadline) and not Pool.IsResultReady(1) do
      Pool.WaitForResult(10);
    AssertTrue(Pool.IsResultReady(1),
      'later ordinal did not finish during delayed ordinal zero');
    AssertTrue(not Pool.IsResultReady(0),
      'ordinal zero finished before deliberate out-of-order proof');

    for I := 0 to Pool.MaximumInFlight - 1 do
    begin
      AnalysisResult := nil;
      Deadline := GetTickCount64 + 5000;
      while (GetTickCount64 < Deadline) and
        not Pool.TryTakeResult(I, AnalysisResult) do
        Pool.WaitForResult(10);
      AssertTrue(AnalysisResult <> nil,
        'ordered result did not become available: ' + IntToStr(I));
      AssertTrue(AnalysisResult.Ordinal = QWord(I),
        'pool transferred a result out of ordinal order');
      AnalysisResult.Free;
    end;
    Pool.StopAndJoin;
  finally
    Pool.Free;
  end;
  FinalHandles := S7OpenHandleCount;
  AssertEqual(BaselineHandles, FinalHandles,
    'ordered pool leaked native handles');
end;

procedure TestSprint7PoolCancellation;
var
  RootPath, RaceRoot, RootCanonical, FileName: string;
  Options: TScanExecutionOptions;
  Controller: TS7ProgressCancellation;
  Engine: TScanEngine;
  Task: TScanTask;
  Pool: TScanAnalysisPool;
  Job: TScanAnalysisJob;
  Input: TVerifiedInput;
  BeforeHandles, AfterHandles: Int64;
  Deadline: QWord;
  I: Integer;
begin
  BeforeHandles := S7OpenHandleCount;
  RootPath := NewTemporaryDirectory('sprint7-pool-cancel');
  S7PopulatePoolCorpus(RootPath);
  Options := DefaultScanExecutionOptions;
  Options.WorkerCount := 4;
  SetLength(Options.OrdinalDelays, 1);
  Options.OrdinalDelays[0].Ordinal := 0;
  Options.OrdinalDelays[0].Milliseconds := 1500;
  Controller := TS7ProgressCancellation.Create;
  Controller.ExpectedOldest := 'a/package.json';
  Task := TScanTask.Create;
  Engine := TScanEngine.Create(@Controller.Check, @Controller.Progress,
    Options);
  try
    Task.TargetDirectory := RootPath;
    Task.TargetRootName := 'sprint7-pool-cancel';
    AssertTrue(not Engine.Scan(Task),
      'cancelled pool scan reported success');
    AssertTrue(Task.Status = tsCancelled,
      'cancelled pool scan has the wrong terminal status');
    AssertTrue(Controller.Armed,
      'cancellation was not armed while ordinal zero was pending');
    AssertEqual(0, Task.FilesInspected,
      'cancellation published files beyond the completed prefix');
    AssertEqual(0, Task.Artifacts.Count,
      'cancellation published artifacts beyond the completed prefix');
    AssertEqual(0, Task.Components.Count,
      'cancellation published components beyond the completed prefix');
  finally
    Engine.Free;
    Task.Free;
    Controller.Free;
  end;

  { Cancel after at least one later worker has stored a result. Destruction
    must discard every queued/completed transaction and close all inputs. }
  RaceRoot := NewTemporaryDirectory('sprint7-pool-cancel-store-race');
  RootCanonical := CanonicalPath(RaceRoot);
  Pool := TScanAnalysisPool.Create(4);
  try
    for I := 0 to 3 do
    begin
      FileName := IncludeTrailingPathDelimiter(RaceRoot) + 'job-' +
        IntToStr(I) + DirectorySeparator + 'package.json';
      WriteText(FileName, '{"name":"cancel-job-' + IntToStr(I) +
        '","version":"1.0.' + IntToStr(I) + '"}');
      Input := S7OpenVerified(FileName, RootCanonical);
      Job := TScanAnalysisJob.Create(I, FileName,
        'job-' + IntToStr(I) + '/package.json', Input, True,
        Ord(I = 0) * 1500);
      Input := nil;
      AssertTrue(Pool.Submit(Job),
        'cancel-race pool rejected an in-cap job');
      Job := nil;
    end;
    Deadline := GetTickCount64 + 1000;
    while (GetTickCount64 < Deadline) and not Pool.IsResultReady(1) do
      Pool.WaitForResult(10);
    AssertTrue(Pool.IsResultReady(1),
      'cancel-race fixture never stored a later result');
    Pool.RequestCancel;
    Pool.CancelAndJoin;
  finally
    Pool.Free;
  end;
  AfterHandles := S7OpenHandleCount;
  AssertEqual(BeforeHandles, AfterHandles,
    'cancel/join leaked native handles');
end;

function S7ReadRawFile(const AFileName: string): RawByteString;
var
  Stream: TFileStream;
begin
  Result := '';
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    SetLength(Result, Stream.Size);
    if Length(Result) > 0 then
      Stream.ReadBuffer(Result[1], Length(Result));
  finally
    Stream.Free;
  end;
end;

procedure S7CaptureFile(const AFileName, ARoot: string;
  out AIdentity: TVerifiedFileIdentity; out ADigest: string);
var
  Input: TVerifiedInput;
  Stream: TStream;
  Reason: string;
begin
  AssertTrue(TryCaptureVerifiedFileIdentity(AFileName, ARoot, False,
    AIdentity, Reason), 'cache fixture identity capture failed: ' + Reason);
  AssertTrue(TryOpenVerifiedInput(AFileName, ARoot, False, AIdentity,
    Input, Reason), 'cache fixture verified open failed: ' + Reason);
  try
    Stream := Input.NewStream;
    try
      AssertTrue(SHA256Stream(Stream, ADigest, nil, nil),
        'cache fixture digest was cancelled');
    finally
      Stream.Free;
    end;
    AssertTrue(Input.ValidateStable(Reason),
      'cache fixture changed during hashing: ' + Reason);
  finally
    Input.Free;
  end;
end;

function S7CacheUnicodeName: string;
begin
  Result := 'pr' + #$C3#$B8 + 'be-' + #$E7#$BB#$84#$E4#$BB#$B6;
end;

procedure S7BuildCacheEvidence(const ARelativePath: string;
  const AIdentity: TVerifiedFileIdentity; const AName, AVersion: string;
  AExposeHash: Boolean; const ADigest: string; out AArtifact: TArtifact;
  out AComponents: TObjectList; out ATools, AWarnings: TStringList);
var
  Component: uModels.TComponent;
begin
  AArtifact := TArtifact.Create;
  AArtifact.RelativePath := ARelativePath;
  AArtifact.AbsolutePath := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'private-cache-path' + DirectorySeparator + ExtractFileName(ARelativePath);
  AArtifact.ArtifactType := 'cache fixture';
  AArtifact.Ecosystem := 'native';
  AArtifact.Status := arsParsed;
  AArtifact.ParserName := 'cache-fixture-parser';
  AArtifact.FileSize := AIdentity.Size;
  if AExposeHash then
    AArtifact.SHA256 := ADigest;
  AArtifact.MessageText := 'bounded cache fixture evidence';
  AArtifact.ComponentCount := 1;

  AComponents := TObjectList.Create(True);
  Component := uModels.TComponent.Create;
  Component.ComponentType := 'library';
  Component.Name := AName;
  Component.Version := AVersion;
  Component.Ecosystem := 'native';
  Component.SourceArtifact := ARelativePath;
  Component.SourceParser := 'cache-fixture-parser';
  Component.EvidencePaths.Add(ARelativePath);
  Component.DeclaredLicenses.Add('License-' + #$C3#$A9);
  Component.DeclaredPublishers.Add('Publisher-' + #$E6#$9D#$B1#$E4#$BA#$AC);
  if AExposeHash then
    Component.SHA256 := ADigest;
  AComponents.Add(Component);

  ATools := TStringList.Create;
  ATools.Add('cache-fixture-reader');
  AWarnings := TStringList.Create;
  AWarnings.Add('cache fixture warning for ' + ARelativePath);
end;

procedure S7FreeCacheEvidence(var AArtifact: TArtifact;
  var AComponents: TObjectList; var ATools, AWarnings: TStringList);
begin
  FreeAndNil(AWarnings);
  FreeAndNil(ATools);
  FreeAndNil(AComponents);
  FreeAndNil(AArtifact);
end;

procedure S7StageCacheEvidence(ACache: TScanCache;
  const ARelativePath: string; const AIdentity: TVerifiedFileIdentity;
  const ADigest, AName, AVersion: string; AExposeHash: Boolean);
var
  Artifact: TArtifact;
  Components: TObjectList;
  Tools, Warnings: TStringList;
  Diagnostic: string;
begin
  Artifact := nil;
  Components := nil;
  Tools := nil;
  Warnings := nil;
  S7BuildCacheEvidence(ARelativePath, AIdentity, AName, AVersion,
    AExposeHash, ADigest, Artifact, Components, Tools, Warnings);
  try
    AssertTrue(ACache.Stage(ARelativePath, AIdentity, ADigest, Artifact,
      Components, Tools, Warnings, Diagnostic),
      'cache evidence staging failed: ' + Diagnostic);
  finally
    S7FreeCacheEvidence(Artifact, Components, Tools, Warnings);
  end;
end;

function S7CachePlatformToken: string;
begin
  {$IFDEF Windows}
  Result := 'windows';
  {$ELSE}
  {$IFDEF Linux}
  Result := 'linux';
  {$ELSE}
  Result := 'other';
  {$ENDIF}
  {$ENDIF}
  {$IFDEF CPUX86_64}
  Result := Result + '-x86_64';
  {$ELSE}
  {$IFDEF CPUAARCH64}
  Result := Result + '-aarch64';
  {$ELSE}
  Result := Result + '-unknown-cpu';
  {$ENDIF}
  {$ENDIF}
end;

procedure S7AppendCacheDigestField(var ABuffer: RawByteString;
  const AValue: string);
var
  RawValue: RawByteString;
begin
  RawValue := RawByteString(AValue);
  ABuffer := ABuffer + RawByteString(IntToStr(Length(RawValue))) + ':' +
    RawValue + #0;
end;

function S7CacheSettingsSHA256(ASettings: TScanSettings): string;
var
  Buffer: RawByteString;
  Pattern, PatternValue: string;
  Patterns: TStringList;
  I: Integer;
begin
  Buffer := 'purpleray-analysis-settings-v1'#0;
  S7AppendCacheDigestField(Buffer,
    BoolToStr(ASettings.FollowSymbolicLinks, True));
  S7AppendCacheDigestField(Buffer,
    BoolToStr(ASettings.AllowOutsideRoot, True));
  S7AppendCacheDigestField(Buffer,
    BoolToStr(ASettings.CalculateSHA256, True));
  Patterns := TStringList.Create;
  try
    Patterns.Sorted := True;
    Patterns.Duplicates := dupIgnore;
    Patterns.UseLocale := False;
    {$IFDEF Windows}
    Patterns.CaseSensitive := False;
    {$ELSE}
    Patterns.CaseSensitive := True;
    {$ENDIF}
    for I := 0 to ASettings.IgnorePatterns.Count - 1 do
    begin
      Pattern := NormalizeRelativePath(ASettings.IgnorePatterns[I]);
      if (Pattern = '') or (Pattern[1] = '#') then
        Continue;
      {$IFDEF Windows}
      PatternValue := LowerCase(Pattern);
      {$ELSE}
      PatternValue := Pattern;
      {$ENDIF}
      Patterns.Add(PatternValue);
    end;
    S7AppendCacheDigestField(Buffer, IntToStr(Patterns.Count));
    for I := 0 to Patterns.Count - 1 do
      S7AppendCacheDigestField(Buffer, Patterns[I]);
  finally
    Patterns.Free;
  end;
  Result := SHA256String(Buffer);
end;

procedure S7BuildEngineCacheContext(const AProfile, ARoot: string;
  ASettings: TScanSettings; out AContext: TScanCacheContext);
var
  Pin: TPinnedDirectory;
  RootCanonical: string;
begin
  RootCanonical := CanonicalPath(ARoot);
  Pin := PinExistingDirectory(ARoot);
  try
    InitializeScanCacheContext(AContext, ScanAnalysisContract,
      S7CachePlatformToken, ScanCacheProfilePathSHA256(AProfile),
      SHA256String(RawByteString('purpleray-root-path-v1'#0 +
        RootCanonical)), Pin.IdentityToken, S7CacheSettingsSHA256(ASettings));
  finally
    Pin.Free;
  end;
end;

function S7CacheContextJSON(const AContext: TScanCacheContext): string;
begin
  Result := '"context":{"analysis_contract":"' +
    AContext.AnalysisContract + '","platform":"' + AContext.Platform +
    '","profile_path_sha256":"' + AContext.ProfilePathSHA256 +
    '","root_path_sha256":"' + AContext.RootPathSHA256 +
    '","root_identity_token":"' + AContext.RootIdentityToken +
    '","settings_sha256":"' + AContext.SettingsSHA256 + '"}';
end;

procedure S7ReadPersistedCacheContext(const ACacheFileName: string;
  out AContext: TScanCacheContext);
var
  Data: TJSONData;
  Root, ContextObject: TJSONObject;
begin
  Data := GetJSON(string(S7ReadRawFile(ACacheFileName)));
  try
    AssertTrue(Data.JSONType = jtObject,
      'persisted cache root is not an object');
    Root := TJSONObject(Data);
    ContextObject := JSONObject(Root, 'context');
    AssertTrue(ContextObject <> nil,
      'persisted cache context is missing');
    InitializeScanCacheContext(AContext,
      JSONString(ContextObject, 'analysis_contract'),
      JSONString(ContextObject, 'platform'),
      JSONString(ContextObject, 'profile_path_sha256'),
      JSONString(ContextObject, 'root_path_sha256'),
      JSONString(ContextObject, 'root_identity_token'),
      JSONString(ContextObject, 'settings_sha256'));
  finally
    Data.Free;
  end;
end;

procedure S7AssertCacheContextMiss(const AProfile: string;
  const AContext: TScanCacheContext; const AMessage: string);
var
  Cache: TScanCache;
  Diagnostic: string;
begin
  Cache := TScanCache.Create(scmUse, AProfile, AContext);
  try
    AssertTrue(not Cache.Load(Diagnostic), AMessage);
    AssertEqual('', Diagnostic,
      AMessage + ' was misreported as malformed cache data');
  finally
    Cache.Free;
  end;
end;

procedure S7AssertMalformedCacheRejected(const AProfile: string;
  const AContext: TScanCacheContext; const AContent: RawByteString;
  const AMessage: string);
var
  Cache: TScanCache;
  Diagnostic: string;
begin
  WriteText(IncludeTrailingPathDelimiter(AProfile) +
    DefaultScanCacheFileName, AContent);
  Cache := TScanCache.Create(scmUse, AProfile, AContext);
  try
    AssertTrue(not Cache.Load(Diagnostic), AMessage);
    AssertTrue(Diagnostic <> '', AMessage + ' lacked a diagnostic');
  finally
    Cache.Free;
  end;
end;

function S7CountCacheTemporaryFiles(const AProfile: string): Integer;
var
  SearchRecord: TSearchRec;
  FindResult: Integer;
begin
  Result := 0;
  FindResult := FindFirst(IncludeTrailingPathDelimiter(AProfile) +
    DefaultScanCacheFileName + '.tmp-*', faAnyFile, SearchRecord);
  if FindResult <> 0 then
    Exit;
  try
    while FindResult = 0 do
    begin
      Inc(Result);
      FindResult := FindNext(SearchRecord);
    end;
  finally
    FindClose(SearchRecord);
  end;
end;

procedure TestSprint7CacheUnitContracts;
const
  RelativePath = 'bin/sample.bin';
var
  RootPath, ProfileA, ProfileB, FileName, CacheFileName: string;
  Context, OtherContext: TScanCacheContext;
  Identity, ChangedIdentity, SyntheticIdentity: TVerifiedFileIdentity;
  Digest, ChangedDigest, Diagnostic: string;
  Cache: TScanCache;
  Evidence: TScanCacheEvidence;
  EmptyComponents, Components: TObjectList;
  Artifact: TArtifact;
  Tools, Warnings: TStringList;
  SavedCache, InvalidUTF8, NodeBomb: RawByteString;
  Stream: TFileStream;
  I, NodeCount: Integer;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-unit-root');
  ProfileA := NewTemporaryDirectory('sprint7-cache-unit-profile-a');
  ProfileB := NewTemporaryDirectory('sprint7-cache-unit-profile-b');
  FileName := IncludeTrailingPathDelimiter(RootPath) + 'sample.bin';
  ForceDirectories(ExtractFileDir(IncludeTrailingPathDelimiter(RootPath) +
    RelativePath));
  FileName := IncludeTrailingPathDelimiter(RootPath) +
    StringReplace(RelativePath, '/', DirectorySeparator, [rfReplaceAll]);
  WriteText(FileName, 'alpha');
  S7CaptureFile(FileName, CanonicalPath(RootPath), Identity, Digest);
  InitializeScanCacheContext(Context, 'cache-unit-analysis-v1',
    S7CachePlatformToken, ScanCacheProfilePathSHA256(ProfileA),
    SHA256String('cache-unit-root'), 'cache-unit-root-identity',
    SHA256String('cache-unit-settings'));

  AssertEqual(VerifiedFileIdentityHexLength,
    Length(EncodeVerifiedFileIdentity(Identity)),
    'cache identity encoding length differs');
  SyntheticIdentity := Identity;
  SyntheticIdentity.Valid := False;
  AssertEqual('', EncodeVerifiedFileIdentity(SyntheticIdentity),
    'invalid file identity was encoded');

  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'absent cache unexpectedly loaded');
    AssertEqual('', Diagnostic, 'absent cache emitted a diagnostic');
    S7StageCacheEvidence(Cache, RelativePath, Identity, Digest,
      S7CacheUnicodeName, '1.2.3', False);
    AssertTrue(Cache.Commit(Diagnostic),
      'initial cache commit failed: ' + Diagnostic);
  finally
    Cache.Free;
  end;
  CacheFileName := IncludeTrailingPathDelimiter(ProfileA) +
    DefaultScanCacheFileName;
  SavedCache := S7ReadRawFile(CacheFileName);
  AssertTrue(Pos(TemporaryRoot, string(SavedCache)) = 0,
    'cache persisted a raw absolute path');
  AssertTrue(Pos('private-cache-path', string(SavedCache)) = 0,
    'cache persisted artifact AbsolutePath');
  AssertEqual(0, S7CountCacheTemporaryFiles(ProfileA),
    'atomic cache commit left a temporary file');

  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(Cache.Load(Diagnostic),
      'valid cache did not load: ' + Diagnostic);
    Evidence := nil;
    AssertTrue(Cache.TryLookup(RelativePath, Identity, Digest, Evidence),
      'exact cache lookup missed');
    try
      AssertTrue(Evidence.Artifact <> nil,
        'positive cache hit lost its artifact');
      AssertEqual('', Evidence.Artifact.AbsolutePath,
        'cache hit exposed an absolute path');
      AssertEqual('', Evidence.Artifact.SHA256,
        'private lookup digest leaked into artifact evidence');
      AssertEqual(1, Evidence.Components.Count,
        'positive cache component count differs');
      AssertEqual(S7CacheUnicodeName,
        uModels.TComponent(Evidence.Components[0]).Name,
        'valid UTF-8 cache evidence did not round-trip');
      AssertEqual('', uModels.TComponent(Evidence.Components[0]).SHA256,
        'private lookup digest leaked into component evidence');
      Evidence.Artifact.ParserName := 'mutated-result';
      uModels.TComponent(Evidence.Components[0]).Version := 'mutated-result';
    finally
      Evidence.Free;
    end;
    AssertTrue(Cache.TryLookup(RelativePath, Identity, Digest, Evidence),
      'second exact cache lookup missed');
    try
      AssertEqual('cache-fixture-parser', Evidence.Artifact.ParserName,
        'cache lookup did not return an independent clone');
      AssertEqual('1.2.3',
        uModels.TComponent(Evidence.Components[0]).Version,
        'mutating one hit changed retained cache evidence');
    finally
      Evidence.Free;
    end;
    SyntheticIdentity := Identity;
    SyntheticIdentity.ModifiedNanoseconds :=
      SyntheticIdentity.ModifiedNanoseconds xor 1;
    AssertTrue(not Cache.TryLookup(RelativePath, SyntheticIdentity, Digest,
      Evidence), 'identity mismatch produced a cache hit');
    AssertTrue(not Cache.TryLookup(RelativePath, Identity,
      SHA256String('different bytes'), Evidence),
      'fresh digest mismatch produced a cache hit');
  finally
    Cache.Free;
  end;

  OtherContext := Context;
  OtherContext.AnalysisContract := 'cache-unit-analysis-v2';
  S7AssertCacheContextMiss(ProfileA, OtherContext,
    'analysis-contract mismatch loaded cache');
  OtherContext := Context;
  OtherContext.Platform := OtherContext.Platform + '-other';
  S7AssertCacheContextMiss(ProfileA, OtherContext,
    'platform mismatch loaded cache');
  OtherContext := Context;
  OtherContext.RootPathSHA256 := SHA256String('other-root');
  S7AssertCacheContextMiss(ProfileA, OtherContext,
    'root-path mismatch loaded cache');
  OtherContext := Context;
  OtherContext.RootIdentityToken := 'other-root-identity';
  S7AssertCacheContextMiss(ProfileA, OtherContext,
    'root-identity mismatch loaded cache');
  OtherContext := Context;
  OtherContext.SettingsSHA256 := SHA256String('other-settings');
  S7AssertCacheContextMiss(ProfileA, OtherContext,
    'settings mismatch loaded cache');
  WriteText(IncludeTrailingPathDelimiter(ProfileB) +
    DefaultScanCacheFileName, SavedCache);
  OtherContext := Context;
  OtherContext.ProfilePathSHA256 := ScanCacheProfilePathSHA256(ProfileB);
  S7AssertCacheContextMiss(ProfileB, OtherContext,
    'copied cache loaded under another profile');

  Cache := TScanCache.Create(scmRefresh, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'refresh mode loaded an existing snapshot');
    AssertTrue(not Cache.TryLookup(RelativePath, Identity, Digest, Evidence),
      'refresh mode returned an old hit');
    EmptyComponents := TObjectList.Create(True);
    Warnings := TStringList.Create;
    try
      Warnings.Add('negative cache evidence');
      AssertTrue(Cache.Stage(RelativePath, Identity, Digest, nil,
        EmptyComponents, nil, Warnings, Diagnostic),
        'negative cache entry staging failed: ' + Diagnostic);
    finally
      Warnings.Free;
      EmptyComponents.Free;
    end;
    AssertTrue(Cache.Commit(Diagnostic),
      'negative cache commit failed: ' + Diagnostic);
  finally
    Cache.Free;
  end;
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(Cache.Load(Diagnostic),
      'negative cache snapshot did not load: ' + Diagnostic);
    AssertTrue(Cache.TryLookup(RelativePath, Identity, Digest, Evidence),
      'negative cache entry missed');
    try
      AssertTrue((Evidence.Artifact = nil) and
        (Evidence.Components.Count = 0),
        'negative cache entry fabricated evidence');
      AssertTrue(Evidence.Warnings.IndexOf('negative cache evidence') >= 0,
        'negative cache warning was not preserved');
    finally
      Evidence.Free;
    end;
  finally
    Cache.Free;
  end;

  { Restore a positive snapshot before atomic rollback and parser tests. }
  Cache := TScanCache.Create(scmRefresh, ProfileA, Context);
  try
    S7StageCacheEvidence(Cache, RelativePath, Identity, Digest,
      'restored-cache-entry', '2.0.0', True);
    AssertTrue(Cache.Commit(Diagnostic),
      'positive cache restore failed: ' + Diagnostic);
  finally
    Cache.Free;
  end;
  SavedCache := S7ReadRawFile(CacheFileName);

  Cache := TScanCache.Create(scmRefresh, ProfileA, Context);
  try
    EmptyComponents := TObjectList.Create(True);
    try
      AssertTrue(Cache.Stage('pending/no-commit', Identity, Digest, nil,
        EmptyComponents, Diagnostic),
        'abandoned cache staging fixture failed: ' + Diagnostic);
    finally
      EmptyComponents.Free;
    end;
  finally
    Cache.Free;
  end;
  AssertEqual(string(SavedCache), string(S7ReadRawFile(CacheFileName)),
    'destroying uncommitted cache staging changed the snapshot');

  Artifact := nil;
  Components := nil;
  Tools := nil;
  Warnings := nil;
  Cache := TScanCache.Create(scmRefresh, ProfileA, Context);
  try
    S7BuildCacheEvidence(RelativePath, Identity, 'bad-component-hash',
      '2.0.0', True, Digest, Artifact, Components, Tools, Warnings);
    uModels.TComponent(Components[0]).SHA256 :=
      SHA256String('unrelated component bytes');
    AssertTrue(not Cache.Stage(RelativePath, Identity, Digest, Artifact,
      Components, Tools, Warnings, Diagnostic),
      'unrelated component digest was staged');
    AssertTrue(not Cache.Commit(Diagnostic),
      'invalid cache snapshot was committed');
  finally
    Cache.Free;
    S7FreeCacheEvidence(Artifact, Components, Tools, Warnings);
  end;
  AssertEqual(string(SavedCache), string(S7ReadRawFile(CacheFileName)),
    'failed cache commit changed the previous snapshot');
  AssertEqual(0, S7CountCacheTemporaryFiles(ProfileA),
    'failed cache commit left a temporary file');

  WriteText(FileName, 'bravo');
  S7CaptureFile(FileName, CanonicalPath(RootPath), ChangedIdentity,
    ChangedDigest);
  WriteText(CacheFileName, SavedCache);
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(Cache.Load(Diagnostic),
      'cache did not load for changed-input miss testing');
    AssertTrue(not Cache.TryLookup(RelativePath, ChangedIdentity,
      ChangedDigest, Evidence), 'changed input produced a cache hit');
    AssertTrue(not Cache.TryLookup(RelativePath, Identity,
      ChangedDigest, Evidence),
      'fresh digest did not defeat restored-identity simulation');
  finally
    Cache.Free;
  end;

  S7AssertMalformedCacheRejected(ProfileA, Context,
    RawByteString(StringReplace(string(SavedCache),
      '"context" : { "analysis_contract" : ',
      '"context" : { "analysis_contract" : "duplicate", ' +
      '"analysis_contract" : ', [])),
    'duplicate cache-context key was accepted');
  S7AssertMalformedCacheRejected(ProfileA, Context,
    RawByteString(StringReplace(string(SavedCache),
      '"entries" : [{ "relative_path" : ',
      '"entries" : [{ "relative_path" : "duplicate", ' +
      '"relative_path" : ', [])),
    'duplicate cache-entry key was accepted');
  S7AssertMalformedCacheRejected(ProfileA, Context,
    RawByteString(StringReplace(string(SavedCache),
      '"artifact" : { "relative_path" : ',
      '"artifact" : { "relative_path" : "duplicate", ' +
      '"relative_path" : ', [])),
    'duplicate cache-artifact key was accepted');
  S7AssertMalformedCacheRejected(ProfileA, Context,
    RawByteString(StringReplace(string(SavedCache),
      '"components" : [{ "component_type" : ',
      '"components" : [{ "component_type" : "library", ' +
      '"component_type" : ', [])),
    'duplicate cache-component key was accepted');

  WriteText(CacheFileName, RawByteString(
    '{"format":"purpleray-scan-cache",' +
    '"format":"purpleray-scan-cache","format_version":1,' +
    S7CacheContextJSON(Context) + ',"entries":[]}'));
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'duplicate cache root key was accepted');
    AssertTrue(Diagnostic <> '',
      'duplicate cache root key lacked a diagnostic');
  finally
    Cache.Free;
  end;
  WriteText(CacheFileName, SavedCache + ' trailing-json-junk');
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'trailing cache JSON junk was accepted');
    AssertTrue(Diagnostic <> '',
      'trailing cache JSON junk lacked a diagnostic');
  finally
    Cache.Free;
  end;
  InvalidUTF8 := RawByteString('{"x":"') + RawByteString(#$C0#$AF) +
    RawByteString('"}');
  WriteText(CacheFileName, InvalidUTF8);
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'overlong cache UTF-8 was accepted');
    AssertTrue(Pos('valid UTF-8', Diagnostic) > 0,
      'invalid cache UTF-8 lacked its deterministic diagnostic');
  finally
    Cache.Free;
  end;
  WriteText(CacheFileName, RawByteString(StringOfChar('[', 17) +
    StringOfChar(']', 17)));
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'over-depth cache JSON was accepted');
    AssertTrue(Pos('depth', LowerCase(Diagnostic)) > 0,
      'over-depth cache JSON lacked its bound diagnostic');
  finally
    Cache.Free;
  end;
  NodeCount := MaximumScanCacheJSONNodes + 1;
  SetLength(NodeBomb, (NodeCount * 2) + 1);
  NodeBomb[1] := '[';
  for I := 0 to NodeCount - 1 do
  begin
    NodeBomb[2 + (I * 2)] := '0';
    if I < NodeCount - 1 then
      NodeBomb[3 + (I * 2)] := ',';
  end;
  NodeBomb[Length(NodeBomb)] := ']';
  WriteText(CacheFileName, NodeBomb);
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'flat cache JSON node bomb was accepted');
    AssertTrue(Diagnostic <> '',
      'flat cache JSON node bomb lacked a diagnostic');
  finally
    Cache.Free;
  end;
  Stream := TFileStream.Create(CacheFileName, fmCreate);
  try
    Stream.Size := MaximumScanCacheBytes + 1;
  finally
    Stream.Free;
  end;
  Cache := TScanCache.Create(scmUse, ProfileA, Context);
  try
    AssertTrue(not Cache.Load(Diagnostic),
      'oversized cache file was accepted');
    AssertTrue(Pos('exceeds', LowerCase(Diagnostic)) > 0,
      'oversized cache lacked its bound diagnostic');
  finally
    Cache.Free;
  end;
end;

function S7NewCacheTask(const ARoot: string; ACalculateSHA256,
  ARefresh: Boolean): TScanTask;
begin
  Result := TScanTask.Create;
  S7ConfigureTask(Result, ARoot);
  Result.ID := '00000000-0000-4000-8000-000000000707';
  Result.TargetRootName := 'sprint7-cache-root';
  Result.Settings.CalculateSHA256 := ACalculateSHA256;
  Result.Settings.UseRescanCache := True;
  Result.Settings.RefreshRescanCache := ARefresh;
end;

function S7ScanWithCacheWorkers(const ARoot, AProfile: string;
  AWorkerCount: Integer; ACalculateSHA256: Boolean): TScanTask;
var
  Engine: TScanEngine;
  Options: TScanExecutionOptions;
begin
  Result := S7NewCacheTask(ARoot, ACalculateSHA256, False);
  Options := DefaultScanExecutionOptions;
  Options.WorkerCount := AWorkerCount;
  Options.CacheProfileDirectory := AProfile;
  Engine := TScanEngine.Create(nil, nil, Options);
  try
    try
      AssertTrue(Engine.Scan(Result),
        'cache worker-count scan did not complete');
    except
      Result.Free;
      Result := nil;
      raise;
    end;
  finally
    Engine.Free;
  end;
end;

procedure S7AssertNoExposedEvidenceSHA256(ATask: TScanTask;
  const AMessage: string);
var
  I: Integer;
begin
  for I := 0 to ATask.Artifacts.Count - 1 do
    AssertEqual('', TArtifact(ATask.Artifacts[I]).SHA256,
      AMessage + ': artifact SHA-256 was exposed');
  for I := 0 to ATask.Components.Count - 1 do
    AssertEqual('', uModels.TComponent(ATask.Components[I]).SHA256,
      AMessage + ': component SHA-256 was exposed');
end;

procedure S7AssertDirectAnalysisCacheHit(const AFileName, ARoot,
  ARelativePath, AExpectedDigest: string; ACalculateSHA256: Boolean;
  ACache: TScanCache);
var
  Input: TVerifiedInput;
  Job: TScanAnalysisJob;
  AnalysisResult: TScanAnalysisResult;
begin
  Input := nil;
  Job := nil;
  AnalysisResult := nil;
  try
    Input := S7OpenVerified(AFileName, CanonicalPath(ARoot));
    Job := TScanAnalysisJob.Create(0, AFileName, ARelativePath, Input,
      ACalculateSHA256, 0, ACache);
    Input := nil;
    AnalysisResult := ExecuteScanAnalysis(Job, nil);
    AssertTrue(AnalysisResult.CacheHit,
      'direct analysis did not consume the committed cache entry');
    AssertEqual(AExpectedDigest, AnalysisResult.ContentSHA256,
      'direct cache hit did not retain its private fresh digest');
    AssertTrue(AnalysisResult.Artifact <> nil,
      'direct positive cache hit lost its artifact');
    AssertEqual(ExpandFileName(AFileName),
      AnalysisResult.Artifact.AbsolutePath,
      'direct cache hit did not restore its transient absolute path');
    if not ACalculateSHA256 then
    begin
      AssertEqual('', AnalysisResult.Artifact.SHA256,
        'private digest leaked from a direct cache hit');
      if AnalysisResult.Components.Count > 0 then
        AssertEqual('',
          uModels.TComponent(AnalysisResult.Components[0]).SHA256,
          'private digest leaked into a direct cached component');
    end;
  finally
    AnalysisResult.Free;
    Job.Free;
    Input.Free;
  end;
end;

procedure S7AssertCacheSettingsDigestContract;
var
  Baseline, Changed: TScanSettings;
  BaselineDigest: string;
begin
  Baseline := TScanSettings.Create;
  Changed := TScanSettings.Create;
  try
    Baseline.IgnorePatterns.Clear;
    Baseline.IgnorePatterns.Add('vendor');
    Baseline.IgnorePatterns.Add('build/tmp');
    BaselineDigest := S7CacheSettingsSHA256(Baseline);

    Changed.Assign(Baseline);
    Changed.UseRescanCache := True;
    Changed.RefreshRescanCache := True;
    Changed.IncludeAbsolutePaths := True;
    Changed.SBOMAuthorOrganization := 'Private author organization';
    Changed.SBOMAuthorEmail := 'private@example.invalid';
    Changed.RememberPrivacyChoices := True;
    AssertEqual(BaselineDigest, S7CacheSettingsSHA256(Changed),
      'presentation, persistence, or cache controls changed cache context');

    Changed.Assign(Baseline);
    Changed.IgnorePatterns.Clear;
    Changed.IgnorePatterns.Add('# ignored comment');
    Changed.IgnorePatterns.Add('build/tmp');
    Changed.IgnorePatterns.Add('vendor');
    Changed.IgnorePatterns.Add('vendor');
    AssertEqual(BaselineDigest, S7CacheSettingsSHA256(Changed),
      'equivalent ignore-rule set changed cache context');

    Changed.Assign(Baseline);
    Changed.FollowSymbolicLinks := not Changed.FollowSymbolicLinks;
    AssertTrue(BaselineDigest <> S7CacheSettingsSHA256(Changed),
      'symbolic-link evidence policy was omitted from cache context');
    Changed.Assign(Baseline);
    Changed.AllowOutsideRoot := not Changed.AllowOutsideRoot;
    AssertTrue(BaselineDigest <> S7CacheSettingsSHA256(Changed),
      'root-boundary evidence policy was omitted from cache context');
    Changed.Assign(Baseline);
    Changed.CalculateSHA256 := not Changed.CalculateSHA256;
    AssertTrue(BaselineDigest <> S7CacheSettingsSHA256(Changed),
      'exposed-hash policy was omitted from cache context');
    Changed.Assign(Baseline);
    Changed.IgnorePatterns.Add('generated');
    AssertTrue(BaselineDigest <> S7CacheSettingsSHA256(Changed),
      'changed ignore evidence policy was omitted from cache context');
  finally
    Changed.Free;
    Baseline.Free;
  end;
end;

procedure TestSprint7CacheServiceLifecycle;
const
  PackageRelativePath = 'package.json';
  OrdinaryRelativePath = 'ordinary.txt';
var
  RootPath, ProfilePath, OutputPath, CacheFileName, PackageFileName,
    OrdinaryFileName, PackageDigest, OrdinaryDigest, Diagnostic,
    BaselineSignature, HitSignature, WorkerOneSignature,
    WorkerFourSignature: string;
  BaselineDocument, HitDocument, WorkerOneDocument,
    WorkerFourDocument: UTF8String;
  PersistedContext, ExpectedContext: TScanCacheContext;
  PackageIdentity, OrdinaryIdentity: TVerifiedFileIdentity;
  BaselineTask, HitTask, WorkerOneTask, WorkerFourTask: TScanTask;
  Cache: TScanCache;
  Evidence: TScanCacheEvidence;
  RawCache: RawByteString;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-service-root');
  ProfilePath := NewTemporaryDirectory('sprint7-cache-service-profile');
  OutputPath := IncludeTrailingPathDelimiter(
    NewTemporaryDirectory('sprint7-cache-service-output')) +
    'baseline.cdx.json';
  PackageFileName := IncludeTrailingPathDelimiter(RootPath) +
    PackageRelativePath;
  OrdinaryFileName := IncludeTrailingPathDelimiter(RootPath) +
    OrdinaryRelativePath;
  WriteText(PackageFileName,
    '{"name":"cache-lifecycle","version":"1.2.3"}');
  WriteText(OrdinaryFileName, 'ordinary negative cache entry');
  CacheFileName := IncludeTrailingPathDelimiter(ProfilePath) +
    DefaultScanCacheFileName;
  BaselineTask := nil;
  HitTask := nil;
  WorkerOneTask := nil;
  WorkerFourTask := nil;
  Cache := nil;
  Evidence := nil;
  try
    AssertTrue(not FileExists(CacheFileName),
      'cache service fixture started with an existing snapshot');
    BaselineTask := S7NewCacheTask(RootPath, True, False);
    AssertTrue(ExecuteScanToFile(BaselineTask, OutputPath, nil, nil,
      sopManagedApplicationData, ProfilePath),
      'cache miss service scan did not complete');
    AssertTrue(FileExists(CacheFileName),
      'successful SBOM output did not commit the rescan cache');
    AssertTrue(FindComponent(BaselineTask.Components,
      'cache-lifecycle') <> nil,
      'cache miss scan did not publish manifest evidence');
    BaselineSignature := S7TaskEvidenceSignature(BaselineTask);

    S7ReadPersistedCacheContext(CacheFileName, PersistedContext);
    S7BuildEngineCacheContext(ProfilePath, RootPath,
      BaselineTask.Settings, ExpectedContext);
    AssertEqual(ScanAnalysisContract, PersistedContext.AnalysisContract,
      'cache used a release/build identifier as its analysis contract');
    AssertEqual(ExpectedContext.AnalysisContract,
      PersistedContext.AnalysisContract,
      'persisted cache analysis contract differs');
    AssertEqual(ExpectedContext.Platform, PersistedContext.Platform,
      'persisted cache platform token differs');
    AssertEqual(ExpectedContext.ProfilePathSHA256,
      PersistedContext.ProfilePathSHA256,
      'persisted cache profile binding differs');
    AssertEqual(ExpectedContext.RootPathSHA256,
      PersistedContext.RootPathSHA256,
      'persisted cache root-path binding differs');
    AssertEqual(ExpectedContext.RootIdentityToken,
      PersistedContext.RootIdentityToken,
      'persisted cache root-identity binding differs');
    AssertEqual(S7CacheSettingsSHA256(BaselineTask.Settings),
      PersistedContext.SettingsSHA256,
      'persisted cache settings profile is not the curated evidence digest');
    RawCache := S7ReadRawFile(CacheFileName);
    AssertTrue(Pos(CanonicalPath(RootPath), string(RawCache)) = 0,
      'service cache persisted the raw scan root');
    AssertTrue(Pos(CanonicalPath(ProfilePath), string(RawCache)) = 0,
      'service cache persisted the raw profile path');
    AssertTrue((Pos(PackageRelativePath, string(RawCache)) > 0) and
      (Pos(OrdinaryRelativePath, string(RawCache)) > 0),
      'service cache did not retain its complete positive/negative snapshot');

    S7CaptureFile(PackageFileName, CanonicalPath(RootPath),
      PackageIdentity, PackageDigest);
    S7CaptureFile(OrdinaryFileName, CanonicalPath(RootPath),
      OrdinaryIdentity, OrdinaryDigest);
    Cache := TScanCache.Create(scmUse, ProfilePath, PersistedContext);
    AssertTrue(Cache.Load(Diagnostic),
      'service-generated cache did not load: ' + Diagnostic);
    AssertTrue(Cache.TryLookup(PackageRelativePath, PackageIdentity,
      PackageDigest, Evidence), 'positive service cache entry missed');
    try
      AssertTrue((Evidence.Artifact <> nil) and
        (Evidence.Components.Count > 0),
        'positive service cache entry lost model evidence');
      AssertEqual(PackageDigest, Evidence.Artifact.SHA256,
        'public artifact digest did not round-trip through cache');
      AssertEqual('cache-lifecycle',
        uModels.TComponent(Evidence.Components[0]).Name,
        'positive service cache component differs');
      AssertEqual(CP_UTF8,
        StringCodePage(RawByteString(Evidence.Artifact.RelativePath)),
        'cache-hit artifact relative path is not tagged CP_UTF8');
      AssertEqual(CP_UTF8,
        StringCodePage(RawByteString(Evidence.Artifact.ParserName)),
        'cache-hit artifact parser is not tagged CP_UTF8');
      AssertEqual(CP_UTF8, StringCodePage(RawByteString(
        uModels.TComponent(Evidence.Components[0]).SourceArtifact)),
        'cache-hit component source artifact is not tagged CP_UTF8');
      AssertEqual(CP_UTF8, StringCodePage(RawByteString(
        uModels.TComponent(Evidence.Components[0]).SourceParser)),
        'cache-hit component source parser is not tagged CP_UTF8');
    finally
      FreeAndNil(Evidence);
    end;
    AssertTrue(Cache.TryLookup(OrdinaryRelativePath, OrdinaryIdentity,
      OrdinaryDigest, Evidence), 'negative service cache entry missed');
    try
      AssertTrue((Evidence.Artifact = nil) and
        (Evidence.Components.Count = 0),
        'negative service cache entry fabricated evidence');
    finally
      FreeAndNil(Evidence);
    end;
    S7AssertDirectAnalysisCacheHit(PackageFileName, RootPath,
      PackageRelativePath, PackageDigest, True, Cache);
    FreeAndNil(Cache);

    HitTask := S7NewCacheTask(RootPath, True, False);
    AssertTrue(ExecuteScanToFile(HitTask,
      ChangeFileExt(OutputPath, '.hit.cdx.json'), nil, nil,
      sopManagedApplicationData, ProfilePath),
      'cache-hit service scan did not complete');
    HitSignature := S7TaskEvidenceSignature(HitTask);
    AssertEqual(BaselineSignature, HitSignature,
      'cache miss and service hit produced different evidence models');
    S7StabilizeTaskMetadata(BaselineTask);
    S7StabilizeTaskMetadata(HitTask);
    BaselineDocument := GenerateCycloneDX(BaselineTask);
    HitDocument := GenerateCycloneDX(HitTask);
    AssertEqual(string(BaselineDocument), string(HitDocument),
      'cache miss and service hit produced different CycloneDX bytes');

    RawCache := S7ReadRawFile(CacheFileName);
    WorkerOneTask := S7ScanWithCacheWorkers(RootPath, ProfilePath, 1, True);
    WorkerFourTask := S7ScanWithCacheWorkers(RootPath, ProfilePath, 4, True);
    WorkerOneSignature := S7TaskEvidenceSignature(WorkerOneTask);
    WorkerFourSignature := S7TaskEvidenceSignature(WorkerFourTask);
    AssertEqual(BaselineSignature, WorkerOneSignature,
      'one-worker cache scan changed the evidence model');
    AssertEqual(WorkerOneSignature, WorkerFourSignature,
      'one/four-worker cache scans produced different evidence models');
    S7StabilizeTaskMetadata(WorkerOneTask);
    S7StabilizeTaskMetadata(WorkerFourTask);
    WorkerOneDocument := GenerateCycloneDX(WorkerOneTask);
    WorkerFourDocument := GenerateCycloneDX(WorkerFourTask);
    AssertEqual(string(BaselineDocument), string(WorkerOneDocument),
      'one-worker cache scan changed CycloneDX bytes');
    AssertEqual(string(WorkerOneDocument), string(WorkerFourDocument),
      'one/four-worker cache scans changed CycloneDX bytes');
    AssertEqual(string(RawCache), string(S7ReadRawFile(CacheFileName)),
      'engine-only worker scans committed cache staging implicitly');

    S7AssertCacheSettingsDigestContract;
  finally
    Evidence.Free;
    Cache.Free;
    WorkerFourTask.Free;
    WorkerOneTask.Free;
    HitTask.Free;
    BaselineTask.Free;
  end;
end;

procedure TestSprint7CachePrivateDigest;
const
  PackageRelativePath = 'package.json';
var
  RootPath, ProfilePath, OutputPath, CacheFileName, PackageFileName,
    PackageDigest, Diagnostic: string;
  Context: TScanCacheContext;
  Identity: TVerifiedFileIdentity;
  Task: TScanTask;
  Cache: TScanCache;
  Evidence: TScanCacheEvidence;
  RawCache, RawOutput: RawByteString;
  I: Integer;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-private-root');
  ProfilePath := NewTemporaryDirectory('sprint7-cache-private-profile');
  OutputPath := IncludeTrailingPathDelimiter(
    NewTemporaryDirectory('sprint7-cache-private-output')) +
    'private.cdx.json';
  PackageFileName := IncludeTrailingPathDelimiter(RootPath) +
    PackageRelativePath;
  WriteText(PackageFileName,
    '{"name":"private-cache-digest","version":"4.5.6"}');
  CacheFileName := IncludeTrailingPathDelimiter(ProfilePath) +
    DefaultScanCacheFileName;
  Task := nil;
  Cache := nil;
  Evidence := nil;
  try
    Task := S7NewCacheTask(RootPath, False, False);
    AssertTrue(ExecuteScanToFile(Task, OutputPath, nil, nil,
      sopManagedApplicationData, ProfilePath),
      'private-digest service scan did not complete');
    S7AssertNoExposedEvidenceSHA256(Task, 'private-digest miss scan');
    S7CaptureFile(PackageFileName, CanonicalPath(RootPath),
      Identity, PackageDigest);
    RawCache := S7ReadRawFile(CacheFileName);
    RawOutput := S7ReadRawFile(OutputPath);
    AssertTrue(Pos(PackageDigest, string(RawCache)) > 0,
      'CalculateSHA256=false did not retain a private cache-key digest');
    AssertTrue(Pos(PackageDigest, string(RawOutput)) = 0,
      'private cache-key digest leaked into CycloneDX output');
    AssertTrue(Pos('"sha256"', string(RawOutput)) = 0,
      'CalculateSHA256=false emitted an evidence SHA-256 field');

    S7ReadPersistedCacheContext(CacheFileName, Context);
    Cache := TScanCache.Create(scmUse, ProfilePath, Context);
    AssertTrue(Cache.Load(Diagnostic),
      'private-digest cache did not load: ' + Diagnostic);
    AssertTrue(Cache.TryLookup(PackageRelativePath, Identity,
      PackageDigest, Evidence), 'private-digest cache entry missed');
    try
      AssertTrue(Evidence.Artifact <> nil,
        'private-digest cache hit lost its artifact');
      AssertEqual('', Evidence.Artifact.SHA256,
        'private digest leaked into cached artifact evidence');
      for I := 0 to Evidence.Components.Count - 1 do
        AssertEqual('', uModels.TComponent(Evidence.Components[I]).SHA256,
          'private digest leaked into cached component evidence');
    finally
      FreeAndNil(Evidence);
    end;
    S7AssertDirectAnalysisCacheHit(PackageFileName, RootPath,
      PackageRelativePath, PackageDigest, False, Cache);
  finally
    Evidence.Free;
    Cache.Free;
    Task.Free;
  end;
end;

procedure S7AssertCancelledCacheScanDoesNotCommit;
var
  RootPath, ProfilePath, OutputPath, CacheFileName: string;
  Task: TScanTask;
  Controller: TCancelController;
  I: Integer;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-cancel-root');
  ProfilePath := NewTemporaryDirectory('sprint7-cache-cancel-profile');
  OutputPath := IncludeTrailingPathDelimiter(
    NewTemporaryDirectory('sprint7-cache-cancel-output')) +
    'cancelled.cdx.json';
  for I := 0 to 31 do
    WriteText(IncludeTrailingPathDelimiter(RootPath) +
      Format('package-%2.2d.json', [I]),
      RawByteString('{"name":"cancelled-' + IntToStr(I) +
        '","version":"1.0.0"}'));
  CacheFileName := IncludeTrailingPathDelimiter(ProfilePath) +
    DefaultScanCacheFileName;
  Task := S7NewCacheTask(RootPath, True, False);
  Controller := TCancelController.Create(1);
  try
    AssertTrue(not ExecuteScanToFile(Task, OutputPath, @Controller.Check,
      nil, sopManagedApplicationData, ProfilePath),
      'cancelled cache scan reported success');
    AssertTrue(Task.Status = tsCancelled,
      'cancelled cache scan did not retain cancelled status');
    AssertTrue(not FileExists(OutputPath),
      'cancelled cache scan retained an SBOM output');
    AssertTrue(not FileExists(CacheFileName),
      'cancelled cache scan committed partial staging');
    AssertEqual(0, S7CountCacheTemporaryFiles(ProfilePath),
      'cancelled cache scan left a cache temporary file');
  finally
    Controller.Free;
    Task.Free;
  end;
end;

procedure S7AssertOutputFailureDoesNotCommitCache;
var
  RootPath, ProfilePath, CacheFileName, OutputDirectory,
    OutputFileName: string;
  Task: TScanTask;
  {$IFDEF UNIX}
  Controller: TOutputParentRebindController;
  MovedDirectory, MovedOutputFileName: string;
  {$ENDIF}
  {$IFDEF Windows}
  LockedOutput: TFileStream;
  {$ENDIF}
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-output-fail-root');
  ProfilePath := NewTemporaryDirectory('sprint7-cache-output-fail-profile');
  WriteText(IncludeTrailingPathDelimiter(RootPath) + 'package.json',
    '{"name":"output-must-fail","version":"1.0.0"}');
  CacheFileName := IncludeTrailingPathDelimiter(ProfilePath) +
    DefaultScanCacheFileName;
  OutputDirectory := NewTemporaryDirectory('sprint7-cache-output-fail');
  OutputFileName := IncludeTrailingPathDelimiter(OutputDirectory) +
    'must-not-survive.cdx.json';
  Task := S7NewCacheTask(RootPath, True, False);
  try
    {$IFDEF UNIX}
    MovedDirectory := OutputDirectory + '-moved';
    MovedOutputFileName := IncludeTrailingPathDelimiter(MovedDirectory) +
      ExtractFileName(OutputFileName);
    Controller := TOutputParentRebindController.Create(OutputDirectory,
      MovedDirectory, False);
    try
      AssertTrue(not ExecuteScanToFile(Task, OutputFileName,
        @Controller.Check, nil, sopRequireOutsideTarget, ProfilePath),
        'rebound output parent did not fail a cache-enabled scan');
      AssertTrue(Controller.Triggered and Controller.Succeeded,
        'cache output-failure fixture did not rebind its parent: ' +
        Controller.ErrorText);
      AssertTrue(Task.Status = tsFailed,
        'output failure did not fail the cache-enabled task');
      AssertTrue(not FileExists(OutputFileName) and
        not FileExists(MovedOutputFileName),
        'failed cache-enabled output survived directory revalidation');
    finally
      Controller.Free;
    end;
    {$ELSE}
    {$IFDEF Windows}
    WriteText(OutputFileName, 'locked previous output');
    LockedOutput := TFileStream.Create(OutputFileName,
      fmOpenReadWrite or fmShareExclusive);
    try
      AssertTrue(not ExecuteScanToFile(Task, OutputFileName, nil, nil,
        sopRequireOutsideTarget, ProfilePath),
        'locked output did not fail a cache-enabled Windows scan');
      AssertTrue(Task.Status = tsFailed,
        'locked Windows output did not fail the cache-enabled task');
    finally
      LockedOutput.Free;
    end;
    {$ELSE}
    raise ETestSkipped.Create(
      'requires Unix output revalidation or Windows file locking');
    {$ENDIF}
    {$ENDIF}
    AssertTrue(not FileExists(CacheFileName),
      'failed SBOM output committed cache staging');
    AssertEqual(0, S7CountCacheTemporaryFiles(ProfilePath),
      'failed SBOM output left a cache temporary file');
  finally
    Task.Free;
  end;
end;

procedure S7AssertCacheFailureIsNonFatal;
var
  RootPath, OutputPath, BlockedProfile, OriginalProfileBytes: string;
  Task: TScanTask;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-failure-root');
  OutputPath := IncludeTrailingPathDelimiter(
    NewTemporaryDirectory('sprint7-cache-failure-output')) +
    'cache-failure.cdx.json';
  WriteText(IncludeTrailingPathDelimiter(RootPath) + 'package.json',
    '{"name":"cache-failure-nonfatal","version":"1.0.0"}');
  BlockedProfile := IncludeTrailingPathDelimiter(TemporaryRoot) +
    'sprint7-cache-profile-is-a-file';
  OriginalProfileBytes := 'profile path blocker';
  WriteText(BlockedProfile, OriginalProfileBytes);
  Task := S7NewCacheTask(RootPath, True, False);
  try
    AssertTrue(ExecuteScanToFile(Task, OutputPath, nil, nil,
      sopManagedApplicationData, BlockedProfile),
      'optional cache failure changed successful scan/output status');
    AssertTrue(Task.Status = tsCompleted,
      'optional cache failure changed the completed task status');
    AssertTrue(FileExists(OutputPath),
      'optional cache failure prevented SBOM activation');
    AssertTrue(StringListContainsText(Task.Warnings,
      'optional rescan cache was unavailable or incomplete'),
      'optional cache failure lacked its nonfatal warning');
    AssertEqual(OriginalProfileBytes,
      string(S7ReadRawFile(BlockedProfile)),
      'optional cache failure modified the obstructing profile file');
  finally
    Task.Free;
  end;
end;

procedure TestSprint7CacheRefreshAndTransactions;
const
  PackageRelativePath = 'package.json';
  OrdinaryRelativePath = 'ordinary.txt';
var
  RootPath, ProfilePath, OutputDirectory, OutputPath, CacheFileName,
    PackageFileName, OrdinaryFileName, InitialDigest, RefreshedDigest,
    Diagnostic: string;
  Context: TScanCacheContext;
  InitialIdentity, RefreshedIdentity, OrdinaryIdentity:
    TVerifiedFileIdentity;
  OrdinaryDigest: string;
  InitialTask, RefreshTask, ChangedTask: TScanTask;
  Cache: TScanCache;
  Evidence: TScanCacheEvidence;
  EmptyComponents: TObjectList;
  SentinelSnapshot: RawByteString;
begin
  RootPath := NewTemporaryDirectory('sprint7-cache-refresh-root');
  ProfilePath := NewTemporaryDirectory('sprint7-cache-refresh-profile');
  OutputDirectory := NewTemporaryDirectory('sprint7-cache-refresh-output');
  OutputPath := IncludeTrailingPathDelimiter(OutputDirectory) +
    'initial.cdx.json';
  PackageFileName := IncludeTrailingPathDelimiter(RootPath) +
    PackageRelativePath;
  OrdinaryFileName := IncludeTrailingPathDelimiter(RootPath) +
    OrdinaryRelativePath;
  WriteText(PackageFileName,
    '{"name":"refresh-a","version":"1.0.0"}');
  WriteText(OrdinaryFileName, 'refresh negative entry');
  CacheFileName := IncludeTrailingPathDelimiter(ProfilePath) +
    DefaultScanCacheFileName;
  InitialTask := nil;
  RefreshTask := nil;
  ChangedTask := nil;
  Cache := nil;
  Evidence := nil;
  EmptyComponents := nil;
  try
    InitialTask := S7NewCacheTask(RootPath, True, False);
    AssertTrue(ExecuteScanToFile(InitialTask, OutputPath, nil, nil,
      sopManagedApplicationData, ProfilePath),
      'initial refresh fixture scan did not complete');
    S7ReadPersistedCacheContext(CacheFileName, Context);
    S7CaptureFile(PackageFileName, CanonicalPath(RootPath),
      InitialIdentity, InitialDigest);
    S7CaptureFile(OrdinaryFileName, CanonicalPath(RootPath),
      OrdinaryIdentity, OrdinaryDigest);

    Cache := TScanCache.Create(scmRefresh, ProfilePath, Context);
    S7StageCacheEvidence(Cache, PackageRelativePath, InitialIdentity,
      InitialDigest, 'stale-cache-sentinel', '9.9.9', True);
    EmptyComponents := TObjectList.Create(True);
    AssertTrue(Cache.Stage(OrdinaryRelativePath, OrdinaryIdentity,
      OrdinaryDigest, nil, EmptyComponents, Diagnostic),
      'sentinel negative entry staging failed: ' + Diagnostic);
    FreeAndNil(EmptyComponents);
    AssertTrue(Cache.Commit(Diagnostic),
      'sentinel cache commit failed: ' + Diagnostic);
    FreeAndNil(Cache);
    SentinelSnapshot := S7ReadRawFile(CacheFileName);
    AssertTrue(Pos('stale-cache-sentinel', string(SentinelSnapshot)) > 0,
      'refresh sentinel was not persisted');

    RefreshTask := S7NewCacheTask(RootPath, True, True);
    AssertTrue(ExecuteScanToFile(RefreshTask,
      IncludeTrailingPathDelimiter(OutputDirectory) + 'refresh.cdx.json',
      nil, nil, sopManagedApplicationData, ProfilePath),
      'full-refresh service scan did not complete');
    AssertTrue((FindComponent(RefreshTask.Components, 'refresh-a') <> nil) and
      (FindComponent(RefreshTask.Components,
        'stale-cache-sentinel') = nil),
      'refresh mode consumed stale cached evidence');
    AssertTrue(Pos('stale-cache-sentinel',
      string(S7ReadRawFile(CacheFileName))) = 0,
      'refresh mode did not replace the stale snapshot');
    Cache := TScanCache.Create(scmUse, ProfilePath, Context);
    AssertTrue(Cache.Load(Diagnostic),
      'refreshed cache did not load: ' + Diagnostic);
    AssertTrue(Cache.TryLookup(PackageRelativePath, InitialIdentity,
      InitialDigest, Evidence), 'refreshed cache entry missed');
    try
      AssertEqual('refresh-a',
        uModels.TComponent(Evidence.Components[0]).Name,
        'refreshed cache retained the stale component');
    finally
      FreeAndNil(Evidence);
    end;

    WriteText(PackageFileName,
      '{"name":"refresh-b","version":"1.0.0"}');
    S7CaptureFile(PackageFileName, CanonicalPath(RootPath),
      RefreshedIdentity, RefreshedDigest);
    AssertTrue(InitialDigest <> RefreshedDigest,
      'changed-content cache fixture retained its digest');
    AssertTrue(not Cache.TryLookup(PackageRelativePath, RefreshedIdentity,
      RefreshedDigest, Evidence),
      'changed content/identity reused the previous cache entry');
    FreeAndNil(Cache);

    ChangedTask := S7NewCacheTask(RootPath, True, False);
    AssertTrue(ExecuteScanToFile(ChangedTask,
      IncludeTrailingPathDelimiter(OutputDirectory) + 'changed.cdx.json',
      nil, nil, sopManagedApplicationData, ProfilePath),
      'changed-content cache scan did not complete');
    AssertTrue(FindComponent(ChangedTask.Components, 'refresh-b') <> nil,
      'changed-content cache scan did not publish new evidence');
    Cache := TScanCache.Create(scmUse, ProfilePath, Context);
    AssertTrue(Cache.Load(Diagnostic),
      'changed-content replacement cache did not load: ' + Diagnostic);
    AssertTrue(Cache.TryLookup(PackageRelativePath, RefreshedIdentity,
      RefreshedDigest, Evidence),
      'changed-content replacement was not committed');
    FreeAndNil(Evidence);
    AssertTrue(not Cache.TryLookup(PackageRelativePath, InitialIdentity,
      InitialDigest, Evidence),
      'changed-content replacement retained the old cache key');
    FreeAndNil(Cache);

    S7AssertCancelledCacheScanDoesNotCommit;
    S7AssertOutputFailureDoesNotCommitCache;
    S7AssertCacheFailureIsNonFatal;
  finally
    EmptyComponents.Free;
    Evidence.Free;
    Cache.Free;
    ChangedTask.Free;
    RefreshTask.Free;
    InitialTask.Free;
  end;
end;

function S7UTF8EAcute: RawByteString;
begin
  Result := #$C3#$A9;
end;

function S7UTF8CJK: RawByteString;
begin
  Result := #$E4#$B8#$AD;
end;

function S7UTF8Rocket: RawByteString;
begin
  Result := #$F0#$9F#$9A#$80;
end;

function S7StrictJSONFailureMessage(const AContent: RawByteString): string;
var
  Data: TJSONData;
begin
  Result := '';
  Data := nil;
  try
    try
      Data := ParseStrictUTF8JSON(AContent);
    except
      on E: Exception do
        Result := E.Message;
    end;
  finally
    Data.Free;
  end;
end;

procedure S7AssertStrictJSONRejected(const AContent: RawByteString;
  const AMessage: string);
begin
  AssertTrue(S7StrictJSONFailureMessage(AContent) <> '', AMessage);
end;

procedure S7AssertInvalidUTF8Rejected(const ABytes: RawByteString;
  const AMessage: string);
begin
  AssertTrue(not IsValidUTF8Bytes(ABytes),
    AMessage + ': RFC 3629 validator accepted the bytes');
  S7AssertStrictJSONRejected(RawByteString('{"value":"') + ABytes +
    RawByteString('"}'), AMessage + ': strict JSON accepted the bytes');
end;

function S7NestedArrayJSON(ADepth: Integer): RawByteString;
begin
  Result := RawByteString(StringOfChar('[', ADepth)) + '0' +
    RawByteString(StringOfChar(']', ADepth));
end;

function S7FlatArrayJSON(AValueCount: Integer): RawByteString;
var
  I: Integer;
begin
  if AValueCount <= 0 then
    Exit('[]');
  SetLength(Result, (AValueCount * 2) + 1);
  Result[1] := '[';
  for I := 0 to AValueCount - 1 do
  begin
    Result[2 + (I * 2)] := '0';
    if I < AValueCount - 1 then
      Result[3 + (I * 2)] := ',';
  end;
  Result[Length(Result)] := ']';
end;

procedure TestSprint7StrictJSONUnicodeCore;
var
  Accent, CJK, Rocket, Expected, ExactBytes, Serialized,
    FailureMessage: RawByteString;
  Data: TJSONData;
  Root: TJSONObject;
  Stream: TStringStream;
begin
  Accent := S7UTF8EAcute;
  CJK := S7UTF8CJK;
  Rocket := S7UTF8Rocket;
  Expected := Accent + CJK;
  AssertTrue(IsValidUTF8Bytes(Expected + Rocket +
    RawByteString(#$F4#$8F#$BF#$BF)),
    'RFC 3629 validator rejected valid UTF-8 scalar boundaries');

  Data := ParseStrictUTF8JSON(RawByteString('{"value":"') + Expected +
    RawByteString('"}'));
  try
    AssertTrue(Data.JSONType = jtObject,
      'raw-Unicode JSON root is not an object');
    AssertEqual(string(Expected),
      JSONString(TJSONObject(Data), 'value'),
      'raw UTF-8 JSON value did not round-trip byte-exactly');
  finally
    Data.Free;
  end;
  Data := ParseStrictUTF8JSON(
    '{"value":"\u00e9\u4e2d","rocket":"\ud83d\ude80",' +
    '"\u0000key":"line\u000aend","controls":"\u0000\u001f"}');
  try
    Root := TJSONObject(Data);
    AssertEqual(string(Expected), JSONString(Root, 'value'),
      'adjacent BMP escapes were paired or decoded lossily');
    AssertEqual(string(Rocket), JSONString(Root, 'rocket'),
      'valid surrogate pair did not decode to its UTF-8 scalar');
    AssertEqual('line' + #10 + 'end', JSONString(Root, #0 + 'key'),
      'escaped control in a JSON key/value did not round-trip');
    AssertEqual(#0 + #31, JSONString(Root, 'controls'),
      'escaped NUL/control values were dropped or altered');
  finally
    Data.Free;
  end;

  S7AssertStrictJSONRejected('{"x":"\ud800"}',
    'isolated high surrogate was accepted');
  S7AssertStrictJSONRejected('{"x":"\ud800\u0041"}',
    'high surrogate followed by a non-low escape was accepted');
  S7AssertStrictJSONRejected('{"x":"\udc00"}',
    'isolated low surrogate was accepted');
  S7AssertStrictJSONRejected('{"x":"\u12g4"}',
    'malformed Unicode escape was accepted');
  S7AssertStrictJSONRejected('{"x":1} trailing',
    'trailing JSON data was accepted');
  S7AssertStrictJSONRejected('{"x":1,//comment' + #10 + '"y":2}',
    'JSON comments were accepted');
  S7AssertStrictJSONRejected('{"x":1,}',
    'trailing JSON comma was accepted');
  S7AssertStrictJSONRejected('{"x":1,"x":2}',
    'duplicate raw JSON member was accepted');
  S7AssertStrictJSONRejected(RawByteString('{"') + Accent +
    RawByteString('":1,"\u00e9":2}'),
    'raw/escaped Unicode duplicate member was accepted');

  S7AssertInvalidUTF8Rejected(RawByteString(#$C0#$AF),
    'overlong UTF-8');
  S7AssertInvalidUTF8Rejected(RawByteString(#$ED#$A0#$80),
    'raw UTF-8 surrogate');
  S7AssertInvalidUTF8Rejected(RawByteString(#$F4#$90#$80#$80),
    'UTF-8 scalar above U+10FFFF');
  S7AssertInvalidUTF8Rejected(RawByteString(#$E2#$82),
    'truncated UTF-8 sequence');

  Data := ParseStrictUTF8JSON(
    S7NestedArrayJSON(MaximumJSONNestingDepth));
  Data.Free;
  S7AssertStrictJSONRejected(
    S7NestedArrayJSON(MaximumJSONNestingDepth + 1),
    'JSON nesting depth limit plus one was accepted');
  Data := ParseStrictUTF8JSON(
    S7FlatArrayJSON(MaximumJSONNodeCount - 1));
  Data.Free;
  S7AssertStrictJSONRejected(
    S7FlatArrayJSON(MaximumJSONNodeCount),
    'flat JSON node limit plus one was accepted');
  FailureMessage := RawByteString(S7StrictJSONFailureMessage(
    RawByteString(StringOfChar(',', MaximumJSONTokenCount))));
  AssertTrue((FailureMessage <> '') and
    (Pos('token-count', LowerCase(string(FailureMessage))) = 0),
    'exact JSON token boundary was rejected by the resource preflight');
  FailureMessage := RawByteString(S7StrictJSONFailureMessage(
    RawByteString(StringOfChar(',', MaximumJSONTokenCount + 1))));
  AssertTrue(Pos('token-count', LowerCase(string(FailureMessage))) > 0,
    'JSON token limit plus one did not trigger its resource bound');

  ExactBytes := '0123456789abcdef';
  Stream := TStringStream.Create(string(ExactBytes));
  try
    AssertEqual(string(ExactBytes),
      string(ReadBoundedRawBytes(Stream, Length(ExactBytes))),
      'exact JSON byte boundary did not round-trip');
  finally
    Stream.Free;
  end;
  Stream := TStringStream.Create(string(ExactBytes + 'x'));
  try
    FailureMessage := '';
    try
      Expected := ReadBoundedRawBytes(Stream, Length(ExactBytes));
    except
      on E: Exception do
        FailureMessage := RawByteString(E.Message);
    end;
    AssertTrue(FailureMessage <> '',
      'JSON byte limit plus one was accepted');
  finally
    Stream.Free;
  end;

  Data := ParseStrictUTF8JSON(RawByteString('{"value":"') + Expected +
    RawByteString('"}'));
  try
    Serialized := RawByteString(SerializeJSONUTF8(Data, [], 2, True));
    AssertTrue(IsValidUTF8Bytes(Serialized),
      'strict JSON serializer emitted invalid UTF-8');
    AssertTrue((Pos(string(Expected), string(Serialized)) > 0) and
      (Pos(#13, string(Serialized)) = 0),
      'strict JSON serializer escaped/lost Unicode or emitted CR bytes');
    AssertTrue((Length(Serialized) > 1) and
      (Serialized[Length(Serialized)] = #10) and
      (Serialized[Length(Serialized) - 1] <> #10),
      'strict JSON serializer did not append exactly one final LF');
    AssertTrue(Pos(string(RawByteString(#$C3#$83#$C2#$A9)),
      string(Serialized)) = 0,
      'strict JSON serializer double-encoded UTF-8');
  finally
    Data.Free;
  end;
  Data := ParseStrictUTF8JSON(Serialized);
  try
    AssertEqual(string(Expected),
      JSONString(TJSONObject(Data), 'value'),
      'serialized strict JSON did not parse without Unicode loss');
  finally
    Data.Free;
  end;
end;

procedure TestSprint7StrictJSONApplicationRoundTrips;
var
  Accent, CJK, Rocket, PackageName, LicenseName, OrganizationName,
    IgnorePattern, ManifestBytes, ExpectedPURL, RawSettings, RawHistory,
    CycloneDXBytes: RawByteString;
  Artifact, InvalidArtifact: TArtifact;
  Components, InvalidComponents, Tasks, LoadedTasks: TObjectList;
  Component, LoadedComponent: uModels.TComponent;
  SettingsDirectory, HistoryDirectory, InvalidSettingsDirectory,
    InvalidHistoryDirectory, WarningText: string;
  SettingsStore, InvalidSettingsStore: TSettingsStore;
  Settings, LoadedSettings, InvalidSettings: TScanSettings;
  HistoryStore, InvalidHistoryStore: TTaskHistoryStore;
  Task, LoadedTask: TScanTask;
  Data: TJSONData;
  CycloneComponent: TJSONObject;
begin
  Accent := S7UTF8EAcute;
  CJK := S7UTF8CJK;
  Rocket := S7UTF8Rocket;
  PackageName := 'caf' + Accent + '-' + CJK;
  LicenseName := 'Lic-' + RawByteString(#$E7#$BB#$84#$E4#$BB#$B6);
  OrganizationName := 'Org-' + CJK + '-' + Rocket;
  IgnorePattern := 'ignored-' + Accent + '-' + CJK;
  ExpectedPURL := 'pkg:npm/caf%C3%A9-%E4%B8%AD@1.2.3';
  ManifestBytes := RawByteString('{"name":"') + PackageName +
    RawByteString('","version":"1.2.3",' +
      '"license":"Lic-\u7ec4\u4ef6"}');

  Artifact := TArtifact.Create;
  InvalidArtifact := TArtifact.Create;
  Components := TObjectList.Create(True);
  InvalidComponents := TObjectList.Create(True);
  try
    S7ParseText(string(ManifestBytes), 'package.json', pkPackageJSON,
      Artifact, Components);
    AssertTrue((Artifact.Status = arsParsed) and (Components.Count = 1),
      'strict Unicode package.json did not parse exactly once');
    Component := uModels.TComponent(Components[0]);
    AssertEqual(string(PackageName), Component.Name,
      'Unicode package component name changed during manifest parsing');
    AssertEqual('1.2.3', Component.Version,
      'Unicode package component version changed during parsing');
    AssertEqual(string(ExpectedPURL), Component.PackageURL,
      'Unicode package URL was not derived from exact UTF-8 bytes');
    AssertTrue((Component.DeclaredLicenses.Count = 1) and
      (Component.DeclaredLicenses[0] = string(LicenseName)),
      'escaped Unicode license declaration did not decode exactly');

    S7ParseText('{"name":"first","\u006eame":"second",' +
      '"version":"1.0.0"}', 'package.json', pkPackageJSON,
      InvalidArtifact, InvalidComponents);
    AssertTrue((InvalidArtifact.Status = arsFailed) and
      (InvalidComponents.Count = 0),
      'manifest consumer accepted a raw/escaped duplicate member');
  finally
    InvalidComponents.Free;
    Components.Free;
    InvalidArtifact.Free;
    Artifact.Free;
  end;

  SettingsDirectory := NewTemporaryDirectory('sprint7-unicode-settings');
  SettingsStore := TSettingsStore.Create(SettingsDirectory);
  Settings := TScanSettings.Create;
  LoadedSettings := nil;
  try
    Settings.IgnorePatterns.Clear;
    Settings.IgnorePatterns.Add(string(IgnorePattern));
    Settings.SBOMAuthorOrganization := string(OrganizationName);
    Settings.SBOMAuthorEmail := 'unicode@example.invalid';
    Settings.RememberPrivacyChoices := True;
    Settings.UseRescanCache := True;
    Settings.RefreshRescanCache := True;
    SettingsStore.Save(Settings);
    AssertTrue(Settings.RefreshRescanCache,
      'settings persistence mutated the caller refresh request');
    RawSettings := S7ReadRawFile(SettingsStore.FileName);
    AssertTrue(IsValidUTF8Bytes(RawSettings) and
      (Pos(string(OrganizationName), string(RawSettings)) > 0) and
      (Pos(string(IgnorePattern), string(RawSettings)) > 0),
      'settings on-disk bytes lost raw Unicode');
    AssertTrue((Pos(#13, string(RawSettings)) = 0) and
      (RawSettings[Length(RawSettings)] = #10),
      'settings JSON did not use deterministic LF UTF-8 output');
    AssertTrue(Pos(string(RawByteString(#$C3#$83#$C2#$A9)),
      string(RawSettings)) = 0,
      'settings JSON double-encoded UTF-8');
    LoadedSettings := SettingsStore.Load(WarningText);
    AssertEqual('', WarningText,
      'valid Unicode settings produced a load warning');
    AssertEqual(string(OrganizationName),
      LoadedSettings.SBOMAuthorOrganization,
      'settings organization did not round-trip exactly');
    AssertTrue((LoadedSettings.IgnorePatterns.Count = 1) and
      (LoadedSettings.IgnorePatterns[0] = string(IgnorePattern)),
      'settings ignore pattern did not round-trip exactly');
    AssertTrue(LoadedSettings.UseRescanCache and
      not LoadedSettings.RefreshRescanCache,
      'settings cache-use/one-shot-refresh persistence contract differs');
  finally
    LoadedSettings.Free;
    Settings.Free;
    SettingsStore.Free;
  end;

  HistoryDirectory := NewTemporaryDirectory('sprint7-unicode-history');
  HistoryStore := TTaskHistoryStore.Create(HistoryDirectory);
  Tasks := TObjectList.Create(True);
  LoadedTasks := TObjectList.Create(True);
  Task := NewHistoryTask('00000000-0000-4000-8000-000000000708',
    '2026-08-21T00:00:00.000Z', tsCompleted, string(PackageName));
  try
    Task.TargetRootName := string(PackageName);
    Task.Settings.SBOMAuthorOrganization := string(OrganizationName);
    Task.Warnings.Add('warning-' + string(Rocket));
    Component := uModels.TComponent.Create;
    Component.ComponentType := 'library';
    Component.Name := string(PackageName);
    Component.Version := '1.2.3';
    Component.Ecosystem := 'npm';
    Component.PackageURL := string(ExpectedPURL);
    Component.SourceArtifact := 'package.json';
    Component.SourceParser := 'package-json';
    Component.DependencyScope := 'runtime';
    Component.EvidencePaths.Add('package.json');
    Component.DeclaredLicenses.Add(string(LicenseName));
    Component.DeclaredPublishers.Add(string(OrganizationName));
    Task.Components.Add(Component);
    Task.ComponentsIdentified := 1;
    Tasks.Add(Task);
    Task := nil;
    HistoryStore.Save(Tasks);
    RawHistory := S7ReadRawFile(HistoryStore.HistoryFileName);
    AssertTrue(IsValidUTF8Bytes(RawHistory) and
      (Pos(string(PackageName), string(RawHistory)) > 0) and
      (Pos(string(LicenseName), string(RawHistory)) > 0) and
      (Pos(string(OrganizationName), string(RawHistory)) > 0) and
      (Pos(string(Rocket), string(RawHistory)) > 0),
      'task-history on-disk bytes lost Unicode model evidence');
    AssertTrue((Pos(#13, string(RawHistory)) = 0) and
      (RawHistory[Length(RawHistory)] = #10),
      'task-history JSON did not use deterministic LF UTF-8 output');
    AssertTrue(HistoryStore.Load(LoadedTasks, WarningText),
      'valid Unicode task history did not load');
    AssertEqual('', WarningText,
      'valid Unicode task history produced a warning');
    AssertEqual(1, LoadedTasks.Count,
      'Unicode task-history count differs');
    LoadedTask := TScanTask(LoadedTasks[0]);
    AssertEqual(string(PackageName), LoadedTask.TargetRootName,
      'task-history target name did not round-trip exactly');
    AssertTrue((LoadedTask.Components.Count = 1) and
      (LoadedTask.Warnings.Count = 1),
      'task-history Unicode component/warning model differs');
    LoadedComponent := uModels.TComponent(LoadedTask.Components[0]);
    AssertEqual(string(PackageName), LoadedComponent.Name,
      'task-history component name did not round-trip exactly');
    AssertEqual(string(ExpectedPURL), LoadedComponent.PackageURL,
      'task-history component purl did not round-trip exactly');
    AssertTrue((LoadedComponent.DeclaredLicenses.Count = 1) and
      (LoadedComponent.DeclaredLicenses[0] = string(LicenseName)),
      'task-history component license did not round-trip exactly');

    S7StabilizeTaskMetadata(LoadedTask);
    CycloneDXBytes := RawByteString(GenerateCycloneDX(LoadedTask));
    AssertTrue(IsValidUTF8Bytes(CycloneDXBytes) and
      (Pos(string(PackageName), string(CycloneDXBytes)) > 0) and
      (Pos(string(LicenseName), string(CycloneDXBytes)) > 0) and
      (Pos(string(OrganizationName), string(CycloneDXBytes)) > 0) and
      (Pos(string(ExpectedPURL), string(CycloneDXBytes)) > 0),
      'CycloneDX bytes lost Unicode component/license/publisher/purl data');
    AssertTrue((Pos(#13, string(CycloneDXBytes)) = 0) and
      (CycloneDXBytes[Length(CycloneDXBytes)] = #10),
      'CycloneDX did not use deterministic LF UTF-8 output');
    AssertTrue(Pos(string(RawByteString(#$C3#$83#$C2#$A9)),
      string(CycloneDXBytes)) = 0,
      'CycloneDX double-encoded UTF-8');
    Data := ParseStrictUTF8JSON(CycloneDXBytes);
    try
      CycloneComponent := FindJSONObjectByString(
        JSONArray(TJSONObject(Data), 'components'), 'name',
        string(PackageName));
      AssertTrue(CycloneComponent <> nil,
        'strict reparse lost the Unicode CycloneDX component');
      AssertEqual(string(ExpectedPURL),
        JSONString(CycloneComponent, 'purl'),
        'strict reparse changed the CycloneDX purl');
    finally
      Data.Free;
    end;
  finally
    Task.Free;
    LoadedTasks.Free;
    Tasks.Free;
    HistoryStore.Free;
  end;

  InvalidSettingsDirectory := NewTemporaryDirectory(
    'sprint7-strict-invalid-settings');
  InvalidSettingsStore := TSettingsStore.Create(InvalidSettingsDirectory);
  InvalidSettings := nil;
  try
    WriteText(InvalidSettingsStore.FileName,
      '{"format_version":1,"format_version":1,"scan_settings":{}}');
    InvalidSettings := InvalidSettingsStore.Load(WarningText);
    AssertTrue((WarningText <> '') and
      not InvalidSettings.UseRescanCache,
      'settings consumer accepted duplicate JSON members');
  finally
    InvalidSettings.Free;
    InvalidSettingsStore.Free;
  end;

  InvalidHistoryDirectory := NewTemporaryDirectory(
    'sprint7-strict-invalid-history');
  InvalidHistoryStore := TTaskHistoryStore.Create(InvalidHistoryDirectory);
  LoadedTasks := TObjectList.Create(True);
  try
    WriteText(InvalidHistoryStore.HistoryFileName,
      '{"format_version":1,"tasks":[],"tasks":[]}');
    AssertTrue(not InvalidHistoryStore.Load(LoadedTasks, WarningText),
      'task-history consumer accepted duplicate JSON members');
    AssertTrue(WarningText <> '',
      'rejected duplicate task history lacked a warning');
  finally
    LoadedTasks.Free;
    InvalidHistoryStore.Free;
  end;
end;

procedure S7AssertDefaultSettingsFallback(AStore: TSettingsStore;
  const AContent: RawByteString; const AExpectedWarning: string);
var
  Loaded: TScanSettings;
  WarningText: string;
  I: Integer;
begin
  WriteText(AStore.FileName, AContent);
  for I := 1 to 32 do
  begin
    Loaded := nil;
    try
      Loaded := AStore.Load(WarningText);
      AssertTrue(Loaded <> nil,
        'malformed settings load returned nil');
      AssertTrue((WarningText <> '') and
        (Pos(LowerCase(AExpectedWarning), LowerCase(WarningText)) > 0),
        'malformed settings warning differs: ' + WarningText);
      AssertTrue(not Loaded.IncludeAbsolutePaths and
        not Loaded.FollowSymbolicLinks and
        not Loaded.AllowOutsideRoot and Loaded.CalculateSHA256 and
        not Loaded.UseRescanCache and not Loaded.RefreshRescanCache and
        (Loaded.SBOMAuthorOrganization = '') and
        (Loaded.SBOMAuthorEmail = '') and
        not Loaded.RememberPrivacyChoices and
        (Loaded.IgnorePatterns.Count > 0),
        'malformed settings did not return complete safe defaults');
    finally
      Loaded.Free;
    end;
  end;
end;

procedure TestSprint7MalformedSettingsRecovery;
var
  DirectoryName, WarningText: string;
  Store: TSettingsStore;
  Settings, Loaded: TScanSettings;
begin
  DirectoryName := NewTemporaryDirectory('sprint7-malformed-settings');
  Store := TSettingsStore.Create(DirectoryName);
  Settings := nil;
  Loaded := nil;
  try
    S7AssertDefaultSettingsFallback(Store,
      '{"format_version":1,"scan_settings":{' +
      '"use_rescan_cache":"true"}}',
      'use_rescan_cache" must be a Boolean');
    S7AssertDefaultSettingsFallback(Store,
      '{"format_version":1,"scan_settings":{' +
      '"refresh_rescan_cache":1}}',
      'refresh_rescan_cache" must be a Boolean');
    S7AssertDefaultSettingsFallback(Store,
      '{"format_version":1,"scan_settings":{' +
      '"ignore_patterns":{"pattern":"build"}}}',
      'ignore_patterns" must be an array');
    S7AssertDefaultSettingsFallback(Store,
      '{"format_version":1,"scan_settings":{' +
      '"ignore_patterns":["build",7]}}',
      'ignore_patterns" entries must be strings');

    Settings := TScanSettings.Create;
    Settings.UseRescanCache := True;
    Settings.RefreshRescanCache := True;
    Settings.IgnorePatterns.Clear;
    Settings.IgnorePatterns.Add('restored-valid-setting');
    Store.Save(Settings);
    Loaded := Store.Load(WarningText);
    AssertEqual('', WarningText,
      'valid settings after repeated malformed loads produced a warning');
    AssertTrue(Loaded.UseRescanCache and
      not Loaded.RefreshRescanCache and
      (Loaded.IgnorePatterns.Count = 1) and
      (Loaded.IgnorePatterns[0] = 'restored-valid-setting'),
      'valid settings did not recover after repeated malformed loads');
  finally
    Loaded.Free;
    Settings.Free;
    Store.Free;
  end;
end;

procedure RunSprint7RegressionTests;
begin
  RunTest('Sprint 7 verified-input bounds', @TestSprint7VerifiedInputCore);
  RunTest('Sprint 7 verified-input races', @TestSprint7VerifiedInputRaces);
  RunTest('Sprint 7 installed dependency trees', @TestSprint7InstalledTrees);
  RunTest('Sprint 7 bounded archives', @TestSprint7Archives);
  RunTest('Sprint 7 native structure and identifiers',
    @TestSprint7NativeStructure);
  RunTest('Sprint 7 native model and CycloneDX',
    @TestSprint7NativeModelAndCycloneDX);
  RunTest('Sprint 7 pool worker-count determinism',
    @TestSprint7PoolWorkerCounts);
  RunTest('Sprint 7 pool ordering and bounds',
    @TestSprint7PoolOrderingAndBounds);
  RunTest('Sprint 7 pool cancellation and cleanup',
    @TestSprint7PoolCancellation);
  RunTest('Sprint 7 cache unit contracts',
    @TestSprint7CacheUnitContracts);
  RunTest('Sprint 7 cache service lifecycle',
    @TestSprint7CacheServiceLifecycle);
  RunTest('Sprint 7 cache private digest',
    @TestSprint7CachePrivateDigest);
  RunTest('Sprint 7 cache refresh and transactions',
    @TestSprint7CacheRefreshAndTransactions);
  RunTest('Sprint 7 strict JSON Unicode core',
    @TestSprint7StrictJSONUnicodeCore);
  RunTest('Sprint 7 strict JSON application round trips',
    @TestSprint7StrictJSONApplicationRoundTrips);
  RunTest('Sprint 7 malformed settings recovery',
    @TestSprint7MalformedSettingsRecovery);
end;
