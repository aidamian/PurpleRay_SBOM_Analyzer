(**
  PurpleRay SBOM Analyzer per-file analysis unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Performs path-independent analysis of one already verified scan input and
  returns an owned evidence transaction for ordered coordinator publication.

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
unit uScanAnalysis;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels, uSHA256, uVerifiedInput, uScanCache;

const
  { Increment whenever per-file evidence semantics, parser contracts, or
    identifier synthesis changes. It is deliberately independent of release
    and commit versions so unrelated builds do not invalidate safe evidence. }
  ScanAnalysisContract = 'purpleray-file-analysis-v1';

type
  {**
    Owns the immutable input for one worker analysis operation.

    The verified input is transferred to the result before analysis begins,
    keeping its native handle alive until the coordinator validates and either
    publishes or rejects the completed transaction. Cache is borrowed from the
    engine and must outlive the worker pool; nil keeps analysis cache-free.
  *}
  TScanAnalysisJob = class
  private
    FOrdinal: QWord;
    FFileName: string;
    FRelativePath: string;
    FInput: TVerifiedInput;
    FCalculateSHA256: Boolean;
    FDelayMilliseconds: Cardinal;
    FCache: TScanCache;
  public
    {**
      Creates one immutable analysis job and takes ownership of its input.

      Parameters
      ----------
      AOrdinal
        Consecutive deterministic publication ordinal.
      AFileName
        Absolute display path associated with the verified input.
      ARelativePath
        Root-relative evidence path.
      AInput
        Verified input transferred to the job.
      ACalculateSHA256
        Enables publication of the content digest in evidence.
      ADelayMilliseconds
        Optional cooperative test delay before analysis.
      ACache
        Borrowed cache session that must outlive the job, or nil.

      Returns
      -------
      TScanAnalysisJob
        Caller-owned job containing the supplied input.

      Raises
      ------
      EArgumentNilException
        Raised when AInput is nil.
      EOutOfMemory
        Propagated if job state cannot be allocated.
    *}
    constructor Create(AOrdinal: QWord; const AFileName, ARelativePath: string;
      AInput: TVerifiedInput; ACalculateSHA256: Boolean;
      ADelayMilliseconds: Cardinal = 0; ACache: TScanCache = nil);

    {**
      Releases the verified input still owned by the job.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    destructor Destroy; override;

    {**
      Transfers the verified input out of the job.

      Parameters
      ----------
      None

      Returns
      -------
      TVerifiedInput
        Caller-owned input, or nil after an earlier transfer.

      Raises
      ------
      None
    *}
    function ReleaseInput: TVerifiedInput;
    property Ordinal: QWord read FOrdinal;
    property FileName: string read FFileName;
    property RelativePath: string read FRelativePath;
    property CalculateSHA256: Boolean read FCalculateSHA256;
    property DelayMilliseconds: Cardinal read FDelayMilliseconds;
    property Cache: TScanCache read FCache;
  end;

  {**
    Owns all evidence produced for one input and the still-open verified input.

    No member is published directly by a worker. The scan coordinator consumes
    results in ordinal order, invokes its commit hook, validates input stability
    and root identity, and only then transfers the evidence into the task. A
    cache-enabled result also carries its private fresh content digest and hit
    state without forcing either value into SBOM evidence.
  *}
  TScanAnalysisResult = class
  private
    FOrdinal: QWord;
    FFileName: string;
    FRelativePath: string;
    FInput: TVerifiedInput;
    FArtifact: TArtifact;
    FComponents: TObjectList;
    FInspectionTools: TStringList;
    FWarnings: TStringList;
    FContentSHA256: string;
    FCacheHit: Boolean;
    FCacheDiagnostic: string;
    FCancelled: Boolean;
    FFatalError: string;
  public
    {**
      Creates an empty result and transfers the job's verified input into it.

      Parameters
      ----------
      AJob
        Existing analysis job whose metadata is copied and input is transferred.

      Returns
      -------
      TScanAnalysisResult
        Caller-owned evidence transaction.

      Raises
      ------
      EArgumentNilException
        Raised when AJob is nil.
      EOutOfMemory
        Propagated if result collections cannot be allocated.
    *}
    constructor Create(AJob: TScanAnalysisJob);

    {**
      Frees all evidence and the verified input still owned by the result.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    destructor Destroy; override;

    {**
      Transfers the artifact out of the result transaction.

      Parameters
      ----------
      None

      Returns
      -------
      TArtifact
        Caller-owned artifact, or nil when no artifact is present.

      Raises
      ------
      None
    *}
    function ReleaseArtifact: TArtifact;

    {**
      Replaces the owned artifact with a caller-supplied instance.

      Parameters
      ----------
      AArtifact
        Artifact transferred to the result; nil clears the current artifact.

      Returns
      -------
      None

      Raises
      ------
      None
    *}
    procedure AdoptArtifact(AArtifact: TArtifact);
    property Ordinal: QWord read FOrdinal;
    property FileName: string read FFileName;
    property RelativePath: string read FRelativePath;
    property Input: TVerifiedInput read FInput;
    property Artifact: TArtifact read FArtifact;
    property Components: TObjectList read FComponents;
    property InspectionTools: TStringList read FInspectionTools;
    property Warnings: TStringList read FWarnings;
    property ContentSHA256: string read FContentSHA256 write FContentSHA256;
    property CacheHit: Boolean read FCacheHit write FCacheHit;
    property CacheDiagnostic: string read FCacheDiagnostic
      write FCacheDiagnostic;
    property Cancelled: Boolean read FCancelled write FCancelled;
    property FatalError: string read FFatalError write FFatalError;
  end;

{**
  Analyzes one verified input without consulting or mutating scanner state.

  Ownership of AJob remains with the caller. Its verified input is transferred
  into the returned result. Cancellation produces a non-publishable result
  whose input still remains available for deterministic coordinator cleanup.

  Parameters
  ----------
  AJob
    Caller-owned job containing one verified input and immutable metadata.
  ACancelCheck
    Optional callback polled during delay, hashing, and bounded inspection.

  Returns
  -------
  TScanAnalysisResult
    Caller-owned transaction containing evidence, cancellation state, or a
    contained fatal diagnostic.

  Raises
  ------
  EArgumentNilException
    Raised when AJob is nil.
  EOutOfMemory
    May propagate while the initial result transaction is being created.
*}
function ExecuteScanAnalysis(AJob: TScanAnalysisJob;
  ACancelCheck: TCancelCheck): TScanAnalysisResult;

implementation

uses
  uArtifactIdentifier, uBinaryInspector, uManifestParsers, uSystemInspector,
  uNativeDependencyInspector, uArchiveInspector, uBinaryIdentifiers;

var
  { TUnZipper exposes callback state but no cross-instance thread-safety
    contract. Serialize only Java archive decompression; all other bounded
    analyzers remain parallel. }
  ArchiveInspectionLock: TRTLCriticalSection;

constructor TScanAnalysisJob.Create(AOrdinal: QWord; const AFileName,
  ARelativePath: string; AInput: TVerifiedInput; ACalculateSHA256: Boolean;
  ADelayMilliseconds: Cardinal; ACache: TScanCache);
begin
  inherited Create;
  if AInput = nil then
    raise EArgumentNilException.Create('Verified analysis input must not be nil');
  FOrdinal := AOrdinal;
  FFileName := AFileName;
  FRelativePath := ARelativePath;
  FInput := AInput;
  FCalculateSHA256 := ACalculateSHA256;
  FDelayMilliseconds := ADelayMilliseconds;
  FCache := ACache;
end;

destructor TScanAnalysisJob.Destroy;
begin
  FInput.Free;
  inherited Destroy;
end;

function TScanAnalysisJob.ReleaseInput: TVerifiedInput;
begin
  Result := FInput;
  FInput := nil;
end;

constructor TScanAnalysisResult.Create(AJob: TScanAnalysisJob);
begin
  inherited Create;
  if AJob = nil then
    raise EArgumentNilException.Create('Analysis job must not be nil');
  FOrdinal := AJob.Ordinal;
  FFileName := AJob.FileName;
  FRelativePath := AJob.RelativePath;
  FInput := AJob.ReleaseInput;
  FComponents := TObjectList.Create(True);
  FInspectionTools := TStringList.Create;
  FInspectionTools.Sorted := True;
  FInspectionTools.Duplicates := dupIgnore;
  FWarnings := TStringList.Create;
end;

destructor TScanAnalysisResult.Destroy;
begin
  FWarnings.Free;
  FInspectionTools.Free;
  FComponents.Free;
  FArtifact.Free;
  FInput.Free;
  inherited Destroy;
end;

function TScanAnalysisResult.ReleaseArtifact: TArtifact;
begin
  Result := FArtifact;
  FArtifact := nil;
end;

procedure TScanAnalysisResult.AdoptArtifact(AArtifact: TArtifact);
begin
  if FArtifact = AArtifact then
    Exit;
  FArtifact.Free;
  FArtifact := AArtifact;
end;

{**
  Polls an optional cooperative cancellation callback.

  Parameters
  ----------
  ACancelCheck
    Callback to invoke, or nil when cancellation is disabled.

  Returns
  -------
  Boolean
    True only when an assigned callback requests cancellation.

  Raises
  ------
  Exception
    Propagated when the caller-supplied callback raises.
*}
function AnalysisCancelled(ACancelCheck: TCancelCheck): Boolean;
begin
  Result := Assigned(ACancelCheck) and ACancelCheck();
end;

{**
  Adds one nonempty warning to a result without duplicating exact text.

  Parameters
  ----------
  AResult
    Result transaction whose warning list is updated.
  AMessage
    Candidate warning text.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the warning cannot be stored.
*}
procedure AddResultWarning(AResult: TScanAnalysisResult;
  const AMessage: string);
begin
  if (AMessage <> '') and (AResult.Warnings.IndexOf(AMessage) < 0) then
    AResult.Warnings.Add(AMessage);
end;

{**
  Transfers one caller-owned cache hit into an analysis result.

  Parameters
  ----------
  AResult
    Result transaction that receives all cached evidence.
  AEvidence
    Cache evidence whose artifact and components are transferred. The caller
    still owns and must free the emptied evidence container.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when either argument is nil.
  EOutOfMemory
    Propagated if copied warning or inspection-tool values cannot be stored.
*}
procedure AdoptCachedEvidence(AResult: TScanAnalysisResult;
  AEvidence: TScanCacheEvidence);
var
  Artifact: TArtifact;
  I: Integer;
begin
  if (AResult = nil) or (AEvidence = nil) then
    raise EArgumentNilException.Create('Cached scan evidence must not be nil');
  Artifact := AEvidence.ReleaseArtifact;
  try
    if Artifact <> nil then
      Artifact.AbsolutePath := ExpandFileName(AResult.FileName);
    AResult.AdoptArtifact(Artifact);
    Artifact := nil;
  finally
    Artifact.Free;
  end;
  AEvidence.MoveComponentsTo(AResult.Components);
  for I := 0 to AEvidence.InspectionTools.Count - 1 do
    AResult.InspectionTools.Add(AEvidence.InspectionTools[I]);
  for I := 0 to AEvidence.Warnings.Count - 1 do
    AddResultWarning(AResult, AEvidence.Warnings[I]);
end;

{**
  Reduces one linked-library declaration to its final path component.

  Parameters
  ----------
  ADeclaration
    Dependency name or path reported by a native inspector.

  Returns
  -------
  string
    Trimmed basename, or the trimmed declaration when no separator is present.

  Raises
  ------
  EOutOfMemory
    Propagated if the result cannot be allocated.
*}
function LinkedLibraryComponentName(const ADeclaration: string): string;
var
  SeparatorAt: Integer;
begin
  Result := Trim(ADeclaration);
  SeparatorAt := LastDelimiter('/\', Result);
  if (SeparatorAt > 0) and (SeparatorAt < Length(Result)) then
    Result := Copy(Result, SeparatorAt + 1, MaxInt);
end;

{**
  Waits for a configured delay while polling cancellation in short quanta.

  Parameters
  ----------
  ADelayMilliseconds
    Total delay requested by the deterministic test seam.
  ACancelCheck
    Optional callback polled before and during the wait.

  Returns
  -------
  Boolean
    True when the delay completes without cancellation.

  Raises
  ------
  Exception
    Propagated when the caller-supplied cancellation callback raises.
*}
function WaitForAnalysisDelay(ADelayMilliseconds: Cardinal;
  ACancelCheck: TCancelCheck): Boolean;
const
  DelayQuantumMilliseconds = 5;
var
  Remaining, Quantum: Cardinal;
begin
  Remaining := ADelayMilliseconds;
  while Remaining > 0 do
  begin
    if AnalysisCancelled(ACancelCheck) then
      Exit(False);
    Quantum := DelayQuantumMilliseconds;
    if Remaining < Quantum then
      Quantum := Remaining;
    Sleep(Quantum);
    Dec(Remaining, Quantum);
  end;
  Result := not AnalysisCancelled(ACancelCheck);
end;

function ExecuteScanAnalysis(AJob: TScanAnalysisJob;
  ACancelCheck: TCancelCheck): TScanAnalysisResult;
var
  Definition: TArtifactDefinition;
  BinaryInfo: TBinaryInfo;
  ArchiveKind: TJavaArchiveKind;
  ArchiveResult: TArchiveInspectionResult;
  Component, BinaryComponent: uModels.TComponent;
  Inspection: TSystemInspection;
  CacheEvidence: TScanCacheEvidence;
  InputStream: TStream;
  HashValue, InspectionSummary: string;
  I: Integer;
  ManifestLimit, FileSize: Int64;
  IsArtifact, IsBinary, IsJavaArchive, IsStaticLibrary,
    AnalysisAllowed: Boolean;
begin
  Result := TScanAnalysisResult.Create(AJob);
  FillChar(Definition, SizeOf(Definition), 0);
  InputStream := nil;
  BinaryComponent := nil;
  CacheEvidence := nil;
  try
    if not WaitForAnalysisDelay(AJob.DelayMilliseconds, ACancelCheck) then
    begin
      Result.Cancelled := True;
      Exit;
    end;

    { A cache key always includes a fresh digest from this bounded verified
      handle, even when the digest is intentionally omitted from SBOM output. }
    if AJob.Cache <> nil then
    begin
      try
        InputStream := Result.Input.NewStream;
        try
          if not SHA256Stream(InputStream, HashValue, ACancelCheck, nil) then
          begin
            Result.Cancelled := True;
            Exit;
          end;
        finally
          FreeAndNil(InputStream);
        end;
        Result.ContentSHA256 := HashValue;
      except
        on E: Exception do
          Result.CacheDiagnostic := 'fresh content hashing failed';
      end;
      if Result.ContentSHA256 <> '' then
      begin
        try
          if AJob.Cache.TryLookup(AJob.RelativePath, Result.Input.Identity,
            Result.ContentSHA256, CacheEvidence) then
          begin
            AdoptCachedEvidence(Result, CacheEvidence);
            FreeAndNil(CacheEvidence);
            Result.CacheHit := True;
            if AnalysisCancelled(ACancelCheck) then
              Result.Cancelled := True;
            Exit;
          end;
        except
          on E: Exception do
          begin
            Result.AdoptArtifact(nil);
            Result.Components.Clear;
            Result.InspectionTools.Clear;
            Result.Warnings.Clear;
            Result.CacheDiagnostic := 'cache lookup failed';
          end;
        end;
        FreeAndNil(CacheEvidence);
      end;
    end;

    FileSize := Result.Input.Size;
    IsJavaArchive := TryJavaArchiveKind(ExtractFileName(AJob.FileName),
      ArchiveKind);
    IsStaticLibrary := IsStaticLibraryFileName(ExtractFileName(AJob.FileName));
    IsArtifact := IsJavaArchive or IsStaticLibrary;
    if not IsArtifact then
      IsArtifact := IdentifyArtifact(ExtractFileName(AJob.FileName),
        AJob.RelativePath, Definition);
    IsBinary := False;
    if not IsArtifact then
    begin
      try
        InputStream := Result.Input.NewStream;
        try
          IsBinary := InspectBinary(InputStream, ExtractFileName(AJob.FileName),
            BinaryInfo);
        finally
          FreeAndNil(InputStream);
        end;
      except
        on E: Exception do
        begin
          AddResultWarning(Result, 'Unable to inspect ' + AJob.RelativePath +
            ': ' + E.Message);
          Exit;
        end;
      end;
      if not IsBinary then
        Exit;
    end;

    Result.AdoptArtifact(TArtifact.Create);
    Result.Artifact.RelativePath := AJob.RelativePath;
    Result.Artifact.AbsolutePath := ExpandFileName(AJob.FileName);
    Result.Artifact.FileSize := FileSize;
    if IsBinary then
    begin
      Result.Artifact.ArtifactType := BinaryInfo.FormatName + ' ' +
        BinaryInfo.Classification;
      Result.Artifact.Ecosystem := 'native';
      Result.Artifact.ParserName := 'binary-header';
      Result.Artifact.Status := arsParsed;
      Result.Artifact.MessageText := BinaryInfo.FormatName +
        '; architecture: ' + BinaryInfo.Architecture + '; classification: ' +
        BinaryInfo.Classification;
      if BinaryInfo.Diagnostic <> '' then
      begin
        Result.Artifact.Status := arsFailed;
        Result.Artifact.MessageText := Result.Artifact.MessageText + '; ' +
          BinaryInfo.Diagnostic;
      end;
    end
    else if IsJavaArchive then
    begin
      Result.Artifact.ArtifactType := 'Java archive';
      Result.Artifact.Ecosystem := 'Maven';
      Result.Artifact.ParserName := 'java-archive-metadata';
      Result.Artifact.Status := arsUnsupported;
    end
    else if IsStaticLibrary then
    begin
      Result.Artifact.ArtifactType := 'ar static library';
      Result.Artifact.Ecosystem := 'native';
      Result.Artifact.ParserName := 'ar-header';
      Result.Artifact.Status := arsUnsupported;
    end
    else
    begin
      Result.Artifact.ArtifactType := Definition.ArtifactType;
      Result.Artifact.Ecosystem := Definition.Ecosystem;
      Result.Artifact.ParserName := Definition.ParserName;
      Result.Artifact.Status := arsUnsupported;
    end;

    AnalysisAllowed := not IsBinary or (BinaryInfo.Diagnostic = '');
    if not IsBinary and not IsJavaArchive and not IsStaticLibrary and
      (Definition.ParserKind <> pkNone) then
    begin
      ManifestLimit := ManifestSizeLimit(Definition.ParserKind);
      if (ManifestLimit > 0) and (FileSize > ManifestLimit) then
      begin
        Result.Artifact.MessageText := 'Manifest exceeds the size limit for ' +
          Definition.ParserName + ': ' + IntToStr(FileSize) +
          ' bytes (maximum ' + IntToStr(ManifestLimit) + ' bytes).';
        Result.Artifact.Status := arsFailed;
        AnalysisAllowed := False;
      end;
    end;

    if AnalysisAllowed then
      try
        if AJob.CalculateSHA256 and
          (IsBinary or IsJavaArchive or IsStaticLibrary or
          (Definition.ArtifactType <> 'license evidence')) then
        begin
          if Result.ContentSHA256 <> '' then
            HashValue := Result.ContentSHA256
          else
          begin
            InputStream := Result.Input.NewStream;
            try
              if not SHA256Stream(InputStream, HashValue, ACancelCheck, nil) then
              begin
                Result.Cancelled := True;
                Exit;
              end;
            finally
              FreeAndNil(InputStream);
            end;
            if AJob.Cache <> nil then
              Result.ContentSHA256 := HashValue;
          end;
          Result.Artifact.SHA256 := HashValue;
        end;
        if IsJavaArchive then
        begin
          EnterCriticalSection(ArchiveInspectionLock);
          try
            if AnalysisCancelled(ACancelCheck) then
            begin
              Result.Cancelled := True;
              Exit;
            end;
            ArchiveResult := InspectJavaArchive(Result.Input, ArchiveKind,
              AJob.RelativePath, Result.Artifact.SHA256, Result.Artifact,
              Result.Components, ACancelCheck);
          finally
            LeaveCriticalSection(ArchiveInspectionLock);
          end;
          if ArchiveResult = airCancelled then
          begin
            Result.Cancelled := True;
            Exit;
          end;
        end
        else if IsStaticLibrary then
        begin
          ArchiveResult := InspectStaticLibrary(Result.Input,
            AJob.RelativePath, Result.Artifact.SHA256, Result.Artifact,
            Result.Components, ACancelCheck);
          if ArchiveResult = airCancelled then
          begin
            Result.Cancelled := True;
            Exit;
          end;
        end
        else if IsBinary then
        begin
          Component := uModels.TComponent.Create;
          Component.Name := ExtractFileName(AJob.FileName);
          Component.Version := NativeDependencyVersion(Component.Name);
          Component.Ecosystem := 'native';
          if BinaryInfo.Classification = 'executable' then
            Component.ComponentType := 'application'
          else if BinaryInfo.Classification = 'library' then
            Component.ComponentType := 'library'
          else
            Component.ComponentType := 'file';
          Component.SourceArtifact := AJob.RelativePath;
          Component.SourceParser := 'binary-header';
          Component.SHA256 := Result.Artifact.SHA256;
          Component.EvidencePaths.Add(AJob.RelativePath);
          Result.Components.Add(Component);
          BinaryComponent := Component;
          Result.Artifact.ComponentCount := 1;
          Inspection := nil;
          try
            InputStream := Result.Input.NewStream;
            try
              if InspectBinarySystemEvidence(InputStream,
                BinaryInfo.FormatName, Inspection, ACancelCheck) then
              begin
                Result.InspectionTools.Add(Inspection.ToolName);
                InspectionSummary := Inspection.Summary;
                if InspectionSummary <> '' then
                  Result.Artifact.MessageText :=
                    Result.Artifact.MessageText + '; ' + InspectionSummary;
                if (BinaryComponent.Version = '') and
                  (Inspection.ComponentVersion <> '') then
                  BinaryComponent.Version := Inspection.ComponentVersion;
                BinaryComponent.CompanyName := Inspection.CompanyName;
                BinaryComponent.ProductName := Inspection.ProductName;
                BinaryComponent.NativeSONAME := Inspection.SONAME;
                BinaryComponent.NativeBuildID := Inspection.BuildID;
                for I := 0 to Inspection.Dependencies.Count - 1 do
                begin
                  Component := uModels.TComponent.Create;
                  Component.Name := LinkedLibraryComponentName(
                    Inspection.Dependencies[I]);
                  Component.Version := NativeDependencyVersion(
                    Inspection.Dependencies[I]);
                  Component.ComponentType := 'library';
                  Component.Ecosystem := 'native';
                  Component.SourceArtifact := AJob.RelativePath;
                  Component.SourceParser := Inspection.ToolName;
                  Component.DependencyScope := 'runtime';
                  Component.EvidencePaths.Add(AJob.RelativePath);
                  Result.Components.Add(Component);
                  Inc(Result.Artifact.ComponentCount);
                end;
              end;
            finally
              FreeAndNil(InputStream);
            end;
            if AnalysisCancelled(ACancelCheck) then
            begin
              Result.Cancelled := True;
              Exit;
            end;
            BinaryComponent.PackageURL := BuildGenericBinaryPackageURL(
              BinaryComponent.Name, BinaryComponent.Version,
              BinaryComponent.SHA256);
            BinaryComponent.CPE := BuildEvidenceCPE(
              BinaryComponent.CompanyName, BinaryComponent.ProductName,
              BinaryComponent.Version);
            if BinaryComponent.CPE <> '' then
              BinaryComponent.CPEEvidence :=
                'PE VERSIONINFO CompanyName + ProductName; ' +
                'inventory candidate only';
          finally
            Inspection.Free;
          end;
        end
        else
        begin
          InputStream := Result.Input.NewStream;
          try
            ParseArtifact(InputStream, AJob.RelativePath,
              Definition.ParserKind, Result.Artifact, Result.Components);
          finally
            FreeAndNil(InputStream);
          end;
        end;
      except
        on E: Exception do
        begin
          Result.Components.Clear;
          Result.InspectionTools.Clear;
          Result.Artifact.ComponentCount := 0;
          Result.Artifact.Status := arsFailed;
          Result.Artifact.MessageText := E.Message;
        end;
      end;
    if AnalysisCancelled(ACancelCheck) then
      Result.Cancelled := True;
  except
    on E: Exception do
      Result.FatalError := 'Unable to analyze ' + AJob.RelativePath + ' (' +
        E.ClassName + '): ' + E.Message;
  end;
end;

initialization
  InitCriticalSection(ArchiveInspectionLock);

finalization
  DoneCriticalSection(ArchiveInspectionLock);

end.
