(**
  PurpleRay SBOM Analyzer shared scan-service unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Owns the reusable, non-visual scan-to-CycloneDX pipeline used by both the
  desktop worker and headless command-line execution.

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
unit uScanService;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels, uScanEngine, uSHA256;

type
  TScanOutputPolicy = (
    sopRequireOutsideTarget,
    sopManagedApplicationData
  );

{**
  Resolves and validates an output path before any scan work begins.

  Parameters
  ----------
  ATargetDirectory
    Existing directory that will be scanned.
  AOutputFileName
    Caller-requested output filename.
  AOutputPolicy
    Whether the destination must remain outside the scan target, as required
    for untrusted CLI output, or is a trusted application-managed data path.

  Returns
  -------
  string
    Absolute filename built from the canonical existing parent directory and
    the requested final filename.

  Raises
  ------
  EArgumentException
    Raised when either path is blank or the output has no filename.
  EInOutError
    Raised when the output parent does not exist, the output names a directory,
    or strict policy finds the canonical output equal to or below the target.
}
function ResolveScanOutputFileName(const ATargetDirectory,
  AOutputFileName: string;
  AOutputPolicy: TScanOutputPolicy = sopRequireOutsideTarget): string;

{**
  Scans one target and atomically writes its CycloneDX document.

  Parameters
  ----------
  ATask
    Mutable task containing the target and settings and receiving all scan
    results, output metadata, warnings, errors, and terminal status.
  AOutputFileName
    Exact destination requested by the caller. Its parent directory must
    already exist; strict policy additionally requires it to be outside the
    scan target. The service itself does not access application data.
  ACancelCheck
    Optional cooperative cancellation callback used during scanning and
    output hashing.
  AProgressCallback
    Optional callback receiving throttled scanner progress snapshots.
  AOutputPolicy
    Validation policy for the destination. Command-line callers retain the
    strict default, which pins and revalidates the exact output parent across
    the scan; the GUI worker explicitly selects managed application data and
    retains the application-owned path behavior.
  ACacheProfileDirectory
    Optional application-data directory for the explicitly enabled GUI rescan
    cache. An empty value disables cache access regardless of task settings;
    command-line callers intentionally retain that default.

  Returns
  -------
  Boolean
    True only when scanning, generation, atomic activation, and output hashing
    all complete successfully.

  Raises
  ------
  EArgumentNilException
    Raised when ATask is nil.
  EArgumentException
    Raised when AOutputFileName is blank.
  EInOutError
    Raised by output-path preflight or pin acquisition before scanning begins.
  EOutOfMemory
    May propagate if the engine or generated document cannot be allocated.
  Exception
    Unexpected engine construction or timing failures may propagate. Scanner
    and post-scan output failures are converted into task diagnostics.
}
function ExecuteScanToFile(ATask: TScanTask; const AOutputFileName: string;
  ACancelCheck: TCancelCheck = nil;
  AProgressCallback: TScanProgressCallback = nil;
  AOutputPolicy: TScanOutputPolicy = sopRequireOutsideTarget;
  const ACacheProfileDirectory: string = ''): Boolean;

implementation

uses
  uAtomicFiles, uCycloneDX, uPlatform, uTimeUtils;

{**
  Pins and revalidates the strict command-line output parent.

  Parameters
  ----------
  ATargetDirectory
    Existing scan root used for the outside-target containment check.
  AOutputFileName
    Caller-requested output path whose parent must already exist.
  APinnedDirectory
    Receives a caller-owned pin for the exact validated parent directory.
  AOutputLeafName
    Receives the single final filename used for directory-relative writing.

  Returns
  -------
  string
    Canonical display path composed from the pinned parent and output leaf.

  Raises
  ------
  EArgumentException, EInOutError
    Raised for malformed paths, containment violations, or a parent that
    cannot be pinned consistently.
}
function PinStrictScanOutput(const ATargetDirectory, AOutputFileName: string;
  out APinnedDirectory: TPinnedDirectory;
  out AOutputLeafName: string): string;
var
  PreflightName, TargetCanonical: string;
begin
  APinnedDirectory := nil;
  AOutputLeafName := '';
  PreflightName := ResolveScanOutputFileName(ATargetDirectory,
    AOutputFileName, sopRequireOutsideTarget);
  AOutputLeafName := ExtractFileName(PreflightName);
  APinnedDirectory := PinExistingDirectory(ExtractFileDir(PreflightName));
  try
    Result := IncludeTrailingPathDelimiter(APinnedDirectory.DirectoryName) +
      AOutputLeafName;
    { The directory might have changed between the pathname preflight and the
      pin acquisition. Validate the identity-backed canonical path again. }
    TargetCanonical := CanonicalPath(ATargetDirectory);
    if PathIsWithin(Result, TargetCanonical) then
      raise EInOutError.Create(
        'output file must be outside the scan directory: ' + Result);
  except
    APinnedDirectory.Free;
    APinnedDirectory := nil;
    raise;
  end;
end;

function ResolveScanOutputFileName(const ATargetDirectory,
  AOutputFileName: string; AOutputPolicy: TScanOutputPolicy): string;
var
  OutputDirectory, OutputName, TargetCanonical: string;
begin
  if Trim(ATargetDirectory) = '' then
    raise EArgumentException.Create('Scan target directory must not be empty');
  if Trim(AOutputFileName) = '' then
    raise EArgumentException.Create('SBOM output filename must not be empty');
  Result := ExpandFileName(AOutputFileName);
  if DirectoryExists(Result) then
    raise EInOutError.Create('SBOM output path names a directory: ' + Result);
  OutputName := ExtractFileName(Result);
  if (OutputName = '') or (OutputName = '.') or (OutputName = '..') then
    raise EArgumentException.Create('SBOM output path has no filename');
  OutputDirectory := ExtractFileDir(Result);
  if not DirectoryExists(OutputDirectory) then
    raise EInOutError.Create('SBOM output directory does not exist: ' +
      OutputDirectory);
  OutputDirectory := CanonicalPath(OutputDirectory);
  Result := IncludeTrailingPathDelimiter(OutputDirectory) + OutputName;
  if AOutputPolicy = sopRequireOutsideTarget then
  begin
    TargetCanonical := CanonicalPath(ATargetDirectory);
    if PathIsWithin(Result, TargetCanonical) then
      raise EInOutError.Create(
        'output file must be outside the scan directory: ' + Result);
  end;
end;

{**
  Adds one normalized task error without duplicating an existing diagnostic.

  Parameters
  ----------
  ATask
    Task whose owned error collection receives the message.
  AMessage
    Error text; surrounding whitespace is removed and a stable fallback is
    used for an empty message.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
  EOutOfMemory
    May propagate while adding a new diagnostic.
}
procedure AddTaskError(ATask: TScanTask; const AMessage: string);
var
  MessageValue: string;
begin
  MessageValue := Trim(AMessage);
  if MessageValue = '' then
    MessageValue := 'Unable to generate the CycloneDX file';
  if ATask.Errors.IndexOf(MessageValue) < 0 then
    ATask.Errors.Add(MessageValue);
end;

{**
  Refreshes terminal timing after output generation or an output failure.

  Parameters
  ----------
  ATask
    Task whose completion timestamp and duration are updated.

  Returns
  -------
  None

  Raises
  ------
  EAccessViolation
    Raised when ATask is nil.
  Exception
    Time conversion failures may propagate to the caller.
}
procedure FinalizeTaskTiming(ATask: TScanTask);
begin
  ATask.CompletedUTC := UTCNowISO8601;
  ATask.DurationMS := DurationMilliseconds(ATask.StartedUTC,
    ATask.CompletedUTC);
end;

function ExecuteScanToFile(ATask: TScanTask; const AOutputFileName: string;
  ACancelCheck: TCancelCheck; AProgressCallback: TScanProgressCallback;
  AOutputPolicy: TScanOutputPolicy;
  const ACacheProfileDirectory: string): Boolean;
var
  Content: UTF8String;
  CacheDiagnostic, Digest, OutputFileName, OutputLeafName: string;
  Engine: TScanEngine;
  ExecutionOptions: TScanExecutionOptions;
  OutputDirectoryPin: TPinnedDirectory;
  PinnedOutputActivated: Boolean;
begin
  if ATask = nil then
    raise EArgumentNilException.Create('Scan task must not be nil');
  if Trim(AOutputFileName) = '' then
    raise EArgumentException.Create('SBOM output filename must not be empty');

  Engine := nil;
  OutputDirectoryPin := nil;
  if AOutputPolicy = sopRequireOutsideTarget then
    OutputFileName := PinStrictScanOutput(ATask.TargetDirectory,
      AOutputFileName, OutputDirectoryPin, OutputLeafName)
  else
  begin
    OutputFileName := ResolveScanOutputFileName(ATask.TargetDirectory,
      AOutputFileName, AOutputPolicy);
    OutputLeafName := ExtractFileName(OutputFileName);
  end;
  try
    PinnedOutputActivated := False;
    ATask.GeneratedSBOMPath := '';
    ATask.GeneratedSBOMSHA256 := '';
    ExecutionOptions := DefaultScanExecutionOptions;
    ExecutionOptions.CacheProfileDirectory := ACacheProfileDirectory;
    Engine := TScanEngine.Create(ACancelCheck, AProgressCallback,
      ExecutionOptions);
    Engine.Scan(ATask);

    if ATask.Status = tsCompleted then
    begin
      try
        if Assigned(ACancelCheck) and ACancelCheck() then
          raise EAbort.Create('SBOM generation was cancelled');
        Content := GenerateCycloneDX(ATask);
        if OutputDirectoryPin <> nil then
        begin
          WriteAtomicUTF8ToPinnedDirectory(OutputDirectoryPin,
            OutputLeafName, Content);
          PinnedOutputActivated := True;
          if Assigned(ACancelCheck) and ACancelCheck() then
            raise EAbort.Create('SBOM generation was cancelled');
          Digest := SHA256String(Content);
          OutputDirectoryPin.VerifyCurrentPath;
        end
        else
        begin
          WriteAtomicUTF8(OutputFileName, Content, False);
          if not SHA256File(OutputFileName, Digest, ACancelCheck, nil) then
            raise EAbort.Create('SBOM generation was cancelled');
        end;
        ATask.GeneratedSBOMPath := OutputFileName;
        ATask.GeneratedSBOMSHA256 := Digest;
        if not (Assigned(ACancelCheck) and ACancelCheck()) then
          Engine.CommitRescanCache(CacheDiagnostic);
      except
        on E: EAbort do
        begin
          if PinnedOutputActivated then
          begin
            OutputDirectoryPin.DeleteFile(OutputLeafName);
            PinnedOutputActivated := False;
          end;
          ATask.Status := tsCancelled;
          ATask.GeneratedSBOMPath := '';
          ATask.GeneratedSBOMSHA256 := '';
        end;
        on E: Exception do
        begin
          if PinnedOutputActivated then
          begin
            OutputDirectoryPin.DeleteFile(OutputLeafName);
            PinnedOutputActivated := False;
          end;
          ATask.Status := tsFailed;
          ATask.GeneratedSBOMPath := '';
          ATask.GeneratedSBOMSHA256 := '';
          AddTaskError(ATask, 'Unable to generate the CycloneDX file: ' +
            E.Message);
        end;
      end;
    end;

    FinalizeTaskTiming(ATask);
    Result := ATask.Status = tsCompleted;
  finally
    Engine.Free;
    OutputDirectoryPin.Free;
  end;
end;

end.
