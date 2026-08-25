(**
  PurpleRay SBOM Analyzer scan-details report builder.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Builds the plain-text "Details" report shown in the analyzer and copied
  to the clipboard. The unit is LCL-free so every sentence, count, and cap
  can be exercised by the non-UI regression tests. The report is written
  for a reader who did not run the scan: causes and consequences are kept
  apart, outcome codes are translated, and only relative paths are used
  unless the scan explicitly opted in to absolute paths.

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
unit uScanDetailsReport;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uModels, uKnownIssues;

const
  {** Upper bound on advisory lines listed in one report. *}
  MaximumDisplayedKnownIssueMatches = 500;
  {** Persisted outcome code written when no TLS transport exists. *}
  KnownIssueOutcomeTransportUnavailable = 'transport-unavailable';
  {** Persisted outcome code written when the check failed locally. *}
  KnownIssueOutcomeLookupFailed = 'lookup-failed';

{**
  Explains why a known-issue check ended the way it did.

  Parameters
  ----------
  ACheck
    Recorded check state; must not be nil.
  ATaskStatus
    Status of the owning task, used when no outcome was recorded yet.
  AAffectedCount
    Number of distinct affected packages, used for the success sentence.

  Returns
  -------
  string
    One or two plain-language sentences describing the cause. Never starts
    with a bare outcome code.

  Raises
  ------
  None
}
function KnownIssueOutcomeSentence(ACheck: TKnownIssueCheck;
  ATaskStatus: TTaskStatus; AAffectedCount: Integer): string;

{**
  States what the recorded findings mean after a check that did not
  succeed, derived from the data rather than from the outcome code.

  Parameters
  ----------
  ACheck
    Recorded check state; must not be nil.

  Returns
  -------
  string
    Empty for a successful or never-started check; otherwise a sentence
    saying whether findings were retained and that they are incomplete.

  Raises
  ------
  None
}
function KnownIssueConsequenceSentence(ACheck: TKnownIssueCheck): string;

{**
  Reduces an advisory revision timestamp to its calendar date.

  Parameters
  ----------
  AValue
    OSV ``modified`` value. ISO-8601 shaped values become ``yyyy-mm-dd``;
    anything else is returned unchanged.

  Returns
  -------
  string
    Calendar date or the original text.

  Raises
  ------
  None
}
function AdvisoryDateText(const AValue: string): string;

{**
  Appends one sentence per scan setting in report form.

  Parameters
  ----------
  ASettings
    Settings to describe; must not be nil.
  ALines
    Destination list.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure DescribeScanSettings(ASettings: TScanSettings; ALines: TStrings);

{**
  Builds the complete scan-details report.

  Parameters
  ----------
  ATask
    Task to describe; nil yields an empty report.
  AOnlineCheckPending
    True while a scan that asked for the online check is still pending or
    running and no check result has been recorded yet.

  Returns
  -------
  string
    LineEnding-separated report text.

  Raises
  ------
  None
}
function BuildScanDetailsReport(ATask: TScanTask;
  AOnlineCheckPending: Boolean): string;

implementation

uses
  uOSVCore, uPresentation, uTimeUtils, uVersionInfo;

function Plural(ACount: Integer; const ASingular, APlural: string): string;
begin
  if ACount = 1 then
    Result := ASingular
  else
    Result := APlural;
end;

function KnownIssueOutcomeSentence(ACheck: TKnownIssueCheck;
  ATaskStatus: TTaskStatus; AAffectedCount: Integer): string;
var
  Code: string;
begin
  Code := ACheck.OutcomeCode;
  if Code = '' then
  begin
    if ATaskStatus in [tsPending, tsRunning] then
      Result := 'The online check has not finished yet.'
    else
      Result := 'No outcome was recorded for the online check.';
  end
  else if Code = OSVOutcomeCode(osoSucceeded) then
  begin
    if ACheck.MatchCount = 0 then
      Result := 'The online check completed and OSV.dev reported no known ' +
        'advisories for the packages it could look up.'
    else
      Result := Format('The online check completed. OSV.dev reported %d ' +
        '%s affecting %d %s.', [ACheck.AdvisoryCount,
        Plural(ACheck.AdvisoryCount, 'advisory', 'advisories'),
        AAffectedCount, Plural(AAffectedCount, 'package', 'packages')]);
  end
  else if Code = OSVOutcomeCode(osoNoEligibleCandidates) then
    Result := 'Nothing was checked: no component had an exact, canonical ' +
      'package URL that OSV.dev can look up (for example, version ranges ' +
      'and native libraries without a registry identity are skipped).'
  else if Code = OSVOutcomeCode(osoCancelled) then
    Result := 'The online check was cancelled before it finished.'
  else if Code = OSVOutcomeCode(osoTransportFailed) then
    Result := 'OSV.dev could not be reached (network or TLS problem).'
  else if Code = OSVOutcomeCode(osoHTTPStatusFailed) then
    Result := Format('OSV.dev answered with HTTP status %d instead of a ' +
      'result.', [ACheck.HTTPStatus])
  else if Code = OSVOutcomeCode(osoMalformedResponse) then
    Result := 'OSV.dev returned a response this version could not ' +
      'understand.'
  else if Code = OSVOutcomeCode(osoCandidateLimitExceeded) then
    Result := 'The online check did not start: the inventory has more ' +
      'non-empty package-URL candidates than this version accepts for ' +
      'one check.'
  else if Code = OSVOutcomeCode(osoRequestLimitExceeded) then
    Result := 'The online check stopped early: it would have needed more ' +
      'requests to OSV.dev than this version allows for one check.'
  else if Code = OSVOutcomeCode(osoResponseLimitExceeded) then
    Result := 'The online check stopped early: one OSV.dev response was ' +
      'larger than this version accepts.'
  else if Code = OSVOutcomeCode(osoAggregateResponseLimitExceeded) then
    Result := 'The online check stopped early: the OSV.dev responses ' +
      'together exceeded the total size this version accepts.'
  else if Code = OSVOutcomeCode(osoAdvisoryLimitExceeded) then
    Result := 'The online check stopped early: OSV.dev reported more ' +
      'distinct advisories than this version keeps for one check.'
  else if Code = OSVOutcomeCode(osoMatchLimitExceeded) then
    Result := 'The online check stopped early: OSV.dev reported more ' +
      'package/advisory matches than this version keeps for one check.'
  else if Pos('limit-exceeded', Code) > 0 then
    Result := 'The online check stopped early because a built-in safety ' +
      'limit was reached (' + Code + ').'
  else if Code = KnownIssueOutcomeTransportUnavailable then
    Result := 'The online check could not run: this application could ' +
      'not set up its secure (TLS) connection to OSV.dev on this computer. ' +
      'Nothing was sent, and the inventory is complete.'
  else if Code = KnownIssueOutcomeLookupFailed then
    Result := 'The online check stopped because of an internal error in ' +
      'this application; no result was kept. The inventory is complete.'
  else
    Result := 'The online check ended with an outcome this version cannot ' +
      'describe (code: ' + Code + ').';
end;

function KnownIssueConsequenceSentence(ACheck: TKnownIssueCheck): string;
begin
  Result := '';
  if (ACheck.OutcomeCode = '') or
    (ACheck.OutcomeCode = OSVOutcomeCode(osoSucceeded)) or
    (ACheck.OutcomeCode = OSVOutcomeCode(osoNoEligibleCandidates)) then
    Exit;
  if ACheck.MatchCount > 0 then
    Result := 'The findings listed below were received before the check ' +
      'stopped and are incomplete: packages that were not looked up may ' +
      'have advisories that were not retrieved.'
  else if (ACheck.OutcomeCode = OSVOutcomeCode(osoCandidateLimitExceeded)) or
    (ACheck.OutcomeCode = KnownIssueOutcomeTransportUnavailable) or
    (ACheck.OutcomeCode = KnownIssueOutcomeLookupFailed) then
    Result := 'No findings were recorded.'
  else
    Result := 'No findings were retained, and the check did not cover ' +
      'every package: packages that were not looked up may still have ' +
      'advisories.';
end;

function AdvisoryDateText(const AValue: string): string;
var
  Year, Month, Day: Integer;
  Date: TDateTime;
begin
  Result := AValue;
  if Length(AValue) < 10 then
    Exit;
  if (AValue[5] <> '-') or (AValue[8] <> '-') then
    Exit;
  if Length(AValue) > 10 then
  begin
    if (Length(AValue) < 12) or not (AValue[11] in ['T', ' ']) then
      Exit;
    for Year := 12 to Length(AValue) do
      if not (AValue[Year] in ['0'..'9', ':', '.', 'Z', '+', '-']) then
        Exit;
  end;
  if not TryStrToInt(Copy(AValue, 1, 4), Year) or
    not TryStrToInt(Copy(AValue, 6, 2), Month) or
    not TryStrToInt(Copy(AValue, 9, 2), Day) then
    Exit;
  if TryEncodeDate(Year, Month, Day, Date) then
    Result := Copy(AValue, 1, 10);
end;

procedure DescribeScanSettings(ASettings: TScanSettings; ALines: TStrings);

  function YesNo(AValue: Boolean): string;
  begin
    if AValue then
      Result := 'yes'
    else
      Result := 'no';
  end;

begin
  ALines.Add('Absolute paths permitted in the exported SBOM and in this ' +
    'report: ' + YesNo(ASettings.IncludeAbsolutePaths) + '.');
  ALines.Add('Following symbolic links was enabled by policy: ' +
    YesNo(ASettings.FollowSymbolicLinks) + '.');
  if ASettings.FollowSymbolicLinks then
    ALines.Add('Followed links were permitted to leave the selected ' +
      'folder: ' + YesNo(ASettings.AllowOutsideRoot) + '.');
  ALines.Add('SHA-256 calculation for manifests and binaries enabled: ' +
    YesNo(ASettings.CalculateSHA256) + '.');
  ALines.Add('Verified rescan-cache reuse enabled: ' +
    YesNo(ASettings.UseRescanCache) + '.');
  if ASettings.UseRescanCache then
    ALines.Add('Cache reads bypassed for this scan, with a rebuild ' +
      'requested after successful completion: ' +
      YesNo(ASettings.RefreshRescanCache) + '.');
  ALines.Add(Format('Ignore patterns applied: %d.',
    [ASettings.IgnorePatterns.Count]));
  ALines.Add('SBOM author details configured: ' +
    YesNo((Trim(ASettings.SBOMAuthorOrganization) <> '') or
    (Trim(ASettings.SBOMAuthorEmail) <> '')) + ' (the details themselves ' +
    'are shown on the Summary tab, not in this report).');
  ALines.Add('Absolute-path and outside-root choices remembered for future ' +
    'scans: ' + YesNo(ASettings.RememberPrivacyChoices) + '.');
end;

function BuildScanDetailsReport(ATask: TScanTask;
  AOnlineCheckPending: Boolean): string;
var
  Lines: TStringList;
  Affected: TStringList;
  FirstSection: Boolean;

  procedure AddLine(const AText: string);
  begin
    Lines.Add(AText);
  end;

  procedure AddSection(const ACaption: string);
  begin
    if not FirstSection then
      AddLine('');
    AddLine(ACaption);
    AddLine(StringOfChar('-', Length(ACaption)));
    FirstSection := False;
  end;

  function StatusSentence: string;
  begin
    case ATask.Status of
      tsCompleted:
        if ATask.Warnings.Count + ATask.Errors.Count > 0 then
          Result := 'The scan completed, but see the warnings and errors below.'
        else
          Result := 'The scan completed without warnings or errors.';
      tsRunning: Result := 'The scan is still running.';
      tsPending: Result := 'The scan has not started yet.';
      tsCancelled: Result := 'The scan was cancelled before it finished; ' +
        'results are partial.';
      tsFailed: Result := 'The scan failed; see the errors below.';
    else
      Result := 'Status: ' + TaskStatusToString(ATask.Status) + '.';
    end;
  end;

  function IsLeafName(const AName: string): Boolean;
  var
    K: Integer;
  begin
    Result := (AName <> '') and (AName <> '.') and (AName <> '..') and
      (Pos('/', AName) = 0) and (Pos('\', AName) = 0) and
      (Pos(':', AName) = 0);
    if Result then
      for K := 1 to Length(AName) do
        if (Ord(AName[K]) < 32) or (Ord(AName[K]) = 127) then
          Exit(False);
  end;

  function IsFilesystemRoot(const ADirectory: string): Boolean;
  var
    Body: string;
    Separators, K: Integer;
  begin
    { Unix root, Windows drive root (C:, C:\, C:/) and UNC share root
      (\\server\share with an optional trailing separator) have no
      meaningful prefix to redact. }
    Result := (ADirectory = '') or (ADirectory = '/') or (ADirectory = '\');
    if Result then
      Exit;
    if (Length(ADirectory) in [2, 3]) and (ADirectory[2] = ':') and
      ((Length(ADirectory) = 2) or (ADirectory[3] in ['\', '/'])) then
      Exit(True);
    if (Length(ADirectory) > 2) and (ADirectory[1] in ['\', '/']) and
      (ADirectory[2] = ADirectory[1]) then
    begin
      Body := Copy(ADirectory, 3, MaxInt);
      if (Body <> '') and (Body[Length(Body)] in ['\', '/']) then
        Delete(Body, Length(Body), 1);
      Separators := 0;
      for K := 1 to Length(Body) do
        if Body[K] in ['\', '/'] then
          Inc(Separators);
      Result := Separators <= 1;
    end;
  end;

  function RedactSpelling(const AText, ARoot: string): string;
  var
    Flags: TReplaceFlags;
  begin
    Result := AText;
    if ARoot = '' then
      Exit;
    Flags := [rfReplaceAll];
    {$IFDEF WINDOWS}
    Include(Flags, rfIgnoreCase);
    {$ENDIF}
    Result := StringReplace(Result, ARoot, '[scanned folder]', Flags);
  end;

  function Redact(const AText: string): string;
  var
    Root, Swapped: string;
  begin
    { Free-text messages may embed the scanned folder; keep the report
      relative unless the scan opted in to absolute paths. Both separator
      spellings are covered; a filesystem root has nothing to redact. }
    Result := AText;
    if ATask.Settings.IncludeAbsolutePaths or
      IsFilesystemRoot(ATask.TargetDirectory) then
      Exit;
    Root := ExcludeTrailingPathDelimiter(ATask.TargetDirectory);
    if Root = '' then
      Exit;
    Swapped := StringReplace(Root, '/', '\', [rfReplaceAll]);
    if Swapped = Root then
      Swapped := StringReplace(Root, '\', '/', [rfReplaceAll]);
    Result := RedactSpelling(Result, Root);
    if Swapped <> Root then
      Result := RedactSpelling(Result, Swapped);
  end;

  function FolderLine: string;
  var
    Name: string;
  begin
    if ATask.Settings.IncludeAbsolutePaths then
      Exit('Folder: ' + ATask.TargetDirectory);
    { Only a genuine leaf name recorded by the scan is shown; anything
      else falls back to a neutral label rather than a derived path. }
    Name := ATask.TargetRootName;
    if not IsLeafName(Name) then
      Name := 'scanned folder';
    Result := 'Folder: ' + Name + ' (folder name only; the full path is ' +
      'omitted unless "Include absolute paths in exported SBOM" was ' +
      'enabled for this scan)';
  end;

  function ComponentLabelFor(const APackageURL: string): string;
  var
    K: Integer;
    C: uModels.TComponent;
  begin
    for K := 0 to ATask.Components.Count - 1 do
    begin
      C := uModels.TComponent(ATask.Components[K]);
      if C.PackageURL = APackageURL then
      begin
        Result := C.Name;
        if C.Version <> '' then
          Result := Result + ' ' + C.Version;
        if C.Ecosystem <> '' then
          Result := Result + ' (' + C.Ecosystem + ')';
        Exit;
      end;
    end;
    Result := APackageURL;
  end;

  procedure AddKnownIssuesSection;
  var
    Check: TKnownIssueCheck;
    I, J, Shown, Omitted, WithoutPackageURL: Integer;
    Match: TKnownIssueMatch;
    PackageURL: string;
    Consequence: string;
  begin
    Check := ATask.KnownIssueCheck;
    if not Check.Requested then
    begin
      AddSection('Known issues (OSV.dev online check)');
      if AOnlineCheckPending then
        AddLine('You asked for the OSV.dev online check. It runs only ' +
          'after the inventory SBOM has been written and hashed; its ' +
          'results will appear here when the scan finishes.')
      else if ATask.Status in [tsCancelled, tsFailed] then
        AddLine('No online check was recorded. The check is attempted ' +
          'only after the inventory is complete and the SBOM has been ' +
          'written and hashed; this scan did not reach a recorded check.')
      else
        AddLine('Not requested for this scan. The application never ' +
          'contacts the network unless you ask: enable the online check ' +
          'when starting a scan, or use "Refresh intelligence..." on this ' +
          'completed scan to look up its exact package versions on ' +
          'OSV.dev.');
      Exit;
    end;

    if Check.IsPartial then
      AddSection('Known issues (OSV.dev online check) ' + #$E2#$80#$94 +
        ' incomplete')
    else
      AddSection('Known issues (OSV.dev online check)');
    AddLine(KnownIssueOutcomeSentence(Check, ATask.Status, Affected.Count));
    Consequence := KnownIssueConsequenceSentence(Check);
    if Consequence <> '' then
      AddLine(Consequence);
    if Check.CheckedUTC <> '' then
    begin
      if ATask.Status = tsCompleted then
        AddLine('Checked: ' + LocalTimestampText(Check.CheckedUTC) +
          ' (local time). Advisory data changes daily; use "Refresh ' +
          'intelligence..." to re-check this inventory without rescanning.')
      else
        AddLine('Checked: ' + LocalTimestampText(Check.CheckedUTC) +
          ' (local time).');
    end;
    if (Check.OutcomeCode <> KnownIssueOutcomeTransportUnavailable) and
      (Check.OutcomeCode <> KnownIssueOutcomeLookupFailed) then
    begin
      AddLine(Format('Unique canonical package URLs eligible for lookup: ' +
        '%d.', [Check.EligibleCandidateCount]));
      AddLine(Format('Skipped because the package URL has no exact ' +
        'registry version, uses an ecosystem OSV.dev does not index, or ' +
        'is a generic or native identity: %d.',
        [Check.RejectedCandidateCount]));
      if Check.DuplicateCandidateCount > 0 then
        AddLine(Format('Repeated package URLs folded into one query: %d.',
          [Check.DuplicateCandidateCount]));
      WithoutPackageURL := 0;
      for I := 0 to ATask.Components.Count - 1 do
        if Trim(uModels.TComponent(ATask.Components[I]).PackageURL) = '' then
          Inc(WithoutPackageURL);
      if WithoutPackageURL > 0 then
        AddLine(Format('Components with no package URL at all (for ' +
          'example native linked libraries) are never looked up: %d.',
          [WithoutPackageURL]));
    end;
    if Check.Diagnostic <> '' then
      AddLine('Technical detail: ' + Redact(Check.Diagnostic));
    if Check.MatchCount > 0 then
    begin
      AddLine('A finding means an advisory names this exact package ' +
        'version; it does not by itself mean the vulnerable code is ' +
        'reachable in your application. Review each advisory link.');
      AddLine('The affected components are listed below; in the ' +
        'application they are shown in red in the Components tab, where ' +
        'the "Known issues" column gives the number of advisories per ' +
        'component.');
      if Check.IsPartial then
        AddLine('Findings received before the check stopped:');
      Shown := 0;
      for I := 0 to Affected.Count - 1 do
      begin
        if Shown >= MaximumDisplayedKnownIssueMatches then
          Break;
        PackageURL := Affected[I];
        AddLine('');
        AddLine('* ' + ComponentLabelFor(PackageURL));
        AddLine('  Package URL: ' + PackageURL);
        for J := 0 to Check.MatchCount - 1 do
        begin
          if Shown >= MaximumDisplayedKnownIssueMatches then
            Break;
          Match := Check.Matches[J];
          if Match.PackageURL <> PackageURL then
            Continue;
          AddLine('  - ' + Match.AdvisoryID + ' (advisory last updated ' +
            AdvisoryDateText(Match.Modified) + '): ' +
            'https://osv.dev/vulnerability/' + Match.AdvisoryID);
          Inc(Shown);
        end;
      end;
      Omitted := Check.MatchCount - Shown;
      if Omitted > 0 then
      begin
        AddLine('');
        if Omitted = 1 then
          AddLine('1 additional match is kept in the task history but ' +
            'not listed here.')
        else
          AddLine(Format('%d additional matches are kept in the task ' +
            'history but not listed here.', [Omitted]));
      end;
    end;
    AddLine('');
    AddLine('A lookup with no finding is not a clean bill of health: when ' +
      'a lookup runs, it covers only packages with an exact registry ' +
      'identity, and only advisories published on OSV.dev at check time.');
  end;

var
  I, ArtifactNoteCount: Integer;
  Artifact: TArtifact;
begin
  Result := '';
  if ATask = nil then
    Exit;
  Lines := TStringList.Create;
  Affected := TStringList.Create;
  try
    FirstSection := True;
    Affected.Sorted := True;
    Affected.Duplicates := dupIgnore;
    Affected.CaseSensitive := True;
    Affected.UseLocale := False;
    if ATask.KnownIssueCheck.Requested then
      for I := 0 to ATask.KnownIssueCheck.MatchCount - 1 do
        Affected.Add(ATask.KnownIssueCheck.Matches[I].PackageURL);

    AddLine(AppName + ' ' + DisplayVersion + ' ' + #$E2#$80#$94 +
      ' scan details');
    AddLine('');

    AddSection('Scan summary');
    AddLine(FolderLine);
    AddLine('Created: ' + LocalTimestampText(ATask.CreatedUTC) +
      ' (local time)');
    if ATask.StartedUTC <> '' then
      AddLine('Started: ' + LocalTimestampText(ATask.StartedUTC) +
        ' (local time)');
    if ATask.CompletedUTC <> '' then
    begin
      if ATask.StartedUTC <> '' then
        AddLine('Finished: ' + LocalTimestampText(ATask.CompletedUTC) +
          ' (local time), after ' + FormatDuration(ATask.DurationMS))
      else
        AddLine('Finished: ' + LocalTimestampText(ATask.CompletedUTC) +
          ' (local time; the start time was not recorded)');
    end;
    AddLine('Result: ' + StatusSentence);
    AddLine(Format('Inspected %d files; recognized %d artifacts ' +
      '(%d parsed, %d partially parsed, %d unsupported, %d failed); ' +
      'identified %d components.', [ATask.FilesInspected,
      ATask.ArtifactsDetected, ATask.ArtifactsParsed,
      ATask.ArtifactsPartiallyParsed, ATask.UnsupportedArtifacts,
      ATask.FailedArtifacts, ATask.ComponentsIdentified]));
    if ATask.GeneratedSBOMSHA256 <> '' then
      AddLine('CycloneDX SBOM SHA-256: ' + ATask.GeneratedSBOMSHA256);

    AddKnownIssuesSection;

    if ATask.Warnings.Count > 0 then
    begin
      AddSection(Format('Warnings (%d)', [ATask.Warnings.Count]));
      AddLine('Warnings record limits or degraded steps the scan ran ' +
        'into. Some describe places the inventory could not see (it may ' +
        'be incomplete there); others concern optional steps such as the ' +
        'online check or the verified cache and do not affect the ' +
        'inventory itself.');
      for I := 0 to ATask.Warnings.Count - 1 do
        AddLine('- ' + Redact(ATask.Warnings[I]));
    end;
    if ATask.Errors.Count > 0 then
    begin
      AddSection(Format('Errors (%d)', [ATask.Errors.Count]));
      AddLine('Errors stopped part of the work. Fix the cause and rescan ' +
        'to obtain complete results.');
      for I := 0 to ATask.Errors.Count - 1 do
        AddLine('- ' + Redact(ATask.Errors[I]));
    end;

    ArtifactNoteCount := 0;
    for I := 0 to ATask.Artifacts.Count - 1 do
      if Trim(TArtifact(ATask.Artifacts[I]).MessageText) <> '' then
        Inc(ArtifactNoteCount);
    if ArtifactNoteCount > 0 then
    begin
      AddSection(Format('Artifact notes (%d)', [ArtifactNoteCount]));
      AddLine('Per-file observations recorded while reading manifests and ' +
        'binaries, with the status each file ended up with.');
      for I := 0 to ATask.Artifacts.Count - 1 do
      begin
        Artifact := TArtifact(ATask.Artifacts[I]);
        if Trim(Artifact.MessageText) <> '' then
          AddLine('- ' + Redact(Artifact.RelativePath) + ' [' +
            ArtifactStatusDisplayText(Artifact.Status) + ']: ' +
            Redact(Artifact.MessageText));
      end;
    end;

    AddSection('What this scan can and cannot tell you');
    AddLine('The inventory comes from reading manifests, lock files, and ' +
      'binary headers on disk. Nothing was executed, and the inventory ' +
      'itself was built without network access; the only network ' +
      'activity, when you enable it, is the OSV.dev known-issues lookup ' +
      'described above.');
    AddLine('Components are identified from what the scanned files ' +
      'declare or carry: package manifests, lock files (which normally ' +
      'list transitive dependencies as well as direct ones), the ' +
      'metadata inside Java and similar package archives, and the ' +
      'identity and shared-library declarations inside ELF, PE, and ' +
      'Mach-O binaries, which are themselves recorded as components. ' +
      'The inventory does not mark which entries are direct and which ' +
      'are transitive.');
    AddLine('Dependencies that are resolved only at run time, installed ' +
      'outside the scanned folder, or not declared in those files can be ' +
      'missed. Treat the result as best-effort evidence, not as proof of ' +
      'completeness.');

    AddSection('Scan settings');
    DescribeScanSettings(ATask.Settings, Lines);
    if ATask.ScannerVersion <> '' then
      AddLine('Scanner version: ' + ATask.ScannerVersion);

    Result := TrimRight(Lines.Text);
  finally
    Affected.Free;
    Lines.Free;
  end;
end;

end.
