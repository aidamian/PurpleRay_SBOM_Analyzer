(**
  PurpleRay SBOM Analyzer known-issue lookup service.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  This non-visual boundary collects only component Package URLs, delegates a
  bounded query to the injected OSV client transport, and persists the
  privacy-minimized outcome on the scan task. It never alters the generated
  inventory document or retains request bodies, raw responses, or page tokens.
*)
unit uKnownIssueService;

{$mode objfpc}{$H+}

interface

uses
  uKnownIssues, uModels, uOSVCore;

(**
  Reports whether a completed lookup may replace an older valid snapshot.

  Only successful and no-eligible-candidate outcomes are complete snapshots.
  Cancellation, transport/protocol failure, and resource-limit outcomes must
  leave the previous result in place.
*)
function KnownIssueCheckCanReplace(ACheck: TKnownIssueCheck): Boolean;

(**
  Runs one explicitly requested OSV.dev check over a completed inventory.

  Parameters
  ----------
  ATask
    Completed task whose component Package URLs are queried and whose owned
    known-issue result receives the bounded outcome.
  ATransport
    Injected verified transport. A nil value records a deterministic
    unavailable outcome without attempting network access.
  ACancelCheck
    Optional cooperative cancellation check. Cancellation affects only the
    lookup; the already-generated inventory remains completed.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when ATask is nil.
  EOutOfMemory
    May propagate while allocating the bounded candidate or result model.
*)
procedure ExecuteKnownIssueCheck(ATask: TScanTask;
  const ATransport: IOSVTransport; ACancelCheck: TOSVCancelCheck = nil);

implementation

uses
  Classes, SysUtils, uTimeUtils;

function KnownIssueCheckCanReplace(ACheck: TKnownIssueCheck): Boolean;
begin
  Result := (ACheck <> nil) and ACheck.Requested and
    ((ACheck.OutcomeCode = OSVOutcomeCode(osoSucceeded)) or
    (ACheck.OutcomeCode = OSVOutcomeCode(osoNoEligibleCandidates)));
end;

procedure AddTaskWarning(ATask: TScanTask; const AMessage: string);
var
  MessageValue: string;
begin
  MessageValue := Trim(AMessage);
  if (MessageValue <> '') and (ATask.Warnings.IndexOf(MessageValue) < 0) then
    ATask.Warnings.Add(MessageValue);
end;

function LookupWarning(AResult: TOSVLookupResult): string;
begin
  if AResult = nil then
    Exit('The optional OSV.dev known-issue check was unavailable.');
  case AResult.Outcome of
    osoSucceeded:
      Result := '';
    osoNoEligibleCandidates:
      Result := 'The optional OSV.dev known-issue check found no eligible ' +
        'versioned ecosystem Package URLs.';
    osoCancelled:
      Result := 'The optional OSV.dev known-issue check was cancelled after ' +
        'the inventory SBOM was written.';
  else
    begin
      Result := 'The optional OSV.dev known-issue check did not complete';
      if AResult.Diagnostic <> '' then
        Result := Result + ': ' + AResult.Diagnostic
      else
        Result := Result + '.';
    end;
  end;
end;

procedure ExecuteKnownIssueCheck(ATask: TScanTask;
  const ATransport: IOSVTransport; ACancelCheck: TOSVCancelCheck);
var
  Candidates: TStringList;
  CheckTime, WarningText: string;
  Client: TOSVClient;
  Component: uModels.TComponent;
  I: Integer;
  LookupResult: TOSVLookupResult;
begin
  if ATask = nil then
    raise EArgumentNilException.Create('Known-issue task must not be nil');
  CheckTime := UTCNowISO8601;
  if ATransport = nil then
  begin
    ATask.KnownIssueCheck.MarkUnavailable(CheckTime,
      'transport-unavailable',
      'The native verified-TLS OSV transport is unavailable.');
    AddTaskWarning(ATask,
      'The optional OSV.dev known-issue check was unavailable.');
    Exit;
  end;

  Candidates := TStringList.Create;
  Client := nil;
  LookupResult := nil;
  try
    for I := 0 to ATask.Components.Count - 1 do
    begin
      Component := uModels.TComponent(ATask.Components[I]);
      if Trim(Component.PackageURL) <> '' then
      begin
        if Candidates.Count >= OSVMaximumCandidates then
        begin
          { Trigger the core's count-only fail-closed boundary without copying
            another caller-controlled coordinate into transient memory. }
          Candidates.Add('');
          Break;
        end;
        Candidates.Add(Component.PackageURL);
      end;
    end;
    Client := TOSVClient.Create(ATransport);
    LookupResult := Client.Query(Candidates, ACancelCheck);
    ATask.KnownIssueCheck.AssignOSVResult(LookupResult, CheckTime);
    WarningText := LookupWarning(LookupResult);
    AddTaskWarning(ATask, WarningText);
  finally
    LookupResult.Free;
    Client.Free;
    Candidates.Free;
  end;
end;

end.
