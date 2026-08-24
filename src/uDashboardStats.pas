(**
  PurpleRay SBOM Analyzer dashboard statistics.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  LCL-free aggregation of persisted scan tasks into the numbers the
  Dashboard feature displays. Everything is computed locally from the
  in-memory task list; nothing is estimated or fetched.

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
unit uDashboardStats;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels;

type
  TDashboardStats = record
    ScanCount: Integer;
    CompletedScanCount: Integer;
    RunningScanCount: Integer;
    FailedScanCount: Integer;
    ComponentsDiscovered: Int64;
    ArtifactsInspected: Int64;
    FilesInspected: Int64;
    UniqueAdvisoryCount: Integer;
  end;

{**
  Aggregates a task list into dashboard statistics.

  Parameters
  ----------
  ATasks
    List of TScanTask instances in history order; nil counts as empty.
    Ownership stays with the caller.

  Returns
  -------
  TDashboardStats
    Zero-initialized totals summed over every task, with advisory IDs
    from per-task known-issue checks counted once each across the
    whole history.

  Raises
  ------
  None
}
function ComputeDashboardStats(ATasks: TObjectList): TDashboardStats;

implementation

function ComputeDashboardStats(ATasks: TObjectList): TDashboardStats;
var
  Advisories: TStringList;
  Task: TScanTask;
  I, J: Integer;
  AdvisoryID: string;
begin
  FillChar(Result, SizeOf(Result), 0);
  if ATasks = nil then
    Exit;
  Advisories := TStringList.Create;
  try
    Advisories.Sorted := True;
    Advisories.Duplicates := dupIgnore;
    Advisories.CaseSensitive := True;
    for I := 0 to ATasks.Count - 1 do
    begin
      Task := TScanTask(ATasks[I]);
      if Task = nil then
        Continue;
      Inc(Result.ScanCount);
      case Task.Status of
        tsCompleted: Inc(Result.CompletedScanCount);
        tsRunning, tsPending: Inc(Result.RunningScanCount);
        tsFailed: Inc(Result.FailedScanCount);
        tsCancelled: ;
      end;
      Inc(Result.ComponentsDiscovered, Task.ComponentsIdentified);
      Inc(Result.ArtifactsInspected, Task.ArtifactsDetected);
      Inc(Result.FilesInspected, Task.FilesInspected);
      if Task.KnownIssueCheck <> nil then
        for J := 0 to Task.KnownIssueCheck.MatchCount - 1 do
        begin
          AdvisoryID := Trim(Task.KnownIssueCheck.Matches[J].AdvisoryID);
          if AdvisoryID <> '' then
            Advisories.Add(AdvisoryID);
        end;
    end;
    Result.UniqueAdvisoryCount := Advisories.Count;
  finally
    Advisories.Free;
  end;
end;

end.
