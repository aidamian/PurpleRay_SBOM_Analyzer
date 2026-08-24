(**
  PurpleRay SBOM Analyzer dashboard feature frame.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Home screen of the application shell: large launchers for the main
  features, activity statistics aggregated from the shared task
  history, and the most recent scans. Everything shown is computed
  locally; the frame never starts network or filesystem work itself.

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
unit uDashboardFrame;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, Forms, Controls, StdCtrls, ExtCtrls,
  ComCtrls, Graphics, uTaskHistory, uModels, uDashboardStats,
  uPresentation, uGlossary, uGlossaryContent;

const
  DashboardStatTileCount = 5;
  DashboardRecentScanLimit = 3;

type
  TDashboardFrame = class(TFrame)
  private
    FHistory: TTaskHistoryService;
    FGlossaryTermCount: Integer;
    FHeaderPanel: TPanel;
    FTitleLabel: TLabel;
    FSubtitleLabel: TLabel;
    FCardsPanel: TPanel;
    FAnalyzerCard: TPanel;
    FKnowledgeCard: TPanel;
    FStatsHeading: TLabel;
    FStatsPanel: TPanel;
    FStatValueLabels: array[0..DashboardStatTileCount - 1] of TLabel;
    FRecentHeading: TLabel;
    FRecentList: TListView;
    FOnOpenAnalyzer: TNotifyEvent;
    FOnOpenKnowledgeBase: TNotifyEvent;
    FOnNewScan: TNotifyEvent;
    FOnCompare: TNotifyEvent;

    {**
      Builds every child control.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated when a control cannot be allocated.
    }
    procedure InitializeFrame;

    {**
      Builds one feature-launcher card.

      Parameters
      ----------
      ATitle
        Card heading text.
      ADescription
        Wrapped explanatory text.
      AButtons
        Captions for the card's action buttons in display order.
      AHandlers
        Click handlers matching AButtons one-to-one.

      Returns
      -------
      TPanel
        Card panel parented to the cards row.

      Raises
      ------
      EOutOfMemory
        Propagated when a control cannot be allocated.
    }
    function BuildCard(const ATitle, ADescription: string;
      const AButtons: array of string;
      const AHandlers: array of TNotifyEvent): TPanel;

    {**
      Forwards the Open action of the analyzer card.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure OpenAnalyzerClicked(Sender: TObject);

    {**
      Forwards the New Scan action of the analyzer card.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure NewScanClicked(Sender: TObject);

    {**
      Forwards the Compare action of the analyzer card.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure CompareClicked(Sender: TObject);

    {**
      Forwards the Open action of the Knowledge Base card.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure OpenKnowledgeBaseClicked(Sender: TObject);

    {**
      Opens the analyzer when a recent-scan row is double-clicked.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure RecentListDoubleClicked(Sender: TObject);
  public
    {**
      Creates the dashboard bound to the shared task history.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      AHistory
        Shared task-history service; must not be nil.

      Returns
      -------
      TDashboardFrame
        Initialized dashboard with current statistics.

      Raises
      ------
      EArgumentException
        Raised when AHistory is nil.
      EOutOfMemory
        Propagated when the frame cannot be allocated.
    }
    constructor CreateWithHistoryService(TheOwner: Classes.TComponent;
      AHistory: TTaskHistoryService);

    {**
      Recomputes statistics and the recent-scan rows.

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
    procedure RefreshFromHistory;

    {**
      Refreshes the dashboard when shared history changes.

      Parameters
      ----------
      AKind
        Reset, add, update, or removal operation that completed.
      ATaskID
        Affected task identifier; not otherwise used.
      ARevision
        In-memory history revision; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure HistoryChanged(AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);

    {**
      Prepares the feature for display with fresh numbers.

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
    procedure Activate;

    {**
      Releases transient state when leaving the feature.

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
    procedure Deactivate;

    property OnOpenAnalyzer: TNotifyEvent read FOnOpenAnalyzer
      write FOnOpenAnalyzer;
    property OnOpenKnowledgeBase: TNotifyEvent read FOnOpenKnowledgeBase
      write FOnOpenKnowledgeBase;
    property OnNewScan: TNotifyEvent read FOnNewScan write FOnNewScan;
    property OnCompare: TNotifyEvent read FOnCompare write FOnCompare;
  end;

implementation

{$R *.lfm}

const
  StatCaptions: array[0..DashboardStatTileCount - 1] of string = (
    'Scans recorded',
    'Components discovered',
    'Artifacts inspected',
    'Advisories on record',
    'Knowledge Base terms');

constructor TDashboardFrame.CreateWithHistoryService(
  TheOwner: Classes.TComponent; AHistory: TTaskHistoryService);
var
  Glossary: TGlossary;
begin
  if AHistory = nil then
    raise EArgumentException.Create(
      'A shared task-history service is required');
  inherited Create(TheOwner);
  FHistory := AHistory;
  Glossary := TGlossary.Create;
  try
    Glossary.LoadFromMarkdown(GlossaryMarkdown);
    FGlossaryTermCount := Glossary.Count;
  finally
    Glossary.Free;
  end;
  InitializeFrame;
  RefreshFromHistory;
end;

function TDashboardFrame.BuildCard(const ATitle, ADescription: string;
  const AButtons: array of string;
  const AHandlers: array of TNotifyEvent): TPanel;
var
  TitleLabel, DescriptionLabel: TLabel;
  ButtonRow: TPanel;
  ActionButton: TButton;
  I: Integer;
begin
  Result := TPanel.Create(Self);
  Result.Parent := FCardsPanel;
  Result.BevelOuter := bvNone;
  Result.BorderStyle := bsSingle;

  TitleLabel := TLabel.Create(Self);
  TitleLabel.Parent := Result;
  TitleLabel.Align := alTop;
  TitleLabel.Caption := ATitle;
  TitleLabel.Font.Style := [fsBold];
  TitleLabel.Font.Height := -16;
  TitleLabel.BorderSpacing.Left := 16;
  TitleLabel.BorderSpacing.Top := 14;
  TitleLabel.BorderSpacing.Right := 16;
  TitleLabel.Top := 0;

  DescriptionLabel := TLabel.Create(Self);
  DescriptionLabel.Parent := Result;
  DescriptionLabel.Align := alTop;
  DescriptionLabel.Caption := ADescription;
  DescriptionLabel.WordWrap := True;
  DescriptionLabel.BorderSpacing.Left := 16;
  DescriptionLabel.BorderSpacing.Top := 6;
  DescriptionLabel.BorderSpacing.Right := 16;
  DescriptionLabel.Top := 1;

  ButtonRow := TPanel.Create(Self);
  ButtonRow.Parent := Result;
  ButtonRow.Align := alBottom;
  ButtonRow.BevelOuter := bvNone;
  ButtonRow.Height := 42;
  ButtonRow.ChildSizing.Layout := cclLeftToRightThenTopToBottom;
  ButtonRow.ChildSizing.ControlsPerLine := 8;
  ButtonRow.ChildSizing.HorizontalSpacing := 8;
  ButtonRow.BorderSpacing.Left := 16;
  ButtonRow.BorderSpacing.Bottom := 4;

  for I := 0 to High(AButtons) do
  begin
    ActionButton := TButton.Create(Self);
    ActionButton.Parent := ButtonRow;
    ActionButton.Caption := AButtons[I];
    ActionButton.AutoSize := True;
    if I <= High(AHandlers) then
      ActionButton.OnClick := AHandlers[I];
  end;
end;

procedure TDashboardFrame.InitializeFrame;
var
  I: Integer;
  Tile: TPanel;
  CaptionLabel: TLabel;
begin
  FHeaderPanel := TPanel.Create(Self);
  FHeaderPanel.Parent := Self;
  FHeaderPanel.Align := alTop;
  FHeaderPanel.Height := 74;
  FHeaderPanel.BevelOuter := bvNone;

  FTitleLabel := TLabel.Create(Self);
  FTitleLabel.Parent := FHeaderPanel;
  FTitleLabel.Caption := 'Dashboard';
  FTitleLabel.Font.Style := [fsBold];
  FTitleLabel.Font.Height := -19;
  FTitleLabel.Left := 16;
  FTitleLabel.Top := 14;

  FSubtitleLabel := TLabel.Create(Self);
  FSubtitleLabel.Parent := FHeaderPanel;
  FSubtitleLabel.Caption := 'Local software inventory at a glance. ' +
    'Everything below is computed on this machine.';
  FSubtitleLabel.Left := 16;
  FSubtitleLabel.Top := 44;

  FCardsPanel := TPanel.Create(Self);
  FCardsPanel.Parent := Self;
  FCardsPanel.Align := alTop;
  FCardsPanel.Height := 140;
  FCardsPanel.BevelOuter := bvNone;
  FCardsPanel.BorderSpacing.Left := 16;
  FCardsPanel.BorderSpacing.Right := 16;
  FCardsPanel.ChildSizing.Layout := cclLeftToRightThenTopToBottom;
  FCardsPanel.ChildSizing.ControlsPerLine := 2;
  FCardsPanel.ChildSizing.HorizontalSpacing := 14;
  FCardsPanel.ChildSizing.EnlargeHorizontal := crsHomogenousChildResize;
  FCardsPanel.ChildSizing.EnlargeVertical := crsHomogenousChildResize;

  FAnalyzerCard := BuildCard('SBOM Analyzer',
    'Scan a local folder, inspect components and artifacts, and export ' +
    'CycloneDX with security and readiness reports.',
    ['Open', 'New Scan...', 'Compare scans...'],
    [@OpenAnalyzerClicked, @NewScanClicked, @CompareClicked]);
  FKnowledgeCard := BuildCard('Knowledge Base',
    Format('Plain-language definitions for every term PurpleRay uses. ' +
    '%d glossary entries, readable offline.', [FGlossaryTermCount]),
    ['Open'], [@OpenKnowledgeBaseClicked]);

  FStatsHeading := TLabel.Create(Self);
  FStatsHeading.Parent := Self;
  FStatsHeading.Align := alTop;
  FStatsHeading.Caption := 'Activity';
  FStatsHeading.Font.Style := [fsBold];
  FStatsHeading.BorderSpacing.Left := 16;
  FStatsHeading.BorderSpacing.Top := 16;

  FStatsPanel := TPanel.Create(Self);
  FStatsPanel.Parent := Self;
  FStatsPanel.Align := alTop;
  FStatsPanel.Height := 78;
  FStatsPanel.BevelOuter := bvNone;
  FStatsPanel.BorderSpacing.Left := 16;
  FStatsPanel.BorderSpacing.Top := 6;
  FStatsPanel.BorderSpacing.Right := 16;
  FStatsPanel.ChildSizing.Layout := cclLeftToRightThenTopToBottom;
  FStatsPanel.ChildSizing.ControlsPerLine := DashboardStatTileCount;
  FStatsPanel.ChildSizing.HorizontalSpacing := 12;
  FStatsPanel.ChildSizing.EnlargeHorizontal := crsHomogenousChildResize;
  FStatsPanel.ChildSizing.EnlargeVertical := crsHomogenousChildResize;

  for I := 0 to DashboardStatTileCount - 1 do
  begin
    Tile := TPanel.Create(Self);
    Tile.Parent := FStatsPanel;
    Tile.BevelOuter := bvNone;
    Tile.BorderStyle := bsSingle;

    FStatValueLabels[I] := TLabel.Create(Self);
    FStatValueLabels[I].Parent := Tile;
    FStatValueLabels[I].Align := alTop;
    FStatValueLabels[I].Caption := '0';
    FStatValueLabels[I].Font.Style := [fsBold];
    FStatValueLabels[I].Font.Height := -22;
    FStatValueLabels[I].BorderSpacing.Left := 14;
    FStatValueLabels[I].BorderSpacing.Top := 10;
    FStatValueLabels[I].Top := 0;

    CaptionLabel := TLabel.Create(Self);
    CaptionLabel.Parent := Tile;
    CaptionLabel.Align := alTop;
    CaptionLabel.Caption := StatCaptions[I];
    CaptionLabel.Font.Color := clGrayText;
    CaptionLabel.BorderSpacing.Left := 14;
    CaptionLabel.BorderSpacing.Top := 4;
    CaptionLabel.Top := 1;
  end;

  FRecentHeading := TLabel.Create(Self);
  FRecentHeading.Parent := Self;
  FRecentHeading.Align := alTop;
  FRecentHeading.Caption := 'Recent scans';
  FRecentHeading.Font.Style := [fsBold];
  FRecentHeading.BorderSpacing.Left := 16;
  FRecentHeading.BorderSpacing.Top := 16;

  FRecentList := TListView.Create(Self);
  FRecentList.Parent := Self;
  FRecentList.Align := alTop;
  FRecentList.Height := 128;
  FRecentList.BorderSpacing.Left := 16;
  FRecentList.BorderSpacing.Top := 6;
  FRecentList.BorderSpacing.Right := 16;
  FRecentList.ViewStyle := vsReport;
  FRecentList.ReadOnly := True;
  FRecentList.RowSelect := True;
  FRecentList.OnDblClick := @RecentListDoubleClicked;
  with FRecentList.Columns.Add do
  begin
    Caption := 'Created (local)';
    Width := 150;
  end;
  with FRecentList.Columns.Add do
  begin
    Caption := 'Folder';
    Width := 260;
  end;
  with FRecentList.Columns.Add do
  begin
    Caption := 'Status';
    Width := 130;
  end;
  with FRecentList.Columns.Add do
  begin
    Caption := 'Components';
    Width := 110;
  end;

  { alTop stacking order, top to bottom. }
  FHeaderPanel.Top := 0;
  FCardsPanel.Top := 1;
  FStatsHeading.Top := 2;
  FStatsPanel.Top := 3;
  FRecentHeading.Top := 4;
  FRecentList.Top := 5;
end;

procedure TDashboardFrame.RefreshFromHistory;
var
  Tasks: TObjectList;
  Stats: TDashboardStats;
  Task: TScanTask;
  Row: TListItem;
  I: Integer;
begin
  Tasks := TObjectList.Create(False);
  try
    for I := 0 to FHistory.TaskCount - 1 do
      Tasks.Add(FHistory.TaskAt(I));
    Stats := ComputeDashboardStats(Tasks);
    FStatValueLabels[0].Caption := IntToStr(Stats.ScanCount);
    FStatValueLabels[1].Caption := IntToStr(Stats.ComponentsDiscovered);
    FStatValueLabels[2].Caption := IntToStr(Stats.ArtifactsInspected);
    FStatValueLabels[3].Caption := IntToStr(Stats.UniqueAdvisoryCount);
    FStatValueLabels[4].Caption := IntToStr(FGlossaryTermCount);

    FRecentList.Items.BeginUpdate;
    try
      FRecentList.Items.Clear;
      for I := 0 to Tasks.Count - 1 do
      begin
        if I >= DashboardRecentScanLimit then
          Break;
        Task := TScanTask(Tasks[I]);
        Row := FRecentList.Items.Add;
        Row.Caption := LocalTimestampText(Task.CreatedUTC);
        Row.SubItems.Add(Task.TargetRootName);
        Row.SubItems.Add(TaskStatusDisplayText(Task));
        Row.SubItems.Add(IntToStr(Task.ComponentsIdentified));
      end;
    finally
      FRecentList.Items.EndUpdate;
    end;
  finally
    Tasks.Free;
  end;
end;

procedure TDashboardFrame.HistoryChanged(AKind: TTaskHistoryChangeKind;
  const ATaskID: string; ARevision: QWord);
begin
  RefreshFromHistory;
end;

procedure TDashboardFrame.Activate;
begin
  RefreshFromHistory;
end;

procedure TDashboardFrame.Deactivate;
begin
  { No transient state to release. }
end;

procedure TDashboardFrame.OpenAnalyzerClicked(Sender: TObject);
begin
  if Assigned(FOnOpenAnalyzer) then
    FOnOpenAnalyzer(Self);
end;

procedure TDashboardFrame.NewScanClicked(Sender: TObject);
begin
  if Assigned(FOnNewScan) then
    FOnNewScan(Self);
end;

procedure TDashboardFrame.CompareClicked(Sender: TObject);
begin
  if Assigned(FOnCompare) then
    FOnCompare(Self);
end;

procedure TDashboardFrame.OpenKnowledgeBaseClicked(Sender: TObject);
begin
  if Assigned(FOnOpenKnowledgeBase) then
    FOnOpenKnowledgeBase(Self);
end;

procedure TDashboardFrame.RecentListDoubleClicked(Sender: TObject);
begin
  OpenAnalyzerClicked(Sender);
end;

end.
