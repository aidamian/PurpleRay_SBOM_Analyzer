(**
  PurpleRay SBOM Analyzer scan-comparison feature-frame unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents a directional comparison of two completed scan-history tasks. The
  frame retains task identifiers and caller-owned summaries only, clones task
  models before comparison, and never rescans target files.

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
unit uCompareScansFrame;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls, Menus,
  Contnrs, uTaskHistory, uComponentComparison;

type
  TCompareScansFrame = class(TFrame)
  published
    PickerPanel: TPanel;
    BaselineRowPanel: TPanel;
    BaselineLabel: TLabel;
    FBaselinePicker: TComboBox;
    FSwapButton: TButton;
    ComparisonRowPanel: TPanel;
    ComparisonLabel: TLabel;
    FComparisonPicker: TComboBox;
    FRefreshButton: TButton;
    FSelectionMessage: TLabel;
    SummaryPanel: TPanel;
    FDirectionLabel: TLabel;
    FCountSummary: TLabel;
    FilterPanel: TPanel;
    SearchLabel: TLabel;
    FSearchEdit: TEdit;
    FChangeFilter: TComboBox;
    FooterPanel: TPanel;
    FFooterLabel: TLabel;
    ResultPanel: TPanel;
    FResultEmptyLabel: TLabel;
    FResultList: TListView;
    FCopyMenu: TPopupMenu;
    CopySelectedMenuItem: TMenuItem;
    CopyIdentityMenuItem: TMenuItem;

    {**
      Rebuilds the comparison when either task picker changes.

      Parameters
      ----------
      Sender
        Baseline or comparison picker that raised the event.

      Returns
      -------
      None

      Raises
      ------
      None
        Comparison failures are converted to an in-frame validation state.
    }
    procedure PickerChanged(Sender: TObject);

    {**
      Exchanges the directional baseline and comparison task selections.

      Parameters
      ----------
      Sender
        Swap button that raised the event; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Invalid or incomplete selections leave the action disabled.
    }
    procedure SwapClicked(Sender: TObject);

    {**
      Rebuilds task choices from the current shared-history revision.

      Parameters
      ----------
      Sender
        Refresh button that raised the event; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        History and comparison failures are rendered inside the frame.
    }
    procedure RefreshClicked(Sender: TObject);

    {**
      Reapplies the free-text and change-kind filters to comparison rows.

      Parameters
      ----------
      Sender
        Search edit or change-kind picker that changed; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Display-allocation failures are converted to an empty-state message.
    }
    procedure FiltersChanged(Sender: TObject);

    {**
      Selects or reverses the report sort column and rebuilds visible rows.

      Parameters
      ----------
      Sender
        Comparison report that raised the event; not otherwise used.
      Column
        Clicked report column.

      Returns
      -------
      None

      Raises
      ------
      None
        Display-allocation failures are converted to an empty-state message.
    }
    procedure ResultColumnClicked(Sender: TObject; Column: TListColumn);

    {**
      Copies selected comparison rows when the primary copy shortcut is used.

      Parameters
      ----------
      Sender
        Comparison report receiving the key event; not otherwise used.
      Key
        Virtual key code; cleared when the shortcut is consumed.
      Shift
        Active modifier-key state.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Clipboard backend failures may propagate from the native widgetset.
    }
    procedure ResultListKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);

    {**
      Copies every selected visible comparison row as tab-delimited text.

      Parameters
      ----------
      Sender
        Popup-menu action or report control invoking the copy.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Clipboard backend failures may propagate from the native widgetset.
    }
    procedure CopySelectedClicked(Sender: TObject);

    {**
      Copies the complete stable identity of the focused comparison row.

      Parameters
      ----------
      Sender
        Popup-menu action invoking the copy; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Clipboard backend failures may propagate from the native widgetset.
    }
    procedure CopyIdentityClicked(Sender: TObject);

    {**
      Refreshes copy-action availability immediately before the menu opens.

      Parameters
      ----------
      Sender
        Comparison popup menu that is about to be displayed.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure CopyMenuPopup(Sender: TObject);
  private
    FHistory: TTaskHistoryService;
    FOwnsHistory: Boolean;
    FSummaries: TObjectList;
    FComparisonResult: TComponentComparison;
    FBaselineTaskID: string;
    FComparisonTaskID: string;
    FDefaultsApplied: Boolean;
    FUpdatingPickers: Boolean;
    FActive: Boolean;
    FClosing: Boolean;
    FHistoryDirty: Boolean;
    FLastRevision: QWord;
    FSortColumn: Integer;
    FSortAscending: Boolean;

    {**
      Adapts the service's sender-bearing event to the shell-facing callback.

      Parameters
      ----------
      Sender
        Owned history service issuing the event.
      AKind
        Reset, add, update, or removal classification.
      ATaskID
        Affected task identifier, or blank for a reset.
      ARevision
        New monotonically increasing service revision.

      Returns
      -------
      None

      Raises
      ------
      None
        HistoryChanged converts refresh failures into frame state.
    }
    procedure HistoryServiceChanged(Sender: TObject;
      AKind: TTaskHistoryChangeKind; const ATaskID: string;
      ARevision: QWord);

    {**
      Initializes state and presentation after the LFM resource has loaded.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if summaries or initial comparison state cannot be allocated.
    }
    procedure InitializeFrame;

    {**
      Returns a caller-owned summary at an ordinal history index.

      Parameters
      ----------
      AIndex
        Zero-based position within the frame-owned summary collection.

      Returns
      -------
      TTaskHistorySummary
        Borrowed summary, or nil when AIndex is outside the collection.

      Raises
      ------
      None
    }
    function SummaryAt(AIndex: Integer): TTaskHistorySummary;

    {**
      Finds a frame-owned completed-task summary by stable task identifier.

      Parameters
      ----------
      ATaskID
        Task identifier to locate.

      Returns
      -------
      TTaskHistorySummary
        Borrowed matching summary, or nil when no eligible task matches.

      Raises
      ------
      None
    }
    function FindSummary(const ATaskID: string): TTaskHistorySummary;

    {**
      Returns the summary object represented by a picker selection.

      Parameters
      ----------
      APicker
        Baseline or comparison picker.

      Returns
      -------
      TTaskHistorySummary
        Borrowed selected summary, or nil for the placeholder item.

      Raises
      ------
      None
    }
    function PickerSummary(APicker: TComboBox): TTaskHistorySummary;

    {**
      Formats one task summary for an unambiguous native combo-box item.

      Parameters
      ----------
      ASummary
        Completed task to format.

      Returns
      -------
      string
        Folder, local timestamp, component count, short ID, and review marker.

      Raises
      ------
      EOutOfMemory
        May propagate while constructing the display text.
    }
    function TaskChoiceText(ASummary: TTaskHistorySummary): string;

    {**
      Returns the picker index associated with a stable task identifier.

      Parameters
      ----------
      APicker
        Picker whose item objects should be searched.
      ATaskID
        Stable identifier to locate.

      Returns
      -------
      Integer
        Matching index, or zero for the placeholder when no match exists.

      Raises
      ------
      None
    }
    function PickerIndexForTask(APicker: TComboBox;
      const ATaskID: string): Integer;

    {**
      Rebuilds completed-task choices while preserving selected task IDs.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated if repository snapshots or picker entries cannot be allocated.
    }
    procedure RefreshTaskChoices;

    {**
      Chooses the newest scan and its nearest same-target predecessor once.

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
    procedure ApplyInitialSelection;

    {**
      Updates picker hints with full local target paths for selected tasks.

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
    procedure UpdatePickerHints;

    {**
      Validates task choices, clones both tasks, and creates a directional diff.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Clone or comparison failures are converted to validation text.
    }
    procedure RebuildComparison;

    {**
      Clears owned comparison state and renders a validation or empty message.

      Parameters
      ----------
      AMessage
        Message explaining why no comparison is currently displayed.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SetUnavailableState(const AMessage: string);

    {**
      Renders direction, counts, and non-blocking trust cautions.

      Parameters
      ----------
      ABaseline
        Selected baseline task summary.
      AComparison
        Selected comparison task summary.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while composing summary and warning text.
    }
    procedure UpdateComparisonSummary(ABaseline,
      AComparison: TTaskHistorySummary);

    {**
      Filters, sorts, and renders comparison rows without changing core order.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while allocating temporary row pointers or list items.
    }
    procedure PopulateRows;

    {**
      Tests one comparison row against the active kind and text filters.

      Parameters
      ----------
      AChange
        Candidate comparison row.

      Returns
      -------
      Boolean
        True when the row should be visible.

      Raises
      ------
      EOutOfMemory
        May propagate while composing searchable text.
    }
    function ChangeMatchesFilters(AChange: TComponentChange): Boolean;

    {**
      Compares two rows according to the active report sort policy.

      Parameters
      ----------
      ALeft
        Left comparison row.
      ARight
        Right comparison row.

      Returns
      -------
      Integer
        Negative, zero, or positive ordering result.

      Raises
      ------
      EOutOfMemory
        May propagate while normalizing case-insensitive text.
    }
    function CompareChangeRows(ALeft, ARight: TComponentChange): Integer;

    {**
      Sorts a temporary pointer list using the current stable row comparator.

      Parameters
      ----------
      AItems
        Non-owning list of TComponentChange pointers.
      ALeft
        Inclusive lower index.
      ARight
        Inclusive upper index.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate from text comparison.
    }
    procedure SortChangePointers(AItems: TList; ALeft, ARight: Integer);

    {**
      Updates picker, filter, swap, and copy-action enabled states.

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
    procedure UpdateControlStates;

    {**
      Returns a full tab-delimited clipboard representation of one row.

      Parameters
      ----------
      AChange
        Comparison row to serialize.

      Returns
      -------
      string
        Change, component, versions, ecosystem, type, and complete identity.

      Raises
      ------
      EOutOfMemory
        May propagate while constructing the result.
    }
    function ClipboardRow(AChange: TComponentChange): string;
  public
    {**
      Creates the LFM-backed frame with an owned default history service.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.

      Returns
      -------
      TCompareScansFrame
        Initialized comparison feature using standard application data.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
      EOutOfMemory, EInOutError
        May propagate while history or initial UI state is loaded.
    }
    constructor Create(TheOwner: TComponent); override;

    {**
      Creates the frame with an owned history service rooted in isolated data.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      ADataDirectory
        Explicit directory containing the task history and stored SBOMs.

      Returns
      -------
      TCompareScansFrame
        Initialized comparison feature using ADataDirectory.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
      EOutOfMemory, EInOutError
        May propagate while history or initial UI state is loaded.
    }
    constructor CreateForDataDirectory(TheOwner: TComponent;
      const ADataDirectory: string);

    {**
      Creates the frame with a borrowed shell-owned shared-history service.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      AHistory
        Non-nil service whose lifetime exceeds the frame lifetime.

      Returns
      -------
      TCompareScansFrame
        Initialized comparison feature sharing AHistory.

      Raises
      ------
      EArgumentException
        Raised when AHistory is nil.
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
      EOutOfMemory
        May propagate while initial UI state is populated.
    }
    constructor CreateWithHistoryService(TheOwner: TComponent;
      AHistory: TTaskHistoryService);

    {**
      Detaches owned callbacks and releases comparison and summary models.

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
    destructor Destroy; override;

    {**
      Refreshes stale history state and focuses the most useful control.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Refresh failures are rendered inside the frame.
    }
    procedure Activate;

    {**
      Marks the feature hidden while retaining selections, filters, and results.

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

    {**
      Receives a shell-fanned shared-history revision notification.

      Parameters
      ----------
      AKind
        Reset, add, update, or removal classification.
      ATaskID
        Affected task identifier, or an empty value for a complete reset.
      ARevision
        Monotonically increasing repository revision.

      Returns
      -------
      None

      Raises
      ------
      None
        Refresh failures are converted to in-frame validation text.
    }
    procedure HistoryChanged(AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);

    {**
      Handles comparison-feature keyboard commands delegated by the shell.

      Parameters
      ----------
      AKey
        Virtual key code; cleared when consumed.
      AShift
        Active modifier-key state.

      Returns
      -------
      Boolean
        True when the comparison feature consumed the shortcut.

      Raises
      ------
      None
        Refresh failures stay inside the frame; clipboard failures propagate
        only from direct list copy events.
    }
    function HandleShortcut(var AKey: Word; AShift: TShiftState): Boolean;

    {**
      Makes shutdown preparation immediate, idempotent, and non-blocking.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        Always True after owned callbacks have been detached.

      Raises
      ------
      None
    }
    function PrepareForClose: Boolean;

    property BaselineTaskID: string read FBaselineTaskID;
    property ComparisonTaskID: string read FComparisonTaskID;
    property HistoryService: TTaskHistoryService read FHistory;
  end;

implementation

uses
  Clipbrd, LCLType, uModels, uPresentation;

{$R *.lfm}

const
  DefaultFooterText =
    'Comparison uses saved component inventories; files are not rescanned.';
  EmptyCountText =
    'Added —   •   Removed —   •   Changed —   •   Unchanged —';

{**
  Tests whether the platform's primary command modifier is pressed.

  Parameters
  ----------
  AShift
    LCL modifier-key state for the current key event.

  Returns
  -------
  Boolean
    True for Command on macOS or Control on other supported platforms.

  Raises
  ------
  None
}
function PrimaryShortcut(AShift: TShiftState): Boolean;
begin
  {$IFDEF Darwin}
  Result := ssMeta in AShift;
  {$ELSE}
  Result := ssCtrl in AShift;
  {$ENDIF}
end;

{**
  Performs a case-insensitive substring match with empty-query semantics.

  Parameters
  ----------
  AHaystack
    Candidate searchable text.
  ANeedle
    Query text; an empty query matches every candidate.

  Returns
  -------
  Boolean
    True when ANeedle is empty or occurs within AHaystack.

  Raises
  ------
  EOutOfMemory
    May propagate while allocating normalized strings.
}
function ContainsTextValue(const AHaystack, ANeedle: string): Boolean;
begin
  Result := (ANeedle = '') or
    (Pos(LowerCase(ANeedle), LowerCase(AHaystack)) > 0);
end;

{**
  Compares display text case-insensitively with an ordinal case-sensitive tie.

  Parameters
  ----------
  ALeft
    Left text value.
  ARight
    Right text value.

  Returns
  -------
  Integer
    Negative, zero, or positive ordering result.

  Raises
  ------
  EOutOfMemory
    May propagate while allocating lowercase values.
}
function CompareDisplayText(const ALeft, ARight: string): Integer;
begin
  Result := CompareStr(LowerCase(ALeft), LowerCase(ARight));
  if Result = 0 then
    Result := CompareStr(ALeft, ARight);
end;

{**
  Shortens a stable task identifier for dense local presentation.

  Parameters
  ----------
  ATaskID
    Full task identifier.

  Returns
  -------
  string
    First eight characters, or the complete shorter value.

  Raises
  ------
  None
}
function ShortTaskID(const ATaskID: string): string;
begin
  Result := Copy(ATaskID, 1, 8);
end;

{**
  Tests whether two persisted task targets identify the same local directory.

  Parameters
  ----------
  ALeft
    Left task summary.
  ARight
    Right task summary.

  Returns
  -------
  Boolean
    True for equal normalized paths, or equal root names when both paths are
    absent from legacy history.

  Raises
  ------
  None
    Path expansion failures fall back to persisted path text.
}
function SameTaskTarget(ALeft, ARight: TTaskHistorySummary): Boolean;
var
  LeftPath, RightPath: string;
begin
  if (ALeft = nil) or (ARight = nil) then
    Exit(False);
  LeftPath := Trim(ALeft.TargetDirectory);
  RightPath := Trim(ARight.TargetDirectory);
  if (LeftPath = '') or (RightPath = '') then
    Exit((LeftPath = '') and (RightPath = '') and
      SameFileName(ALeft.TargetRootName, ARight.TargetRootName));
  try
    LeftPath := IncludeTrailingPathDelimiter(ExpandFileName(LeftPath));
    RightPath := IncludeTrailingPathDelimiter(ExpandFileName(RightPath));
  except
    { Persisted text remains sufficient for a conservative comparison. }
  end;
  {$IFDEF Windows}
  Result := SameText(LeftPath, RightPath);
  {$ELSE}
  Result := CompareStr(LeftPath, RightPath) = 0;
  {$ENDIF}
end;

{**
  Produces the compact table spelling for a component-change kind.

  Parameters
  ----------
  AKind
    Added, removed, or version-changed classification.

  Returns
  -------
  string
    Theme-independent prefixed change text.

  Raises
  ------
  None
}
function ChangeKindDisplayText(AKind: TComponentChangeKind): string;
begin
  case AKind of
    ccAdded: Result := '+ Added';
    ccRemoved: Result := '- Removed';
    ccVersionChanged: Result := '~ Changed';
  else
    Result := 'Changed';
  end;
end;

{**
  Returns the stable default ordering rank of a component-change kind.

  Parameters
  ----------
  AKind
    Added, removed, or version-changed classification.

  Returns
  -------
  Integer
    Zero for added, one for removed, and two for version changed.

  Raises
  ------
  None
}
function ChangeKindOrder(AKind: TComponentChangeKind): Integer;
begin
  case AKind of
    ccAdded: Result := 0;
    ccRemoved: Result := 1;
  else
    Result := 2;
  end;
end;

constructor TCompareScansFrame.Create(TheOwner: Classes.TComponent);
begin
  inherited Create(TheOwner);
  FHistory := TTaskHistoryService.Create('');
  FOwnsHistory := True;
  InitializeFrame;
end;

constructor TCompareScansFrame.CreateForDataDirectory(
  TheOwner: Classes.TComponent;
  const ADataDirectory: string);
begin
  inherited Create(TheOwner);
  FHistory := TTaskHistoryService.Create(ADataDirectory);
  FOwnsHistory := True;
  InitializeFrame;
end;

constructor TCompareScansFrame.CreateWithHistoryService(
  TheOwner: Classes.TComponent; AHistory: TTaskHistoryService);
begin
  if AHistory = nil then
    raise EArgumentException.Create('A shared task-history service is required');
  inherited Create(TheOwner);
  FHistory := AHistory;
  FOwnsHistory := False;
  InitializeFrame;
end;

destructor TCompareScansFrame.Destroy;
begin
  PrepareForClose;
  if FResultList <> nil then
    FResultList.Items.Clear;
  if FBaselinePicker <> nil then
    FBaselinePicker.Items.Clear;
  if FComparisonPicker <> nil then
    FComparisonPicker.Items.Clear;
  FreeAndNil(FComparisonResult);
  FreeAndNil(FSummaries);
  if FOwnsHistory then
    FreeAndNil(FHistory)
  else
    FHistory := nil;
  inherited Destroy;
end;

procedure TCompareScansFrame.InitializeFrame;
begin
  FSummaries := TObjectList.Create(True);
  FSortColumn := 0;
  FSortAscending := True;
  BaselineLabel.FocusControl := FBaselinePicker;
  ComparisonLabel.FocusControl := FComparisonPicker;
  SearchLabel.FocusControl := FSearchEdit;
  FBaselinePicker.Hint := 'Completed scan used as the starting inventory';
  FComparisonPicker.Hint := 'Completed scan compared against the baseline';
  FSwapButton.Hint := 'Reverse the comparison direction';
  FRefreshButton.Hint := 'Refresh this view from shared task history';
  FFooterLabel.Caption := DefaultFooterText;
  if FOwnsHistory then
    FHistory.OnChanged := @HistoryServiceChanged;
  RefreshTaskChoices;
end;

procedure TCompareScansFrame.HistoryServiceChanged(Sender: TObject;
  AKind: TTaskHistoryChangeKind; const ATaskID: string; ARevision: QWord);
begin
  if Sender = FHistory then
    HistoryChanged(AKind, ATaskID, ARevision);
end;

function TCompareScansFrame.SummaryAt(AIndex: Integer): TTaskHistorySummary;
begin
  if (AIndex < 0) or (AIndex >= FSummaries.Count) then
    Exit(nil);
  Result := TTaskHistorySummary(FSummaries[AIndex]);
end;

function TCompareScansFrame.FindSummary(
  const ATaskID: string): TTaskHistorySummary;
var
  I: Integer;
begin
  if ATaskID = '' then
    Exit(nil);
  for I := 0 to FSummaries.Count - 1 do
    if TTaskHistorySummary(FSummaries[I]).ID = ATaskID then
      Exit(TTaskHistorySummary(FSummaries[I]));
  Result := nil;
end;

function TCompareScansFrame.PickerSummary(
  APicker: TComboBox): TTaskHistorySummary;
begin
  Result := nil;
  if (APicker = nil) or (APicker.ItemIndex <= 0) or
    (APicker.ItemIndex >= APicker.Items.Count) then
    Exit;
  Result := TTaskHistorySummary(APicker.Items.Objects[APicker.ItemIndex]);
end;

function TCompareScansFrame.TaskChoiceText(
  ASummary: TTaskHistorySummary): string;
var
  RootName, ReviewText: string;
begin
  if ASummary = nil then
    Exit('');
  RootName := Trim(ASummary.TargetRootName);
  if RootName = '' then
    RootName := ExtractFileName(ASummary.TargetDirectory);
  if RootName = '' then
    RootName := ASummary.TargetDirectory;
  ReviewText := '';
  if (ASummary.WarningCount > 0) or (ASummary.ErrorCount > 0) then
    ReviewText := ' — review';
  Result := Format('%s — %s — %d components — [%s]%s',
    [RootName, LocalTimestampText(ASummary.CreatedUTC),
    ASummary.ComponentCount, ShortTaskID(ASummary.ID), ReviewText]);
end;

function TCompareScansFrame.PickerIndexForTask(APicker: TComboBox;
  const ATaskID: string): Integer;
var
  I: Integer;
  Summary: TTaskHistorySummary;
begin
  Result := 0;
  if (APicker = nil) or (ATaskID = '') then
    Exit;
  for I := 1 to APicker.Items.Count - 1 do
  begin
    Summary := TTaskHistorySummary(APicker.Items.Objects[I]);
    if (Summary <> nil) and (Summary.ID = ATaskID) then
      Exit(I);
  end;
end;

procedure TCompareScansFrame.RefreshTaskChoices;
var
  I: Integer;
  Summary: TTaskHistorySummary;
begin
  FUpdatingPickers := True;
  try
    FBaselinePicker.Items.Clear;
    FComparisonPicker.Items.Clear;
    FSummaries.Clear;
    FHistory.GetCompletedTaskSummaries(FSummaries);
    FBaselinePicker.Items.Add('Choose a completed scan...');
    FComparisonPicker.Items.Add('Choose a completed scan...');
    for I := 0 to FSummaries.Count - 1 do
    begin
      Summary := SummaryAt(I);
      FBaselinePicker.Items.AddObject(TaskChoiceText(Summary), Summary);
      FComparisonPicker.Items.AddObject(TaskChoiceText(Summary), Summary);
    end;
    if not FDefaultsApplied then
      ApplyInitialSelection;
    FBaselinePicker.ItemIndex := PickerIndexForTask(FBaselinePicker,
      FBaselineTaskID);
    FComparisonPicker.ItemIndex := PickerIndexForTask(FComparisonPicker,
      FComparisonTaskID);
    FLastRevision := FHistory.Revision;
    FHistoryDirty := False;
  finally
    FUpdatingPickers := False;
  end;
  UpdatePickerHints;
  RebuildComparison;
end;

procedure TCompareScansFrame.ApplyInitialSelection;
var
  BaselineIndex, I: Integer;
  Newest, Candidate: TTaskHistorySummary;
begin
  { Keep an empty history eligible for defaults when completed scans first
    become available. Once even one default selection exists, later history
    notifications must preserve it instead of selecting a newly completed
    scan silently. }
  FBaselineTaskID := '';
  FComparisonTaskID := '';
  Newest := SummaryAt(0);
  if Newest = nil then
    Exit;
  FDefaultsApplied := True;
  FComparisonTaskID := Newest.ID;
  if FSummaries.Count < 2 then
    Exit;
  BaselineIndex := -1;
  for I := 1 to FSummaries.Count - 1 do
  begin
    Candidate := SummaryAt(I);
    if SameTaskTarget(Newest, Candidate) then
    begin
      BaselineIndex := I;
      Break;
    end;
  end;
  if BaselineIndex < 0 then
    BaselineIndex := 1;
  FBaselineTaskID := SummaryAt(BaselineIndex).ID;
end;

procedure TCompareScansFrame.UpdatePickerHints;
var
  Summary: TTaskHistorySummary;
begin
  Summary := FindSummary(FBaselineTaskID);
  if Summary <> nil then
    FBaselinePicker.Hint := Summary.TargetDirectory
  else
    FBaselinePicker.Hint :=
      'Completed scan used as the starting inventory';
  Summary := FindSummary(FComparisonTaskID);
  if Summary <> nil then
    FComparisonPicker.Hint := Summary.TargetDirectory
  else
    FComparisonPicker.Hint :=
      'Completed scan compared against the baseline';
end;

procedure TCompareScansFrame.SetUnavailableState(const AMessage: string);
begin
  FResultList.Items.Clear;
  FreeAndNil(FComparisonResult);
  FSelectionMessage.Caption := AMessage;
  FSelectionMessage.Hint := AMessage;
  FDirectionLabel.Caption := 'Select a baseline and comparison scan.';
  FCountSummary.Caption := EmptyCountText;
  FResultList.Visible := False;
  FResultEmptyLabel.Caption := AMessage;
  FResultEmptyLabel.Visible := True;
  FFooterLabel.Caption := DefaultFooterText;
  UpdateControlStates;
end;

procedure TCompareScansFrame.RebuildComparison;
var
  BaselineSummary, ComparisonSummary: TTaskHistorySummary;
  BaselineTask, ComparisonTask: TScanTask;
begin
  BaselineTask := nil;
  ComparisonTask := nil;
  if FSummaries.Count = 0 then
  begin
    SetUnavailableState('No completed scans are available. Run at least two ' +
      'scans in SBOM Analyzer.');
    Exit;
  end;
  if FSummaries.Count = 1 then
  begin
    SetUnavailableState('One completed scan is available. Run another scan ' +
      'to compare changes.');
    Exit;
  end;
  BaselineSummary := FindSummary(FBaselineTaskID);
  ComparisonSummary := FindSummary(FComparisonTaskID);
  if ((FBaselineTaskID <> '') and (BaselineSummary = nil)) or
    ((FComparisonTaskID <> '') and (ComparisonSummary = nil)) then
  begin
    SetUnavailableState('A selected scan is no longer available. Choose ' +
      'another scan.');
    Exit;
  end;
  if (BaselineSummary = nil) or (ComparisonSummary = nil) then
  begin
    SetUnavailableState('Choose a baseline scan and a comparison scan.');
    Exit;
  end;
  if FBaselineTaskID = FComparisonTaskID then
  begin
    SetUnavailableState('Choose two different completed scans.');
    Exit;
  end;
  try
    try
      BaselineTask := FHistory.CloneTaskByID(FBaselineTaskID);
      ComparisonTask := FHistory.CloneTaskByID(FComparisonTaskID);
      if (BaselineTask = nil) or (ComparisonTask = nil) then
      begin
        SetUnavailableState('A selected scan is no longer available. Choose ' +
          'another scan.');
        Exit;
      end;
      FResultList.Items.Clear;
      FreeAndNil(FComparisonResult);
      FComparisonResult := CompareComponentTasks(BaselineTask, ComparisonTask);
      if FComparisonResult = nil then
      begin
        SetUnavailableState('The selected scans could not be compared.');
        Exit;
      end;
      UpdateComparisonSummary(BaselineSummary, ComparisonSummary);
      PopulateRows;
    except
      on E: Exception do
        SetUnavailableState('The selected scans could not be compared: ' +
          E.Message);
    end;
  finally
    BaselineTask.Free;
    ComparisonTask.Free;
  end;
end;

procedure TCompareScansFrame.UpdateComparisonSummary(ABaseline,
  AComparison: TTaskHistorySummary);
var
  CautionText, DetailText: string;
  I: Integer;

  procedure AddCaution(const ACaption, ADetail: string);
  begin
    if CautionText <> '' then
      CautionText := CautionText + ' ';
    CautionText := CautionText + ACaption;
    if ADetail <> '' then
    begin
      if DetailText <> '' then
        DetailText := DetailText + LineEnding;
      DetailText := DetailText + ADetail;
    end;
  end;

begin
  FDirectionLabel.Caption := Format('Changes from %s [%s] to %s [%s]',
    [ABaseline.TargetRootName, ShortTaskID(ABaseline.ID),
    AComparison.TargetRootName, ShortTaskID(AComparison.ID)]);
  FCountSummary.Caption := Format(
    'Added %d   •   Removed %d   •   Changed %d   •   Unchanged %d',
    [FComparisonResult.AddedCount, FComparisonResult.RemovedCount,
    FComparisonResult.VersionChangedCount, FComparisonResult.UnchangedCount]);
  CautionText := '';
  DetailText := '';
  if not SameTaskTarget(ABaseline, AComparison) then
    AddCaution('Caution: the selected scans target different folders.',
      ABaseline.TargetDirectory + LineEnding + AComparison.TargetDirectory);
  if (ABaseline.WarningCount > 0) or (ABaseline.ErrorCount > 0) or
    (AComparison.WarningCount > 0) or (AComparison.ErrorCount > 0) then
    AddCaution('Caution: one or both scans completed with diagnostics.', '');
  if not SameText(Trim(ABaseline.ScannerVersion),
    Trim(AComparison.ScannerVersion)) then
    AddCaution('Caution: the scans were produced by different analyzer ' +
      'versions.', ABaseline.ScannerVersion + ' / ' +
      AComparison.ScannerVersion);
  if FComparisonResult.Warnings.Count > 0 then
  begin
    AddCaution(Format('Caution: comparison reported %d identity warning(s).',
      [FComparisonResult.Warnings.Count]), '');
    for I := 0 to FComparisonResult.Warnings.Count - 1 do
    begin
      if DetailText <> '' then
        DetailText := DetailText + LineEnding;
      DetailText := DetailText + FComparisonResult.Warnings[I];
    end;
  end;
  if CautionText = '' then
    CautionText := 'Changes are directional: baseline → comparison.';
  FSelectionMessage.Caption := CautionText;
  if DetailText <> '' then
    FSelectionMessage.Hint := CautionText + LineEnding + DetailText
  else
    FSelectionMessage.Hint := CautionText;
end;

function TCompareScansFrame.ChangeMatchesFilters(
  AChange: TComponentChange): Boolean;
var
  Searchable, SearchText: string;
begin
  if AChange = nil then
    Exit(False);
  case FChangeFilter.ItemIndex of
    1: if AChange.Kind <> ccAdded then Exit(False);
    2: if AChange.Kind <> ccRemoved then Exit(False);
    3: if AChange.Kind <> ccVersionChanged then Exit(False);
  end;
  SearchText := Trim(FSearchEdit.Text);
  Searchable := ChangeKindDisplayText(AChange.Kind) + ' ' + AChange.Name +
    ' ' + AChange.BeforeVersion + ' ' + AChange.AfterVersion + ' ' +
    AChange.Ecosystem + ' ' + AChange.ComponentType + ' ' +
    AChange.IdentityKey + ' ' + AChange.BeforePackageURL + ' ' +
    AChange.AfterPackageURL + ' ' + AChange.BeforeScope + ' ' +
    AChange.AfterScope;
  Result := ContainsTextValue(Searchable, SearchText);
end;

function TCompareScansFrame.CompareChangeRows(ALeft,
  ARight: TComponentChange): Integer;
var
  LeftText, RightText: string;
begin
  if ALeft = ARight then
    Exit(0);
  if ALeft = nil then
    Exit(-1);
  if ARight = nil then
    Exit(1);
  if FSortColumn = 0 then
    Result := ChangeKindOrder(ALeft.Kind) - ChangeKindOrder(ARight.Kind)
  else
  begin
    case FSortColumn of
      1:
        begin
          LeftText := ALeft.Name;
          RightText := ARight.Name;
        end;
      2:
        begin
          LeftText := ALeft.BeforeVersion;
          RightText := ARight.BeforeVersion;
        end;
      3:
        begin
          LeftText := ALeft.AfterVersion;
          RightText := ARight.AfterVersion;
        end;
      4:
        begin
          LeftText := ALeft.Ecosystem;
          RightText := ARight.Ecosystem;
        end;
      5:
        begin
          LeftText := ALeft.ComponentType;
          RightText := ARight.ComponentType;
        end;
    else
      begin
        LeftText := ALeft.IdentityKey;
        RightText := ARight.IdentityKey;
      end;
    end;
    Result := CompareDisplayText(LeftText, RightText);
  end;
  if Result = 0 then
    Result := CompareStr(ALeft.RowKey, ARight.RowKey);
  if not FSortAscending then
    Result := -Result;
end;

procedure TCompareScansFrame.SortChangePointers(AItems: TList;
  ALeft, ARight: Integer);
var
  I, J: Integer;
  Pivot, Temporary: Pointer;
begin
  I := ALeft;
  J := ARight;
  Pivot := AItems[(ALeft + ARight) div 2];
  repeat
    while CompareChangeRows(TComponentChange(AItems[I]),
      TComponentChange(Pivot)) < 0 do
      Inc(I);
    while CompareChangeRows(TComponentChange(AItems[J]),
      TComponentChange(Pivot)) > 0 do
      Dec(J);
    if I <= J then
    begin
      Temporary := AItems[I];
      AItems[I] := AItems[J];
      AItems[J] := Temporary;
      Inc(I);
      Dec(J);
    end;
  until I > J;
  if ALeft < J then
    SortChangePointers(AItems, ALeft, J);
  if I < ARight then
    SortChangePointers(AItems, I, ARight);
end;

procedure TCompareScansFrame.PopulateRows;
var
  VisibleChanges: TList;
  SelectedKeys: TStringList;
  Change: TComponentChange;
  Item: TListItem;
  I: Integer;
begin
  if FComparisonResult = nil then
    Exit;
  VisibleChanges := TList.Create;
  SelectedKeys := TStringList.Create;
  try
    SelectedKeys.Sorted := True;
    SelectedKeys.Duplicates := dupIgnore;
    SelectedKeys.CaseSensitive := True;
    for I := 0 to FResultList.Items.Count - 1 do
      if FResultList.Items[I].Selected and
        (FResultList.Items[I].Data <> nil) then
        SelectedKeys.Add(TComponentChange(
          FResultList.Items[I].Data).RowKey);
    for I := 0 to FComparisonResult.Changes.Count - 1 do
    begin
      Change := TComponentChange(FComparisonResult.Changes[I]);
      if ChangeMatchesFilters(Change) then
        VisibleChanges.Add(Change);
    end;
    if VisibleChanges.Count > 1 then
      SortChangePointers(VisibleChanges, 0, VisibleChanges.Count - 1);
    FResultList.Items.BeginUpdate;
    try
      FResultList.Items.Clear;
      for I := 0 to VisibleChanges.Count - 1 do
      begin
        Change := TComponentChange(VisibleChanges[I]);
        Item := FResultList.Items.Add;
        Item.Data := Change;
        Item.Caption := ChangeKindDisplayText(Change.Kind);
        Item.SubItems.Add(Change.Name);
        Item.SubItems.Add(Change.BeforeVersion);
        Item.SubItems.Add(Change.AfterVersion);
        Item.SubItems.Add(Change.Ecosystem);
        Item.SubItems.Add(Change.ComponentType);
        Item.SubItems.Add(Change.IdentityKey);
        if SelectedKeys.IndexOf(Change.RowKey) >= 0 then
          Item.Selected := True;
      end;
    finally
      FResultList.Items.EndUpdate;
    end;
    FResultList.Visible := VisibleChanges.Count > 0;
    FResultEmptyLabel.Visible := VisibleChanges.Count = 0;
    if FComparisonResult.Changes.Count = 0 then
    begin
      if (FindSummary(FBaselineTaskID).ComponentCount = 0) and
        (FindSummary(FComparisonTaskID).ComponentCount = 0) then
        FResultEmptyLabel.Caption := 'Both scans contain no identified ' +
          'components. Review their warnings before treating this as no change.'
      else
        FResultEmptyLabel.Caption :=
          'No component changes were found between these scans.';
    end
    else if VisibleChanges.Count = 0 then
      FResultEmptyLabel.Caption :=
        'No changes match the current search and filter.';
    FFooterLabel.Caption := Format(
      'Showing %d of %d changes — Changed means the saved version differs; ' +
      'files are not rescanned.', [VisibleChanges.Count,
      FComparisonResult.Changes.Count]);
    UpdateControlStates;
  finally
    SelectedKeys.Free;
    VisibleChanges.Free;
  end;
end;

procedure TCompareScansFrame.UpdateControlStates;
var
  HasRows, HasValidPair: Boolean;
begin
  if FSummaries = nil then
    Exit;
  FBaselinePicker.Enabled := FSummaries.Count > 0;
  FComparisonPicker.Enabled := FSummaries.Count > 0;
  HasValidPair := (FindSummary(FBaselineTaskID) <> nil) and
    (FindSummary(FComparisonTaskID) <> nil) and
    (FBaselineTaskID <> FComparisonTaskID);
  FSwapButton.Enabled := (not FClosing) and HasValidPair;
  HasRows := (FComparisonResult <> nil) and
    (FComparisonResult.Changes.Count > 0);
  FSearchEdit.Enabled := (not FClosing) and HasRows;
  FChangeFilter.Enabled := (not FClosing) and HasRows;
  CopySelectedMenuItem.Enabled := FResultList.Selected <> nil;
  CopyIdentityMenuItem.Enabled := FResultList.Selected <> nil;
  FRefreshButton.Enabled := not FClosing;
end;

function TCompareScansFrame.ClipboardRow(
  AChange: TComponentChange): string;
begin
  if AChange = nil then
    Exit('');
  Result := ChangeKindDisplayText(AChange.Kind) + #9 + AChange.Name + #9 +
    AChange.BeforeVersion + #9 + AChange.AfterVersion + #9 +
    AChange.Ecosystem + #9 + AChange.ComponentType + #9 +
    AChange.IdentityKey;
end;

procedure TCompareScansFrame.PickerChanged(Sender: TObject);
var
  Summary: TTaskHistorySummary;
begin
  if FUpdatingPickers or FClosing then
    Exit;
  if Sender = FBaselinePicker then
  begin
    Summary := PickerSummary(FBaselinePicker);
    if Summary <> nil then
      FBaselineTaskID := Summary.ID
    else
      FBaselineTaskID := '';
  end
  else if Sender = FComparisonPicker then
  begin
    Summary := PickerSummary(FComparisonPicker);
    if Summary <> nil then
      FComparisonTaskID := Summary.ID
    else
      FComparisonTaskID := '';
  end
  else
    Exit;
  FDefaultsApplied := True;
  UpdatePickerHints;
  RebuildComparison;
end;

procedure TCompareScansFrame.SwapClicked(Sender: TObject);
var
  TemporaryID: string;
begin
  if not FSwapButton.Enabled then
    Exit;
  TemporaryID := FBaselineTaskID;
  FBaselineTaskID := FComparisonTaskID;
  FComparisonTaskID := TemporaryID;
  FDefaultsApplied := True;
  FUpdatingPickers := True;
  try
    FBaselinePicker.ItemIndex := PickerIndexForTask(FBaselinePicker,
      FBaselineTaskID);
    FComparisonPicker.ItemIndex := PickerIndexForTask(FComparisonPicker,
      FComparisonTaskID);
  finally
    FUpdatingPickers := False;
  end;
  UpdatePickerHints;
  RebuildComparison;
end;

procedure TCompareScansFrame.RefreshClicked(Sender: TObject);
begin
  if FClosing then
    Exit;
  try
    RefreshTaskChoices;
  except
    on E: Exception do
      SetUnavailableState('Task history could not be refreshed: ' + E.Message);
  end;
end;

procedure TCompareScansFrame.FiltersChanged(Sender: TObject);
begin
  if FClosing or (FComparisonResult = nil) then
    Exit;
  try
    PopulateRows;
  except
    on E: Exception do
      SetUnavailableState('Comparison rows could not be displayed: ' + E.Message);
  end;
end;

procedure TCompareScansFrame.ResultColumnClicked(Sender: TObject;
  Column: TListColumn);
begin
  if (Column = nil) or (FComparisonResult = nil) then
    Exit;
  if FSortColumn = Column.Index then
    FSortAscending := not FSortAscending
  else
  begin
    FSortColumn := Column.Index;
    FSortAscending := True;
  end;
  FiltersChanged(Sender);
end;

procedure TCompareScansFrame.ResultListKeyPressed(Sender: TObject;
  var Key: Word; Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) and (Key = VK_C) then
  begin
    CopySelectedClicked(Sender);
    Key := 0;
  end;
end;

procedure TCompareScansFrame.CopySelectedClicked(Sender: TObject);
var
  I: Integer;
  Change: TComponentChange;
  Value: string;
begin
  Value := '';
  for I := 0 to FResultList.Items.Count - 1 do
    if FResultList.Items[I].Selected and
      (FResultList.Items[I].Data <> nil) then
    begin
      Change := TComponentChange(FResultList.Items[I].Data);
      if Value <> '' then
        Value := Value + LineEnding;
      Value := Value + ClipboardRow(Change);
    end;
  if Value <> '' then
    Clipboard.AsText := Value;
end;

procedure TCompareScansFrame.CopyIdentityClicked(Sender: TObject);
var
  Change: TComponentChange;
begin
  if (FResultList.Selected = nil) or
    (FResultList.Selected.Data = nil) then
    Exit;
  Change := TComponentChange(FResultList.Selected.Data);
  Clipboard.AsText := Change.IdentityKey;
end;

procedure TCompareScansFrame.CopyMenuPopup(Sender: TObject);
begin
  CopySelectedMenuItem.Enabled := FResultList.Selected <> nil;
  CopyIdentityMenuItem.Enabled := FResultList.Selected <> nil;
end;

procedure TCompareScansFrame.Activate;
begin
  if FClosing then
    Exit;
  FActive := True;
  if FHistoryDirty or (FHistory.Revision <> FLastRevision) then
  begin
    try
      RefreshTaskChoices;
    except
      on E: Exception do
        SetUnavailableState('Task history could not be refreshed: ' + E.Message);
    end;
  end;
  if (FResultList.Visible) and FResultList.CanFocus then
    FResultList.SetFocus
  else if (FindSummary(FBaselineTaskID) = nil) and
    FBaselinePicker.CanFocus then
    FBaselinePicker.SetFocus
  else if FComparisonPicker.CanFocus then
    FComparisonPicker.SetFocus;
end;

procedure TCompareScansFrame.Deactivate;
begin
  FActive := False;
end;

procedure TCompareScansFrame.HistoryChanged(AKind: TTaskHistoryChangeKind;
  const ATaskID: string; ARevision: QWord);
begin
  if FClosing then
    Exit;
  FHistoryDirty := True;
  if not FActive then
    Exit;
  if (ARevision <> 0) and (ARevision = FLastRevision) then
  begin
    FHistoryDirty := False;
    Exit;
  end;
  try
    RefreshTaskChoices;
  except
    on E: Exception do
      SetUnavailableState('Task history could not be refreshed: ' + E.Message);
  end;
  { AKind and ATaskID intentionally remain available for future narrow refreshes. }
end;

function TCompareScansFrame.HandleShortcut(var AKey: Word;
  AShift: TShiftState): Boolean;
begin
  Result := False;
  if FClosing then
    Exit;
  if PrimaryShortcut(AShift) and (AKey = VK_F) then
  begin
    if FSearchEdit.CanFocus then
    begin
      FSearchEdit.SetFocus;
      FSearchEdit.SelectAll;
    end;
    AKey := 0;
    Exit(True);
  end;
  if AKey = VK_F5 then
  begin
    RefreshClicked(Self);
    AKey := 0;
    Exit(True);
  end;
  if PrimaryShortcut(AShift) and (AKey = VK_C) and
    (Screen.ActiveControl = FResultList) then
  begin
    CopySelectedClicked(FResultList);
    AKey := 0;
    Exit(True);
  end;
  { Escape is deliberately not consumed: Compare must never cancel a hidden scan. }
end;

function TCompareScansFrame.PrepareForClose: Boolean;
begin
  if not FClosing then
  begin
    FClosing := True;
    FActive := False;
    if FOwnsHistory and (FHistory <> nil) then
      FHistory.OnChanged := nil;
    UpdateControlStates;
  end;
  Result := True;
end;

end.
