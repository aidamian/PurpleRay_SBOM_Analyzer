(**
  PurpleRay SBOM Analyzer feature-frame unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents the complete SBOM Analyzer workspace over shared task history and
  owns scan lifecycle, filtering, result presentation, exports, drag-and-drop
  delegation, keyboard commands, settings, and worker notifications. The
  application shell embeds this frame and communicates only through its public
  API.

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
unit uSBOMAnalyzerFrame;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls, Dialogs,
  Menus, uModels, uTaskHistory, uSettingsStore, uScanWorker,
  uScanEngine;

type
  {**
    Reports a transition between idle and active analyzer states.

    Parameters
    ----------
    Sender
      Analyzer frame whose activity state changed.
    AScanActive
      True after a scan starts; False after completion or shutdown.

    Returns
    -------
    None

    Raises
    ------
    Exception
      Exceptions raised by the assigned subscriber may propagate to the caller.
  }
  TAnalyzerActivityEvent = procedure(Sender: TObject;
    AScanActive: Boolean) of object;

  TSBOMAnalyzerFrame = class(TFrame)
  published
    HeaderPanel: TPanel;
    FNewButton: TButton;
    FCancelButton: TButton;
    FRescanButton: TButton;
    FRefreshButton: TButton;
    FExportButton: TButton;
    FExportDatabaseButton: TButton;
    ContentPanel: TPanel;
    TaskPane: TPanel;
    TaskHeading: TLabel;
    TaskSearchPanel: TPanel;
    TaskSearchLabel: TLabel;
    FTaskSearch: TEdit;
    FEmptyLabel: TLabel;
    FTaskList: TListView;
    MainSplitter: TSplitter;
    DetailPane: TPanel;
    FDetailEmptyLabel: TLabel;
    FPages: TPageControl;
    SummaryPage: TTabSheet;
    FSummaryList: TListView;
    FSummaryNotes: TMemo;
    ComponentsPage: TTabSheet;
    ComponentFiltersPanel: TPanel;
    ComponentSearchLabel: TLabel;
    FComponentSearch: TEdit;
    FComponentEcosystem: TComboBox;
    FComponentStatus: TComboBox;
    FComponentList: TListView;
    FComponentEmptyLabel: TLabel;
    ArtifactsPage: TTabSheet;
    ArtifactFiltersPanel: TPanel;
    ArtifactSearchLabel: TLabel;
    FArtifactSearch: TEdit;
    FArtifactType: TComboBox;
    FArtifactStatus: TComboBox;
    FArtifactList: TListView;
    FArtifactEmptyLabel: TLabel;
    SBOMPage: TTabSheet;
    FSBOMMemo: TMemo;
    MessagesPage: TTabSheet;
    FMessagesMemo: TMemo;
    StatusPanel: TPanel;
    FProgressPath: TLabel;
    FProgressStats: TLabel;
    FProgressBar: TProgressBar;
    FExportFeedbackPanel: TPanel;
    FOpenExportFolderButton: TButton;
    FCopyExportPathButton: TButton;
    ClosePollTimer: TTimer;
    FCopyMenu: TPopupMenu;
    CopySelectedMenuItem: TMenuItem;
    FExportMenu: TPopupMenu;
    ExportSBOMMenuItem: TMenuItem;
    ExportBSIReadinessMenuItem: TMenuItem;
    FTaskMenu: TPopupMenu;
    DeleteTaskMenuItem: TMenuItem;

    {**
      Opens the directory chooser and configures a new scan when idle.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        User-facing configuration and persistence failures remain in the UI.
    }
    procedure NewScanClicked(Sender: TObject);

    {**
      Requests cooperative cancellation of the running scan, independently of
      the selected history row.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure CancelClicked(Sender: TObject);

    {**
      Reopens scan settings for the selected task's target directory.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Invalid or unavailable targets leave the action disabled or unchanged.
    }
    procedure RescanClicked(Sender: TObject);

    {**
      Reloads persisted task history while no scan is active.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Load warnings and errors are presented through LCL dialogs.
    }
    procedure RefreshClicked(Sender: TObject);

    {**
      Opens a save dialog and copies the selected task's generated SBOM.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Copy errors are shown to the user and do not escape the event handler.
    }
    procedure ExportClicked(Sender: TObject);

    {** Copies the selected task's immutable managed CycloneDX bytes. *}
    procedure ExportSBOMClicked(Sender: TObject);

    {** Builds a path-free BSI TR-03183-2 v2.1.0 readiness assessment. *}
    procedure ExportBSIReadinessClicked(Sender: TObject);

    {**
      Exports all persisted tasks, settings, diagnostics, and SBOMs as one ZIP.

      Parameters
      ----------
      Sender
        LCL action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Archive errors are shown to the user and do not escape the handler.
    }
    procedure ExportDatabaseClicked(Sender: TObject);

    {**
      Refreshes task details when a history row becomes selected.

      Parameters
      ----------
      Sender
        History list that raised the event; not otherwise used.
      Item
        Row whose selection state changed; not otherwise inspected.
      Selected
        True when Item has become the selected history row.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure TaskSelected(Sender: TObject; Item: TListItem; Selected: Boolean);

    {**
      Rebuilds the history list for the current folder/status/date query.

      Parameters
      ----------
      Sender
        Search edit that raised the event; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure TaskSearchChanged(Sender: TObject);

    {**
      Updates task-history context actions for the selected terminal task.

      Parameters
      ----------
      Sender
        Task-history popup menu; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure TaskMenuPopup(Sender: TObject);

    {**
      Confirms and removes the selected terminal task from shared history.

      Parameters
      ----------
      Sender
        Menu or keyboard action source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Persistence failures and deletion cautions are presented in the UI.
    }
    procedure DeleteTaskClicked(Sender: TObject);

    {**
      Handles the Delete key for the task-history list.

      Parameters
      ----------
      Sender
        Task-history list; not otherwise used.
      Key
        LCL virtual key code, cleared when deletion is invoked.
      Shift
        Modifier-key state; deletion requires no modifiers.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure TaskListKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);

    {**
      Rebuilds the affected component or artifact list after filter changes.

      Parameters
      ----------
      Sender
        Search edit or filter combo box that changed.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while rebuilding sorted display rows.
    }
    procedure FiltersChanged(Sender: TObject);

    {**
      Selects or reverses the component sort column and rebuilds its rows.

      Parameters
      ----------
      Sender
        Component list that raised the event; not otherwise used.
      Column
        Clicked report-view column.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while rebuilding sorted display rows.
    }
    procedure ComponentColumnClicked(Sender: TObject; Column: TListColumn);

    {**
      Selects or reverses the artifact sort column and rebuilds its rows.

      Parameters
      ----------
      Sender
        Artifact list that raised the event; not otherwise used.
      Column
        Clicked report-view column.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while rebuilding sorted display rows.
    }
    procedure ArtifactColumnClicked(Sender: TObject; Column: TListColumn);

    {**
      Copies the selected report row when the primary copy shortcut is pressed.

      Parameters
      ----------
      Sender
        Component or artifact list receiving the key event.
      Key
        LCL virtual key code; set to zero when consumed.
      Shift
        Modifier-key state accompanying Key.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Clipboard backend failures may propagate from the copy handler.
    }
    procedure ListKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);

    {**
      Copies the selected component or artifact row as tab-delimited text.

      Parameters
      ----------
      Sender
        Invoking list or popup action used to determine the source list.

      Returns
      -------
      None

      Raises
      ------
      Exception
        Clipboard backend failures may propagate.
    }
    procedure CopySelectedClicked(Sender: TObject);

    {**
      Opens the directory containing the most recently exported file.

      Parameters
      ----------
      Sender
        Footer action button; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Launch failures are reported through the analyzer error dialog.
    }
    procedure OpenExportFolderClicked(Sender: TObject);

    {**
      Copies the most recently exported path to the system clipboard.

      Parameters
      ----------
      Sender
        Footer action button; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Clipboard failures are reported through the analyzer error dialog.
    }
    procedure CopyExportPathClicked(Sender: TObject);

    {**
      Completes an accepted asynchronous close after the worker has finished.

      Parameters
      ----------
      Sender
        LFM-backed polling timer; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Finalization failures keep the close request pending and retryable.
    }
    procedure ClosePollTimerTick(Sender: TObject);
  private
    FHistoryService: TTaskHistoryService;
    FOwnsHistoryService: Boolean;
    FSettingsStore: TSettingsStore;
    FSettings: TScanSettings;
    FWorker: TScanWorker;
    FActiveTaskID: string;
    FCancelRequested: Boolean;
    FClosing: Boolean;
    FClosePending: Boolean;
    FClosePrepared: Boolean;
    FStartupWarning: string;
    FSelectedTaskID: string;
    FUpdatingDetails: Boolean;
    FComponentSortColumn: Integer;
    FComponentSortAscending: Boolean;
    FArtifactSortColumn: Integer;
    FArtifactSortAscending: Boolean;
    FLastExportPath: string;
    FOnActivityChanged: TAnalyzerActivityEvent;
    FOnCloseReady: TNotifyEvent;

    {**
      Adapts owned-service notifications to the shell-facing history API.

      Parameters
      ----------
      Sender
        Owned history service that emitted the notification.
      AKind
        Reset, addition, update, or removal operation that completed.
      ATaskID
        Affected task identifier, or blank for a reset.
      ARevision
        Shared history revision after the mutation.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure ServiceHistoryChanged(Sender: TObject;
      AKind: TTaskHistoryChangeKind; const ATaskID: string;
      ARevision: QWord);

    {**
      Reports whether a worker-backed scan currently owns the workspace.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True while an active task identifier is assigned.

      Raises
      ------
      None
    }
    function GetScanActive: Boolean;

    {**
      Changes the active task identifier and notifies the shell on transitions.

      Parameters
      ----------
      AValue
        Active scan task identifier, or an empty string for the idle state.

      Returns
      -------
      None

      Raises
      ------
      Exception
        An exception from an assigned activity callback may propagate.
    }
    procedure SetActiveTaskID(const AValue: string);

    {**
      Expands the footer into its active-scan progress layout.

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
    procedure SetActiveFooter;

    {**
      Collapses the footer to one idle or terminal status line.

      Parameters
      ----------
      AText
        Single-line status text shown after the progress controls are hidden.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SetCompactFooter(const AText: string);

    {**
      Exposes non-modal open-folder and copy-path actions after an export.

      Parameters
      ----------
      APath
        Successfully exported file path retained for footer actions.
      ADescription
        Short export description displayed in the compact footer.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure ShowExportFeedback(const APath, ADescription: string);

    {**
      Requests cancellation of the active task independently of UI selection.

      Parameters
      ----------
      AConfirm
        True to ask the user before cancelling; False when confirmation was
        already obtained by the close workflow.

      Returns
      -------
      Boolean
        True when cancellation is already pending or was requested now.

      Raises
      ------
      None
    }
    function RequestActiveCancellation(AConfirm: Boolean): Boolean;

    {**
      Copies the worker-owned terminal task into persistent frame state.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while cloning worker result collections.
    }
    procedure AdoptWorkerResult;

    {**
      Adopts and releases a worker only after its thread has finished.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True when no worker remains; False while a worker is still running.

      Raises
      ------
      None
        Result persistence failures are presented through existing UI state.
    }
    function FinalizeFinishedWorker: Boolean;

    {**
      Performs a synchronous emergency shutdown during object destruction.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        This fallback contains failures because normal UI closure is async.
    }
    procedure ForceShutdown;

    {**
      Initializes controls, stores, models, and persisted state after LFM load.

      Parameters
      ----------
      ADataDirectory
        Optional explicit persistence directory used when the frame creates
        its own history service; blank selects the standard user directory.
      AHistoryService
        Shared history service to borrow, or nil to create and own one.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory, EInOutError
        May propagate while creating stores or loading persisted state.
    }
    procedure InitializeFrame(const ADataDirectory: string;
      AHistoryService: TTaskHistoryService);

    {**
      Loads settings and history, combines startup warnings, and selects a task.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate if initial UI or model collections cannot be populated.
    }
    procedure LoadState;

    {**
      Persists the shared task collection and converts errors to UI messages.

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
    procedure SaveHistory;

    {**
      Recreates visible history rows without taking model ownership.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate if LCL list items cannot be allocated.
    }
    procedure RefreshTaskRows;

    {**
      Updates one visible history row from its owned task model.

      Parameters
      ----------
      ATask
        Borrowed service task whose counters, status, target, and timestamps
        should be rendered.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while allocating missing report-view subitems.
    }
    procedure UpdateTaskRow(ATask: TScanTask);

    {**
      Selects and reveals the visible row associated with a task model.

      Parameters
      ----------
      ATask
        Borrowed shared-history task to select when it is visible.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SelectTask(ATask: TScanTask);

    {**
      Returns the task model associated with the selected history row.

      Parameters
      ----------
      None

      Returns
      -------
      TScanTask
        Borrowed shared-history task, or nil when no row is selected.

      Raises
      ------
      None
    }
    function SelectedTask: TScanTask;

    {**
      Finds a shared-history task by its stable identifier.

      Parameters
      ----------
      AID
        Task identifier to locate.

      Returns
      -------
      TScanTask
        Borrowed matching task, or nil when no task has AID.

      Raises
      ------
      None
    }
    function FindTask(const AID: string): TScanTask;

    {**
      Finds the visible report row whose Data pointer references a task.

      Parameters
      ----------
      ATask
        Borrowed shared-history task whose visible row is requested.

      Returns
      -------
      TListItem
        Borrowed list item, or nil when filtering hides the task.

      Raises
      ------
      None
    }
    function FindTaskItem(ATask: TScanTask): TListItem;

    {**
      Tests a task against the case-insensitive task-history search query.

      Parameters
      ----------
      ATask
        Candidate task model; nil never matches.

      Returns
      -------
      Boolean
        True when the query is empty or appears in searchable task fields.

      Raises
      ------
      EOutOfMemory
        May propagate while composing or normalizing searchable text.
    }
    function TaskMatchesSearch(ATask: TScanTask): Boolean;
    {**
      Rebuilds all detail tabs and action states for the selected task.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Missing SBOM files and display failures are rendered as messages.
    }
    procedure UpdateDetails;

    {**
      Rebuilds available component-ecosystem and status filter choices.

      Parameters
      ----------
      ATask
        Selected task whose components supply the filter values.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while collecting and assigning filter strings.
    }
    procedure PopulateComponentFilters(ATask: TScanTask);

    {**
      Rebuilds available artifact-type and status filter choices.

      Parameters
      ----------
      ATask
        Selected task whose artifacts supply the filter values.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while collecting and assigning filter strings.
    }
    procedure PopulateArtifactFilters(ATask: TScanTask);

    {**
      Filters, sorts, and renders component rows for a selected task.

      Parameters
      ----------
      ATask
        Selected task, or nil to clear the component report.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while allocating sort keys or report rows.
    }
    procedure PopulateComponents(ATask: TScanTask);

    {**
      Filters, sorts, and renders artifact rows for a selected task.

      Parameters
      ----------
      ATask
        Selected task, or nil to clear the artifact report.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while allocating sort keys or report rows.
    }
    procedure PopulateArtifacts(ATask: TScanTask);

    {**
      Renders scan metadata, counters, settings, and completeness guidance.

      Parameters
      ----------
      ATask
        Selected task, or nil to render the empty-selection message.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while formatting or adding summary lines.
    }
    procedure PopulateSummary(ATask: TScanTask);

    {**
      Loads the selected task's generated CycloneDX JSON into the viewer.

      Parameters
      ----------
      ATask
        Selected task, or nil when no SBOM should be displayed.

      Returns
      -------
      None

      Raises
      ------
      None
        File-access exceptions are rendered in the SBOM viewer.
    }
    procedure PopulateSBOM(ATask: TScanTask);

    {**
      Renders completeness guidance, task diagnostics, and artifact messages.

      Parameters
      ----------
      ATask
        Selected task, or nil to clear the message viewer.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate while adding diagnostic text to the viewer.
    }
    procedure PopulateMessages(ATask: TScanTask);

    {**
      Resolves the parser status of the artifact that produced a component.

      Parameters
      ----------
      ATask
        Task that owns both the artifact and component collections.
      AComponent
        Component whose source-artifact status is requested.

      Returns
      -------
      string
        Matching artifact status, or ``parsed`` when no source matches.

      Raises
      ------
      None
    }
    function ComponentArtifactStatus(ATask: TScanTask;
      AComponent: uModels.TComponent): string;

    {**
      Enables analyzer actions according to selection and worker state.

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
    procedure UpdateButtons;

    {**
      Releases a completed worker before a subsequent scan is created.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Worker destruction detaches and removes its queued callbacks.
    }
    procedure FreeFinishedWorker;
    {**
      Creates, persists, selects, and starts a new worker-backed scan task.

      Parameters
      ----------
      ADirectory
        Existing target directory selected by the user.
      ASettings
        Accepted per-scan settings copied into the new task.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate if the task or worker cannot be allocated.
    }
    procedure StartScan(const ADirectory: string; ASettings: TScanSettings;
      ACheckKnownIssues: Boolean);

    {**
      Collects per-scan settings, persists safe defaults, and starts the scan.

      Parameters
      ----------
      ADirectory
        Target directory awaiting user confirmation.

      Returns
      -------
      None

      Raises
      ------
      None
        Settings-save errors are shown to the user.
    }
    procedure ConfigureAndStartScan(const ADirectory: string);

    {**
      Presents an analyzer-scoped error unless shutdown has started.

      Parameters
      ----------
      AMessage
        Human-readable failure description.

      Returns
      -------
      None

      Raises
      ------
      None
        The LCL message dialog handles user interaction synchronously.
    }
    procedure ShowError(const AMessage: string);

    {**
      Applies a queued worker progress snapshot to counters and status controls.

      Parameters
      ----------
      Sender
        Worker that produced the update.
      AProgress
        Latest path, counts, byte total, and elapsed time.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure WorkerProgress(Sender: TObject; const AProgress: TScanProgress);

    {**
      Replaces live task state with the completed worker result and persists it.

      Parameters
      ----------
      Sender
        Worker that completed.
      AResult
        Worker-owned task result valid for the duration of the callback.

      Returns
      -------
      None

      Raises
      ------
      None
        Persistence errors are presented through the feature frame.
    }
    procedure WorkerComplete(Sender: TObject; AResult: TScanTask);
  public
    {**
      Creates the LFM-backed feature frame and loads persistent analyzer state.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.

      Returns
      -------
      TSBOMAnalyzerFrame
        Initialized analyzer workspace.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
      EOutOfMemory
        May propagate while allocating models and stores.
    }
    constructor Create(TheOwner: Classes.TComponent); override;

    {**
      Creates the feature frame with an explicit isolated persistence root.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      ADataDirectory
        Directory used for settings, history, backups, and generated SBOMs.

      Returns
      -------
      TSBOMAnalyzerFrame
        Initialized analyzer workspace using ADataDirectory.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
      EOutOfMemory, EInOutError
        May propagate while initializing model or persistence state.
    }
    constructor CreateForDataDirectory(TheOwner: Classes.TComponent;
      const ADataDirectory: string);

    {**
      Creates the feature frame over the application's shared history service.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      AHistoryService
        Non-nil service borrowed for the lifetime of this frame.

      Returns
      -------
      TSBOMAnalyzerFrame
        Initialized analyzer workspace sharing live history with other
        compiled features.

      Raises
      ------
      EArgumentNilException
        Raised when AHistoryService is nil.
      EResNotFound, EReadError
        May propagate when the embedded LFM resource cannot be loaded.
    }
    constructor CreateWithHistoryService(TheOwner: Classes.TComponent;
      AHistoryService: TTaskHistoryService);

    {**
      Stops worker activity and releases analyzer models and persistent stores.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        Normal application shutdown prepares the frame before destruction.
    }
    destructor Destroy; override;

    {**
      Shows migration, settings, or history warnings accumulated at startup.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
        The LCL warning dialog handles the user interaction synchronously.
    }
    procedure ShowPendingWarnings;

    {**
      Starts configuration for the first dropped local directory when idle.

      Parameters
      ----------
      AFileNames
        Paths delivered by the shell's file-drop event.

      Returns
      -------
      None

      Raises
      ------
      None
        Invalid drops are reported through the analyzer error dialog.
    }
    procedure HandleDroppedFiles(const AFileNames: array of string);

    {**
      Handles analyzer-wide keyboard commands delegated by the shell.

      Parameters
      ----------
      AKey
        LCL virtual key code; set to zero when the shortcut is consumed.
      AShift
        Modifier-key state accompanying AKey.

      Returns
      -------
      Boolean
        True when the analyzer consumed the key combination.

      Raises
      ------
      None
        Command failures are presented through existing UI handlers.
    }
    function HandleShortcut(var AKey: Word; AShift: TShiftState): Boolean;

    {**
      Finalizes an already-finished worker and persists state before
      destruction. A running worker is never waited on here; interactive
      callers use RequestClose for asynchronous cancellation.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True after shutdown preparation has completed. Repeated calls are safe.

      Raises
      ------
      None
        History persistence errors are converted to non-modal shutdown state.
    }
    function PrepareForClose: Boolean;

    {**
      Starts or completes the non-blocking user-requested close workflow.

      Parameters
      ----------
      None

      Returns
      -------
      Boolean
        True only when cleanup is complete and the shell may close now.

      Raises
      ------
      None
        Cancellation and persistence failures remain contained in the frame.
    }
    function RequestClose: Boolean;

    {**
      Refreshes analyzer action state when the shell selects this feature.

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
      Releases analyzer focus when another compiled feature becomes active.

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
      Reconciles analyzer rows with a committed shared-history mutation.

      Parameters
      ----------
      AKind
        Reset, addition, update, or removal operation that completed.
      ATaskID
        Affected stable task identifier, or blank for a reset.
      ARevision
        Shared service revision associated with the notification.

      Returns
      -------
      None

      Raises
      ------
      None
        Invalid or stale notifications are ignored safely.
    }
    procedure HistoryChanged(AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);

    property ScanActive: Boolean read GetScanActive;
    property OnActivityChanged: TAnalyzerActivityEvent
      read FOnActivityChanged write FOnActivityChanged;
    property OnCloseReady: TNotifyEvent read FOnCloseReady write FOnCloseReady;
  end;

implementation

uses
  Clipbrd, Graphics, LCLIntf, LCLType, Types, uVersionInfo, uTimeUtils, uPlatform,
  uAtomicFiles, uBSIReadiness, uJSONUtils, uScanSettingsDialog, uExportUtils,
  uOSVCore, uPresentation, uSaveDialogCompat;

{$R *.lfm}

{**
  Performs a case-insensitive substring match with empty-query semantics.

  Parameters
  ----------
  AHaystack
    Candidate text to search.
  ANeedle
    Query text; an empty query matches every candidate.

  Returns
  -------
  Boolean
    True when ANeedle is empty or occurs within AHaystack.

  Raises
  ------
  EOutOfMemory
    May propagate while allocating lowercase comparison strings.
}
function ContainsTextValue(const AHaystack, ANeedle: string): Boolean;
begin
  Result := (ANeedle = '') or
    (Pos(LowerCase(ANeedle), LowerCase(AHaystack)) > 0);
end;

{**
  Tests whether the platform's primary command modifier is pressed.

  Parameters
  ----------
  Shift
    LCL modifier-key state for the current key event.

  Returns
  -------
  Boolean
    True for Command on macOS or Control on other supported platforms.

  Raises
  ------
  None
}
function PrimaryShortcut(Shift: TShiftState): Boolean;
begin
  {$IFDEF Darwin}
  Result := ssMeta in Shift;
  {$ELSE}
  Result := ssCtrl in Shift;
  {$ENDIF}
end;

{**
  Expands a selected directory without collapsing filesystem roots.

  Parameters
  ----------
  ADirectory
    User-selected native directory path.

  Returns
  -------
  string
    Absolute path without a redundant trailing delimiter, except when the path
    itself is a Unix, drive, or UNC root.

  Raises
  ------
  None
}
function NormalizedScanTarget(const ADirectory: string): string;
var
  RootValue: string;
begin
  Result := ExpandFileName(ADirectory);
  RootValue := IncludeTrailingPathDelimiter(ExtractFileDrive(Result));
  if (RootValue = '') or not SameFileName(Result, RootValue) then
    Result := ExcludeTrailingPathDelimiter(Result);
end;

{**
  Joins a string collection for compact, deterministic table presentation.

  Parameters
  ----------
  AValues
    Ordered values to render; nil is treated as an empty collection.

  Returns
  -------
  string
    Values separated by semicolon and space, or an empty string.

  Raises
  ------
  EOutOfMemory
    May propagate while constructing the result.
}
function JoinedValues(AValues: TStrings): string;
var
  I: Integer;
begin
  Result := '';
  if AValues = nil then
    Exit;
  for I := 0 to AValues.Count - 1 do
  begin
    if Result <> '' then
      Result := Result + '; ';
    Result := Result + AValues[I];
  end;
end;

{**
  Renders one component's privacy-safe OSV lookup state.

  Parameters
  ----------
  ATask
    Task containing the point-in-time lookup outcome.
  AComponent
    Component whose exact Package URL eligibility is evaluated locally.
  AMatchCount
    Number of retained advisory matches for that Package URL.

  Returns
  -------
  string
    A warning count, ``0 observed``, ``Incomplete``, ``Not queried``, or an
    empty string when no lookup was requested.

  Raises
  ------
  EOutOfMemory
    May propagate while canonicalizing a bounded Package URL.
*}
function KnownIssueCellText(ATask: TScanTask;
  AComponent: uModels.TComponent; AMatchCount: Integer): string;
var
  CanonicalPackageURL: string;
  RejectionReason: TOSVCandidateRejectionReason;
begin
  Result := '';
  CanonicalPackageURL := '';
  RejectionReason := Low(TOSVCandidateRejectionReason);
  if (ATask = nil) or (AComponent = nil) or
    not ATask.KnownIssueCheck.Requested then
    Exit;
  if AMatchCount > 0 then
    Exit(#$E2#$9A#$A0 + ' ' + IntToStr(AMatchCount));
  if not TryCanonicalOSVPackageURL(AComponent.PackageURL,
    CanonicalPackageURL, RejectionReason) or
    (CanonicalPackageURL = '') then
    Exit('Not queried');
  if ATask.KnownIssueCheck.OutcomeCode = 'ok' then
    Result := '0 observed'
  else
    Result := 'Incomplete';
end;

constructor TSBOMAnalyzerFrame.Create(TheOwner: Classes.TComponent);
begin
  inherited Create(TheOwner);
  InitializeFrame('', nil);
end;

constructor TSBOMAnalyzerFrame.CreateForDataDirectory(
  TheOwner: Classes.TComponent; const ADataDirectory: string);
begin
  inherited Create(TheOwner);
  InitializeFrame(ADataDirectory, nil);
end;

constructor TSBOMAnalyzerFrame.CreateWithHistoryService(
  TheOwner: Classes.TComponent; AHistoryService: TTaskHistoryService);
begin
  if AHistoryService = nil then
    raise EArgumentNilException.Create('AHistoryService must not be nil');
  inherited Create(TheOwner);
  InitializeFrame('', AHistoryService);
end;

procedure TSBOMAnalyzerFrame.InitializeFrame(const ADataDirectory: string;
  AHistoryService: TTaskHistoryService);
begin
  FSBOMMemo.Font.Pitch := fpFixed;
  {$IFDEF Windows}
  FSBOMMemo.Font.Name := 'Consolas';
  {$ELSE}
  {$IFDEF Darwin}
  FSBOMMemo.Font.Name := 'Menlo';
  {$ELSE}
  FSBOMMemo.Font.Name := 'Monospace';
  {$ENDIF}
  {$ENDIF}
  SetCompactFooter('Ready — drop a folder here or choose New Scan.');
  if AHistoryService = nil then
  begin
    FHistoryService := TTaskHistoryService.Create(ADataDirectory);
    FOwnsHistoryService := True;
    FHistoryService.OnChanged := @ServiceHistoryChanged;
  end
  else
  begin
    FHistoryService := AHistoryService;
    FOwnsHistoryService := False;
  end;
  FSettingsStore := TSettingsStore.Create(FHistoryService.DataDirectory);
  FComponentSortColumn := 0;
  FComponentSortAscending := True;
  FArtifactSortColumn := 0;
  FArtifactSortAscending := True;
  LoadState;
end;

destructor TSBOMAnalyzerFrame.Destroy;
begin
  FOnActivityChanged := nil;
  FOnCloseReady := nil;
  ClosePollTimer.Enabled := False;
  if not FClosePrepared then
    ForceShutdown;
  if FOwnsHistoryService and (FHistoryService <> nil) then
    FHistoryService.OnChanged := nil;
  FreeAndNil(FSettings);
  FreeAndNil(FSettingsStore);
  if FOwnsHistoryService then
    FreeAndNil(FHistoryService)
  else
    FHistoryService := nil;
  inherited Destroy;
end;

procedure TSBOMAnalyzerFrame.ServiceHistoryChanged(Sender: TObject;
  AKind: TTaskHistoryChangeKind; const ATaskID: string; ARevision: QWord);
begin
  if Sender = FHistoryService then
    HistoryChanged(AKind, ATaskID, ARevision);
end;

function TSBOMAnalyzerFrame.RequestActiveCancellation(
  AConfirm: Boolean): Boolean;
var
  Task: TScanTask;
begin
  Result := False;
  Task := FindTask(FActiveTaskID);
  if (FWorker = nil) or (Task = nil) or
    not (Task.Status in [tsPending, tsRunning]) then
    Exit;
  if FCancelRequested then
    Exit(True);
  if AConfirm and (MessageDlg(AppName, 'Cancel the running scan of "' +
    Task.TargetRootName + '"?', mtConfirmation, [mbYes, mbNo], 0) <> mrYes) then
    Exit;
  FCancelRequested := True;
  FWorker.Cancel;
  FCancelButton.Enabled := False;
  FProgressPath.Caption := 'Cancelling scan of ' + Task.TargetRootName +
    ' safely...';
  Result := True;
end;

procedure TSBOMAnalyzerFrame.AdoptWorkerResult;
var
  Task: TScanTask;
begin
  if (FWorker = nil) or (FWorker.ResultTask = nil) then
    Exit;
  Task := FindTask(FWorker.ResultTask.ID);
  if Task <> nil then
  begin
    Task.Assign(FWorker.ResultTask);
    UpdateTaskRow(Task);
  end;
end;

function TSBOMAnalyzerFrame.FinalizeFinishedWorker: Boolean;
begin
  Result := FWorker = nil;
  if Result or not FWorker.Finished then
    Exit;
  FWorker.OnProgress := nil;
  FWorker.OnComplete := nil;
  AdoptWorkerResult;
  SetActiveTaskID('');
  FCancelRequested := False;
  SaveHistory;
  if (FWorker.ResultTask <> nil) and
    (FindTask(FWorker.ResultTask.ID) <> nil) then
    try
      FHistoryService.NotifyTaskUpdated(FWorker.ResultTask.ID, False);
    except
      on E: Exception do
        ShowError('The completed scan could not be published: ' + E.Message);
    end;
  FreeAndNil(FWorker);
  Result := True;
end;

procedure TSBOMAnalyzerFrame.ForceShutdown;
begin
  FClosing := True;
  try
    if FWorker <> nil then
    begin
      FWorker.OnProgress := nil;
      FWorker.OnComplete := nil;
      FWorker.Cancel;
      if not FWorker.Finished then
        FWorker.WaitFor;
      AdoptWorkerResult;
    end;
    SetActiveTaskID('');
    if FHistoryService <> nil then
      SaveHistory;
    FreeAndNil(FWorker);
    FClosePrepared := True;
  except
    FreeAndNil(FWorker);
  end;
end;

function TSBOMAnalyzerFrame.GetScanActive: Boolean;
begin
  Result := FActiveTaskID <> '';
end;

procedure TSBOMAnalyzerFrame.SetActiveTaskID(const AValue: string);
var
  WasActive, IsActive: Boolean;
begin
  WasActive := GetScanActive;
  FActiveTaskID := AValue;
  IsActive := GetScanActive;
  if (WasActive <> IsActive) and Assigned(FOnActivityChanged) then
    FOnActivityChanged(Self, IsActive);
end;

procedure TSBOMAnalyzerFrame.SetActiveFooter;
begin
  StatusPanel.Height := 62;
  FProgressPath.Align := alTop;
  FProgressPath.Height := 20;
  FProgressStats.Visible := True;
  FProgressBar.Visible := True;
  FProgressBar.Position := 0;
  FProgressBar.Style := pbstMarquee;
  FExportFeedbackPanel.Visible := False;
  FLastExportPath := '';
end;

procedure TSBOMAnalyzerFrame.SetCompactFooter(const AText: string);
begin
  StatusPanel.Height := 28;
  FProgressBar.Style := pbstNormal;
  FProgressBar.Position := 0;
  FProgressBar.Visible := False;
  FProgressStats.Visible := False;
  FProgressPath.Align := alClient;
  FProgressPath.Caption := AText;
  FExportFeedbackPanel.Visible := False;
end;

procedure TSBOMAnalyzerFrame.ShowExportFeedback(const APath,
  ADescription: string);
begin
  FLastExportPath := ExpandFileName(APath);
  SetCompactFooter(ADescription + ': ' + FLastExportPath);
  FExportFeedbackPanel.Visible := True;
end;

procedure TSBOMAnalyzerFrame.LoadState;
var
  SettingsWarning: string;
begin
  FSettings := FSettingsStore.Load(SettingsWarning);
  { Refresh is intentionally task-local even if an older or hand-edited
    settings file contains it. }
  FSettings.RefreshRescanCache := False;
  FStartupWarning := FHistoryService.StartupWarning;
  if SettingsWarning <> '' then
  begin
    if FStartupWarning <> '' then
      FStartupWarning := FStartupWarning + LineEnding + LineEnding;
    FStartupWarning := FStartupWarning + SettingsWarning;
  end;
  RefreshTaskRows;
  if FTaskList.Items.Count > 0 then
    SelectTask(TScanTask(FTaskList.Items[0].Data));
  UpdateDetails;
  UpdateButtons;
end;

procedure TSBOMAnalyzerFrame.SaveHistory;
begin
  try
    FHistoryService.Save;
  except
    on E: Exception do
      ShowError('Task history could not be saved: ' + E.Message);
  end;
end;

procedure TSBOMAnalyzerFrame.RefreshTaskRows;
var
  I: Integer;
  Item: TListItem;
begin
  FTaskList.Items.BeginUpdate;
  try
    FTaskList.Items.Clear;
    for I := 0 to FHistoryService.TaskCount - 1 do
    begin
      if not TaskMatchesSearch(FHistoryService.TaskAt(I)) then
        Continue;
      Item := FTaskList.Items.Add;
      Item.Data := FHistoryService.TaskAt(I);
      UpdateTaskRow(FHistoryService.TaskAt(I));
    end;
  finally
    FTaskList.Items.EndUpdate;
  end;
  FEmptyLabel.Visible := FTaskList.Items.Count = 0;
  if FHistoryService.TaskCount = 0 then
    FEmptyLabel.Caption := 'No scans yet. Choose New Scan or drop a local ' +
      'folder onto this window.'
  else
    FEmptyLabel.Caption := 'No tasks match the current search.';
end;

function TSBOMAnalyzerFrame.FindTaskItem(ATask: TScanTask): TListItem;
var
  I: Integer;
begin
  for I := 0 to FTaskList.Items.Count - 1 do
    if FTaskList.Items[I].Data = Pointer(ATask) then
      Exit(FTaskList.Items[I]);
  Result := nil;
end;

procedure TSBOMAnalyzerFrame.UpdateTaskRow(ATask: TScanTask);
var
  Item: TListItem;
begin
  Item := FindTaskItem(ATask);
  if Item = nil then
    Exit;
  Item.Caption := LocalTimestampText(ATask.CreatedUTC);
  while Item.SubItems.Count < 5 do
    Item.SubItems.Add('');
  Item.SubItems[0] := ATask.TargetRootName;
  Item.SubItems[1] := TaskStatusDisplayText(ATask);
  Item.SubItems[2] := IntToStr(ATask.ArtifactsDetected);
  Item.SubItems[3] := IntToStr(ATask.ComponentsIdentified);
  Item.SubItems[4] := FormatDuration(ATask.DurationMS);
end;

procedure TSBOMAnalyzerFrame.SelectTask(ATask: TScanTask);
var
  Item: TListItem;
begin
  if ATask = nil then
  begin
    FSelectedTaskID := '';
    FTaskList.Selected := nil;
    FTaskList.ItemFocused := nil;
    UpdateDetails;
    Exit;
  end;
  Item := FindTaskItem(ATask);
  if Item <> nil then
  begin
    FSelectedTaskID := ATask.ID;
    FTaskList.Selected := Item;
    FTaskList.ItemFocused := Item;
    Item.MakeVisible(False);
    UpdateDetails;
  end;
end;

function TSBOMAnalyzerFrame.SelectedTask: TScanTask;
begin
  Result := FindTask(FSelectedTaskID);
end;

function TSBOMAnalyzerFrame.FindTask(const AID: string): TScanTask;
begin
  if (AID = '') or (FHistoryService = nil) then
    Result := nil
  else
    Result := FHistoryService.FindTaskByID(AID);
end;

function TSBOMAnalyzerFrame.TaskMatchesSearch(ATask: TScanTask): Boolean;
var
  Searchable: string;
begin
  if ATask = nil then
    Exit(False);
  Searchable := ATask.CreatedUTC + ' ' + LocalTimestampText(ATask.CreatedUTC) +
    ' ' + ATask.TargetRootName + ' ' + ATask.TargetDirectory + ' ' +
    TaskStatusToString(ATask.Status) + ' ' + TaskStatusDisplayText(ATask) +
    ' ' + ATask.ID;
  Result := ContainsTextValue(Searchable, Trim(FTaskSearch.Text));
end;

procedure TSBOMAnalyzerFrame.PopulateSummary(ATask: TScanTask);
var
  Item: TListItem;

  procedure AddRow(const AField, AValue: string);
  begin
    Item := FSummaryList.Items.Add;
    Item.Caption := AField;
    Item.SubItems.Add(AValue);
  end;

  procedure AddSection(const ACaption: string);
  begin
    AddRow('[' + ACaption + ']', '');
  end;

begin
  FSummaryList.Items.BeginUpdate;
  FSummaryNotes.Lines.BeginUpdate;
  try
    FSummaryList.Items.Clear;
    FSummaryNotes.Clear;
    if ATask = nil then
      Exit;

    AddSection('Result');
    AddRow('Status', TaskStatusDisplayText(ATask));
    AddRow('Duration', FormatDuration(ATask.DurationMS));
    AddRow('Warnings', IntToStr(ATask.Warnings.Count));
    AddRow('Errors', IntToStr(ATask.Errors.Count));
    AddRow('Files inspected', IntToStr(ATask.FilesInspected));
    AddRow('Bytes inspected', FormatByteSize(ATask.BytesInspected) + ' (' +
      IntToStr(ATask.BytesInspected) + ')');
    AddRow('Artifacts detected', IntToStr(ATask.ArtifactsDetected));
    AddRow('Artifacts parsed', IntToStr(ATask.ArtifactsParsed));
    AddRow('Artifacts partially parsed',
      IntToStr(ATask.ArtifactsPartiallyParsed));
    AddRow('Unsupported artifacts', IntToStr(ATask.UnsupportedArtifacts));
    AddRow('Failed artifacts', IntToStr(ATask.FailedArtifacts));
    AddRow('Components identified', IntToStr(ATask.ComponentsIdentified));

    AddSection('Input');
    AddRow('Target folder', ATask.TargetDirectory);
    AddRow('Created (UTC)', ATask.CreatedUTC);
    AddRow('Started (UTC)', ATask.StartedUTC);
    AddRow('Completed (UTC)', ATask.CompletedUTC);

    AddSection('Evidence and output');
    if ATask.InspectionTools.Count > 0 then
      AddRow('Binary evidence readers', JoinedValues(ATask.InspectionTools))
    else
      AddRow('Binary evidence readers',
        'No additional native metadata was applicable');
    AddRow('Generated SBOM', ATask.GeneratedSBOMPath);
    AddRow('Generated SBOM SHA-256', ATask.GeneratedSBOMSHA256);

    AddSection('Known issues');
    if ATask.KnownIssueCheck.Requested then
    begin
      AddRow('Source', 'OSV.dev');
      AddRow('Checked (UTC)', ATask.KnownIssueCheck.CheckedUTC);
      AddRow('Outcome', ATask.KnownIssueCheck.OutcomeCode);
      AddRow('Eligible Package URLs',
        IntToStr(ATask.KnownIssueCheck.EligibleCandidateCount));
      AddRow('Rejected Package URLs',
        IntToStr(ATask.KnownIssueCheck.RejectedCandidateCount));
      AddRow('Advisories', IntToStr(ATask.KnownIssueCheck.AdvisoryCount));
      AddRow('Package/advisory matches',
        IntToStr(ATask.KnownIssueCheck.MatchCount));
      if ATask.KnownIssueCheck.HTTPStatus > 0 then
        AddRow('HTTP status', IntToStr(ATask.KnownIssueCheck.HTTPStatus));
    end
    else
      AddRow('Check', 'Not requested');

    AddSection('Settings');
    AddRow('Scan settings', ATask.Settings.AsSummary);
    if Trim(ATask.Settings.SBOMAuthorOrganization) <> '' then
      AddRow('SBOM author organization',
        ATask.Settings.SBOMAuthorOrganization);
    if Trim(ATask.Settings.SBOMAuthorEmail) <> '' then
      AddRow('SBOM author email', ATask.Settings.SBOMAuthorEmail);

    FSummaryNotes.Lines.Add('Completeness notice');
    FSummaryNotes.Lines.Add('Results use bounded internal static inspection. ' +
      'Direct linked-library declarations may be identified, but ' +
      'runtime-loaded or undeclared dependencies can still be missed. The ' +
      'inventory is not a comprehensive vulnerability or license-compliance ' +
      'assessment.');
    if ATask.KnownIssueCheck.Requested then
    begin
      FSummaryNotes.Lines.Add('');
      FSummaryNotes.Lines.Add('Known-issue notice');
      FSummaryNotes.Lines.Add('OSV.dev results are a point-in-time advisory ' +
        'lookup over eligible exact package coordinates. No finding is not ' +
        'a clean bill of health. The inventory SBOM itself remains offline ' +
        'evidence and contains no vulnerability data.');
    end;
    if ATask.FilesInspected = 0 then
    begin
      FSummaryNotes.Lines.Add('');
      FSummaryNotes.Lines.Add('Caution: No regular files were inspected. ' +
        'Review the selected folder, permissions, symbolic-link policy, and ' +
        'ignore patterns before relying on this result.');
    end;
  finally
    FSummaryNotes.Lines.EndUpdate;
    FSummaryList.Items.EndUpdate;
  end;
end;

procedure TSBOMAnalyzerFrame.PopulateComponentFilters(ATask: TScanTask);
var
  Values: TStringList;
  I: Integer;
  PreviousValue: string;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    for I := 0 to ATask.Components.Count - 1 do
      if uModels.TComponent(ATask.Components[I]).Ecosystem <> '' then
        Values.Add(uModels.TComponent(ATask.Components[I]).Ecosystem);
    PreviousValue := FComponentEcosystem.Text;
    FComponentEcosystem.Items.BeginUpdate;
    try
      FComponentEcosystem.Items.Clear;
      FComponentEcosystem.Items.Add('All ecosystems');
      FComponentEcosystem.Items.AddStrings(Values);
      FComponentEcosystem.ItemIndex := FComponentEcosystem.Items.IndexOf(PreviousValue);
      if FComponentEcosystem.ItemIndex < 0 then
        FComponentEcosystem.ItemIndex := 0;
    finally
      FComponentEcosystem.Items.EndUpdate;
    end;
    PreviousValue := FComponentStatus.Text;
    FComponentStatus.Items.Text := 'All statuses' + LineEnding + 'parsed' +
      LineEnding + 'partially parsed' + LineEnding +
      'detected but unsupported' + LineEnding + 'failed';
    FComponentStatus.ItemIndex := FComponentStatus.Items.IndexOf(PreviousValue);
    if FComponentStatus.ItemIndex < 0 then
      FComponentStatus.ItemIndex := 0;
  finally
    Values.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.PopulateArtifactFilters(ATask: TScanTask);
var
  Values: TStringList;
  I: Integer;
  PreviousValue: string;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    for I := 0 to ATask.Artifacts.Count - 1 do
      Values.Add(TArtifact(ATask.Artifacts[I]).ArtifactType);
    PreviousValue := FArtifactType.Text;
    FArtifactType.Items.BeginUpdate;
    try
      FArtifactType.Items.Clear;
      FArtifactType.Items.Add('All artifact types');
      FArtifactType.Items.AddStrings(Values);
      FArtifactType.ItemIndex := FArtifactType.Items.IndexOf(PreviousValue);
      if FArtifactType.ItemIndex < 0 then
        FArtifactType.ItemIndex := 0;
    finally
      FArtifactType.Items.EndUpdate;
    end;
    PreviousValue := FArtifactStatus.Text;
    FArtifactStatus.Items.Text := 'All statuses' + LineEnding + 'parsed' +
      LineEnding + 'partially parsed' + LineEnding +
      'detected but unsupported' + LineEnding + 'failed';
    FArtifactStatus.ItemIndex := FArtifactStatus.Items.IndexOf(PreviousValue);
    if FArtifactStatus.ItemIndex < 0 then
      FArtifactStatus.ItemIndex := 0;
  finally
    Values.Free;
  end;
end;

function TSBOMAnalyzerFrame.ComponentArtifactStatus(ATask: TScanTask;
  AComponent: uModels.TComponent): string;
var
  I: Integer;
  Artifact: TArtifact;
begin
  for I := 0 to ATask.Artifacts.Count - 1 do
  begin
    Artifact := TArtifact(ATask.Artifacts[I]);
    if Artifact.RelativePath = AComponent.SourceArtifact then
      Exit(ArtifactStatusToString(Artifact.Status));
  end;
  Result := 'parsed';
end;

procedure TSBOMAnalyzerFrame.PopulateComponents(ATask: TScanTask);
var
  IssueCounts, Sorted: TStringList;
  I, IssueIndex, StartAt, EndAt: Integer;
  Component: uModels.TComponent;
  KnownIssueValue, LicenseValue, PublisherValue, SearchValue, StatusValue,
    SortValue: string;
  Item: TListItem;

  function KnownIssueCount(const APackageURL: string): Integer;
  var
    IndexValue: Integer;
  begin
    Result := 0;
    if not ATask.KnownIssueCheck.Requested then
      Exit;
    IndexValue := IssueCounts.IndexOf(APackageURL);
    if IndexValue >= 0 then
      Result := PtrInt(IssueCounts.Objects[IndexValue]);
  end;

begin
  FComponentList.Items.BeginUpdate;
  Sorted := TStringList.Create;
  IssueCounts := TStringList.Create;
  try
    FComponentList.Items.Clear;
    if ATask = nil then
    begin
      ComponentFiltersPanel.Visible := False;
      FComponentList.Visible := False;
      FComponentEmptyLabel.Visible := False;
      Exit;
    end;
    Sorted.Sorted := True;
    Sorted.Duplicates := dupAccept;
    Sorted.CaseSensitive := True;
    Sorted.UseLocale := False;
    IssueCounts.Sorted := True;
    IssueCounts.Duplicates := dupError;
    IssueCounts.CaseSensitive := True;
    IssueCounts.UseLocale := False;
    if ATask.KnownIssueCheck.Requested then
      for I := 0 to ATask.KnownIssueCheck.MatchCount - 1 do
      begin
        IssueIndex := IssueCounts.IndexOf(
          ATask.KnownIssueCheck.Matches[I].PackageURL);
        if IssueIndex < 0 then
          IssueCounts.AddObject(
            ATask.KnownIssueCheck.Matches[I].PackageURL, TObject(PtrInt(1)))
        else
          IssueCounts.Objects[IssueIndex] := TObject(
            PtrInt(IssueCounts.Objects[IssueIndex]) + 1);
      end;
    SearchValue := Trim(FComponentSearch.Text);
    for I := 0 to ATask.Components.Count - 1 do
    begin
      Component := uModels.TComponent(ATask.Components[I]);
      StatusValue := ComponentArtifactStatus(ATask, Component);
      LicenseValue := JoinedValues(Component.DeclaredLicenses);
      PublisherValue := JoinedValues(Component.DeclaredPublishers);
      KnownIssueValue := KnownIssueCellText(ATask, Component,
        KnownIssueCount(Component.PackageURL));
      if (FComponentEcosystem.ItemIndex > 0) and
        not SameText(FComponentEcosystem.Text, Component.Ecosystem) then
        Continue;
      if (FComponentStatus.ItemIndex > 0) and
        not SameText(FComponentStatus.Text, StatusValue) then
        Continue;
      if not ContainsTextValue(Component.Name + ' ' + Component.Version + ' ' +
        Component.Ecosystem + ' ' + Component.ComponentType + ' ' +
        StatusValue + ' ' + KnownIssueValue + ' ' + LicenseValue + ' ' +
        PublisherValue + ' ' + Component.DependencyScope + ' ' +
        Component.SourceArtifact,
        SearchValue) then
        Continue;
      case FComponentSortColumn of
        1: SortValue := Component.Version;
        2: SortValue := Component.Ecosystem;
        3: SortValue := Component.ComponentType;
        4: SortValue := StatusValue;
        5: SortValue := Format('%.10d',
          [KnownIssueCount(Component.PackageURL)]);
        6: SortValue := LicenseValue;
        7: SortValue := PublisherValue;
        8: SortValue := Component.DependencyScope;
        9: SortValue := Component.SourceArtifact;
      else
        SortValue := Component.Name;
      end;
      Sorted.AddObject(LowerCase(SortValue) + #1 + Format('%.10d', [I]),
        Component);
    end;
    if FComponentSortAscending then
    begin
      StartAt := 0;
      EndAt := Sorted.Count - 1;
    end
    else
    begin
      StartAt := Sorted.Count - 1;
      EndAt := 0;
    end;
    I := StartAt;
    while (Sorted.Count > 0) and
      ((FComponentSortAscending and (I <= EndAt)) or
      ((not FComponentSortAscending) and (I >= EndAt))) do
    begin
      Component := uModels.TComponent(Sorted.Objects[I]);
      Item := FComponentList.Items.Add;
      Item.Data := Component;
      Item.Caption := Component.Name;
      Item.SubItems.Add(Component.Version);
      Item.SubItems.Add(Component.Ecosystem);
      Item.SubItems.Add(Component.ComponentType);
      Item.SubItems.Add(StatusDisplayText(ComponentArtifactStatus(ATask,
        Component)));
      Item.SubItems.Add(KnownIssueCellText(ATask, Component,
        KnownIssueCount(Component.PackageURL)));
      Item.SubItems.Add(JoinedValues(Component.DeclaredLicenses));
      Item.SubItems.Add(JoinedValues(Component.DeclaredPublishers));
      Item.SubItems.Add(Component.DependencyScope);
      Item.SubItems.Add(Component.SourceArtifact);
      if FComponentSortAscending then Inc(I) else Dec(I);
    end;
  finally
    IssueCounts.Free;
    Sorted.Free;
    FComponentList.Items.EndUpdate;
  end;
  ComponentFiltersPanel.Visible := ATask.Components.Count > 0;
  FComponentList.Visible := FComponentList.Items.Count > 0;
  FComponentEmptyLabel.Visible := FComponentList.Items.Count = 0;
  if ATask.Components.Count = 0 then
    FComponentEmptyLabel.Caption :=
      'No components were identified for this scan.'
  else
    FComponentEmptyLabel.Caption :=
      'No components match the current filters.';
end;

procedure TSBOMAnalyzerFrame.PopulateArtifacts(ATask: TScanTask);
var
  Sorted: TStringList;
  I, StartAt, EndAt: Integer;
  Artifact: TArtifact;
  SearchValue, StatusValue, SortValue: string;
  Item: TListItem;
begin
  FArtifactList.Items.BeginUpdate;
  Sorted := TStringList.Create;
  try
    FArtifactList.Items.Clear;
    if ATask = nil then
    begin
      ArtifactFiltersPanel.Visible := False;
      FArtifactList.Visible := False;
      FArtifactEmptyLabel.Visible := False;
      Exit;
    end;
    Sorted.Sorted := True;
    Sorted.Duplicates := dupAccept;
    SearchValue := Trim(FArtifactSearch.Text);
    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      StatusValue := ArtifactStatusToString(Artifact.Status);
      if (FArtifactType.ItemIndex > 0) and
        not SameText(FArtifactType.Text, Artifact.ArtifactType) then
        Continue;
      if (FArtifactStatus.ItemIndex > 0) and
        not SameText(FArtifactStatus.Text, StatusValue) then
        Continue;
      if not ContainsTextValue(Artifact.RelativePath + ' ' +
        Artifact.ArtifactType + ' ' + Artifact.Ecosystem + ' ' + StatusValue +
        ' ' + Artifact.MessageText, SearchValue) then
        Continue;
      case FArtifactSortColumn of
        1: SortValue := Artifact.ArtifactType;
        2: SortValue := StatusValue;
        3: SortValue := Artifact.MessageText;
        4: SortValue := Format('%.20d', [Artifact.FileSize]);
        5: SortValue := Artifact.Ecosystem;
        6: SortValue := Artifact.SHA256;
      else
        SortValue := Artifact.RelativePath;
      end;
      Sorted.AddObject(LowerCase(SortValue) + #1 + Format('%.10d', [I]),
        Artifact);
    end;
    if FArtifactSortAscending then
    begin
      StartAt := 0;
      EndAt := Sorted.Count - 1;
    end
    else
    begin
      StartAt := Sorted.Count - 1;
      EndAt := 0;
    end;
    I := StartAt;
    while (Sorted.Count > 0) and
      ((FArtifactSortAscending and (I <= EndAt)) or
      ((not FArtifactSortAscending) and (I >= EndAt))) do
    begin
      Artifact := TArtifact(Sorted.Objects[I]);
      Item := FArtifactList.Items.Add;
      Item.Data := Artifact;
      Item.Caption := Artifact.RelativePath;
      Item.SubItems.Add(Artifact.ArtifactType);
      Item.SubItems.Add(ArtifactStatusDisplayText(Artifact.Status));
      Item.SubItems.Add(Artifact.MessageText);
      Item.SubItems.Add(FormatByteSize(Artifact.FileSize));
      Item.SubItems.Add(Artifact.Ecosystem);
      Item.SubItems.Add(ShortDigest(Artifact.SHA256));
      if FArtifactSortAscending then Inc(I) else Dec(I);
    end;
  finally
    Sorted.Free;
    FArtifactList.Items.EndUpdate;
  end;
  ArtifactFiltersPanel.Visible := ATask.Artifacts.Count > 0;
  FArtifactList.Visible := FArtifactList.Items.Count > 0;
  FArtifactEmptyLabel.Visible := FArtifactList.Items.Count = 0;
  if ATask.Artifacts.Count = 0 then
    FArtifactEmptyLabel.Caption := 'No artifacts were detected for this scan.'
  else
    FArtifactEmptyLabel.Caption := 'No artifacts match the current filters.';
end;

procedure TSBOMAnalyzerFrame.PopulateSBOM(ATask: TScanTask);
begin
  FSBOMMemo.Clear;
  if (ATask = nil) or (ATask.GeneratedSBOMPath = '') then
  begin
    FSBOMMemo.Lines.Add('No CycloneDX JSON is available for this task.');
    Exit;
  end;
  try
    if FileExists(ATask.GeneratedSBOMPath) then
      FSBOMMemo.Lines.LoadFromFile(ATask.GeneratedSBOMPath)
    else
      FSBOMMemo.Lines.Add('The generated SBOM file is no longer present: ' +
        ATask.GeneratedSBOMPath);
  except
    on E: Exception do
      FSBOMMemo.Lines.Add('Unable to load the generated SBOM: ' + E.Message);
  end;
end;

procedure TSBOMAnalyzerFrame.PopulateMessages(ATask: TScanTask);
const
  MaximumDisplayedKnownIssueMatches = 500;
var
  ArtifactNoteCount, I: Integer;
  Artifact: TArtifact;
  FirstSection: Boolean;

  procedure AddSection(const ACaption: string);
  begin
    if not FirstSection then
      FMessagesMemo.Lines.Add('');
    FMessagesMemo.Lines.Add(ACaption);
    FirstSection := False;
  end;

begin
  FMessagesMemo.Lines.BeginUpdate;
  try
    FMessagesMemo.Clear;
    if ATask = nil then
      Exit;
    FirstSection := True;
    AddSection('Completeness notice');
    FMessagesMemo.Lines.Add('Bounded internal static inspection can identify ' +
      'direct declarations, but ' +
      'runtime-loaded or undeclared dependencies can still be missed.');
    if ATask.KnownIssueCheck.Requested then
    begin
      AddSection('Known issues — OSV.dev (' +
        IntToStr(ATask.KnownIssueCheck.MatchCount) + ' matches, ' +
        IntToStr(ATask.KnownIssueCheck.AdvisoryCount) + ' advisories)');
      FMessagesMemo.Lines.Add('Outcome: ' +
        ATask.KnownIssueCheck.OutcomeCode);
      FMessagesMemo.Lines.Add('Checked (UTC): ' +
        ATask.KnownIssueCheck.CheckedUTC);
      if ATask.KnownIssueCheck.Diagnostic <> '' then
        FMessagesMemo.Lines.Add('Diagnostic: ' +
          ATask.KnownIssueCheck.Diagnostic);
      FMessagesMemo.Lines.Add('No finding is not a clean bill of health. ' +
        'Results are point-in-time OSV.dev advisory matches for eligible ' +
        'exact package coordinates.');
      for I := 0 to ATask.KnownIssueCheck.MatchCount - 1 do
      begin
        if I >= MaximumDisplayedKnownIssueMatches then
        begin
          FMessagesMemo.Lines.Add('- ' + IntToStr(
            ATask.KnownIssueCheck.MatchCount - I) +
            ' additional matches are retained in task history but omitted ' +
            'from this view.');
          Break;
        end;
        FMessagesMemo.Lines.Add('- ' +
          ATask.KnownIssueCheck.Matches[I].AdvisoryID + ' — ' +
          ATask.KnownIssueCheck.Matches[I].PackageURL + ' (modified ' +
          ATask.KnownIssueCheck.Matches[I].Modified + ') — ' +
          'https://osv.dev/vulnerability/' +
          ATask.KnownIssueCheck.Matches[I].AdvisoryID);
      end;
    end;
    if ATask.Warnings.Count > 0 then
    begin
      AddSection('Warnings (' + IntToStr(ATask.Warnings.Count) + ')');
      for I := 0 to ATask.Warnings.Count - 1 do
        FMessagesMemo.Lines.Add('- ' + ATask.Warnings[I]);
    end;
    if ATask.Errors.Count > 0 then
    begin
      AddSection('Errors (' + IntToStr(ATask.Errors.Count) + ')');
      for I := 0 to ATask.Errors.Count - 1 do
        FMessagesMemo.Lines.Add('- ' + ATask.Errors[I]);
    end;
    ArtifactNoteCount := 0;
    for I := 0 to ATask.Artifacts.Count - 1 do
      if Trim(TArtifact(ATask.Artifacts[I]).MessageText) <> '' then
        Inc(ArtifactNoteCount);
    if ArtifactNoteCount > 0 then
      AddSection('Artifact notes (' + IntToStr(ArtifactNoteCount) + ')');
    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      if Trim(Artifact.MessageText) <> '' then
        FMessagesMemo.Lines.Add(Artifact.RelativePath + ': ' +
          Artifact.MessageText);
    end;
  finally
    FMessagesMemo.Lines.EndUpdate;
  end;
end;

procedure TSBOMAnalyzerFrame.UpdateDetails;
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  FDetailEmptyLabel.Visible := Task = nil;
  FPages.Visible := Task <> nil;
  if Task = nil then
  begin
    SummaryPage.Caption := 'Summary';
    ComponentsPage.Caption := 'Components';
    ArtifactsPage.Caption := 'Artifacts';
    MessagesPage.Caption := 'Messages';
  end
  else
  begin
    SummaryPage.Caption := 'Summary';
    ComponentsPage.Caption := 'Components (' +
      IntToStr(Task.Components.Count) + ')';
    ArtifactsPage.Caption := 'Artifacts (' +
      IntToStr(Task.Artifacts.Count) + ')';
    MessagesPage.Caption := 'Messages (' +
      IntToStr(TaskMessageCount(Task)) + ')';
  end;
  FUpdatingDetails := True;
  try
    PopulateSummary(Task);
    if Task <> nil then
    begin
      PopulateComponentFilters(Task);
      PopulateArtifactFilters(Task);
    end;
    PopulateComponents(Task);
    PopulateArtifacts(Task);
    PopulateSBOM(Task);
    PopulateMessages(Task);
  finally
    FUpdatingDetails := False;
  end;
  UpdateButtons;
end;

procedure TSBOMAnalyzerFrame.UpdateButtons;
var
  Task, ActiveTask: TScanTask;
  IsScanActive: Boolean;
begin
  Task := SelectedTask;
  ActiveTask := FindTask(FActiveTaskID);
  IsScanActive := FActiveTaskID <> '';
  FNewButton.Enabled := not IsScanActive;
  FRefreshButton.Enabled := not IsScanActive;
  FRescanButton.Enabled := (not IsScanActive) and (Task <> nil) and
    DirectoryExists(Task.TargetDirectory);
  FCancelButton.Enabled := IsScanActive and (ActiveTask <> nil) and
    (ActiveTask.Status in [tsPending, tsRunning]) and not FCancelRequested;
  FExportButton.Enabled := (Task <> nil) and
    (Task.Status = tsCompleted) and FileExists(Task.GeneratedSBOMPath);
  FExportDatabaseButton.Enabled := (not IsScanActive) and
    (FHistoryService.TaskCount > 0) and
    DirectoryExists(FHistoryService.DataDirectory);
end;

procedure TSBOMAnalyzerFrame.FreeFinishedWorker;
begin
  FinalizeFinishedWorker;
end;

procedure TSBOMAnalyzerFrame.StartScan(const ADirectory: string;
  ASettings: TScanSettings; ACheckKnownIssues: Boolean);
var
  Task: TScanTask;
  Target: string;
begin
  FreeFinishedWorker;
  if FWorker <> nil then
    Exit;
  Target := NormalizedScanTarget(ADirectory);
  if not DirectoryExists(Target) then
  begin
    ShowError('The selected folder does not exist: ' + Target);
    Exit;
  end;
  Task := TScanTask.Create;
  Task.TargetDirectory := Target;
  Task.TargetRootName := ExtractFileName(Target);
  if Task.TargetRootName = '' then
    Task.TargetRootName := Target;
  Task.Settings.Assign(ASettings);
  Task.Status := tsPending;
  FTaskSearch.Clear;
  FHistoryService.AddTask(Task, 0);
  SelectTask(Task);
  SaveHistory;
  Task.Status := tsRunning;
  FCancelRequested := False;
  SetActiveTaskID(Task.ID);
  UpdateTaskRow(Task);
  SetActiveFooter;
  FProgressPath.Caption := 'Starting scan of ' + Task.TargetRootName + '...';
  FProgressStats.Caption := 'Preparing worker thread';
  FWorker := TScanWorker.Create(Task, FHistoryService.DataDirectory,
    ACheckKnownIssues);
  FWorker.OnProgress := @WorkerProgress;
  FWorker.OnComplete := @WorkerComplete;
  FWorker.Start;
  SaveHistory;
  try
    FHistoryService.NotifyTaskUpdated(Task.ID, False);
  except
    on E: Exception do
      ShowError('The running scan could not be published: ' + E.Message);
  end;
  UpdateButtons;
end;

procedure TSBOMAnalyzerFrame.ConfigureAndStartScan(const ADirectory: string);
var
  CheckKnownIssues: Boolean;
  WorkingSettings, PersistedSettings: TScanSettings;
  Target: string;
begin
  if FActiveTaskID <> '' then
    Exit;
  Target := NormalizedScanTarget(ADirectory);
  WorkingSettings := FSettings.Clone;
  PersistedSettings := nil;
  try
    if not WorkingSettings.RememberPrivacyChoices then
    begin
      WorkingSettings.IncludeAbsolutePaths := False;
      WorkingSettings.AllowOutsideRoot := False;
    end;
    if not TScanSettingsDialog.Execute(WorkingSettings, Target,
      CheckKnownIssues) then
      Exit;
    PersistedSettings := WorkingSettings.Clone;
    { A full-cache refresh is a deliberate one-scan override. Cache reuse may
      persist, but a later scan must never inherit the refresh request. }
    PersistedSettings.RefreshRescanCache := False;
    if not PersistedSettings.RememberPrivacyChoices then
    begin
      PersistedSettings.IncludeAbsolutePaths := False;
      PersistedSettings.AllowOutsideRoot := False;
    end;
    FSettings.Assign(PersistedSettings);
    try
      FSettingsStore.Save(FSettings);
    except
      on E: Exception do
        ShowError('Scan settings could not be saved: ' + E.Message);
    end;
    StartScan(Target, WorkingSettings, CheckKnownIssues);
  finally
    PersistedSettings.Free;
    WorkingSettings.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.ShowError(const AMessage: string);
begin
  if not FClosing then
    MessageDlg(AppName, AMessage, mtError, [mbOK], 0);
end;

procedure TSBOMAnalyzerFrame.ShowPendingWarnings;
begin
  if (not FClosing) and (FStartupWarning <> '') then
  begin
    MessageDlg(AppName, FStartupWarning, mtWarning, [mbOK], 0);
    FStartupWarning := '';
  end;
end;

function TSBOMAnalyzerFrame.PrepareForClose: Boolean;
begin
  if FClosePrepared then
    Exit(True);
  Result := False;
  if not FinalizeFinishedWorker then
    Exit;
  FClosing := True;
  try
    ClosePollTimer.Enabled := False;
    SetActiveTaskID('');
    if FHistoryService <> nil then
      SaveHistory;
    FClosePrepared := True;
    Result := True;
  except
    FClosing := False;
    Result := False;
  end;
end;

function TSBOMAnalyzerFrame.RequestClose: Boolean;
var
  Task: TScanTask;
  TargetName: string;
begin
  if FClosePrepared then
    Exit(True);
  if FinalizeFinishedWorker then
    Exit(PrepareForClose);
  Result := False;
  if FClosePending then
    Exit;
  Task := FindTask(FActiveTaskID);
  if Task <> nil then
    TargetName := Task.TargetRootName
  else
    TargetName := 'the selected folder';
  if MessageDlg(AppName, 'A scan of "' + TargetName +
    '" is running. Cancel it and quit?', mtConfirmation,
    [mbYes, mbNo], 0) <> mrYes then
    Exit;
  if FinalizeFinishedWorker then
    Exit(PrepareForClose);
  FClosePending := True;
  if (FActiveTaskID <> '') and not RequestActiveCancellation(False) then
  begin
    FClosePending := False;
    Exit;
  end;
  ClosePollTimer.Enabled := True;
end;

procedure TSBOMAnalyzerFrame.ClosePollTimerTick(Sender: TObject);
begin
  if not FClosePending then
  begin
    ClosePollTimer.Enabled := False;
    Exit;
  end;
  if not FinalizeFinishedWorker then
    Exit;
  ClosePollTimer.Enabled := False;
  if PrepareForClose and Assigned(FOnCloseReady) then
    FOnCloseReady(Self);
end;

procedure TSBOMAnalyzerFrame.HandleDroppedFiles(
  const AFileNames: array of string);
var
  I: Integer;
begin
  if FActiveTaskID <> '' then
  begin
    MessageDlg(AppName, 'A scan is already running. Wait for it to finish or ' +
      'cancel it before dropping another folder.', mtInformation, [mbOK], 0);
    Exit;
  end;
  for I := Low(AFileNames) to High(AFileNames) do
    if DirectoryExists(AFileNames[I]) then
    begin
      ConfigureAndStartScan(AFileNames[I]);
      Exit;
    end;
  ShowError('Drop a local folder to start a scan.');
end;

function TSBOMAnalyzerFrame.HandleShortcut(var AKey: Word;
  AShift: TShiftState): Boolean;
begin
  Result := True;
  if PrimaryShortcut(AShift) and (AKey = VK_N) then
  begin
    NewScanClicked(Self);
    AKey := 0;
  end
  else if PrimaryShortcut(AShift) and (AKey = VK_E) then
  begin
    ExportClicked(Self);
    AKey := 0;
  end
  else if AKey = VK_F5 then
  begin
    RefreshClicked(Self);
    AKey := 0;
  end
  else if AKey = VK_ESCAPE then
  begin
    if (Screen.ActiveControl is TCustomEdit) or
      (Screen.ActiveControl is TCustomComboBox) then
      Result := False
    else if RequestActiveCancellation(True) then
      AKey := 0
    else
      Result := False;
  end
  else
    Result := False;
end;

procedure TSBOMAnalyzerFrame.Activate;
begin
  if FClosing then
    Exit;
  UpdateButtons;
  if FTaskList.CanFocus then
    FTaskList.SetFocus;
end;

procedure TSBOMAnalyzerFrame.Deactivate;
begin
  { Feature state intentionally remains live while another page is active. }
end;

procedure TSBOMAnalyzerFrame.HistoryChanged(AKind: TTaskHistoryChangeKind;
  const ATaskID: string; ARevision: QWord);
var
  Task: TScanTask;
  WantedID: string;
begin
  if (FHistoryService = nil) or (ARevision > FHistoryService.Revision) then
    Exit;
  WantedID := FSelectedTaskID;
  if (AKind = thcRemoved) and (WantedID = ATaskID) then
    WantedID := '';
  RefreshTaskRows;
  Task := FindTask(WantedID);
  if (Task <> nil) and (FindTaskItem(Task) <> nil) then
    SelectTask(Task)
  else
    SelectTask(nil);
  UpdateButtons;
end;

procedure TSBOMAnalyzerFrame.NewScanClicked(Sender: TObject);
var
  Dialog: TPurpleRaySelectDirectoryDialog;
begin
  if FActiveTaskID <> '' then
  begin
    MessageDlg(AppName, 'A scan is already running. Wait for it to finish or ' +
      'cancel it before starting another scan.', mtInformation, [mbOK], 0);
    Exit;
  end;
  Dialog := TPurpleRaySelectDirectoryDialog.Create(Self);
  try
    Dialog.Title := 'Select a folder to scan';
    if Dialog.Execute then
      ConfigureAndStartScan(Dialog.FileName);
  finally
    Dialog.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.CancelClicked(Sender: TObject);
begin
  RequestActiveCancellation(True);
end;

procedure TSBOMAnalyzerFrame.RescanClicked(Sender: TObject);
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  if (FActiveTaskID = '') and (Task <> nil) then
    ConfigureAndStartScan(Task.TargetDirectory);
end;

procedure TSBOMAnalyzerFrame.RefreshClicked(Sender: TObject);
var
  SelectedID: string;
  Task: TScanTask;
  WarningText: string;
begin
  if FActiveTaskID <> '' then
    Exit;
  SelectedID := FSelectedTaskID;
  if not FHistoryService.Reload(WarningText) then
    ShowError(WarningText)
  else if WarningText <> '' then
    MessageDlg(AppName, WarningText, mtWarning, [mbOK], 0);
  Task := FindTask(SelectedID);
  if (Task <> nil) and (FindTaskItem(Task) <> nil) then
    SelectTask(Task)
  else if FTaskList.Items.Count > 0 then
    SelectTask(TScanTask(FTaskList.Items[0].Data))
  else
    SelectTask(nil);
  UpdateDetails;
end;

procedure TSBOMAnalyzerFrame.ExportClicked(Sender: TObject);
var
  MenuPoint: TPoint;
begin
  if not FExportButton.Enabled then
    Exit;
  MenuPoint := FExportButton.ClientToScreen(Point(0, FExportButton.Height));
  FExportMenu.PopUp(MenuPoint.X, MenuPoint.Y);
end;

procedure TSBOMAnalyzerFrame.ExportSBOMClicked(Sender: TObject);
var
  Task: TScanTask;
  Dialog: TPurpleRaySaveDialog;
begin
  Task := SelectedTask;
  if (Task = nil) or not FileExists(Task.GeneratedSBOMPath) then
    Exit;
  Dialog := TPurpleRaySaveDialog.Create(Self);
  try
    Dialog.Title := 'Export CycloneDX SBOM';
    Dialog.Filter := 'CycloneDX JSON (*.cdx.json)|*.cdx.json|JSON files (*.json)|*.json|All files|*';
    Dialog.DefaultExt := 'cdx.json';
    Dialog.FileName := TaskSBOMExportFileName(Task);
    Dialog.Options := Dialog.Options + [ofOverwritePrompt];
    if Dialog.Execute then
    begin
      try
        if not SameFileName(ExpandFileName(Dialog.FileName),
          ExpandFileName(Task.GeneratedSBOMPath)) then
          CopyFileContents(Task.GeneratedSBOMPath, Dialog.FileName);
        ShowExportFeedback(Dialog.FileName, 'SBOM exported');
      except
        on E: Exception do
          ShowError('The SBOM could not be exported: ' + E.Message);
      end;
    end;
  finally
    Dialog.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.ExportBSIReadinessClicked(Sender: TObject);
var
  Dialog: TPurpleRaySaveDialog;
  ManagedBytes: RawByteString;
  Report: UTF8String;
  SourceStream: TFileStream;
  Summary: TBSIReadinessSummary;
  SuggestedName: string;
  Task: TScanTask;
begin
  Task := SelectedTask;
  if (Task = nil) or (Task.Status <> tsCompleted) or
    not FileExists(Task.GeneratedSBOMPath) then
    Exit;
  SourceStream := nil;
  Dialog := TPurpleRaySaveDialog.Create(Self);
  try
    try
      try
        SourceStream := TFileStream.Create(Task.GeneratedSBOMPath,
          fmOpenRead or fmShareDenyWrite);
        ManagedBytes := ReadBoundedRawBytes(SourceStream,
          DefaultMaximumJSONBytes);
      finally
        SourceStream.Free;
      end;
      Report := GenerateBSIReadinessReport(ManagedBytes,
        Task.GeneratedSBOMSHA256, Task.ID, Summary);
      SuggestedName := ChangeFileExt(ChangeFileExt(
        TaskSBOMExportFileName(Task), ''), '') +
        BSIReadinessSuggestedExtension;
      Dialog.Title := 'Export BSI TR-03183-2 v2.1.0 readiness report';
      Dialog.Filter := 'JSON files (*.json)|*.json|All files|*';
      Dialog.DefaultExt := 'json';
      Dialog.FileName := SuggestedName;
      Dialog.Options := Dialog.Options + [ofOverwritePrompt];
      if Dialog.Execute then
      begin
        if SameFileName(ExpandFileName(Dialog.FileName),
          ExpandFileName(Task.GeneratedSBOMPath)) then
          raise EInOutError.Create(
            'The readiness report cannot replace the managed SBOM');
        WriteAtomicUTF8(Dialog.FileName, Report, False);
        ShowExportFeedback(Dialog.FileName,
          'BSI readiness report exported (' +
          BSIReadinessStatusToString(Summary.Status) + ')');
      end;
    except
      on E: Exception do
        ShowError('The BSI readiness report could not be exported: ' +
          E.Message);
    end;
  finally
    Dialog.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.ExportDatabaseClicked(Sender: TObject);
var
  Dialog: TPurpleRaySaveDialog;
begin
  if (FActiveTaskID <> '') or (FHistoryService.TaskCount = 0) then
    Exit;
  Dialog := TPurpleRaySaveDialog.Create(Self);
  try
    Dialog.Title := 'Back up all tasks and results';
    Dialog.Filter := 'ZIP archives (*.zip)|*.zip|All files|*';
    Dialog.DefaultExt := 'zip';
    Dialog.FileName := DatabaseArchiveFileName;
    Dialog.Options := Dialog.Options + [ofOverwritePrompt];
    if Dialog.Execute then
    begin
      try
        ExportDatabaseArchive(FHistoryService.DataDirectory, Dialog.FileName);
        ShowExportFeedback(Dialog.FileName, 'Data backup created');
      except
        on E: Exception do
          ShowError('The task database could not be exported: ' + E.Message);
      end;
    end;
  finally
    Dialog.Free;
  end;
end;

procedure TSBOMAnalyzerFrame.TaskSelected(Sender: TObject; Item: TListItem;
  Selected: Boolean);
begin
  if Selected then
  begin
    if (Item <> nil) and (Item.Data <> nil) then
      FSelectedTaskID := TScanTask(Item.Data).ID;
    UpdateDetails;
  end
  else if FTaskList.Selected = nil then
  begin
    FSelectedTaskID := '';
    UpdateDetails;
  end;
end;

procedure TSBOMAnalyzerFrame.TaskSearchChanged(Sender: TObject);
var
  SelectedID: string;
  Task: TScanTask;
begin
  SelectedID := FSelectedTaskID;
  RefreshTaskRows;
  Task := FindTask(SelectedID);
  if (Task <> nil) and (FindTaskItem(Task) <> nil) then
    SelectTask(Task)
  else if FTaskList.Items.Count > 0 then
    SelectTask(TScanTask(FTaskList.Items[0].Data))
  else
    SelectTask(nil);
end;

procedure TSBOMAnalyzerFrame.TaskMenuPopup(Sender: TObject);
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  DeleteTaskMenuItem.Enabled := (Task <> nil) and
    not (Task.Status in [tsPending, tsRunning]);
end;

procedure TSBOMAnalyzerFrame.DeleteTaskClicked(Sender: TObject);
var
  PreferredIndex: Integer;
  Task: TScanTask;
  TaskID, TargetName, WarningText: string;
begin
  Task := SelectedTask;
  if (Task = nil) or (Task.Status in [tsPending, tsRunning]) then
    Exit;
  TaskID := Task.ID;
  TargetName := Task.TargetRootName;
  PreferredIndex := -1;
  if FTaskList.Selected <> nil then
    PreferredIndex := FTaskList.Selected.Index;
  if MessageDlg(AppName, 'Delete the scan of "' + TargetName + '" [' +
    Copy(TaskID, 1, 8) + '] from task history?' + LineEnding + LineEnding +
    'Its application-managed SBOM will also be deleted. Files exported to ' +
    'other locations will be kept.', mtConfirmation, [mbYes, mbNo], 0) <>
    mrYes then
    Exit;

  FSelectedTaskID := '';
  FTaskList.Selected := nil;
  FTaskList.ItemFocused := nil;
  UpdateDetails;
  if not FHistoryService.DeleteTask(TaskID, WarningText) then
  begin
    Task := FindTask(TaskID);
    if Task <> nil then
      SelectTask(Task);
    if WarningText <> '' then
      ShowError(WarningText);
    Exit;
  end;

  if FTaskList.Items.Count > 0 then
  begin
    if PreferredIndex < 0 then
      PreferredIndex := 0;
    if PreferredIndex >= FTaskList.Items.Count then
      PreferredIndex := FTaskList.Items.Count - 1;
    SelectTask(TScanTask(FTaskList.Items[PreferredIndex].Data));
  end
  else
    SelectTask(nil);
  if WarningText <> '' then
    MessageDlg(AppName, WarningText, mtWarning, [mbOK], 0);
end;

procedure TSBOMAnalyzerFrame.TaskListKeyPressed(Sender: TObject;
  var Key: Word; Shift: TShiftState);
begin
  if (Key = VK_DELETE) and (Shift = []) then
  begin
    DeleteTaskClicked(Sender);
    Key := 0;
  end;
end;

procedure TSBOMAnalyzerFrame.FiltersChanged(Sender: TObject);
var
  Task: TScanTask;
begin
  if FUpdatingDetails then
    Exit;
  Task := SelectedTask;
  if (Sender = FComponentSearch) or (Sender = FComponentEcosystem) or
    (Sender = FComponentStatus) then
    PopulateComponents(Task)
  else
    PopulateArtifacts(Task);
end;

procedure TSBOMAnalyzerFrame.ComponentColumnClicked(Sender: TObject;
  Column: TListColumn);
begin
  if FComponentSortColumn = Column.Index then
    FComponentSortAscending := not FComponentSortAscending
  else
  begin
    FComponentSortColumn := Column.Index;
    FComponentSortAscending := True;
  end;
  PopulateComponents(SelectedTask);
end;

procedure TSBOMAnalyzerFrame.ArtifactColumnClicked(Sender: TObject;
  Column: TListColumn);
begin
  if FArtifactSortColumn = Column.Index then
    FArtifactSortAscending := not FArtifactSortAscending
  else
  begin
    FArtifactSortColumn := Column.Index;
    FArtifactSortAscending := True;
  end;
  PopulateArtifacts(SelectedTask);
end;

procedure TSBOMAnalyzerFrame.ListKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) and (Key = VK_C) then
  begin
    CopySelectedClicked(Sender);
    Key := 0;
  end;
end;

procedure TSBOMAnalyzerFrame.CopySelectedClicked(Sender: TObject);
var
  Artifact: TArtifact;
  Component: uModels.TComponent;
  List: TListView;
  I: Integer;
  Task: TScanTask;
  KnownIssueValue, Value: string;
begin
  List := nil;
  if (Sender = FSummaryList) or (FCopyMenu.PopupComponent = FSummaryList) then
    List := FSummaryList
  else if (Sender = FComponentList) or
    (FCopyMenu.PopupComponent = FComponentList) then
    List := FComponentList
  else if (Sender = FArtifactList) or
    (FCopyMenu.PopupComponent = FArtifactList) then
    List := FArtifactList;
  if (List = nil) or (List.Selected = nil) then
    Exit;
  if (List = FArtifactList) and (List.Selected.Data <> nil) then
  begin
    Artifact := TArtifact(List.Selected.Data);
    Value := Artifact.RelativePath + #9 + Artifact.ArtifactType + #9 +
      ArtifactStatusDisplayText(Artifact.Status) + #9 + Artifact.MessageText +
      #9 + FormatByteSize(Artifact.FileSize) + #9 + Artifact.Ecosystem + #9 +
      Artifact.SHA256;
  end
  else if (List = FComponentList) and (List.Selected.Data <> nil) then
  begin
    Component := uModels.TComponent(List.Selected.Data);
    Task := SelectedTask;
    Value := Component.Name + #9 + Component.Version + #9 +
      Component.Ecosystem + #9 + Component.ComponentType + #9;
    if Task <> nil then
      Value := Value + StatusDisplayText(ComponentArtifactStatus(Task,
        Component));
    if Task <> nil then
      KnownIssueValue := KnownIssueCellText(Task, Component,
        Task.KnownIssueCheck.MatchCountForPackageURL(Component.PackageURL))
    else
      KnownIssueValue := '';
    Value := Value + #9 + KnownIssueValue + #9 +
      JoinedValues(Component.DeclaredLicenses) + #9 +
      JoinedValues(Component.DeclaredPublishers) + #9 +
      Component.DependencyScope + #9 + Component.SourceArtifact;
  end
  else
  begin
    Value := List.Selected.Caption;
    for I := 0 to List.Selected.SubItems.Count - 1 do
      Value := Value + #9 + List.Selected.SubItems[I];
  end;
  Clipboard.AsText := Value;
end;

procedure TSBOMAnalyzerFrame.OpenExportFolderClicked(Sender: TObject);
var
  DirectoryName: string;
begin
  if FLastExportPath = '' then
    Exit;
  DirectoryName := ExtractFileDir(FLastExportPath);
  try
    if (DirectoryName = '') or not OpenDocument(DirectoryName) then
      ShowError('The exported file folder could not be opened: ' +
        DirectoryName);
  except
    on E: Exception do
      ShowError('The exported file folder could not be opened: ' + E.Message);
  end;
end;

procedure TSBOMAnalyzerFrame.CopyExportPathClicked(Sender: TObject);
begin
  if FLastExportPath = '' then
    Exit;
  try
    Clipboard.AsText := FLastExportPath;
  except
    on E: Exception do
      ShowError('The exported path could not be copied: ' + E.Message);
  end;
end;

procedure TSBOMAnalyzerFrame.WorkerProgress(Sender: TObject;
  const AProgress: TScanProgress);
var
  Task: TScanTask;
begin
  if FClosing then
    Exit;
  Task := FindTask(FActiveTaskID);
  if Task = nil then
    Exit;
  Task.FilesInspected := AProgress.FilesInspected;
  Task.BytesInspected := AProgress.BytesInspected;
  Task.ArtifactsDetected := AProgress.ArtifactsDetected;
  Task.ComponentsIdentified := AProgress.ComponentsIdentified;
  Task.DurationMS := AProgress.ElapsedMS;
  UpdateTaskRow(Task);
  FProgressPath.Caption := AProgress.CurrentRelativePath;
  FProgressStats.Caption := Format('%d files  •  %s  •  %d artifacts  •  '+
    '%d components  •  %s', [AProgress.FilesInspected,
    FormatByteSize(AProgress.BytesInspected), AProgress.ArtifactsDetected,
    AProgress.ComponentsIdentified, FormatDuration(AProgress.ElapsedMS)]);
  if SelectedTask = Task then
    PopulateSummary(Task);
end;

procedure TSBOMAnalyzerFrame.WorkerComplete(Sender: TObject; AResult: TScanTask);
var
  FooterText: string;
  Task: TScanTask;
  WasSelected: Boolean;
begin
  if FClosing then
    Exit;
  Task := FindTask(AResult.ID);
  WasSelected := FSelectedTaskID = AResult.ID;
  if Task <> nil then
  begin
    Task.Assign(AResult);
    UpdateTaskRow(Task);
  end;
  SetActiveTaskID('');
  FCancelRequested := False;
  if AResult.Status = tsCompleted then
    FooterText := 'Scan completed: '
  else
    FooterText := 'Scan ' + TaskStatusToString(AResult.Status) + ': ';
  FooterText := FooterText + AResult.TargetRootName + ' [' +
    Copy(AResult.ID, 1, 8) + '] ' + #$E2#$80#$94 + Format(
    ' %d files  •  %s  •  %d artifacts  •  %d components  •  %s',
    [AResult.FilesInspected,
    FormatByteSize(AResult.BytesInspected), AResult.ArtifactsDetected,
    AResult.ComponentsIdentified, FormatDuration(AResult.DurationMS)]);
  SetCompactFooter(FooterText);
  SaveHistory;
  if Task <> nil then
  begin
    try
      FHistoryService.NotifyTaskUpdated(Task.ID, False);
    except
      on E: Exception do
        ShowError('The completed scan could not be published: ' + E.Message);
    end;
    if WasSelected and (SelectedTask <> Task) then
      SelectTask(Task);
  end
  else
    UpdateDetails;
  UpdateButtons;
  if FClosePending then
    ClosePollTimer.Enabled := True;
end;

end.
