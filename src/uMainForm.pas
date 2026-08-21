(**
  PurpleRay SBOM Analyzer application-shell unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Owns the product identity, shared task-history service, feature selector,
  tabless feature workspace, and form-level event routing. Analysis and
  comparison behavior remain encapsulated by their feature frames.

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
unit uMainForm;

{$mode objfpc}{$H+}

interface

uses
  Classes, Forms, Controls, StdCtrls, ExtCtrls, uTaskHistory,
  uSBOMAnalyzerFrame, uCompareScansFrame;

type
  TMainForm = class(TForm)
  published
    AnalyzerPage: TPage;
    ApplicationTitleLabel: TLabel;
    AppIconImage: TImage;
    ComparePage: TPage;
    FeatureSelector: TComboBox;
    ShellHeaderPanel: TPanel;
    WorkspaceNotebook: TNotebook;

    {**
      Activates the selected feature when the main window is shown.

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
    procedure FormShown(Sender: TObject);

    {**
      Delegates application shutdown preparation to both compiled features.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      CanClose
        Receives whether every feature completed its shutdown preparation.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FormCloseRequested(Sender: TObject; var CanClose: Boolean);

    {**
      Routes files and directories dropped on the shell to the analyzer feature.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      FileNames
        Absolute or platform-native paths supplied by the LCL drop event.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FormDropFiles(Sender: TObject;
      const FileNames: array of string);

    {**
      Offers form-level keyboard input to the active compiled feature.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      Key
        Virtual key code; cleared when the feature handles the shortcut.
      Shift
        Active modifier-key state.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FormKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);

    {**
      Selects the workspace page represented by the feature selector.

      Parameters
      ----------
      Sender
        Feature selector that raised the event; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FeatureSelectionChanged(Sender: TObject);
  private
    FHistoryService: TTaskHistoryService;
    FAnalyzerFrame: TSBOMAnalyzerFrame;
    FCompareFrame: TCompareScansFrame;
    FCloseReissueQueued: Boolean;
    FActiveFeatureIndex: Integer;
    FSelectingFeature: Boolean;

    {**
      Initializes product identity, shared history, and compiled features.

      Parameters
      ----------
      ADataDirectory
        Optional explicit persistence root used by isolated UI probes.

      Returns
      -------
      None

      Raises
      ------
      EResNotFound, EReadError
        May propagate when an embedded LFM resource cannot be loaded.
      EOutOfMemory, EInOutError
        May propagate while loading shared task history or feature state.
    }
    procedure InitializeShell(const ADataDirectory: string);

    {**
      Creates and embeds both statically registered feature frames.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EResNotFound, EReadError
        May propagate when a feature-frame resource cannot be loaded.
      EOutOfMemory
        May propagate when the frame or its model state cannot be allocated.
    }
    procedure CreateFeatureFrames;

    {**
      Activates one compiled feature without destroying the other frame.

      Parameters
      ----------
      AIndex
        Selector/notebook index: zero for Analyzer or one for Compare Scans.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SelectFeature(AIndex: Integer);

    {**
      Fans one revisioned shared-history event out to both feature frames.

      Parameters
      ----------
      Sender
        Shared history service that emitted the notification.
      AKind
        Reset, add, update, or removal operation that completed.
      ATaskID
        Affected task identifier, or an empty string for a reset.
      ARevision
        Monotonically increasing in-memory history revision.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure HistoryChanged(Sender: TObject; AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);

    {**
      Tests the platform's primary application-shortcut modifier.

      Parameters
      ----------
      AShift
        Modifier state supplied by the LCL key event.

      Returns
      -------
      Boolean
        True for Ctrl on Windows/Linux or Command on macOS.

      Raises
      ------
      None
    }
    function PrimaryShortcut(AShift: TShiftState): Boolean;

    {**
      Reflects analyzer activity without changing the stable feature name.

      Parameters
      ----------
      Sender
        Analyzer frame reporting its state transition.
      AScanActive
        True while a scan worker is active; otherwise False.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure AnalyzerActivityChanged(Sender: TObject; AScanActive: Boolean);

    {**
      Queues a second close request after asynchronous scan cancellation.

      Parameters
      ----------
      Sender
        Analyzer frame whose close preparation has completed.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure AnalyzerCloseReady(Sender: TObject);

    {**
      Reissues the native form close outside the worker-completion callback.

      Parameters
      ----------
      Data
        Unused asynchronous callback payload.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure ReissueClose(Data: PtrInt);
  public
    {**
      Creates the LFM-backed shell, shared history, and compiled features.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.

      Returns
      -------
      TMainForm
        Initialized application shell containing Analyzer and Compare Scans.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when an embedded LFM resource cannot be loaded.
      EOutOfMemory
        May propagate while allocating the shell or either feature.
    }
    constructor Create(TheOwner: TComponent); override;

    {**
      Creates the complete shell with an explicit isolated persistence root.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      ADataDirectory
        Directory used by shared history, settings, and generated SBOMs.

      Returns
      -------
      TMainForm
        Initialized two-feature shell isolated from the operator profile.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when an embedded LFM resource cannot be loaded.
      EOutOfMemory, EInOutError
        May propagate while loading shared state.
    }
    constructor CreateForDataDirectory(TheOwner: TComponent;
      const ADataDirectory: string);

    {**
      Detaches callbacks, prepares both frames, and frees history last.

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
  end;

var
  MainForm: TMainForm;

implementation

uses
  SysUtils, Graphics, LCLType, uVersionInfo;

{$R *.lfm}

constructor TMainForm.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  InitializeShell('');
end;

constructor TMainForm.CreateForDataDirectory(TheOwner: TComponent;
  const ADataDirectory: string);
begin
  inherited Create(TheOwner);
  InitializeShell(ADataDirectory);
end;

procedure TMainForm.InitializeShell(const ADataDirectory: string);
begin
  Caption := AppName + ' ' + DisplayVersion;
  ApplicationTitleLabel.Caption := AppName + '  ' + DisplayVersion;
  if Application.Icon <> nil then
    AppIconImage.Picture.Icon.Assign(Application.Icon);
  FActiveFeatureIndex := -1;
  FHistoryService := TTaskHistoryService.Create(ADataDirectory);
  FHistoryService.OnChanged := @HistoryChanged;
  CreateFeatureFrames;
  { Keep construction free of focus changes. GTK can report child controls as
    focusable before their parent form is visible and then reject SetFocus. }
  FSelectingFeature := True;
  try
    FeatureSelector.ItemIndex := 0;
    WorkspaceNotebook.PageIndex := 0;
  finally
    FSelectingFeature := False;
  end;
  { FormShown performs the first real feature activation. }
end;

destructor TMainForm.Destroy;
begin
  if FHistoryService <> nil then
    FHistoryService.OnChanged := nil;
  if FAnalyzerFrame <> nil then
  begin
    FAnalyzerFrame.OnActivityChanged := nil;
    FAnalyzerFrame.OnCloseReady := nil;
    FAnalyzerFrame.PrepareForClose;
  end;
  if FCompareFrame <> nil then
    FCompareFrame.PrepareForClose;
  FreeAndNil(FCompareFrame);
  FreeAndNil(FAnalyzerFrame);
  FreeAndNil(FHistoryService);
  inherited Destroy;
end;

procedure TMainForm.CreateFeatureFrames;
begin
  FAnalyzerFrame := TSBOMAnalyzerFrame.CreateWithHistoryService(AnalyzerPage,
    FHistoryService);
  FAnalyzerFrame.Parent := AnalyzerPage;
  FAnalyzerFrame.Align := alClient;
  FAnalyzerFrame.OnActivityChanged := @AnalyzerActivityChanged;
  FAnalyzerFrame.OnCloseReady := @AnalyzerCloseReady;
  FCompareFrame := TCompareScansFrame.CreateWithHistoryService(ComparePage,
    FHistoryService);
  FCompareFrame.Parent := ComparePage;
  FCompareFrame.Align := alClient;
  AnalyzerActivityChanged(FAnalyzerFrame, FAnalyzerFrame.ScanActive);
end;

procedure TMainForm.SelectFeature(AIndex: Integer);
begin
  if FSelectingFeature or not (AIndex in [0, 1]) then
    Exit;
  FSelectingFeature := True;
  try
    if (FActiveFeatureIndex = 0) and (FAnalyzerFrame <> nil) then
      FAnalyzerFrame.Deactivate
    else if (FActiveFeatureIndex = 1) and (FCompareFrame <> nil) then
      FCompareFrame.Deactivate;
    FeatureSelector.ItemIndex := AIndex;
    WorkspaceNotebook.PageIndex := AIndex;
    FActiveFeatureIndex := AIndex;
    if (AIndex = 0) and (FAnalyzerFrame <> nil) then
      FAnalyzerFrame.Activate
    else if (AIndex = 1) and (FCompareFrame <> nil) then
      FCompareFrame.Activate;
  finally
    FSelectingFeature := False;
  end;
end;

procedure TMainForm.HistoryChanged(Sender: TObject;
  AKind: TTaskHistoryChangeKind; const ATaskID: string; ARevision: QWord);
begin
  if Sender <> FHistoryService then
    Exit;
  if FAnalyzerFrame <> nil then
    FAnalyzerFrame.HistoryChanged(AKind, ATaskID, ARevision);
  if FCompareFrame <> nil then
    FCompareFrame.HistoryChanged(AKind, ATaskID, ARevision);
end;

function TMainForm.PrimaryShortcut(AShift: TShiftState): Boolean;
begin
  {$IFDEF Darwin}
  Result := (ssMeta in AShift) and not (ssCtrl in AShift);
  {$ELSE}
  Result := (ssCtrl in AShift) and not (ssMeta in AShift);
  {$ENDIF}
end;

procedure TMainForm.FormShown(Sender: TObject);
begin
  if FAnalyzerFrame = nil then
    Exit;
  FAnalyzerFrame.ShowPendingWarnings;
  SelectFeature(FeatureSelector.ItemIndex);
end;

procedure TMainForm.FormCloseRequested(Sender: TObject; var CanClose: Boolean);
begin
  CanClose := (FAnalyzerFrame = nil) or FAnalyzerFrame.RequestClose;
  if CanClose and (FCompareFrame <> nil) then
    CanClose := FCompareFrame.PrepareForClose;
end;

procedure TMainForm.FormDropFiles(Sender: TObject;
  const FileNames: array of string);
begin
  if FAnalyzerFrame <> nil then
  begin
    SelectFeature(0);
    FAnalyzerFrame.HandleDroppedFiles(FileNames);
  end;
end;

procedure TMainForm.FormKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) and (Key = VK_1) then
  begin
    SelectFeature(0);
    Key := 0;
    Exit;
  end;
  if PrimaryShortcut(Shift) and (Key = VK_2) then
  begin
    SelectFeature(1);
    Key := 0;
    Exit;
  end;
  if PrimaryShortcut(Shift) and (Key = VK_N) then
    SelectFeature(0);
  if (FActiveFeatureIndex = 0) and (FAnalyzerFrame <> nil) then
  begin
    if FAnalyzerFrame.HandleShortcut(Key, Shift) then
      Key := 0;
  end
  else if (FActiveFeatureIndex = 1) and (FCompareFrame <> nil) then
    if FCompareFrame.HandleShortcut(Key, Shift) then
      Key := 0;
end;

procedure TMainForm.FeatureSelectionChanged(Sender: TObject);
begin
  SelectFeature(FeatureSelector.ItemIndex);
end;

procedure TMainForm.AnalyzerActivityChanged(Sender: TObject;
  AScanActive: Boolean);
begin
  if Sender <> FAnalyzerFrame then
    Exit;
  if AScanActive then
  begin
    FeatureSelector.Hint := 'SBOM Analyzer — scan in progress';
    FeatureSelector.Font.Style := [fsBold];
  end
  else
  begin
    FeatureSelector.Hint := 'SBOM Analyzer';
    FeatureSelector.Font.Style := [];
  end;
end;

procedure TMainForm.AnalyzerCloseReady(Sender: TObject);
begin
  if (Sender <> FAnalyzerFrame) or FCloseReissueQueued then
    Exit;
  FCloseReissueQueued := True;
  Application.QueueAsyncCall(@ReissueClose, 0);
end;

procedure TMainForm.ReissueClose(Data: PtrInt);
begin
  FCloseReissueQueued := False;
  Close;
end;

end.
