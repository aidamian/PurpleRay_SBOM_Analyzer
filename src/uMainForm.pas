(**
  PurpleRay SBOM Analyzer application-shell unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Owns the product identity, shared task-history service, left
  navigation rail, and form-level event routing across the Dashboard,
  SBOM Analyzer, and Knowledge Base features. Scan comparison runs in a
  modal dialog owned by the shell. Feature behavior remains
  encapsulated by the feature frames.

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
  Classes, Forms, Controls, StdCtrls, ExtCtrls, Buttons, Graphics,
  uTaskHistory, uSBOMAnalyzerFrame, uCompareScansDialog, uDashboardFrame,
  uKnowledgeBaseFrame;

const
  FeatureIndexDashboard = 0;
  FeatureIndexAnalyzer = 1;
  FeatureIndexKnowledgeBase = 2;

type
  TMainForm = class(TForm)
  published
    NavigationRail: TPanel;
    BrandPanel: TPanel;
    AppIconImage: TImage;
    ApplicationTitleLabel: TLabel;
    ApplicationSubtitleLabel: TLabel;
    DashboardNavButton: TSpeedButton;
    AnalyzerNavButton: TSpeedButton;
    KnowledgeNavButton: TSpeedButton;
    VersionLabel: TLabel;
    WorkspaceNotebook: TNotebook;
    DashboardPage: TPage;
    AnalyzerPage: TPage;
    KnowledgeBasePage: TPage;

    {**
      Activates the startup feature when the main window is shown.

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
      Delegates application shutdown preparation to the features.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      CanClose
        Receives whether every feature completed its shutdown
        preparation.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FormCloseRequested(Sender: TObject; var CanClose: Boolean);

    {**
      Routes files and directories dropped on the shell to the analyzer.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      FileNames
        Absolute or platform-native paths supplied by the LCL drop
        event.

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
      Offers form-level keyboard input to the active feature.

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
      Activates the Dashboard feature.

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
    procedure DashboardNavClicked(Sender: TObject);

    {**
      Activates the SBOM Analyzer feature.

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
    procedure AnalyzerNavClicked(Sender: TObject);

    {**
      Activates the Knowledge Base feature.

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
    procedure KnowledgeNavClicked(Sender: TObject);
  private
    FHistoryService: TTaskHistoryService;
    FAnalyzerFrame: TSBOMAnalyzerFrame;
    FDashboardFrame: TDashboardFrame;
    FKnowledgeBaseFrame: TKnowledgeBaseFrame;
    FCompareDialog: TCompareScansDialog;
    FCloseReissueQueued: Boolean;
    FActiveFeatureIndex: Integer;
    FSelectingFeature: Boolean;

    {**
      Initializes product identity, shared history, and features.

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
        May propagate while loading shared task history or feature
        state.
    }
    procedure InitializeShell(const ADataDirectory: string);

    {**
      Creates and embeds the three feature frames.

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
        May propagate when a frame or its model state cannot be
        allocated.
    }
    procedure CreateFeatureFrames;

    {**
      Draws the navigation glyphs used by the rail buttons at the
      current DPI-scaled size.

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
    procedure AssignNavigationGlyphs;

    {**
      Picks the embedded icon frame that best fills the brand image box.

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
    procedure SelectBrandIconFrame;

    {**
      Applies DPI-scaled glyph margin and spacing to the rail buttons.

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
    procedure ApplyNavigationMetrics;
  protected
    {**
      Re-applies DPI-dependent rail metrics after LCL layout scaling.

      Parameters
      ----------
      AMode
        Layout adjustment policy supplied by the LCL.
      AFromPPI
        Source pixels per inch.
      AToPPI
        Target pixels per inch.
      AOldFormWidth
        Form width before adjustment.
      ANewFormWidth
        Form width after adjustment.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure AutoAdjustLayout(AMode: TLayoutAdjustmentPolicy;
      const AFromPPI, AToPPI, AOldFormWidth, ANewFormWidth: Integer);
      override;

    {**
      Activates one feature without destroying the other frames.

      Parameters
      ----------
      AIndex
        Feature index: Dashboard, Analyzer, or Knowledge Base.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SelectFeature(AIndex: Integer);

    {**
      Opens the modal Compare Scans dialog over the shell.

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
    procedure OpenCompareDialog;

    {**
      Fans one revisioned shared-history event out to the features.

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
      Reflects analyzer activity on the navigation rail.

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
      Queues a second close request after asynchronous scan
      cancellation.

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
      Reissues the native form close outside the worker-completion
      callback.

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

    {**
      Opens the analyzer from a dashboard launcher.

      Parameters
      ----------
      Sender
        Dashboard frame; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure DashboardOpenAnalyzer(Sender: TObject);

    {**
      Opens the Knowledge Base from a dashboard launcher.

      Parameters
      ----------
      Sender
        Dashboard frame; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure DashboardOpenKnowledgeBase(Sender: TObject);

    {**
      Starts a new scan from a dashboard launcher.

      Parameters
      ----------
      Sender
        Dashboard frame; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure DashboardNewScan(Sender: TObject);

    {**
      Opens the Compare Scans dialog from a feature request.

      Parameters
      ----------
      Sender
        Requesting frame; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure CompareRequested(Sender: TObject);
  public
    {**
      Creates the LFM-backed shell, shared history, and features.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.

      Returns
      -------
      TMainForm
        Initialized application shell containing all three features.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when an embedded LFM resource cannot be loaded.
      EOutOfMemory
        May propagate while allocating the shell or a feature.
    }
    constructor Create(TheOwner: TComponent); override;

    {**
      Creates the complete shell with an explicit isolated persistence
      root.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      ADataDirectory
        Directory used by shared history, settings, and generated
        SBOMs.

      Returns
      -------
      TMainForm
        Initialized three-feature shell isolated from the operator
        profile.

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
      Detaches callbacks, prepares the frames, and frees history last.

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
  SysUtils, LCLType, uVersionInfo;

{$R *.lfm}

const
  { PurpleRay brand accent in TColor byte order (BGR of #5F57AD). }
  NavigationAccentColor: TColor = TColor($AD575F);
  NavigationGlyphSize = 16;

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
  ApplicationTitleLabel.Caption := 'PurpleRay';
  ApplicationSubtitleLabel.Caption := 'SBOM Analyzer';
  VersionLabel.Caption := DisplayVersion;
  VersionLabel.Font.Color := clGrayText;
  ApplicationSubtitleLabel.Font.Color := clGrayText;
  if Application.Icon <> nil then
  begin
    AppIconImage.Picture.Icon.Assign(Application.Icon);
    SelectBrandIconFrame;
  end;
  ApplyNavigationMetrics;
  AssignNavigationGlyphs;
  FActiveFeatureIndex := -1;
  FHistoryService := TTaskHistoryService.Create(ADataDirectory);
  FHistoryService.OnChanged := @HistoryChanged;
  CreateFeatureFrames;
  { Keep construction free of focus changes. GTK can report child
    controls as focusable before their parent form is visible and then
    reject SetFocus. }
  FSelectingFeature := True;
  try
    DashboardNavButton.Down := True;
    WorkspaceNotebook.PageIndex := FeatureIndexDashboard;
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
    FAnalyzerFrame.OnCompareRequested := nil;
    FAnalyzerFrame.PrepareForClose;
  end;
  FreeAndNil(FCompareDialog);
  FreeAndNil(FKnowledgeBaseFrame);
  FreeAndNil(FDashboardFrame);
  FreeAndNil(FAnalyzerFrame);
  FreeAndNil(FHistoryService);
  inherited Destroy;
end;

procedure TMainForm.SelectBrandIconFrame;
var
  BrandIcon: TIcon;
  I, BestIndex, BestSize, Target, Size: Integer;
begin
  BrandIcon := AppIconImage.Picture.Icon;
  if (BrandIcon = nil) or (BrandIcon.Count = 0) then
    Exit;
  Target := AppIconImage.Width;
  BestIndex := 0;
  BestSize := 0;
  { Prefer the smallest frame that is at least the box size; otherwise the
    largest available, so the brand mark never upscales from a tiny frame. }
  for I := 0 to BrandIcon.Count - 1 do
  begin
    BrandIcon.Current := I;
    Size := BrandIcon.Width;
    if ((Size >= Target) and ((BestSize < Target) or (Size < BestSize))) or
      ((Size < Target) and (BestSize < Target) and (Size > BestSize)) then
    begin
      BestIndex := I;
      BestSize := Size;
    end;
  end;
  BrandIcon.Current := BestIndex;
end;

procedure TMainForm.ApplyNavigationMetrics;
const
  DesignMargin = 10;
  DesignSpacing = 8;
var
  Buttons: array[0..2] of TSpeedButton;
  I: Integer;
begin
  Buttons[0] := DashboardNavButton;
  Buttons[1] := AnalyzerNavButton;
  Buttons[2] := KnowledgeNavButton;
  for I := Low(Buttons) to High(Buttons) do
  begin
    Buttons[I].Margin := Scale96ToForm(DesignMargin);
    Buttons[I].Spacing := Scale96ToForm(DesignSpacing);
  end;
end;

procedure TMainForm.AutoAdjustLayout(AMode: TLayoutAdjustmentPolicy;
  const AFromPPI, AToPPI, AOldFormWidth, ANewFormWidth: Integer);
begin
  inherited AutoAdjustLayout(AMode, AFromPPI, AToPPI, AOldFormWidth,
    ANewFormWidth);
  if AMode = lapAutoAdjustForDPI then
  begin
    { The image box was just rescaled; reselect the best icon frame and
      rescale the rail metrics the LCL does not scale on its own. }
    SelectBrandIconFrame;
    ApplyNavigationMetrics;
    AssignNavigationGlyphs;
  end;
end;

procedure TMainForm.AssignNavigationGlyphs;
var
  Size: Integer;

  function P(AValue: Integer): Integer;
  begin
    { Scale a 16-px design coordinate to the current glyph size. }
    Result := Round(AValue * Size / NavigationGlyphSize);
  end;

  function NewGlyph: TBitmap;
  begin
    Result := TBitmap.Create;
    Result.SetSize(Size, Size);
    Result.Canvas.Brush.Color := clFuchsia;
    Result.Canvas.FillRect(0, 0, Size, Size);
    Result.Canvas.Pen.Color := NavigationAccentColor;
    Result.Canvas.Brush.Color := NavigationAccentColor;
    Result.TransparentColor := clFuchsia;
    Result.Transparent := True;
  end;

var
  Glyph: TBitmap;
begin
  Size := Scale96ToForm(NavigationGlyphSize);
  if Size < NavigationGlyphSize then
    Size := NavigationGlyphSize;
  { Dashboard: four tiles. }
  Glyph := NewGlyph;
  try
    Glyph.Canvas.FillRect(P(1), P(1), P(7), P(7));
    Glyph.Canvas.FillRect(P(9), P(1), P(15), P(7));
    Glyph.Canvas.FillRect(P(1), P(9), P(7), P(15));
    Glyph.Canvas.FillRect(P(9), P(9), P(15), P(15));
    DashboardNavButton.Glyph.Assign(Glyph);
  finally
    Glyph.Free;
  end;
  { Analyzer: magnifier. }
  Glyph := NewGlyph;
  try
    Glyph.Canvas.Brush.Style := bsClear;
    Glyph.Canvas.Pen.Width := P(2);
    Glyph.Canvas.Ellipse(P(1), P(1), P(11), P(11));
    Glyph.Canvas.MoveTo(P(10), P(10));
    Glyph.Canvas.LineTo(P(15), P(15));
    AnalyzerNavButton.Glyph.Assign(Glyph);
  finally
    Glyph.Free;
  end;
  { Knowledge Base: open book. }
  Glyph := NewGlyph;
  try
    Glyph.Canvas.Brush.Style := bsClear;
    Glyph.Canvas.Pen.Width := P(2);
    Glyph.Canvas.Rectangle(P(1), P(2), P(15), P(14));
    Glyph.Canvas.MoveTo(P(8), P(2));
    Glyph.Canvas.LineTo(P(8), P(14));
    KnowledgeNavButton.Glyph.Assign(Glyph);
  finally
    Glyph.Free;
  end;
end;

procedure TMainForm.CreateFeatureFrames;
begin
  FAnalyzerFrame := TSBOMAnalyzerFrame.CreateWithHistoryService(AnalyzerPage,
    FHistoryService);
  FAnalyzerFrame.Parent := AnalyzerPage;
  FAnalyzerFrame.Align := alClient;
  FAnalyzerFrame.OnActivityChanged := @AnalyzerActivityChanged;
  FAnalyzerFrame.OnCloseReady := @AnalyzerCloseReady;
  FAnalyzerFrame.OnCompareRequested := @CompareRequested;

  FDashboardFrame := TDashboardFrame.CreateWithHistoryService(DashboardPage,
    FHistoryService);
  FDashboardFrame.Parent := DashboardPage;
  FDashboardFrame.Align := alClient;
  FDashboardFrame.OnOpenAnalyzer := @DashboardOpenAnalyzer;
  FDashboardFrame.OnOpenKnowledgeBase := @DashboardOpenKnowledgeBase;
  FDashboardFrame.OnNewScan := @DashboardNewScan;
  FDashboardFrame.OnCompare := @CompareRequested;

  FKnowledgeBaseFrame := TKnowledgeBaseFrame.Create(KnowledgeBasePage);
  FKnowledgeBaseFrame.Parent := KnowledgeBasePage;
  FKnowledgeBaseFrame.Align := alClient;

  AnalyzerActivityChanged(FAnalyzerFrame, FAnalyzerFrame.ScanActive);
end;

procedure TMainForm.SelectFeature(AIndex: Integer);
begin
  if FSelectingFeature or not (AIndex in [FeatureIndexDashboard,
    FeatureIndexAnalyzer, FeatureIndexKnowledgeBase]) then
    Exit;
  FSelectingFeature := True;
  try
    case FActiveFeatureIndex of
      FeatureIndexDashboard:
        if FDashboardFrame <> nil then
          FDashboardFrame.Deactivate;
      FeatureIndexAnalyzer:
        if FAnalyzerFrame <> nil then
          FAnalyzerFrame.Deactivate;
      FeatureIndexKnowledgeBase:
        if FKnowledgeBaseFrame <> nil then
          FKnowledgeBaseFrame.Deactivate;
    end;
    case AIndex of
      FeatureIndexDashboard: DashboardNavButton.Down := True;
      FeatureIndexAnalyzer: AnalyzerNavButton.Down := True;
      FeatureIndexKnowledgeBase: KnowledgeNavButton.Down := True;
    end;
    WorkspaceNotebook.PageIndex := AIndex;
    FActiveFeatureIndex := AIndex;
    case AIndex of
      FeatureIndexDashboard:
        if FDashboardFrame <> nil then
          FDashboardFrame.Activate;
      FeatureIndexAnalyzer:
        if FAnalyzerFrame <> nil then
          FAnalyzerFrame.Activate;
      FeatureIndexKnowledgeBase:
        if FKnowledgeBaseFrame <> nil then
          FKnowledgeBaseFrame.Activate;
    end;
  finally
    FSelectingFeature := False;
  end;
end;

procedure TMainForm.OpenCompareDialog;
begin
  if FCompareDialog <> nil then
    Exit;
  FCompareDialog := TCompareScansDialog.CreateForHistory(Self,
    FHistoryService);
  try
    FCompareDialog.ShowModal;
  finally
    FreeAndNil(FCompareDialog);
  end;
end;

procedure TMainForm.HistoryChanged(Sender: TObject;
  AKind: TTaskHistoryChangeKind; const ATaskID: string; ARevision: QWord);
begin
  if Sender <> FHistoryService then
    Exit;
  if FAnalyzerFrame <> nil then
    FAnalyzerFrame.HistoryChanged(AKind, ATaskID, ARevision);
  if FDashboardFrame <> nil then
    FDashboardFrame.HistoryChanged(AKind, ATaskID, ARevision);
  if FCompareDialog <> nil then
    FCompareDialog.HistoryChanged(AKind, ATaskID, ARevision);
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
  SelectFeature(FeatureIndexDashboard);
end;

procedure TMainForm.FormCloseRequested(Sender: TObject; var CanClose: Boolean);
begin
  CanClose := (FAnalyzerFrame = nil) or FAnalyzerFrame.RequestClose;
end;

procedure TMainForm.FormDropFiles(Sender: TObject;
  const FileNames: array of string);
begin
  if FAnalyzerFrame <> nil then
  begin
    SelectFeature(FeatureIndexAnalyzer);
    FAnalyzerFrame.HandleDroppedFiles(FileNames);
  end;
end;

procedure TMainForm.FormKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) then
    case Key of
      VK_1:
        begin
          SelectFeature(FeatureIndexDashboard);
          Key := 0;
          Exit;
        end;
      VK_2:
        begin
          SelectFeature(FeatureIndexAnalyzer);
          Key := 0;
          Exit;
        end;
      VK_3:
        begin
          SelectFeature(FeatureIndexKnowledgeBase);
          Key := 0;
          Exit;
        end;
      VK_N:
        SelectFeature(FeatureIndexAnalyzer);
    end;
  if (FActiveFeatureIndex = FeatureIndexAnalyzer) and
    (FAnalyzerFrame <> nil) then
    if FAnalyzerFrame.HandleShortcut(Key, Shift) then
      Key := 0;
end;

procedure TMainForm.DashboardNavClicked(Sender: TObject);
begin
  SelectFeature(FeatureIndexDashboard);
end;

procedure TMainForm.AnalyzerNavClicked(Sender: TObject);
begin
  SelectFeature(FeatureIndexAnalyzer);
end;

procedure TMainForm.KnowledgeNavClicked(Sender: TObject);
begin
  SelectFeature(FeatureIndexKnowledgeBase);
end;

procedure TMainForm.AnalyzerActivityChanged(Sender: TObject;
  AScanActive: Boolean);
begin
  if Sender <> FAnalyzerFrame then
    Exit;
  if AScanActive then
  begin
    AnalyzerNavButton.Hint := 'SBOM Analyzer — scan in progress';
    AnalyzerNavButton.Font.Style := [fsBold];
  end
  else
  begin
    AnalyzerNavButton.Hint := 'SBOM Analyzer';
    AnalyzerNavButton.Font.Style := [];
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

procedure TMainForm.DashboardOpenAnalyzer(Sender: TObject);
begin
  SelectFeature(FeatureIndexAnalyzer);
end;

procedure TMainForm.DashboardOpenKnowledgeBase(Sender: TObject);
begin
  SelectFeature(FeatureIndexKnowledgeBase);
end;

procedure TMainForm.DashboardNewScan(Sender: TObject);
begin
  SelectFeature(FeatureIndexAnalyzer);
  if FAnalyzerFrame <> nil then
    FAnalyzerFrame.StartNewScan;
end;

procedure TMainForm.CompareRequested(Sender: TObject);
begin
  OpenCompareDialog;
end;

end.
