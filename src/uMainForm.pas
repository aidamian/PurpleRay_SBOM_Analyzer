(**
  PurpleRay SBOM Analyzer application-shell unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Owns the product identity, feature selector, tabless feature workspace, and
  form-level event routing. SBOM analysis behavior is encapsulated by the
  analyzer feature frame.

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
  Classes, Forms, Controls, StdCtrls, ExtCtrls, uSBOMAnalyzerFrame;

type
  TMainForm = class(TForm)
  published
    AnalyzerPage: TPage;
    ApplicationTitleLabel: TLabel;
    AppIconImage: TImage;
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
      Delegates application shutdown preparation to the analyzer feature.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      CanClose
        Receives whether the feature completed its shutdown preparation.

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
      Offers form-level keyboard input to the active analyzer feature.

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
    FAnalyzerFrame: TSBOMAnalyzerFrame;
    FCloseReissueQueued: Boolean;

    {**
      Creates and embeds the statically registered SBOM Analyzer feature.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EResNotFound, EReadError
        May propagate when the analyzer frame resource cannot be loaded.
      EOutOfMemory
        May propagate when the frame or its model state cannot be allocated.
    }
    procedure CreateFeatureFrames;

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
      Creates the LFM-backed shell and its application-lifetime feature frame.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.

      Returns
      -------
      TMainForm
        Initialized application shell containing the analyzer feature.

      Raises
      ------
      EResNotFound, EReadError
        May propagate when an embedded LFM resource cannot be loaded.
      EOutOfMemory
        May propagate while allocating the shell or analyzer feature.
    }
    constructor Create(TheOwner: TComponent); override;

    {**
      Detaches shell callbacks and prepares the analyzer before owned cleanup.

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
  Graphics, uVersionInfo;

{$R *.lfm}

constructor TMainForm.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  Caption := AppName + ' ' + DisplayVersion;
  ApplicationTitleLabel.Caption := AppName + '  ' + DisplayVersion;
  if Application.Icon <> nil then
    AppIconImage.Picture.Icon.Assign(Application.Icon);
  FeatureSelector.ItemIndex := 0;
  WorkspaceNotebook.PageIndex := 0;
  CreateFeatureFrames;
end;

destructor TMainForm.Destroy;
begin
  if FAnalyzerFrame <> nil then
  begin
    FAnalyzerFrame.OnActivityChanged := nil;
    FAnalyzerFrame.OnCloseReady := nil;
    FAnalyzerFrame.PrepareForClose;
  end;
  inherited Destroy;
end;

procedure TMainForm.CreateFeatureFrames;
begin
  FAnalyzerFrame := TSBOMAnalyzerFrame.Create(AnalyzerPage);
  FAnalyzerFrame.Parent := AnalyzerPage;
  FAnalyzerFrame.Align := alClient;
  FAnalyzerFrame.OnActivityChanged := @AnalyzerActivityChanged;
  FAnalyzerFrame.OnCloseReady := @AnalyzerCloseReady;
  AnalyzerActivityChanged(FAnalyzerFrame, FAnalyzerFrame.ScanActive);
end;

procedure TMainForm.FormShown(Sender: TObject);
begin
  if FAnalyzerFrame = nil then
    Exit;
  FAnalyzerFrame.ShowPendingWarnings;
  FAnalyzerFrame.Activate;
end;

procedure TMainForm.FormCloseRequested(Sender: TObject; var CanClose: Boolean);
begin
  CanClose := (FAnalyzerFrame = nil) or FAnalyzerFrame.RequestClose;
end;

procedure TMainForm.FormDropFiles(Sender: TObject;
  const FileNames: array of string);
begin
  if FAnalyzerFrame <> nil then
    FAnalyzerFrame.HandleDroppedFiles(FileNames);
end;

procedure TMainForm.FormKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if (FAnalyzerFrame <> nil) and
    FAnalyzerFrame.HandleShortcut(Key, Shift) then
    Key := 0;
end;

procedure TMainForm.FeatureSelectionChanged(Sender: TObject);
begin
  if FeatureSelector.ItemIndex <> 0 then
    FeatureSelector.ItemIndex := 0;
  WorkspaceNotebook.PageIndex := 0;
  if FAnalyzerFrame <> nil then
    FAnalyzerFrame.Activate;
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
