(**
  PurpleRay SBOM Analyzer compare-scans dialog.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Modal host for the existing Compare Scans feature frame. Comparing
  two persisted scans is a focused activity launched from the SBOM
  Analyzer or the Dashboard rather than a root feature of the shell.

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
unit uCompareScansDialog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, LCLType,
  uTaskHistory, uCompareScansFrame;

type
  TCompareScansDialog = class(TForm)
  private
    FFrame: TCompareScansFrame;
    FCloseButton: TButton;

    {**
      Activates the hosted frame when the dialog becomes visible.

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
    procedure DialogShown(Sender: TObject);

    {**
      Lets the hosted frame consume shortcuts before dialog handling.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      Key
        Virtual key code; cleared when handled.
      Shift
        Active modifier-key state.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure DialogKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);
  public
    {**
      Creates the modal dialog around a fresh Compare Scans frame.

      Parameters
      ----------
      TheOwner
        Owning form used for centering.
      AHistory
        Shared task-history service; must not be nil.

      Returns
      -------
      TCompareScansDialog
        Initialized, not yet shown dialog.

      Raises
      ------
      EArgumentException
        Raised when AHistory is nil.
      EOutOfMemory
        Propagated when the dialog cannot be allocated.
    }
    constructor CreateForHistory(TheOwner: TComponent;
      AHistory: TTaskHistoryService);

    {**
      Prepares the hosted frame for destruction.

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
      Forwards shared-history changes to the hosted frame.

      Parameters
      ----------
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
    procedure HistoryChanged(AKind: TTaskHistoryChangeKind;
      const ATaskID: string; ARevision: QWord);
  end;

implementation

constructor TCompareScansDialog.CreateForHistory(TheOwner: TComponent;
  AHistory: TTaskHistoryService);
var
  ButtonPanel: TPanel;
begin
  inherited CreateNew(TheOwner);
  Caption := 'Compare scans';
  Width := 900;
  Height := 620;
  Constraints.MinWidth := 640;
  Constraints.MinHeight := 420;
  Position := poOwnerFormCenter;
  BorderIcons := [biSystemMenu];
  KeyPreview := True;
  OnShow := @DialogShown;
  OnKeyDown := @DialogKeyPressed;

  ButtonPanel := TPanel.Create(Self);
  ButtonPanel.Parent := Self;
  ButtonPanel.Align := alBottom;
  ButtonPanel.Height := 44;
  ButtonPanel.BevelOuter := bvNone;

  FCloseButton := TButton.Create(Self);
  FCloseButton.Parent := ButtonPanel;
  FCloseButton.Caption := 'Close';
  FCloseButton.ModalResult := mrClose;
  FCloseButton.Cancel := True;
  FCloseButton.AutoSize := True;
  FCloseButton.Anchors := [akTop, akRight];
  FCloseButton.AnchorSideTop.Control := ButtonPanel;
  FCloseButton.AnchorSideTop.Side := asrTop;
  FCloseButton.AnchorSideRight.Control := ButtonPanel;
  FCloseButton.AnchorSideRight.Side := asrRight;
  FCloseButton.BorderSpacing.Top := 8;
  FCloseButton.BorderSpacing.Right := 12;

  FFrame := TCompareScansFrame.CreateWithHistoryService(Self, AHistory);
  FFrame.Parent := Self;
  FFrame.Align := alClient;
end;

destructor TCompareScansDialog.Destroy;
begin
  if FFrame <> nil then
  begin
    FFrame.Deactivate;
    FFrame.PrepareForClose;
  end;
  inherited Destroy;
end;

procedure TCompareScansDialog.DialogShown(Sender: TObject);
begin
  if FFrame <> nil then
    FFrame.Activate;
end;

procedure TCompareScansDialog.DialogKeyPressed(Sender: TObject;
  var Key: Word; Shift: TShiftState);
begin
  if (FFrame <> nil) and FFrame.HandleShortcut(Key, Shift) then
    Key := 0;
end;

procedure TCompareScansDialog.HistoryChanged(AKind: TTaskHistoryChangeKind;
  const ATaskID: string; ARevision: QWord);
begin
  if FFrame <> nil then
    FFrame.HistoryChanged(AKind, ATaskID, ARevision);
end;

end.
