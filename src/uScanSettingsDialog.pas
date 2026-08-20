(**
  PurpleRay SBOM Analyzer scan-settings dialog unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents and validates the user-editable path, symlink, hashing, and ignore
  options before a scan begins.

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
unit uScanSettingsDialog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, uModels;

type
  TScanSettingsDialog = class(TForm)
  published
    DescriptionTopSpacer: TPanel;
    DescriptionLabel: TLabel;
    FIncludeAbsolutePaths: TCheckBox;
    FFollowSymbolicLinks: TCheckBox;
    FAllowOutsideRoot: TCheckBox;
    FCalculateSHA256: TCheckBox;
    IgnorePatternsLabel: TLabel;
    FIgnorePatterns: TMemo;
    ButtonsPanel: TPanel;
    OKButton: TButton;
    CancelButton: TButton;
    {**
      Keeps the outside-root option consistent with the follow-links checkbox.

      Parameters
      ----------
      Sender
        LCL control that raised the event; the value is not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure FollowLinksChanged(Sender: TObject);
  public
    {**
      Creates the LFM-backed modal settings dialog.

      Parameters
      ----------
      TheOwner
        Optional component owner.

      Returns
      -------
      TScanSettingsDialog
        Initialized form instance.

      Raises
      ------
      EResNotFound, EReadError
        May propagate if the embedded LFM resource cannot be loaded.
    }
    constructor Create(TheOwner: Classes.TComponent); override;

    {**
      Edits scan settings modally and applies them only after confirmation.

      Parameters
      ----------
      ASettings
        Existing settings displayed and updated when the user selects Start.

      Returns
      -------
      Boolean
        True when the user confirms and ASettings was updated.

      Raises
      ------
      EAccessViolation
        Raised when ASettings is nil.
      EResNotFound, EReadError
        May propagate if form creation fails.
    }
    class function Execute(ASettings: TScanSettings): Boolean;
  end;

implementation

{$R *.lfm}

constructor TScanSettingsDialog.Create(TheOwner: Classes.TComponent);
begin
  inherited Create(TheOwner);
end;

procedure TScanSettingsDialog.FollowLinksChanged(Sender: TObject);
begin
  FAllowOutsideRoot.Enabled := FFollowSymbolicLinks.Checked;
  if not FAllowOutsideRoot.Enabled then
    FAllowOutsideRoot.Checked := False;
end;

class function TScanSettingsDialog.Execute(ASettings: TScanSettings): Boolean;
var
  Dialog: TScanSettingsDialog;
  I: Integer;
begin
  Dialog := TScanSettingsDialog.Create(nil);
  try
    Dialog.FIncludeAbsolutePaths.Checked := ASettings.IncludeAbsolutePaths;
    Dialog.FFollowSymbolicLinks.Checked := ASettings.FollowSymbolicLinks;
    Dialog.FAllowOutsideRoot.Checked := ASettings.AllowOutsideRoot;
    Dialog.FCalculateSHA256.Checked := ASettings.CalculateSHA256;
    Dialog.FIgnorePatterns.Lines.Assign(ASettings.IgnorePatterns);
    Dialog.FollowLinksChanged(nil);
    Result := Dialog.ShowModal = mrOK;
    if Result then
    begin
      ASettings.IncludeAbsolutePaths := Dialog.FIncludeAbsolutePaths.Checked;
      ASettings.FollowSymbolicLinks := Dialog.FFollowSymbolicLinks.Checked;
      ASettings.AllowOutsideRoot := Dialog.FAllowOutsideRoot.Checked;
      ASettings.CalculateSHA256 := Dialog.FCalculateSHA256.Checked;
      ASettings.IgnorePatterns.Clear;
      for I := 0 to Dialog.FIgnorePatterns.Lines.Count - 1 do
        if Trim(Dialog.FIgnorePatterns.Lines[I]) <> '' then
          ASettings.IgnorePatterns.Add(Trim(Dialog.FIgnorePatterns.Lines[I]));
    end;
  finally
    Dialog.Free;
  end;
end;

end.
