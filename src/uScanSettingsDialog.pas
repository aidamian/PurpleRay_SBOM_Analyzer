unit uScanSettingsDialog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, uModels;

type
  TScanSettingsDialog = class(TForm)
  private
    FIncludeAbsolutePaths: TCheckBox;
    FFollowSymbolicLinks: TCheckBox;
    FAllowOutsideRoot: TCheckBox;
    FCalculateSHA256: TCheckBox;
    FIgnorePatterns: TMemo;
    procedure FollowLinksChanged(Sender: TObject);
    procedure BuildUI;
  public
    constructor Create(TheOwner: Classes.TComponent); override;
    class function Execute(ASettings: TScanSettings): Boolean;
  end;

implementation

constructor TScanSettingsDialog.Create(TheOwner: Classes.TComponent);
begin
  inherited CreateNew(TheOwner, 1);
  BuildUI;
end;

procedure TScanSettingsDialog.BuildUI;
var
  Description: TLabel;
  Buttons: TPanel;
  OKButton, CancelButton: TButton;
begin
  Caption := 'Scan settings';
  BorderStyle := bsDialog;
  Position := poScreenCenter;
  ClientWidth := 570;
  ClientHeight := 500;
  Constraints.MinWidth := 500;
  Constraints.MinHeight := 430;

  Description := TLabel.Create(Self);
  Description.Parent := Self;
  Description.Align := alTop;
  Description.AutoSize := False;
  Description.Height := 54;
  Description.BorderSpacing.Around := 12;
  Description.WordWrap := True;
  Description.Caption := 'Choose how this scan treats paths, symbolic links, '+
    'hashes, and ignored files. Absolute paths are excluded from exported '+
    'CycloneDX data by default.';

  FIncludeAbsolutePaths := TCheckBox.Create(Self);
  FIncludeAbsolutePaths.Parent := Self;
  FIncludeAbsolutePaths.Align := alTop;
  FIncludeAbsolutePaths.BorderSpacing.Left := 12;
  FIncludeAbsolutePaths.BorderSpacing.Right := 12;
  FIncludeAbsolutePaths.BorderSpacing.Bottom := 8;
  FIncludeAbsolutePaths.Caption := 'Include absolute paths in exported SBOM';

  FFollowSymbolicLinks := TCheckBox.Create(Self);
  FFollowSymbolicLinks.Parent := Self;
  FFollowSymbolicLinks.Align := alTop;
  FFollowSymbolicLinks.BorderSpacing.Left := 12;
  FFollowSymbolicLinks.BorderSpacing.Right := 12;
  FFollowSymbolicLinks.BorderSpacing.Bottom := 8;
  FFollowSymbolicLinks.Caption := 'Follow symbolic links';
  FFollowSymbolicLinks.OnChange := @FollowLinksChanged;

  FAllowOutsideRoot := TCheckBox.Create(Self);
  FAllowOutsideRoot.Parent := Self;
  FAllowOutsideRoot.Align := alTop;
  FAllowOutsideRoot.BorderSpacing.Left := 34;
  FAllowOutsideRoot.BorderSpacing.Right := 12;
  FAllowOutsideRoot.BorderSpacing.Bottom := 8;
  FAllowOutsideRoot.Caption := 'Allow followed links to leave the selected root';

  FCalculateSHA256 := TCheckBox.Create(Self);
  FCalculateSHA256.Parent := Self;
  FCalculateSHA256.Align := alTop;
  FCalculateSHA256.BorderSpacing.Left := 12;
  FCalculateSHA256.BorderSpacing.Right := 12;
  FCalculateSHA256.BorderSpacing.Bottom := 12;
  FCalculateSHA256.Caption := 'Calculate SHA-256 for manifests and binaries';

  Description := TLabel.Create(Self);
  Description.Parent := Self;
  Description.Align := alTop;
  Description.BorderSpacing.Left := 12;
  Description.BorderSpacing.Right := 12;
  Description.BorderSpacing.Bottom := 5;
  Description.Caption := 'Ignore patterns (one per line)';

  FIgnorePatterns := TMemo.Create(Self);
  FIgnorePatterns.Parent := Self;
  FIgnorePatterns.Align := alClient;
  FIgnorePatterns.BorderSpacing.Left := 12;
  FIgnorePatterns.BorderSpacing.Right := 12;
  FIgnorePatterns.BorderSpacing.Bottom := 12;
  FIgnorePatterns.ScrollBars := ssAutoVertical;
  FIgnorePatterns.WordWrap := False;

  Buttons := TPanel.Create(Self);
  Buttons.Parent := Self;
  Buttons.Align := alBottom;
  Buttons.BevelOuter := bvNone;
  Buttons.Height := 50;

  CancelButton := TButton.Create(Self);
  CancelButton.Parent := Buttons;
  CancelButton.Align := alRight;
  CancelButton.Width := 96;
  CancelButton.BorderSpacing.Right := 12;
  CancelButton.BorderSpacing.Top := 8;
  CancelButton.BorderSpacing.Bottom := 8;
  CancelButton.Caption := 'Cancel';
  CancelButton.ModalResult := mrCancel;
  CancelButton.Cancel := True;

  OKButton := TButton.Create(Self);
  OKButton.Parent := Buttons;
  OKButton.Align := alRight;
  OKButton.Width := 96;
  OKButton.BorderSpacing.Right := 8;
  OKButton.BorderSpacing.Top := 8;
  OKButton.BorderSpacing.Bottom := 8;
  OKButton.Caption := 'Start scan';
  OKButton.ModalResult := mrOK;
  OKButton.Default := True;
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
