unit uScanSettingsDialog;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, uModels;

type
  TScanSettingsDialog = class(TForm)
  published
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
    procedure FollowLinksChanged(Sender: TObject);
  public
    constructor Create(TheOwner: Classes.TComponent); override;
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
