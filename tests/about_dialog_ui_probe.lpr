(**
  PurpleRay SBOM Analyzer About-dialog UI probe.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Opens the real application shell against an isolated data directory, invokes
  the real About rail action in expanded and collapsed modes, verifies the
  native modal controls and copied license text, then exits without human input.
*)
program about_dialog_ui_probe;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  Classes, Interfaces, Forms, Controls, StdCtrls, ExtCtrls, Graphics, Clipbrd,
  SysUtils, uMainForm, uAboutDialog, uLicenseContent, uVersionInfo;

{$R ../src/app_icon.res}

type
  TAboutDialogProbe = class
  private
    FMainForm: TMainForm;
    FInspector: TTimer;
    FInitialPageIndex: Integer;
    FDialogCount: Integer;
    FInspectionTicks: Integer;
    FDialogSeen: Boolean;
    FFailure: string;
    procedure Check(ACondition: Boolean; const AMessage: string);
    procedure Fail(const AMessage: string);
    procedure InspectDialog(Sender: TObject);
    procedure OpenAbout(Data: PtrInt);
    procedure Finish;
  public
    constructor Create(AMainForm: TMainForm);
    destructor Destroy; override;
    procedure Start;
    property Failure: string read FFailure;
  end;

function NormalizeLF(const AText: string): string;
begin
  Result := StringReplace(AText, #13#10, #10, [rfReplaceAll]);
  Result := StringReplace(Result, #13, #10, [rfReplaceAll]);
end;

function WithoutTerminalLF(const AText: string): string;
begin
  Result := NormalizeLF(AText);
  if (Result <> '') and (Result[Length(Result)] = #10) then
    SetLength(Result, Length(Result) - 1);
end;

procedure LoadApplicationIcon;
begin
  try
    Application.Icon.LoadFromResourceName(HInstance, 'MAINICON');
  except
    { The About behavior remains testable when an icon resource is unavailable. }
  end;
end;

constructor TAboutDialogProbe.Create(AMainForm: TMainForm);
begin
  inherited Create;
  FMainForm := AMainForm;
  FInitialPageIndex := FMainForm.WorkspaceNotebook.PageIndex;
  FInspector := TTimer.Create(nil);
  FInspector.Enabled := False;
  FInspector.Interval := 50;
  FInspector.OnTimer := @InspectDialog;
end;

destructor TAboutDialogProbe.Destroy;
begin
  FInspector.Free;
  inherited Destroy;
end;

procedure TAboutDialogProbe.Check(ACondition: Boolean;
  const AMessage: string);
begin
  if not ACondition then
    Fail(AMessage);
end;

procedure TAboutDialogProbe.Fail(const AMessage: string);
begin
  if FFailure = '' then
    FFailure := AMessage;
end;

procedure TAboutDialogProbe.InspectDialog(Sender: TObject);
var
  Dialog: TAboutDialog;
  Component: TComponent;
  Memo: TMemo;
  CloseButton: TButton;
begin
  Inc(FInspectionTicks);
  if not (Screen.ActiveCustomForm is TAboutDialog) then
  begin
    if FInspectionTicks >= 200 then
    begin
      Fail('About dialog did not become active within ten seconds');
      if (Screen.ActiveCustomForm <> nil) and
        (Screen.ActiveCustomForm <> FMainForm) then
        Screen.ActiveCustomForm.ModalResult := mrClose
      else
        Application.Terminate;
    end;
    Exit;
  end;

  Dialog := TAboutDialog(Screen.ActiveCustomForm);
  FDialogSeen := True;
  Inc(FDialogCount);
  try
    Check(Dialog.Caption = 'About ' + AppName,
      'About dialog caption differs');

    Component := Dialog.FindComponent('VersionLabel');
    Check(Component is TLabel, 'About version label is missing');
    if Component is TLabel then
      Check(Pos('Version ' + DisplayVersion, TLabel(Component).Caption) = 1,
        'About dialog version differs from DisplayVersion');

    Component := Dialog.FindComponent('LicenseMemo');
    Check(Component is TMemo, 'About license memo is missing');
    if Component is TMemo then
    begin
      Memo := TMemo(Component);
      Check(Memo.ReadOnly, 'About license memo is writable');
      Check(Memo.Enabled, 'About license memo is disabled');
      Check(not Memo.WordWrap, 'About license memo unexpectedly wraps lines');
      Check(Memo.ScrollBars = ssAutoBoth,
        'About license memo lacks both scroll bars');
      Check(NormalizeLF(Memo.Text) = ApacheLicenseText,
        'About license memo differs from the complete embedded license');
      Clipboard.AsText := '';
      Memo.SetFocus;
      Memo.SelectAll;
      Check(WithoutTerminalLF(Memo.SelText) =
        WithoutTerminalLF(ApacheLicenseText),
        'About license text could not be fully selected');
      Memo.CopyToClipboard;
      {$IFDEF Windows}
      Check(WithoutTerminalLF(Clipboard.AsText) =
        WithoutTerminalLF(ApacheLicenseText),
        'About license text could not be selected and copied');
      {$ENDIF}
      Memo.SelStart := 0;
      Memo.SelLength := 0;
    end;
  except
    on E: Exception do
      Fail('About dialog inspection raised ' + E.ClassName + ': ' + E.Message);
  end;

  Component := Dialog.FindComponent('CloseButton');
  if Component is TButton then
  begin
    CloseButton := TButton(Component);
    Check(CloseButton.Cancel, 'About Close button does not handle Escape');
    Check(CloseButton.ModalResult = mrClose,
      'About Close button has the wrong modal result');
    CloseButton.Click;
  end
  else
  begin
    Fail('About Close button is missing');
    Dialog.ModalResult := mrClose;
  end;
end;

procedure TAboutDialogProbe.OpenAbout(Data: PtrInt);
begin
  FDialogSeen := False;
  FInspectionTicks := 0;
  FInspector.Enabled := True;
  try
    FMainForm.AboutButton.Click;
  except
    on E: Exception do
      Fail('About action raised ' + E.ClassName + ': ' + E.Message);
  end;
  FInspector.Enabled := False;

  Check(FDialogSeen, 'About action returned without a modal dialog');
  Check(FMainForm.WorkspaceNotebook.PageIndex = FInitialPageIndex,
    'About action changed the active feature');
  if (FFailure = '') and (FDialogCount = 1) then
  begin
    FMainForm.RailToggleButton.Click;
    Check(FMainForm.AboutButton.Visible and FMainForm.AboutButton.Enabled,
      'collapsed About action is not available');
    Check(not FMainForm.AboutButton.ShowCaption,
      'collapsed About action still shows its caption');
    Check((FMainForm.AboutButton.Hint <> '') and
      (FMainForm.AboutButton.Glyph.Width > 0),
      'collapsed About action lacks its hint or glyph');
    if FFailure = '' then
    begin
      Application.QueueAsyncCall(@OpenAbout, 0);
      Exit;
    end;
  end;
  Finish;
end;

procedure TAboutDialogProbe.Finish;
begin
  if FFailure = '' then
    WriteLn('[PASS] About dialog opened twice with the complete read-only license')
  else
    WriteLn(StdErr, '[FAIL] ', FFailure);
  FMainForm.Close;
  Application.Terminate;
end;

procedure TAboutDialogProbe.Start;
begin
  Check(FMainForm.Caption = AppName + ' ' + DisplayVersion,
    'main window title differs from DisplayVersion');
  Check(FMainForm.AboutButton.Visible and FMainForm.AboutButton.Enabled and
    FMainForm.AboutButton.ShowCaption,
    'expanded About action is not visible and enabled');
  if FFailure <> '' then
  begin
    Finish;
    Exit;
  end;
  Application.QueueAsyncCall(@OpenAbout, 0);
end;

var
  DataDirectory: string;
  Probe: TAboutDialogProbe;

begin
  if ParamCount <> 1 then
  begin
    WriteLn(StdErr, 'Usage: about-dialog-ui-probe DATA-DIRECTORY');
    Halt(2);
  end;
  DataDirectory := ExpandFileName(ParamStr(1));
  if not ForceDirectories(DataDirectory) then
  begin
    WriteLn(StdErr, 'Unable to create isolated data directory');
    Halt(2);
  end;

  RequireDerivedFormResource := True;
  Application.Scaled := True;
  Application.Initialize;
  Application.Title := AppName + ' ' + DisplayVersion;
  LoadApplicationIcon;
  MainForm := TMainForm.CreateForDataDirectory(Application, DataDirectory);
  MainForm.Show;
  Probe := TAboutDialogProbe.Create(MainForm);
  try
    Probe.Start;
    Application.Run;
    if Probe.Failure <> '' then
      Halt(1);
  finally
    Probe.Free;
  end;
end.
