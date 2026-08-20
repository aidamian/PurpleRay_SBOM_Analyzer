(**
  PurpleRay SBOM Analyzer scan-settings dialog unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents and validates the target, privacy, author, symlink, hashing, and
  ignore options before a scan begins.

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
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, Dialogs, uModels;

type
  TScanSettingsDialog = class(TForm)
  published
    SettingsContentPanel: TPanel;
    DescriptionTopSpacer: TPanel;
    DescriptionLabel: TLabel;
    TargetFolderLabel: TLabel;
    FTargetFolder: TEdit;
    FIncludeAbsolutePaths: TCheckBox;
    FFollowSymbolicLinks: TCheckBox;
    FAllowOutsideRoot: TCheckBox;
    FRememberPrivacyChoices: TCheckBox;
    FCalculateSHA256: TCheckBox;
    AuthorPersistenceLabel: TLabel;
    AuthorOrganizationPanel: TPanel;
    AuthorOrganizationLabel: TLabel;
    FAuthorOrganization: TEdit;
    AuthorEmailPanel: TPanel;
    AuthorEmailLabel: TLabel;
    FAuthorEmail: TEdit;
    IgnoreHeaderPanel: TPanel;
    IgnorePatternsLabel: TLabel;
    RestoreDefaultsButton: TButton;
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

    {**
      Restores the default ignore-pattern list without changing other fields.

      Parameters
      ----------
      Sender
        LCL control that raised the event; the value is not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        May propagate if the temporary defaults or memo lines cannot be
        allocated.
    }
    procedure RestoreDefaultsClicked(Sender: TObject);

    {**
      Validates optional author contact data before allowing the dialog to close.

      Parameters
      ----------
      Sender
        Start button that raised the event; the value is not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
        Invalid input is reported in a user-visible dialog and focus returns to
        the email field.
    }
    procedure StartScanClicked(Sender: TObject);
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
      ATargetDirectory
        Folder to identify in the dialog caption and read-only target field.

      Returns
      -------
      Boolean
        True when the user confirms and ASettings was updated.

      Raises
      ------
      EArgumentNilException
        Raised when ASettings is nil.
      EResNotFound, EReadError
        May propagate if form creation fails.
    }
    class function Execute(ASettings: TScanSettings;
      const ATargetDirectory: string): Boolean;
  end;

implementation

{$R *.lfm}

{**
  Derives a single-line root name suitable for the native window caption.

  Parameters
  ----------
  ATargetDirectory
    Target path whose final path component should identify the dialog.

  Returns
  -------
  string
    Sanitized final component, the original root path, or ``selected folder``
    when no path was supplied.

  Raises
  ------
  None
}
function SafeTargetRootName(const ATargetDirectory: string): string;
var
  I: Integer;
  PathValue: string;
begin
  PathValue := Trim(ATargetDirectory);
  while (PathValue <> '') and
    IsPathDelimiter(PathValue, Length(PathValue)) do
    Delete(PathValue, Length(PathValue), 1);
  Result := ExtractFileName(PathValue);
  if Result = '' then
    Result := Trim(ATargetDirectory);
  for I := 1 to Length(Result) do
    if (Ord(Result[I]) < 32) or (Ord(Result[I]) = 127) then
      Result[I] := ' ';
  Result := Trim(Result);
  if Result = '' then
    Result := 'selected folder';
end;

{**
  Applies a conservative common-address check to optional author email text.

  Parameters
  ----------
  AValue
    Nonblank candidate email address after surrounding whitespace is ignored.

  Returns
  -------
  Boolean
    True for a conventional ASCII mailbox and dotted DNS domain.

  Raises
  ------
  None
}
function IsPlausibleEmail(const AValue: string): Boolean;
const
  AllowedLocalCharacters =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' +
    '.!#$%&''*+-/=?^_`{|}~';
  AllowedDomainCharacters =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.';
var
  AtPosition, I: Integer;
  DomainPart, EmailValue, LocalPart: string;
begin
  Result := False;
  EmailValue := Trim(AValue);
  if (EmailValue = '') or (Length(EmailValue) > 254) then
    Exit;
  AtPosition := Pos('@', EmailValue);
  if (AtPosition <= 1) or (AtPosition >= Length(EmailValue)) or
    (Pos('@', Copy(EmailValue, AtPosition + 1, MaxInt)) > 0) then
    Exit;
  LocalPart := Copy(EmailValue, 1, AtPosition - 1);
  DomainPart := Copy(EmailValue, AtPosition + 1, MaxInt);
  if (Length(LocalPart) > 64) or (LocalPart[1] = '.') or
    (LocalPart[Length(LocalPart)] = '.') or (Pos('..', LocalPart) > 0) then
    Exit;
  for I := 1 to Length(LocalPart) do
    if Pos(LocalPart[I], AllowedLocalCharacters) = 0 then
      Exit;
  if (Pos('.', DomainPart) = 0) or (DomainPart[1] in ['.', '-']) or
    (DomainPart[Length(DomainPart)] in ['.', '-']) or
    (Pos('..', DomainPart) > 0) or (Pos('.-', DomainPart) > 0) or
    (Pos('-.', DomainPart) > 0) then
    Exit;
  for I := 1 to Length(DomainPart) do
    if Pos(DomainPart[I], AllowedDomainCharacters) = 0 then
      Exit;
  Result := True;
end;

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

procedure TScanSettingsDialog.RestoreDefaultsClicked(Sender: TObject);
var
  Defaults: TScanSettings;
begin
  Defaults := TScanSettings.Create;
  try
    FIgnorePatterns.Lines.Assign(Defaults.IgnorePatterns);
  finally
    Defaults.Free;
  end;
end;

procedure TScanSettingsDialog.StartScanClicked(Sender: TObject);
begin
  if (Trim(FAuthorEmail.Text) <> '') and
    not IsPlausibleEmail(FAuthorEmail.Text) then
  begin
    ModalResult := mrNone;
    MessageDlg('Invalid author email',
      'Enter a conventional email address such as name@example.com, or leave ' +
      'the optional email field blank.', mtError, [mbOK], 0);
    if FAuthorEmail.CanFocus then
    begin
      FAuthorEmail.SetFocus;
      FAuthorEmail.SelectAll;
    end;
  end;
end;

class function TScanSettingsDialog.Execute(ASettings: TScanSettings;
  const ATargetDirectory: string): Boolean;
var
  Dialog: TScanSettingsDialog;
  I: Integer;
begin
  if ASettings = nil then
    raise EArgumentNilException.Create('ASettings must not be nil');
  Dialog := TScanSettingsDialog.Create(nil);
  try
    Dialog.Caption := 'Scan settings — ' +
      SafeTargetRootName(ATargetDirectory);
    Dialog.FTargetFolder.Text := ATargetDirectory;
    Dialog.FIncludeAbsolutePaths.Checked := ASettings.IncludeAbsolutePaths;
    Dialog.FFollowSymbolicLinks.Checked := ASettings.FollowSymbolicLinks;
    Dialog.FAllowOutsideRoot.Checked := ASettings.AllowOutsideRoot;
    Dialog.FRememberPrivacyChoices.Checked :=
      ASettings.RememberPrivacyChoices;
    Dialog.FCalculateSHA256.Checked := ASettings.CalculateSHA256;
    Dialog.FAuthorOrganization.Text := ASettings.SBOMAuthorOrganization;
    Dialog.FAuthorEmail.Text := ASettings.SBOMAuthorEmail;
    Dialog.FIgnorePatterns.Lines.Assign(ASettings.IgnorePatterns);
    Dialog.FollowLinksChanged(nil);
    Result := Dialog.ShowModal = mrOK;
    if Result then
    begin
      ASettings.IncludeAbsolutePaths := Dialog.FIncludeAbsolutePaths.Checked;
      ASettings.FollowSymbolicLinks := Dialog.FFollowSymbolicLinks.Checked;
      ASettings.AllowOutsideRoot := Dialog.FAllowOutsideRoot.Checked;
      ASettings.RememberPrivacyChoices :=
        Dialog.FRememberPrivacyChoices.Checked;
      ASettings.CalculateSHA256 := Dialog.FCalculateSHA256.Checked;
      ASettings.SBOMAuthorOrganization :=
        Trim(Dialog.FAuthorOrganization.Text);
      ASettings.SBOMAuthorEmail := Trim(Dialog.FAuthorEmail.Text);
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
