(**
  PurpleRay SBOM Analyzer About dialog.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents the compiled product identity, version, project address, and the
  complete Apache-2.0 license text in one native, read-only modal dialog.

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
unit uAboutDialog;

{$mode objfpc}{$H+}

interface

uses
  Classes, Forms, Controls, StdCtrls, ExtCtrls;

type
  TAboutDialog = class(TForm)
  published
    HeaderPanel: TPanel;
    ApplicationIcon: TImage;
    ProductLabel: TLabel;
    VersionLabel: TLabel;
    CopyrightLabel: TLabel;
    HomepageLabel: TLabel;
    ButtonPanel: TPanel;
    CloseButton: TButton;
    ContentPanel: TPanel;
    LicenseLabel: TLabel;
    LicenseMemo: TMemo;
  public
    {**
      Loads and initializes the owner-centered LFM-backed About dialog.

      Parameters
      ----------
      TheOwner
        Component that owns the modal dialog.

      Returns
      -------
      TAboutDialog
        Initialized dialog containing the complete embedded license.

      Raises
      ------
      EResNotFound, EReadError
        May propagate if the embedded form resource cannot be loaded.
      EOutOfMemory
        Propagated when the embedded text cannot be allocated.
    }
    constructor Create(TheOwner: TComponent); override;

    {**
      Opens and releases one modal About dialog.

      Parameters
      ----------
      AOwner
        Component that owns and centers the dialog.

      Returns
      -------
      None

      Raises
      ------
      EResNotFound, EReadError
        May propagate if the embedded form resource cannot be loaded.
      EOutOfMemory
        Propagated if dialog construction fails.
    }
    class procedure Execute(AOwner: TComponent); static;
  end;

implementation

uses
  uVersionInfo, uLicenseContent;

{$R *.lfm}

constructor TAboutDialog.Create(TheOwner: TComponent);
var
  VersionText: string;
begin
  inherited Create(TheOwner);
  Caption := 'About ' + AppName;
  if Application.Icon <> nil then
    ApplicationIcon.Picture.Icon.Assign(Application.Icon);
  ProductLabel.Caption := AppName;

  VersionText := 'Version ' + DisplayVersion;
  if AbbreviatedCommit <> '' then
    VersionText := VersionText + ' (' + AbbreviatedCommit + ')';
  VersionLabel.Caption := VersionText;
  LicenseMemo.Text := ApacheLicenseText;
  LicenseMemo.SelStart := 0;
end;

class procedure TAboutDialog.Execute(AOwner: TComponent);
var
  Dialog: TAboutDialog;
begin
  Dialog := TAboutDialog.Create(AOwner);
  try
    Dialog.ShowModal;
  finally
    Dialog.Free;
  end;
end;

end.
