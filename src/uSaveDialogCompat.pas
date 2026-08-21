(**
  PurpleRay SBOM Analyzer save-dialog compatibility unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Exposes the application's save and directory-dialog classes. The GTK3
  specializations keep the standard LCL API while supplying a complete
  widgetset class for each dialog subclass. This avoids the GTK3
  dynamic-widgetset VMT gap that leaves inherited open-dialog helper slots
  unavailable. Other widgetsets use the standard LCL dialog classes directly.

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
unit uSaveDialogCompat;

{$mode objfpc}{$H+}

interface

uses
  Dialogs;

type
  {$IFDEF LCLGTK3}
  {**
    Provides a private GTK3 widgetset-registration target for save dialogs.

    The class intentionally adds no behavior. Its distinct identity lets the
    application register a complete GTK3 widgetset VMT without replacing the
    process-wide registration for the LCL TSaveDialog class.
  *}
  TPurpleRaySaveDialog = class(TSaveDialog);

  {** Provides the equivalent private GTK3 target for directory selection. *}
  TPurpleRaySelectDirectoryDialog = class(TSelectDirectoryDialog);
  {$ELSE}
  TPurpleRaySaveDialog = TSaveDialog;
  TPurpleRaySelectDirectoryDialog = TSelectDirectoryDialog;
  {$ENDIF}

implementation

{$IFDEF LCLGTK3}

uses
  Gtk3WSDialogs, WSLCLClasses;

type
  {**
    Supplies the GTK3 open-dialog helpers and common-dialog lifecycle methods
    in one concrete widgetset VMT.
  *}
  TPurpleRayGTK3WSFileDialog = class(TGtk3WSOpenDialog)
  published
    {** Shows the native modal GTK3 chooser through the common-dialog backend. *}
    class procedure ShowModal(const ACommonDialog: TCommonDialog); override;

    {** Releases the native GTK3 chooser through the common-dialog backend. *}
    class procedure DestroyHandle(const ACommonDialog: TCommonDialog); override;
  end;

class procedure TPurpleRayGTK3WSFileDialog.ShowModal(
  const ACommonDialog: TCommonDialog);
begin
  TGtk3WSCommonDialog.ShowModal(ACommonDialog);
end;

class procedure TPurpleRayGTK3WSFileDialog.DestroyHandle(
  const ACommonDialog: TCommonDialog);
begin
  TGtk3WSCommonDialog.DestroyHandle(ACommonDialog);
end;

initialization
  RegisterWSComponent(TPurpleRaySaveDialog, TPurpleRayGTK3WSFileDialog);
  RegisterWSComponent(TPurpleRaySelectDirectoryDialog,
    TPurpleRayGTK3WSFileDialog);

{$ENDIF}

end.
