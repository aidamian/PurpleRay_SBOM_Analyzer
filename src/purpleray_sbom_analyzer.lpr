(**
  PurpleRay SBOM Analyzer desktop-application entry point.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Initializes the LCL application, loads the embedded icon and form resources,
  creates the main window, and enters the native event loop.

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
program purpleray_sbom_analyzer;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  Interfaces, Forms, Graphics, uMainForm, uVersionInfo;

{$R *.res}
{$R app_icon.res}

{**
  Loads the embedded MAINICON resource into the LCL application object.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
    A missing or incompatible icon is intentionally ignored so startup can
    continue on every widgetset.
}
procedure LoadApplicationIcon;
begin
  try
    Application.Icon.LoadFromResourceName(HInstance, 'MAINICON');
  except
    { A missing platform icon must not prevent startup. }
  end;
end;

begin
  RequireDerivedFormResource := True;
  Application.Scaled := True;
  Application.Initialize;
  Application.Title := AppName;
  LoadApplicationIcon;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
