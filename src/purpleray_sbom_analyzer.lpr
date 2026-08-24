(**
  PurpleRay SBOM Analyzer desktop-application entry point.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Dispatches informational or headless scan commands before the LCL widgetset
  initializes. With no arguments, loads the embedded icon and form resources,
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
  uCommandLine, Interfaces, Forms, Graphics, uMainForm, uVersionInfo,
  uSplashForm;

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

var
  Splash: TSplashForm;

begin
  RequireDerivedFormResource := True;
  Application.Scaled := True;
  Application.Initialize;
  Application.Title := AppName + ' ' + DisplayVersion;
  LoadApplicationIcon;
  Splash := TSplashForm.CreateSplash(nil, DisplayVersion);
  try
    Splash.Show;
    Splash.SetStatus('Loading application...');
    { One deliberate pump so the widget set maps and paints the splash
      before the main window is constructed; later statuses only repaint. }
    Application.ProcessMessages;
    Application.CreateForm(TMainForm, MainForm);
    MainForm.WarmUpFeaturePages(Splash);
    Splash.SetStatus('Ready');
  finally
    Splash.Free;
  end;
  Application.Run;
end.
