program sbom_analyzer;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  Interfaces, Forms, Graphics, uMainForm, uVersionInfo;

{$R app_icon.res}

procedure LoadApplicationIcon;
begin
  try
    Application.Icon.LoadFromResourceName(HInstance, 'MAINICON');
  except
    { A missing platform icon must not prevent startup. }
  end;
end;

begin
  RequireDerivedFormResource := False;
  Application.Scaled := True;
  Application.Initialize;
  Application.Title := AppName;
  LoadApplicationIcon;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
