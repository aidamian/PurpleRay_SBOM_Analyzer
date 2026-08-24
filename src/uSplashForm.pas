(**
  PurpleRay SBOM Analyzer startup splash.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Borderless, stay-on-top splash shown while the application shell is
  constructed and its feature pages are realized. It is code-built (no LFM),
  carries only the brand mark, product name, version, a status line, and a
  marquee bar, and is freed before the main window appears.

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
unit uSplashForm;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls, Graphics;

type
  TSplashForm = class(TForm)
  private
    FIconImage: TImage;
    FTitleLabel: TLabel;
    FSubtitleLabel: TLabel;
    FVersionLabel: TLabel;
    FStatusLabel: TLabel;
    FProgressBar: TProgressBar;

    {**
      Selects the embedded icon frame that best fills the splash icon box.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SelectIconFrame;
  protected
    {**
      Reselects the icon frame after LCL has DPI-scaled the icon box.

      Parameters
      ----------
      AMode
        Layout adjustment policy supplied by the LCL.
      AFromPPI
        Source pixels per inch.
      AToPPI
        Target pixels per inch.
      AOldFormWidth
        Form width before adjustment.
      ANewFormWidth
        Form width after adjustment.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure AutoAdjustLayout(AMode: TLayoutAdjustmentPolicy;
      const AFromPPI, AToPPI, AOldFormWidth, ANewFormWidth: Integer);
      override;
  public
    {**
      Builds the splash window centered on the screen.

      Parameters
      ----------
      TheOwner
        Optional LCL component owner.
      AVersionText
        Display version placed under the product name.

      Returns
      -------
      TSplashForm
        Constructed, not yet visible splash.

      Raises
      ------
      EOutOfMemory
        Propagated when a control cannot be allocated.
    }
    constructor CreateSplash(TheOwner: TComponent; const AVersionText: string);

    {**
      Updates the status line and repaints it synchronously.

      This deliberately does not pump the message queue: the caller pumps
      once after the splash is first shown, so later status changes never
      dispatch unrelated input, timers, or shutdown messages mid-startup.

      Parameters
      ----------
      AText
        Short progress message, for example "Preparing SBOM Analyzer...".

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SetStatus(const AText: string);
  end;

implementation

const
  SplashWidth = 440;
  SplashHeight = 236;
  SplashIconSize = 96;

constructor TSplashForm.CreateSplash(TheOwner: TComponent;
  const AVersionText: string);
var
  Frame: TPanel;
begin
  inherited CreateNew(TheOwner);
  BorderStyle := bsNone;
  FormStyle := fsSplash;
  Position := poScreenCenter;
  ShowInTaskBar := stNever;
  Width := Scale96ToForm(SplashWidth);
  Height := Scale96ToForm(SplashHeight);
  Caption := 'PurpleRay SBOM Analyzer';

  Frame := TPanel.Create(Self);
  Frame.Parent := Self;
  Frame.Align := alClient;
  Frame.BevelOuter := bvNone;
  Frame.BorderStyle := bsSingle;

  FIconImage := TImage.Create(Self);
  FIconImage.Parent := Frame;
  FIconImage.SetBounds(Scale96ToForm(28), Scale96ToForm(28),
    Scale96ToForm(SplashIconSize), Scale96ToForm(SplashIconSize));
  FIconImage.Center := True;
  FIconImage.Proportional := True;
  FIconImage.Stretch := True;
  if Application.Icon <> nil then
  begin
    FIconImage.Picture.Icon.Assign(Application.Icon);
    SelectIconFrame;
  end;

  FTitleLabel := TLabel.Create(Self);
  FTitleLabel.Parent := Frame;
  FTitleLabel.Caption := 'PurpleRay';
  FTitleLabel.Font.Style := [fsBold];
  FTitleLabel.Font.Height := -Scale96ToForm(28);
  FTitleLabel.Left := Scale96ToForm(148);
  FTitleLabel.Top := Scale96ToForm(34);

  FSubtitleLabel := TLabel.Create(Self);
  FSubtitleLabel.Parent := Frame;
  FSubtitleLabel.Caption := 'SBOM Analyzer';
  FSubtitleLabel.Font.Height := -Scale96ToForm(16);
  FSubtitleLabel.Font.Color := clGrayText;
  FSubtitleLabel.Left := Scale96ToForm(150);
  FSubtitleLabel.Top := Scale96ToForm(74);

  FVersionLabel := TLabel.Create(Self);
  FVersionLabel.Parent := Frame;
  FVersionLabel.Caption := AVersionText;
  FVersionLabel.Font.Color := clGrayText;
  FVersionLabel.Left := Scale96ToForm(150);
  FVersionLabel.Top := Scale96ToForm(100);

  FStatusLabel := TLabel.Create(Self);
  FStatusLabel.Parent := Frame;
  FStatusLabel.Caption := 'Loading...';
  FStatusLabel.Left := Scale96ToForm(28);
  FStatusLabel.Top := Scale96ToForm(164);
  FStatusLabel.AutoSize := False;
  FStatusLabel.Width := Scale96ToForm(SplashWidth - 56);
  FStatusLabel.Height := Scale96ToForm(20);

  FProgressBar := TProgressBar.Create(Self);
  FProgressBar.Parent := Frame;
  FProgressBar.SetBounds(Scale96ToForm(28), Scale96ToForm(192),
    Scale96ToForm(SplashWidth - 56), Scale96ToForm(14));
  FProgressBar.Style := pbstMarquee;
end;

procedure TSplashForm.SelectIconFrame;
var
  SplashIcon: TIcon;
  I, BestIndex, BestSize, Target, Size: Integer;
begin
  SplashIcon := FIconImage.Picture.Icon;
  if (SplashIcon = nil) or (SplashIcon.Count = 0) then
    Exit;
  Target := FIconImage.Width;
  BestIndex := 0;
  BestSize := 0;
  for I := 0 to SplashIcon.Count - 1 do
  begin
    SplashIcon.Current := I;
    Size := SplashIcon.Width;
    if ((Size >= Target) and ((BestSize < Target) or (Size < BestSize))) or
      ((Size < Target) and (BestSize < Target) and (Size > BestSize)) then
    begin
      BestIndex := I;
      BestSize := Size;
    end;
  end;
  SplashIcon.Current := BestIndex;
end;

procedure TSplashForm.AutoAdjustLayout(AMode: TLayoutAdjustmentPolicy;
  const AFromPPI, AToPPI, AOldFormWidth, ANewFormWidth: Integer);
begin
  inherited AutoAdjustLayout(AMode, AFromPPI, AToPPI, AOldFormWidth,
    ANewFormWidth);
  if AMode = lapAutoAdjustForDPI then
    SelectIconFrame;
end;

procedure TSplashForm.SetStatus(const AText: string);
begin
  FStatusLabel.Caption := AText;
  FStatusLabel.Update;
  Update;
end;

end.
