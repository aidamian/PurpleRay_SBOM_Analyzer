{ Sprint 13 regressions: the self-contained About dialog, license content,
  and application-shell entry point. Tests are deterministic and offline. }

procedure TestEmbeddedLicenseContent;
var
  TrackedLicense, EmbeddedLicense: RawByteString;
begin
  TrackedLicense := S8ReadFileBytes(IncludeTrailingPathDelimiter(ProjectRoot) +
    'LICENSE');
  EmbeddedLicense := RawByteString(ApacheLicenseText);
  AssertTrue(Length(EmbeddedLicense) > 0,
    'the embedded Apache license is empty');
  AssertTrue(EmbeddedLicense = TrackedLicense,
    'the embedded Apache license differs byte-for-byte from LICENSE');
end;

procedure TestAboutDialogContract;
var
  AboutSource, AboutResource, ProjectSource, ShellSource, ShellResource,
    AboutButtonSection, LayoutBlock, GlyphBlock, KeyBlock,
    HandlerBlock: string;
begin
  AboutSource := S12ReadProjectFile('src/uAboutDialog.pas');
  AboutResource := S12ReadProjectFile('src/uAboutDialog.lfm');
  ProjectSource := S12ReadProjectFile('src/purpleray_sbom_analyzer.lpi');
  ShellSource := S12ReadProjectFile('src/uMainForm.pas');
  ShellResource := S12ReadProjectFile('src/uMainForm.lfm');
  AboutButtonSection := ExtractTextSection(ShellResource,
    'object AboutButton: TSpeedButton',
    'object RailToggleButton: TSpeedButton');
  LayoutBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.ApplyRailLayout;',
    'procedure TMainForm.RailToggleClicked');
  GlyphBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.AssignNavigationGlyphs;',
    'procedure TMainForm.AssignAnalyzerGlyph');
  KeyBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.FormKeyPressed',
    'procedure TMainForm.DashboardNavClicked');
  HandlerBlock := ExtractTextSection(ShellSource,
    'procedure TMainForm.AboutClicked',
    'procedure TMainForm.AnalyzerActivityChanged');

  AssertTrue((Pos('TAboutDialog = class(TForm)', AboutSource) > 0) and
    (Pos('{$R *.lfm}', AboutSource) > 0) and
    (Pos('inherited Create(TheOwner)', AboutSource) > 0) and
    (Pos('CreateNew', AboutSource) = 0) and
    (Pos('.Create(Self)', AboutSource) = 0),
    'the About dialog is not a conventional resource-backed Lazarus form');
  AssertTrue((Pos('object AboutDialog: TAboutDialog', AboutResource) > 0) and
    (Pos('Position = poOwnerFormCenter', AboutResource) > 0) and
    (Pos('BorderStyle = bsSizeable', AboutResource) > 0) and
    (Pos('ShowInTaskBar = stNever', AboutResource) > 0) and
    (Pos('Constraints.MinWidth = 480', AboutResource) > 0) and
    (Pos('Constraints.MinHeight = 360', AboutResource) > 0),
    'the About LFM lost its owner-centered sizeable layout contract');
  AssertTrue((Pos('<Filename Value="uAboutDialog.pas"/>', ProjectSource) > 0) and
    (Pos('<ComponentName Value="AboutDialog"/>', ProjectSource) > 0) and
    (Pos('<ResourceBaseClass Value="Form"/>', ProjectSource) > 0),
    'the About form is not registered in the Lazarus project');
  AssertTrue((Pos('ProductLabel.Caption := AppName', AboutSource) > 0) and
    (Pos('''Version '' + DisplayVersion', AboutSource) > 0) and
    (Pos('1.3.0', AboutSource) = 0) and
    (Pos('1.3.0', AboutResource) = 0),
    'the About dialog duplicates instead of consuming product identity');
  AssertTrue((Pos('object LicenseMemo: TMemo', AboutResource) > 0) and
    (Pos('ReadOnly = True', AboutResource) > 0) and
    (Pos('WordWrap = False', AboutResource) > 0) and
    (Pos('ScrollBars = ssAutoBoth', AboutResource) > 0) and
    (Pos('LicenseMemo.Text := ApacheLicenseText', AboutSource) > 0) and
    (Pos('LoadFromFile', AboutSource) = 0) and
    (Pos('FileExists', AboutSource) = 0),
    'the license text is incomplete, mutable, or runtime-path dependent');
  AssertTrue((Pos('object CloseButton: TButton', AboutResource) > 0) and
    (Pos('ModalResult = 11', AboutResource) > 0) and
    (Pos('Cancel = True', AboutResource) > 0) and
    (Pos('Dialog.ShowModal', AboutSource) > 0) and
    (Pos('Dialog.Free', AboutSource) > 0),
    'the About dialog does not close cleanly through button and Escape');

  AssertTrue((AboutButtonSection <> '') and
    (Pos('Align = alBottom', AboutButtonSection) > 0) and
    (Pos('Caption = ''About''', AboutButtonSection) > 0) and
    (Pos('OnClick = AboutClicked', AboutButtonSection) > 0) and
    (Pos('GroupIndex = 1', AboutButtonSection) = 0),
    'the About rail action is missing, unwired, or joined to feature selection');
  AssertTrue((Pos('Buttons[3] := AboutButton', LayoutBlock) > 0) and
    (Pos('AboutButton.Hint := ''About '' + AppName + '' (F1)''',
      LayoutBlock) > 0) and
    (Pos('AboutButton.Top := RailToggleButton.Top', LayoutBlock) > 0),
    'collapsed About visibility, hinting, or bottom stacking regressed');
  AssertTrue((Pos('AboutButton.Glyph.Assign(Glyph)', GlyphBlock) > 0) and
    (Pos('VK_F1', KeyBlock) > 0) and
    (Pos('AboutClicked(nil)', KeyBlock) > 0) and
    (Pos('TAboutDialog.Execute(Self)', HandlerBlock) > 0),
    'the About glyph, F1 shortcut, or modal route is incomplete');
end;

procedure TestAboutDialogCIContract;
var
  Workflow: string;
begin
  Workflow := S12ReadProjectFile('.github/workflows/build-release.yml');
  AssertTrue((Pos('xvfb xauth', Workflow) > 0) and
    (Pos('Build native About-dialog UI probe', Workflow) > 0) and
    (Pos('Verify native Linux About dialog', Workflow) > 0) and
    (Pos('build/ui-probe/about-dialog-ui-probe "$data_root"', Workflow) > 0),
    'the Linux About-dialog CI gate is incomplete');
  AssertTrue((Pos('Verify native Windows About dialog', Workflow) > 0) and
    (Pos('build/ui-probe/about-dialog-ui-probe.exe', Workflow) > 0),
    'the Windows About-dialog CI gate is incomplete');
end;

procedure RunSprint13RegressionTests;
begin
  RunTest('embedded Apache license content', @TestEmbeddedLicenseContent);
  RunTest('About dialog contract', @TestAboutDialogContract);
  RunTest('About dialog CI contract', @TestAboutDialogCIContract);
end;
