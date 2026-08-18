unit uMainForm;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, ComCtrls, Dialogs,
  Menus, Contnrs, uModels, uTaskHistory, uSettingsStore, uScanWorker,
  uScanEngine;

type
  TMainForm = class(TForm)
  private
    FTasks: TObjectList;
    FHistoryStore: TTaskHistoryStore;
    FSettingsStore: TSettingsStore;
    FSettings: TScanSettings;
    FWorker: TScanWorker;
    FActiveTaskID: string;
    FClosing: Boolean;
    FStartupWarning: string;
    FUpdatingDetails: Boolean;
    FComponentSortColumn: Integer;
    FComponentSortAscending: Boolean;
    FArtifactSortColumn: Integer;
    FArtifactSortAscending: Boolean;

    FNewButton: TButton;
    FCancelButton: TButton;
    FRescanButton: TButton;
    FRefreshButton: TButton;
    FExportButton: TButton;
    FTaskList: TListView;
    FEmptyLabel: TLabel;
    FPages: TPageControl;
    FSummaryMemo: TMemo;
    FComponentSearch: TEdit;
    FComponentEcosystem: TComboBox;
    FComponentStatus: TComboBox;
    FComponentList: TListView;
    FArtifactSearch: TEdit;
    FArtifactType: TComboBox;
    FArtifactStatus: TComboBox;
    FArtifactList: TListView;
    FSBOMMemo: TMemo;
    FMessagesMemo: TMemo;
    FProgressBar: TProgressBar;
    FProgressPath: TLabel;
    FProgressStats: TLabel;
    FCopyMenu: TPopupMenu;

    procedure BuildUI;
    procedure BuildHeader(AParent: TWinControl);
    procedure BuildTaskPane(AParent: TWinControl);
    procedure BuildDetailPane(AParent: TWinControl);
    procedure BuildStatusBar(AParent: TWinControl);
    function AddPage(const ACaption: string): TTabSheet;
    procedure ConfigureList(AList: TListView);
    procedure AddColumn(AList: TListView; const ACaption: string;
      AWidth: Integer);
    procedure LoadState;
    procedure SaveHistory;
    procedure RefreshTaskRows;
    procedure UpdateTaskRow(ATask: TScanTask);
    procedure SelectTask(ATask: TScanTask);
    function SelectedTask: TScanTask;
    function FindTask(const AID: string): TScanTask;
    function FindTaskItem(ATask: TScanTask): TListItem;
    procedure UpdateDetails;
    procedure PopulateComponentFilters(ATask: TScanTask);
    procedure PopulateArtifactFilters(ATask: TScanTask);
    procedure PopulateComponents(ATask: TScanTask);
    procedure PopulateArtifacts(ATask: TScanTask);
    procedure PopulateSummary(ATask: TScanTask);
    procedure PopulateSBOM(ATask: TScanTask);
    procedure PopulateMessages(ATask: TScanTask);
    function ComponentArtifactStatus(ATask: TScanTask;
      AComponent: uModels.TComponent): string;
    procedure UpdateButtons;
    procedure FreeFinishedWorker;
    procedure StartScan(const ADirectory: string);
    procedure ConfigureAndStartScan(const ADirectory: string);
    procedure ShowError(const AMessage: string);

    procedure FormShown(Sender: TObject);
    procedure FormCloseRequested(Sender: TObject; var CanClose: Boolean);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of string);
    procedure FormKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure NewScanClicked(Sender: TObject);
    procedure CancelClicked(Sender: TObject);
    procedure RescanClicked(Sender: TObject);
    procedure RefreshClicked(Sender: TObject);
    procedure ExportClicked(Sender: TObject);
    procedure TaskSelected(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure FiltersChanged(Sender: TObject);
    procedure ComponentColumnClicked(Sender: TObject; Column: TListColumn);
    procedure ArtifactColumnClicked(Sender: TObject; Column: TListColumn);
    procedure ListKeyPressed(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure CopySelectedClicked(Sender: TObject);
    procedure WorkerProgress(Sender: TObject; const AProgress: TScanProgress);
    procedure WorkerComplete(Sender: TObject; AResult: TScanTask);
  public
    constructor Create(TheOwner: Classes.TComponent); override;
    destructor Destroy; override;
  end;

var
  MainForm: TMainForm;

implementation

uses
  Clipbrd, LCLType, Graphics, uVersionInfo, uTimeUtils, uPlatform,
  uScanSettingsDialog;

function DisplayTimestamp(const AValue: string): string;
begin
  Result := StringReplace(AValue, 'T', ' ', []);
  if Pos('.', Result) > 0 then
    Result := Copy(Result, 1, Pos('.', Result) - 1);
  if (Length(Result) > 0) and (Result[Length(Result)] = 'Z') then
    Delete(Result, Length(Result), 1);
end;

function ContainsTextValue(const AHaystack, ANeedle: string): Boolean;
begin
  Result := (ANeedle = '') or
    (Pos(LowerCase(ANeedle), LowerCase(AHaystack)) > 0);
end;

function PrimaryShortcut(Shift: TShiftState): Boolean;
begin
  {$IFDEF Darwin}
  Result := ssMeta in Shift;
  {$ELSE}
  Result := ssCtrl in Shift;
  {$ENDIF}
end;

constructor TMainForm.Create(TheOwner: Classes.TComponent);
begin
  inherited CreateNew(TheOwner, 1);
  FTasks := TObjectList.Create(True);
  FHistoryStore := TTaskHistoryStore.Create;
  FSettingsStore := TSettingsStore.Create;
  FComponentSortColumn := 0;
  FComponentSortAscending := True;
  FArtifactSortColumn := 0;
  FArtifactSortAscending := True;
  BuildUI;
  LoadState;
end;

destructor TMainForm.Destroy;
begin
  FClosing := True;
  if FWorker <> nil then
  begin
    FWorker.OnProgress := nil;
    FWorker.OnComplete := nil;
    FWorker.Cancel;
    FWorker.WaitFor;
    FWorker.Free;
  end;
  FSettings.Free;
  FSettingsStore.Free;
  FHistoryStore.Free;
  FTasks.Free;
  inherited Destroy;
end;

procedure TMainForm.BuildUI;
var
  Header, Content, LeftPane, RightPane: TPanel;
  Splitter: TSplitter;
begin
  Caption := AppName + ' ' + DisplayVersion;
  Position := poScreenCenter;
  Width := 1240;
  Height := 780;
  Constraints.MinWidth := 900;
  Constraints.MinHeight := 600;
  KeyPreview := True;
  AllowDropFiles := True;
  OnShow := @FormShown;
  OnCloseQuery := @FormCloseRequested;
  OnDropFiles := @FormDropFiles;
  OnKeyDown := @FormKeyPressed;

  Header := TPanel.Create(Self);
  Header.Parent := Self;
  Header.Align := alTop;
  Header.Height := 62;
  Header.BevelOuter := bvNone;
  Header.BorderSpacing.Bottom := 1;
  BuildHeader(Header);

  BuildStatusBar(Self);

  Content := TPanel.Create(Self);
  Content.Parent := Self;
  Content.Align := alClient;
  Content.BevelOuter := bvNone;

  LeftPane := TPanel.Create(Self);
  LeftPane.Parent := Content;
  LeftPane.Align := alLeft;
  LeftPane.Width := 390;
  LeftPane.Constraints.MinWidth := 280;
  LeftPane.BevelOuter := bvNone;
  BuildTaskPane(LeftPane);

  Splitter := TSplitter.Create(Self);
  Splitter.Parent := Content;
  Splitter.Align := alLeft;
  Splitter.Width := 5;

  RightPane := TPanel.Create(Self);
  RightPane.Parent := Content;
  RightPane.Align := alClient;
  RightPane.BevelOuter := bvNone;
  BuildDetailPane(RightPane);
end;

procedure TMainForm.BuildHeader(AParent: TWinControl);
var
  TitleLabel: TLabel;

  function HeaderButton(const ACaption: string; AHandler: TNotifyEvent;
    AWidth: Integer): TButton;
  begin
    Result := TButton.Create(Self);
    Result.Parent := AParent;
    Result.Align := alRight;
    Result.Width := AWidth;
    Result.BorderSpacing.Right := 8;
    Result.BorderSpacing.Top := 13;
    Result.BorderSpacing.Bottom := 13;
    Result.Caption := ACaption;
    Result.OnClick := AHandler;
  end;

begin
  FExportButton := HeaderButton('Export SBOM', @ExportClicked, 112);
  FRefreshButton := HeaderButton('Refresh', @RefreshClicked, 88);
  FRescanButton := HeaderButton('Rescan', @RescanClicked, 88);
  FCancelButton := HeaderButton('Cancel', @CancelClicked, 88);
  FNewButton := HeaderButton('New Scan', @NewScanClicked, 100);

  TitleLabel := TLabel.Create(Self);
  TitleLabel.Parent := AParent;
  TitleLabel.Align := alClient;
  TitleLabel.Layout := tlCenter;
  TitleLabel.BorderSpacing.Left := 16;
  TitleLabel.Font.Style := [fsBold];
  TitleLabel.Font.Size := TitleLabel.Font.Size + 4;
  TitleLabel.Caption := AppName + '  ' + DisplayVersion;
end;

procedure TMainForm.ConfigureList(AList: TListView);
begin
  AList.ViewStyle := vsReport;
  AList.ReadOnly := True;
  AList.RowSelect := True;
  AList.HideSelection := False;
  AList.MultiSelect := False;
  AList.GridLines := True;
end;

procedure TMainForm.AddColumn(AList: TListView; const ACaption: string;
  AWidth: Integer);
var
  Column: TListColumn;
begin
  Column := AList.Columns.Add;
  Column.Caption := ACaption;
  Column.Width := AWidth;
end;

procedure TMainForm.BuildTaskPane(AParent: TWinControl);
var
  Heading: TLabel;
begin
  Heading := TLabel.Create(Self);
  Heading.Parent := AParent;
  Heading.Align := alTop;
  Heading.AutoSize := False;
  Heading.Height := 38;
  Heading.Layout := tlCenter;
  Heading.BorderSpacing.Left := 10;
  Heading.Font.Style := [fsBold];
  Heading.Caption := 'Task history';

  FEmptyLabel := TLabel.Create(Self);
  FEmptyLabel.Parent := AParent;
  FEmptyLabel.Align := alTop;
  FEmptyLabel.AutoSize := False;
  FEmptyLabel.Height := 48;
  FEmptyLabel.BorderSpacing.Left := 10;
  FEmptyLabel.BorderSpacing.Right := 10;
  FEmptyLabel.WordWrap := True;
  FEmptyLabel.Caption := 'No scans yet. Choose New Scan or drop a local folder '+
    'onto this window.';

  FTaskList := TListView.Create(Self);
  FTaskList.Parent := AParent;
  FTaskList.Align := alClient;
  ConfigureList(FTaskList);
  AddColumn(FTaskList, 'Created (UTC)', 134);
  AddColumn(FTaskList, 'Folder', 125);
  AddColumn(FTaskList, 'Status', 82);
  AddColumn(FTaskList, 'Artifacts', 64);
  AddColumn(FTaskList, 'Components', 78);
  AddColumn(FTaskList, 'Duration', 76);
  FTaskList.OnSelectItem := @TaskSelected;
end;

function TMainForm.AddPage(const ACaption: string): TTabSheet;
begin
  Result := TTabSheet.Create(Self);
  Result.PageControl := FPages;
  Result.Caption := ACaption;
end;

procedure TMainForm.BuildDetailPane(AParent: TWinControl);
var
  Page: TTabSheet;
  Filters: TPanel;
  LabelValue: TLabel;
  CopyItem: TMenuItem;

  procedure SetupMemo(AMemo: TMemo; AParentControl: TWinControl;
    AMonospaced: Boolean);
  begin
    AMemo.Parent := AParentControl;
    AMemo.Align := alClient;
    AMemo.ReadOnly := True;
    AMemo.ScrollBars := ssBoth;
    AMemo.WordWrap := False;
    AMemo.BorderSpacing.Around := 8;
    if AMonospaced then
      AMemo.Font.Name := 'Monospace';
  end;

  function FilterLabel(const ACaption: string; AWidth: Integer): TLabel;
  begin
    Result := TLabel.Create(Self);
    Result.Parent := Filters;
    Result.Align := alLeft;
    Result.AutoSize := False;
    Result.Width := AWidth;
    Result.Layout := tlCenter;
    Result.BorderSpacing.Left := 8;
    Result.Caption := ACaption;
  end;

begin
  FPages := TPageControl.Create(Self);
  FPages.Parent := AParent;
  FPages.Align := alClient;
  FPages.BorderSpacing.Around := 6;

  Page := AddPage('Summary');
  FSummaryMemo := TMemo.Create(Self);
  SetupMemo(FSummaryMemo, Page, False);

  Page := AddPage('Components');
  Filters := TPanel.Create(Self);
  Filters.Parent := Page;
  Filters.Align := alTop;
  Filters.Height := 44;
  Filters.BevelOuter := bvNone;
  LabelValue := FilterLabel('Search', 58);
  FComponentSearch := TEdit.Create(Self);
  FComponentSearch.Parent := Filters;
  FComponentSearch.Align := alLeft;
  FComponentSearch.Width := 200;
  FComponentSearch.BorderSpacing.Top := 8;
  FComponentSearch.BorderSpacing.Bottom := 8;
  FComponentSearch.OnChange := @FiltersChanged;
  LabelValue := FilterLabel('Ecosystem', 78);
  FComponentEcosystem := TComboBox.Create(Self);
  FComponentEcosystem.Parent := Filters;
  FComponentEcosystem.Align := alLeft;
  FComponentEcosystem.Width := 150;
  FComponentEcosystem.Style := csDropDownList;
  FComponentEcosystem.BorderSpacing.Top := 8;
  FComponentEcosystem.BorderSpacing.Bottom := 8;
  FComponentEcosystem.OnChange := @FiltersChanged;
  LabelValue := FilterLabel('Status', 57);
  FComponentStatus := TComboBox.Create(Self);
  FComponentStatus.Parent := Filters;
  FComponentStatus.Align := alLeft;
  FComponentStatus.Width := 180;
  FComponentStatus.Style := csDropDownList;
  FComponentStatus.BorderSpacing.Top := 8;
  FComponentStatus.BorderSpacing.Bottom := 8;
  FComponentStatus.OnChange := @FiltersChanged;
  FComponentList := TListView.Create(Self);
  FComponentList.Parent := Page;
  FComponentList.Align := alClient;
  ConfigureList(FComponentList);
  AddColumn(FComponentList, 'Name', 190);
  AddColumn(FComponentList, 'Version', 110);
  AddColumn(FComponentList, 'Ecosystem', 90);
  AddColumn(FComponentList, 'Type', 90);
  AddColumn(FComponentList, 'Scope', 110);
  AddColumn(FComponentList, 'Source artifact', 260);
  FComponentList.OnColumnClick := @ComponentColumnClicked;
  FComponentList.OnKeyDown := @ListKeyPressed;

  Page := AddPage('Artifacts');
  Filters := TPanel.Create(Self);
  Filters.Parent := Page;
  Filters.Align := alTop;
  Filters.Height := 44;
  Filters.BevelOuter := bvNone;
  LabelValue := FilterLabel('Search', 58);
  FArtifactSearch := TEdit.Create(Self);
  FArtifactSearch.Parent := Filters;
  FArtifactSearch.Align := alLeft;
  FArtifactSearch.Width := 200;
  FArtifactSearch.BorderSpacing.Top := 8;
  FArtifactSearch.BorderSpacing.Bottom := 8;
  FArtifactSearch.OnChange := @FiltersChanged;
  LabelValue := FilterLabel('Type', 45);
  FArtifactType := TComboBox.Create(Self);
  FArtifactType.Parent := Filters;
  FArtifactType.Align := alLeft;
  FArtifactType.Width := 190;
  FArtifactType.Style := csDropDownList;
  FArtifactType.BorderSpacing.Top := 8;
  FArtifactType.BorderSpacing.Bottom := 8;
  FArtifactType.OnChange := @FiltersChanged;
  LabelValue := FilterLabel('Status', 57);
  FArtifactStatus := TComboBox.Create(Self);
  FArtifactStatus.Parent := Filters;
  FArtifactStatus.Align := alLeft;
  FArtifactStatus.Width := 180;
  FArtifactStatus.Style := csDropDownList;
  FArtifactStatus.BorderSpacing.Top := 8;
  FArtifactStatus.BorderSpacing.Bottom := 8;
  FArtifactStatus.OnChange := @FiltersChanged;
  FArtifactList := TListView.Create(Self);
  FArtifactList.Parent := Page;
  FArtifactList.Align := alClient;
  ConfigureList(FArtifactList);
  AddColumn(FArtifactList, 'Relative path', 260);
  AddColumn(FArtifactList, 'Type', 160);
  AddColumn(FArtifactList, 'Ecosystem', 90);
  AddColumn(FArtifactList, 'Status', 150);
  AddColumn(FArtifactList, 'Size', 90);
  AddColumn(FArtifactList, 'SHA-256', 220);
  AddColumn(FArtifactList, 'Message', 280);
  FArtifactList.OnColumnClick := @ArtifactColumnClicked;
  FArtifactList.OnKeyDown := @ListKeyPressed;

  FCopyMenu := TPopupMenu.Create(Self);
  CopyItem := TMenuItem.Create(FCopyMenu);
  CopyItem.Caption := 'Copy selected value';
  CopyItem.OnClick := @CopySelectedClicked;
  FCopyMenu.Items.Add(CopyItem);
  FComponentList.PopupMenu := FCopyMenu;
  FArtifactList.PopupMenu := FCopyMenu;

  Page := AddPage('SBOM JSON');
  FSBOMMemo := TMemo.Create(Self);
  SetupMemo(FSBOMMemo, Page, True);

  Page := AddPage('Messages');
  FMessagesMemo := TMemo.Create(Self);
  SetupMemo(FMessagesMemo, Page, False);
end;

procedure TMainForm.BuildStatusBar(AParent: TWinControl);
var
  StatusPanel: TPanel;
begin
  StatusPanel := TPanel.Create(Self);
  StatusPanel.Parent := AParent;
  StatusPanel.Align := alBottom;
  StatusPanel.Height := 68;
  StatusPanel.BevelOuter := bvNone;
  StatusPanel.BorderSpacing.Top := 1;

  FProgressPath := TLabel.Create(Self);
  FProgressPath.Parent := StatusPanel;
  FProgressPath.Align := alTop;
  FProgressPath.AutoSize := False;
  FProgressPath.Height := 22;
  FProgressPath.BorderSpacing.Left := 10;
  FProgressPath.BorderSpacing.Right := 10;
  FProgressPath.Layout := tlCenter;
  FProgressPath.Caption := 'Ready';

  FProgressStats := TLabel.Create(Self);
  FProgressStats.Parent := StatusPanel;
  FProgressStats.Align := alBottom;
  FProgressStats.AutoSize := False;
  FProgressStats.Height := 22;
  FProgressStats.BorderSpacing.Left := 10;
  FProgressStats.BorderSpacing.Right := 10;
  FProgressStats.Layout := tlCenter;
  FProgressStats.Caption := 'Drop a folder here or choose New Scan.';

  FProgressBar := TProgressBar.Create(Self);
  FProgressBar.Parent := StatusPanel;
  FProgressBar.Align := alClient;
  FProgressBar.BorderSpacing.Left := 10;
  FProgressBar.BorderSpacing.Right := 10;
  FProgressBar.BorderSpacing.Top := 3;
  FProgressBar.BorderSpacing.Bottom := 3;
  FProgressBar.Min := 0;
  FProgressBar.Max := 100;
end;

procedure TMainForm.LoadState;
var
  HistoryWarning, SettingsWarning: string;
begin
  FSettings := FSettingsStore.Load(SettingsWarning);
  FHistoryStore.Load(FTasks, HistoryWarning);
  if (HistoryWarning <> '') and (SettingsWarning <> '') then
    FStartupWarning := HistoryWarning + LineEnding + LineEnding + SettingsWarning
  else
    FStartupWarning := HistoryWarning + SettingsWarning;
  RefreshTaskRows;
  if FTaskList.Items.Count > 0 then
  begin
    FTaskList.Items[0].Selected := True;
    FTaskList.Items[0].Focused := True;
  end;
  UpdateDetails;
  UpdateButtons;
end;

procedure TMainForm.SaveHistory;
begin
  try
    FHistoryStore.Save(FTasks);
  except
    on E: Exception do
      ShowError('Task history could not be saved: ' + E.Message);
  end;
end;

procedure TMainForm.RefreshTaskRows;
var
  I: Integer;
  Item: TListItem;
begin
  FTaskList.Items.BeginUpdate;
  try
    FTaskList.Items.Clear;
    for I := 0 to FTasks.Count - 1 do
    begin
      Item := FTaskList.Items.Add;
      Item.Data := FTasks[I];
      UpdateTaskRow(TScanTask(FTasks[I]));
    end;
  finally
    FTaskList.Items.EndUpdate;
  end;
  FEmptyLabel.Visible := FTasks.Count = 0;
end;

function TMainForm.FindTaskItem(ATask: TScanTask): TListItem;
var
  I: Integer;
begin
  for I := 0 to FTaskList.Items.Count - 1 do
    if FTaskList.Items[I].Data = Pointer(ATask) then
      Exit(FTaskList.Items[I]);
  Result := nil;
end;

procedure TMainForm.UpdateTaskRow(ATask: TScanTask);
var
  Item: TListItem;
begin
  Item := FindTaskItem(ATask);
  if Item = nil then
    Exit;
  Item.Caption := DisplayTimestamp(ATask.CreatedUTC);
  while Item.SubItems.Count < 5 do
    Item.SubItems.Add('');
  Item.SubItems[0] := ATask.TargetRootName;
  Item.SubItems[1] := TaskStatusToString(ATask.Status);
  Item.SubItems[2] := IntToStr(ATask.ArtifactsDetected);
  Item.SubItems[3] := IntToStr(ATask.ComponentsIdentified);
  Item.SubItems[4] := FormatDuration(ATask.DurationMS);
end;

procedure TMainForm.SelectTask(ATask: TScanTask);
var
  Item: TListItem;
begin
  Item := FindTaskItem(ATask);
  if Item <> nil then
  begin
    Item.Selected := True;
    Item.Focused := True;
    Item.MakeVisible(False);
    UpdateDetails;
  end;
end;

function TMainForm.SelectedTask: TScanTask;
begin
  if (FTaskList.Selected <> nil) and (FTaskList.Selected.Data <> nil) then
    Result := TScanTask(FTaskList.Selected.Data)
  else
    Result := nil;
end;

function TMainForm.FindTask(const AID: string): TScanTask;
var
  I: Integer;
begin
  for I := 0 to FTasks.Count - 1 do
    if TScanTask(FTasks[I]).ID = AID then
      Exit(TScanTask(FTasks[I]));
  Result := nil;
end;

procedure TMainForm.PopulateSummary(ATask: TScanTask);
begin
  FSummaryMemo.Lines.BeginUpdate;
  try
    FSummaryMemo.Clear;
    if ATask = nil then
    begin
      FSummaryMemo.Lines.Add('Select a scan task to view its details.');
      Exit;
    end;
    FSummaryMemo.Lines.Add('Target folder: ' + ATask.TargetDirectory);
    FSummaryMemo.Lines.Add('Created (UTC): ' + ATask.CreatedUTC);
    FSummaryMemo.Lines.Add('Started (UTC): ' + ATask.StartedUTC);
    FSummaryMemo.Lines.Add('Completed (UTC): ' + ATask.CompletedUTC);
    FSummaryMemo.Lines.Add('Status: ' + TaskStatusToString(ATask.Status));
    FSummaryMemo.Lines.Add('Duration: ' + FormatDuration(ATask.DurationMS));
    FSummaryMemo.Lines.Add('Files inspected: ' + IntToStr(ATask.FilesInspected));
    FSummaryMemo.Lines.Add('Total bytes inspected: ' +
      FormatByteSize(ATask.BytesInspected) + ' (' +
      IntToStr(ATask.BytesInspected) + ')');
    FSummaryMemo.Lines.Add('Artifacts detected: ' +
      IntToStr(ATask.ArtifactsDetected));
    FSummaryMemo.Lines.Add('Artifacts parsed: ' +
      IntToStr(ATask.ArtifactsParsed));
    FSummaryMemo.Lines.Add('Artifacts partially parsed: ' +
      IntToStr(ATask.ArtifactsPartiallyParsed));
    FSummaryMemo.Lines.Add('Unsupported artifacts: ' +
      IntToStr(ATask.UnsupportedArtifacts));
    FSummaryMemo.Lines.Add('Failed artifacts: ' +
      IntToStr(ATask.FailedArtifacts));
    FSummaryMemo.Lines.Add('Components identified: ' +
      IntToStr(ATask.ComponentsIdentified));
    FSummaryMemo.Lines.Add('Generated SBOM: ' + ATask.GeneratedSBOMPath);
    FSummaryMemo.Lines.Add('Generated SBOM SHA-256: ' +
      ATask.GeneratedSBOMSHA256);
    FSummaryMemo.Lines.Add('Scan settings: ' + ATask.Settings.AsSummary);
    FSummaryMemo.Lines.Add('');
    FSummaryMemo.Lines.Add('Completeness warning: Results come from local '+
      'static artifact inspection and are best effort. They are not a guarantee '+
      'of complete dependency discovery and are not a vulnerability or '+
      'license-compliance assessment.');
  finally
    FSummaryMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.PopulateComponentFilters(ATask: TScanTask);
var
  Values: TStringList;
  I: Integer;
  PreviousValue: string;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    for I := 0 to ATask.Components.Count - 1 do
      if uModels.TComponent(ATask.Components[I]).Ecosystem <> '' then
        Values.Add(uModels.TComponent(ATask.Components[I]).Ecosystem);
    PreviousValue := FComponentEcosystem.Text;
    FComponentEcosystem.Items.BeginUpdate;
    try
      FComponentEcosystem.Items.Clear;
      FComponentEcosystem.Items.Add('All ecosystems');
      FComponentEcosystem.Items.AddStrings(Values);
      FComponentEcosystem.ItemIndex := FComponentEcosystem.Items.IndexOf(PreviousValue);
      if FComponentEcosystem.ItemIndex < 0 then
        FComponentEcosystem.ItemIndex := 0;
    finally
      FComponentEcosystem.Items.EndUpdate;
    end;
    PreviousValue := FComponentStatus.Text;
    FComponentStatus.Items.Text := 'All statuses' + LineEnding + 'parsed' +
      LineEnding + 'partially parsed' + LineEnding +
      'detected but unsupported' + LineEnding + 'failed';
    FComponentStatus.ItemIndex := FComponentStatus.Items.IndexOf(PreviousValue);
    if FComponentStatus.ItemIndex < 0 then
      FComponentStatus.ItemIndex := 0;
  finally
    Values.Free;
  end;
end;

procedure TMainForm.PopulateArtifactFilters(ATask: TScanTask);
var
  Values: TStringList;
  I: Integer;
  PreviousValue: string;
begin
  Values := TStringList.Create;
  try
    Values.Sorted := True;
    Values.Duplicates := dupIgnore;
    for I := 0 to ATask.Artifacts.Count - 1 do
      Values.Add(TArtifact(ATask.Artifacts[I]).ArtifactType);
    PreviousValue := FArtifactType.Text;
    FArtifactType.Items.BeginUpdate;
    try
      FArtifactType.Items.Clear;
      FArtifactType.Items.Add('All artifact types');
      FArtifactType.Items.AddStrings(Values);
      FArtifactType.ItemIndex := FArtifactType.Items.IndexOf(PreviousValue);
      if FArtifactType.ItemIndex < 0 then
        FArtifactType.ItemIndex := 0;
    finally
      FArtifactType.Items.EndUpdate;
    end;
    PreviousValue := FArtifactStatus.Text;
    FArtifactStatus.Items.Text := 'All statuses' + LineEnding + 'parsed' +
      LineEnding + 'partially parsed' + LineEnding +
      'detected but unsupported' + LineEnding + 'failed';
    FArtifactStatus.ItemIndex := FArtifactStatus.Items.IndexOf(PreviousValue);
    if FArtifactStatus.ItemIndex < 0 then
      FArtifactStatus.ItemIndex := 0;
  finally
    Values.Free;
  end;
end;

function TMainForm.ComponentArtifactStatus(ATask: TScanTask;
  AComponent: uModels.TComponent): string;
var
  I: Integer;
  Artifact: TArtifact;
begin
  for I := 0 to ATask.Artifacts.Count - 1 do
  begin
    Artifact := TArtifact(ATask.Artifacts[I]);
    if Artifact.RelativePath = AComponent.SourceArtifact then
      Exit(ArtifactStatusToString(Artifact.Status));
  end;
  Result := 'parsed';
end;

procedure TMainForm.PopulateComponents(ATask: TScanTask);
var
  Sorted: TStringList;
  I, StartAt, EndAt: Integer;
  Component: uModels.TComponent;
  SearchValue, StatusValue, SortValue: string;
  Item: TListItem;
begin
  FComponentList.Items.BeginUpdate;
  Sorted := TStringList.Create;
  try
    FComponentList.Items.Clear;
    if ATask = nil then
      Exit;
    Sorted.Sorted := True;
    Sorted.Duplicates := dupAccept;
    SearchValue := Trim(FComponentSearch.Text);
    for I := 0 to ATask.Components.Count - 1 do
    begin
      Component := uModels.TComponent(ATask.Components[I]);
      StatusValue := ComponentArtifactStatus(ATask, Component);
      if (FComponentEcosystem.ItemIndex > 0) and
        not SameText(FComponentEcosystem.Text, Component.Ecosystem) then
        Continue;
      if (FComponentStatus.ItemIndex > 0) and
        not SameText(FComponentStatus.Text, StatusValue) then
        Continue;
      if not ContainsTextValue(Component.Name + ' ' + Component.Version + ' ' +
        Component.Ecosystem + ' ' + Component.ComponentType + ' ' +
        Component.DependencyScope + ' ' + Component.SourceArtifact, SearchValue) then
        Continue;
      case FComponentSortColumn of
        1: SortValue := Component.Version;
        2: SortValue := Component.Ecosystem;
        3: SortValue := Component.ComponentType;
        4: SortValue := Component.DependencyScope;
        5: SortValue := Component.SourceArtifact;
      else
        SortValue := Component.Name;
      end;
      Sorted.AddObject(LowerCase(SortValue) + #1 + Format('%.10d', [I]),
        Component);
    end;
    if FComponentSortAscending then
    begin
      StartAt := 0;
      EndAt := Sorted.Count - 1;
    end
    else
    begin
      StartAt := Sorted.Count - 1;
      EndAt := 0;
    end;
    I := StartAt;
    while (Sorted.Count > 0) and
      ((FComponentSortAscending and (I <= EndAt)) or
      ((not FComponentSortAscending) and (I >= EndAt))) do
    begin
      Component := uModels.TComponent(Sorted.Objects[I]);
      Item := FComponentList.Items.Add;
      Item.Data := Component;
      Item.Caption := Component.Name;
      Item.SubItems.Add(Component.Version);
      Item.SubItems.Add(Component.Ecosystem);
      Item.SubItems.Add(Component.ComponentType);
      Item.SubItems.Add(Component.DependencyScope);
      Item.SubItems.Add(Component.SourceArtifact);
      if FComponentSortAscending then Inc(I) else Dec(I);
    end;
  finally
    Sorted.Free;
    FComponentList.Items.EndUpdate;
  end;
end;

procedure TMainForm.PopulateArtifacts(ATask: TScanTask);
var
  Sorted: TStringList;
  I, StartAt, EndAt: Integer;
  Artifact: TArtifact;
  SearchValue, StatusValue, SortValue: string;
  Item: TListItem;
begin
  FArtifactList.Items.BeginUpdate;
  Sorted := TStringList.Create;
  try
    FArtifactList.Items.Clear;
    if ATask = nil then
      Exit;
    Sorted.Sorted := True;
    Sorted.Duplicates := dupAccept;
    SearchValue := Trim(FArtifactSearch.Text);
    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      StatusValue := ArtifactStatusToString(Artifact.Status);
      if (FArtifactType.ItemIndex > 0) and
        not SameText(FArtifactType.Text, Artifact.ArtifactType) then
        Continue;
      if (FArtifactStatus.ItemIndex > 0) and
        not SameText(FArtifactStatus.Text, StatusValue) then
        Continue;
      if not ContainsTextValue(Artifact.RelativePath + ' ' +
        Artifact.ArtifactType + ' ' + Artifact.Ecosystem + ' ' + StatusValue +
        ' ' + Artifact.MessageText, SearchValue) then
        Continue;
      case FArtifactSortColumn of
        1: SortValue := Artifact.ArtifactType;
        2: SortValue := Artifact.Ecosystem;
        3: SortValue := StatusValue;
        4: SortValue := Format('%.20d', [Artifact.FileSize]);
        5: SortValue := Artifact.SHA256;
        6: SortValue := Artifact.MessageText;
      else
        SortValue := Artifact.RelativePath;
      end;
      Sorted.AddObject(LowerCase(SortValue) + #1 + Format('%.10d', [I]),
        Artifact);
    end;
    if FArtifactSortAscending then
    begin
      StartAt := 0;
      EndAt := Sorted.Count - 1;
    end
    else
    begin
      StartAt := Sorted.Count - 1;
      EndAt := 0;
    end;
    I := StartAt;
    while (Sorted.Count > 0) and
      ((FArtifactSortAscending and (I <= EndAt)) or
      ((not FArtifactSortAscending) and (I >= EndAt))) do
    begin
      Artifact := TArtifact(Sorted.Objects[I]);
      Item := FArtifactList.Items.Add;
      Item.Data := Artifact;
      Item.Caption := Artifact.RelativePath;
      Item.SubItems.Add(Artifact.ArtifactType);
      Item.SubItems.Add(Artifact.Ecosystem);
      Item.SubItems.Add(ArtifactStatusToString(Artifact.Status));
      Item.SubItems.Add(FormatByteSize(Artifact.FileSize));
      Item.SubItems.Add(Artifact.SHA256);
      Item.SubItems.Add(Artifact.MessageText);
      if FArtifactSortAscending then Inc(I) else Dec(I);
    end;
  finally
    Sorted.Free;
    FArtifactList.Items.EndUpdate;
  end;
end;

procedure TMainForm.PopulateSBOM(ATask: TScanTask);
begin
  FSBOMMemo.Clear;
  if (ATask = nil) or (ATask.GeneratedSBOMPath = '') then
  begin
    FSBOMMemo.Lines.Add('No CycloneDX JSON is available for this task.');
    Exit;
  end;
  try
    if FileExists(ATask.GeneratedSBOMPath) then
      FSBOMMemo.Lines.LoadFromFile(ATask.GeneratedSBOMPath)
    else
      FSBOMMemo.Lines.Add('The generated SBOM file is no longer present: ' +
        ATask.GeneratedSBOMPath);
  except
    on E: Exception do
      FSBOMMemo.Lines.Add('Unable to load the generated SBOM: ' + E.Message);
  end;
end;

procedure TMainForm.PopulateMessages(ATask: TScanTask);
var
  I: Integer;
  Artifact: TArtifact;
begin
  FMessagesMemo.Lines.BeginUpdate;
  try
    FMessagesMemo.Clear;
    if ATask = nil then
      Exit;
    FMessagesMemo.Lines.Add('Best-effort completeness notice: local static '+
      'inspection can miss dynamically resolved or undeclared dependencies.');
    if ATask.Warnings.Count > 0 then
    begin
      FMessagesMemo.Lines.Add('');
      FMessagesMemo.Lines.Add('Warnings');
      for I := 0 to ATask.Warnings.Count - 1 do
        FMessagesMemo.Lines.Add('- ' + ATask.Warnings[I]);
    end;
    if ATask.Errors.Count > 0 then
    begin
      FMessagesMemo.Lines.Add('');
      FMessagesMemo.Lines.Add('Errors');
      for I := 0 to ATask.Errors.Count - 1 do
        FMessagesMemo.Lines.Add('- ' + ATask.Errors[I]);
    end;
    for I := 0 to ATask.Artifacts.Count - 1 do
    begin
      Artifact := TArtifact(ATask.Artifacts[I]);
      if Artifact.MessageText <> '' then
      begin
        if I = 0 then
          FMessagesMemo.Lines.Add('');
        FMessagesMemo.Lines.Add(Artifact.RelativePath + ': ' +
          Artifact.MessageText);
      end;
    end;
  finally
    FMessagesMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.UpdateDetails;
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  FUpdatingDetails := True;
  try
    PopulateSummary(Task);
    if Task <> nil then
    begin
      PopulateComponentFilters(Task);
      PopulateArtifactFilters(Task);
    end;
    PopulateComponents(Task);
    PopulateArtifacts(Task);
    PopulateSBOM(Task);
    PopulateMessages(Task);
  finally
    FUpdatingDetails := False;
  end;
  UpdateButtons;
end;

procedure TMainForm.UpdateButtons;
var
  Task: TScanTask;
  ScanActive: Boolean;
begin
  Task := SelectedTask;
  ScanActive := FActiveTaskID <> '';
  FNewButton.Enabled := not ScanActive;
  FRefreshButton.Enabled := not ScanActive;
  FRescanButton.Enabled := (not ScanActive) and (Task <> nil) and
    DirectoryExists(Task.TargetDirectory);
  FCancelButton.Enabled := ScanActive and (Task <> nil) and
    (Task.ID = FActiveTaskID) and (Task.Status = tsRunning);
  FExportButton.Enabled := (Task <> nil) and
    (Task.Status = tsCompleted) and FileExists(Task.GeneratedSBOMPath);
end;

procedure TMainForm.FreeFinishedWorker;
begin
  if (FWorker <> nil) and FWorker.Finished then
    FreeAndNil(FWorker);
end;

procedure TMainForm.StartScan(const ADirectory: string);
var
  Task: TScanTask;
  Target: string;
begin
  FreeFinishedWorker;
  if FWorker <> nil then
    Exit;
  Target := ExcludeTrailingPathDelimiter(ExpandFileName(ADirectory));
  if not DirectoryExists(Target) then
  begin
    ShowError('The selected folder does not exist: ' + Target);
    Exit;
  end;
  Task := TScanTask.Create;
  Task.TargetDirectory := Target;
  Task.TargetRootName := ExtractFileName(Target);
  if Task.TargetRootName = '' then
    Task.TargetRootName := Target;
  Task.Settings.Assign(FSettings);
  Task.Status := tsPending;
  FTasks.Insert(0, Task);
  RefreshTaskRows;
  SelectTask(Task);
  SaveHistory;
  Task.Status := tsRunning;
  FActiveTaskID := Task.ID;
  UpdateTaskRow(Task);
  FProgressBar.Style := pbstMarquee;
  FProgressPath.Caption := 'Starting scan of ' + Task.TargetRootName + '...';
  FProgressStats.Caption := 'Preparing worker thread';
  FWorker := TScanWorker.Create(Task, FHistoryStore.DataDirectory);
  FWorker.OnProgress := @WorkerProgress;
  FWorker.OnComplete := @WorkerComplete;
  FWorker.Start;
  SaveHistory;
  UpdateButtons;
end;

procedure TMainForm.ConfigureAndStartScan(const ADirectory: string);
begin
  if FActiveTaskID <> '' then
    Exit;
  if not TScanSettingsDialog.Execute(FSettings) then
    Exit;
  try
    FSettingsStore.Save(FSettings);
  except
    on E: Exception do
      ShowError('Scan settings could not be saved: ' + E.Message);
  end;
  StartScan(ADirectory);
end;

procedure TMainForm.ShowError(const AMessage: string);
begin
  if not FClosing then
    MessageDlg(AppName, AMessage, mtError, [mbOK], 0);
end;

procedure TMainForm.FormShown(Sender: TObject);
begin
  if FStartupWarning <> '' then
  begin
    MessageDlg(AppName, FStartupWarning, mtWarning, [mbOK], 0);
    FStartupWarning := '';
  end;
end;

procedure TMainForm.FormCloseRequested(Sender: TObject; var CanClose: Boolean);
var
  Task: TScanTask;
begin
  FClosing := True;
  if FWorker <> nil then
  begin
    FWorker.OnProgress := nil;
    FWorker.OnComplete := nil;
    if not FWorker.Finished then
    begin
      FWorker.Cancel;
      FWorker.WaitFor;
    end;
    Task := FindTask(FActiveTaskID);
    if (Task <> nil) and (FWorker.ResultTask <> nil) then
      Task.Assign(FWorker.ResultTask);
    FActiveTaskID := '';
    SaveHistory;
  end;
  CanClose := True;
end;

procedure TMainForm.FormDropFiles(Sender: TObject;
  const FileNames: array of string);
var
  I: Integer;
begin
  if FActiveTaskID <> '' then
    Exit;
  for I := Low(FileNames) to High(FileNames) do
    if DirectoryExists(FileNames[I]) then
    begin
      ConfigureAndStartScan(FileNames[I]);
      Exit;
    end;
  ShowError('Drop a local folder to start a scan.');
end;

procedure TMainForm.FormKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) and (Key = VK_N) then
  begin
    NewScanClicked(Sender);
    Key := 0;
  end
  else if PrimaryShortcut(Shift) and (Key = VK_E) then
  begin
    ExportClicked(Sender);
    Key := 0;
  end
  else if Key = VK_F5 then
  begin
    RefreshClicked(Sender);
    Key := 0;
  end
  else if Key = VK_ESCAPE then
  begin
    CancelClicked(Sender);
    Key := 0;
  end;
end;

procedure TMainForm.NewScanClicked(Sender: TObject);
var
  Dialog: TSelectDirectoryDialog;
begin
  if FActiveTaskID <> '' then
    Exit;
  Dialog := TSelectDirectoryDialog.Create(Self);
  try
    Dialog.Title := 'Select a folder to scan';
    if Dialog.Execute then
      ConfigureAndStartScan(Dialog.FileName);
  finally
    Dialog.Free;
  end;
end;

procedure TMainForm.CancelClicked(Sender: TObject);
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  if (FWorker <> nil) and (Task <> nil) and
    (Task.ID = FActiveTaskID) then
  begin
    FWorker.Cancel;
    FCancelButton.Enabled := False;
    FProgressPath.Caption := 'Cancelling safely...';
  end;
end;

procedure TMainForm.RescanClicked(Sender: TObject);
var
  Task: TScanTask;
begin
  Task := SelectedTask;
  if (FActiveTaskID = '') and (Task <> nil) then
    ConfigureAndStartScan(Task.TargetDirectory);
end;

procedure TMainForm.RefreshClicked(Sender: TObject);
var
  WarningText: string;
begin
  if FActiveTaskID <> '' then
    Exit;
  if not FHistoryStore.Load(FTasks, WarningText) then
    ShowError(WarningText)
  else if WarningText <> '' then
    MessageDlg(AppName, WarningText, mtWarning, [mbOK], 0);
  RefreshTaskRows;
  if FTaskList.Items.Count > 0 then
    FTaskList.Items[0].Selected := True;
  UpdateDetails;
end;

procedure TMainForm.ExportClicked(Sender: TObject);
var
  Task: TScanTask;
  Dialog: TSaveDialog;
begin
  Task := SelectedTask;
  if (Task = nil) or not FileExists(Task.GeneratedSBOMPath) then
    Exit;
  Dialog := TSaveDialog.Create(Self);
  try
    Dialog.Title := 'Export CycloneDX SBOM';
    Dialog.Filter := 'CycloneDX JSON (*.cdx.json)|*.cdx.json|JSON files (*.json)|*.json|All files|*';
    Dialog.DefaultExt := 'cdx.json';
    Dialog.FileName := Task.ID + '.cdx.json';
    if Dialog.Execute then
    begin
      try
        if not SameFileName(ExpandFileName(Dialog.FileName),
          ExpandFileName(Task.GeneratedSBOMPath)) then
          CopyFileContents(Task.GeneratedSBOMPath, Dialog.FileName);
        FProgressPath.Caption := 'SBOM exported to ' + Dialog.FileName;
      except
        on E: Exception do
          ShowError('The SBOM could not be exported: ' + E.Message);
      end;
    end;
  finally
    Dialog.Free;
  end;
end;

procedure TMainForm.TaskSelected(Sender: TObject; Item: TListItem;
  Selected: Boolean);
begin
  if Selected then
    UpdateDetails;
end;

procedure TMainForm.FiltersChanged(Sender: TObject);
var
  Task: TScanTask;
begin
  if FUpdatingDetails then
    Exit;
  Task := SelectedTask;
  if (Sender = FComponentSearch) or (Sender = FComponentEcosystem) or
    (Sender = FComponentStatus) then
    PopulateComponents(Task)
  else
    PopulateArtifacts(Task);
end;

procedure TMainForm.ComponentColumnClicked(Sender: TObject;
  Column: TListColumn);
begin
  if FComponentSortColumn = Column.Index then
    FComponentSortAscending := not FComponentSortAscending
  else
  begin
    FComponentSortColumn := Column.Index;
    FComponentSortAscending := True;
  end;
  PopulateComponents(SelectedTask);
end;

procedure TMainForm.ArtifactColumnClicked(Sender: TObject;
  Column: TListColumn);
begin
  if FArtifactSortColumn = Column.Index then
    FArtifactSortAscending := not FArtifactSortAscending
  else
  begin
    FArtifactSortColumn := Column.Index;
    FArtifactSortAscending := True;
  end;
  PopulateArtifacts(SelectedTask);
end;

procedure TMainForm.ListKeyPressed(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  if PrimaryShortcut(Shift) and (Key = VK_C) then
  begin
    CopySelectedClicked(Sender);
    Key := 0;
  end;
end;

procedure TMainForm.CopySelectedClicked(Sender: TObject);
var
  List: TListView;
  I: Integer;
  Value: string;
begin
  List := nil;
  if (Sender = FComponentList) or (FCopyMenu.PopupComponent = FComponentList) then
    List := FComponentList
  else if (Sender = FArtifactList) or (FCopyMenu.PopupComponent = FArtifactList) then
    List := FArtifactList;
  if (List = nil) or (List.Selected = nil) then
    Exit;
  Value := List.Selected.Caption;
  for I := 0 to List.Selected.SubItems.Count - 1 do
    Value := Value + #9 + List.Selected.SubItems[I];
  Clipboard.AsText := Value;
end;

procedure TMainForm.WorkerProgress(Sender: TObject;
  const AProgress: TScanProgress);
var
  Task: TScanTask;
begin
  if FClosing then
    Exit;
  Task := FindTask(FActiveTaskID);
  if Task = nil then
    Exit;
  Task.FilesInspected := AProgress.FilesInspected;
  Task.BytesInspected := AProgress.BytesInspected;
  Task.ArtifactsDetected := AProgress.ArtifactsDetected;
  Task.ComponentsIdentified := AProgress.ComponentsIdentified;
  Task.DurationMS := AProgress.ElapsedMS;
  UpdateTaskRow(Task);
  FProgressPath.Caption := AProgress.CurrentRelativePath;
  FProgressStats.Caption := Format('%d files  •  %s  •  %d artifacts  •  '+
    '%d components  •  %s', [AProgress.FilesInspected,
    FormatByteSize(AProgress.BytesInspected), AProgress.ArtifactsDetected,
    AProgress.ComponentsIdentified, FormatDuration(AProgress.ElapsedMS)]);
  if SelectedTask = Task then
    PopulateSummary(Task);
end;

procedure TMainForm.WorkerComplete(Sender: TObject; AResult: TScanTask);
var
  Task: TScanTask;
begin
  if FClosing then
    Exit;
  Task := FindTask(AResult.ID);
  if Task <> nil then
  begin
    Task.Assign(AResult);
    UpdateTaskRow(Task);
  end;
  FActiveTaskID := '';
  FProgressBar.Style := pbstNormal;
  if AResult.Status = tsCompleted then
  begin
    FProgressBar.Position := 100;
    FProgressPath.Caption := 'Scan completed';
  end
  else
  begin
    FProgressBar.Position := 0;
    FProgressPath.Caption := 'Scan ' + TaskStatusToString(AResult.Status);
  end;
  FProgressStats.Caption := Format('%d files  •  %s  •  %d artifacts  •  '+
    '%d components  •  %s', [AResult.FilesInspected,
    FormatByteSize(AResult.BytesInspected), AResult.ArtifactsDetected,
    AResult.ComponentsIdentified, FormatDuration(AResult.DurationMS)]);
  SaveHistory;
  if Task <> nil then
    SelectTask(Task)
  else
    UpdateDetails;
  UpdateButtons;
end;

end.
