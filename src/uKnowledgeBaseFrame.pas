(**
  PurpleRay SBOM Analyzer Knowledge Base feature frame.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Presents the bundled glossary: a searchable term list, a reading pane
  with the selected definition, and derived related-term navigation.
  Content comes from the embedded copy of docs/GLOSSARY.md, so the
  feature works offline inside the self-contained executable.

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
unit uKnowledgeBaseFrame;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ExtCtrls, Graphics,
  uGlossary, uGlossaryContent;

const
  MaximumRelatedTerms = 4;

type
  TKnowledgeBaseFrame = class(TFrame)
  private
    FGlossary: TGlossary;
    FVisibleEntries: TIntegerArray;
    FHeaderPanel: TPanel;
    FTitleLabel: TLabel;
    FSubtitleLabel: TLabel;
    FSearchLabel: TLabel;
    FSearchEdit: TEdit;
    FTermList: TListBox;
    FReadingPanel: TPanel;
    FTermLabel: TLabel;
    FDefinitionLabel: TLabel;
    FRelatedHeading: TLabel;
    FRelatedPanel: TPanel;
    FRelatedButtons: array[0..MaximumRelatedTerms - 1] of TButton;
    FSourceLabel: TLabel;

    {**
      Builds every child control and loads the embedded glossary.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      EOutOfMemory
        Propagated when a control or the model cannot be allocated.
    }
    procedure InitializeFrame;

    {**
      Repopulates the term list from the current search text.

      Parameters
      ----------
      APreferredEntry
        Glossary index to keep selected when it stays visible, or -1 to
        select the first visible entry.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure RefreshTermList(APreferredEntry: Integer);

    {**
      Shows the selected entry in the reading pane.

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
    procedure RefreshReadingPane;

    {**
      Handles live search-text changes.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure SearchChanged(Sender: TObject);

    {**
      Handles term-list selection changes.

      Parameters
      ----------
      Sender
        LCL event source; not otherwise used.
      User
        True when the change came from user interaction.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure TermSelectionChanged(Sender: TObject; User: Boolean);

    {**
      Navigates to the related term stored in the clicked button's Tag.

      Parameters
      ----------
      Sender
        Related-term button carrying the target glossary index.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure RelatedTermClicked(Sender: TObject);
  public
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;

    {**
      Prepares the feature for display.

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
    procedure Activate;

    {**
      Releases transient focus-related state when leaving the feature.

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
    procedure Deactivate;

    {**
      Returns the number of glossary terms for shell-level statistics.

      Parameters
      ----------
      None

      Returns
      -------
      Integer
        Parsed glossary entry count.

      Raises
      ------
      None
    }
    function TermCount: Integer;
  end;

implementation

{$R *.lfm}

constructor TKnowledgeBaseFrame.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  InitializeFrame;
end;

destructor TKnowledgeBaseFrame.Destroy;
begin
  FreeAndNil(FGlossary);
  inherited Destroy;
end;

procedure TKnowledgeBaseFrame.InitializeFrame;
var
  I: Integer;
begin
  FGlossary := TGlossary.Create;
  FGlossary.LoadFromMarkdown(GlossaryMarkdown);

  FHeaderPanel := TPanel.Create(Self);
  FHeaderPanel.Parent := Self;
  FHeaderPanel.Align := alTop;
  FHeaderPanel.Height := 72;
  FHeaderPanel.BevelOuter := bvNone;

  FTitleLabel := TLabel.Create(Self);
  FTitleLabel.Parent := FHeaderPanel;
  FTitleLabel.Caption := 'Knowledge Base';
  FTitleLabel.Font.Style := [fsBold];
  FTitleLabel.Font.Height := -19;
  FTitleLabel.Left := 16;
  FTitleLabel.Top := 12;

  FSubtitleLabel := TLabel.Create(Self);
  FSubtitleLabel.Parent := FHeaderPanel;
  FSubtitleLabel.Caption := Format(
    'Glossary %s %d terms %s available offline',
    [#$E2#$80#$A2, FGlossary.Count, #$E2#$80#$A2]);
  FSubtitleLabel.Left := 16;
  FSubtitleLabel.Top := 42;

  FSearchEdit := TEdit.Create(Self);
  FSearchEdit.Parent := FHeaderPanel;
  FSearchEdit.Width := 240;
  FSearchEdit.Anchors := [akTop, akRight];
  FSearchEdit.AnchorSideTop.Control := FHeaderPanel;
  FSearchEdit.AnchorSideTop.Side := asrTop;
  FSearchEdit.AnchorSideRight.Control := FHeaderPanel;
  FSearchEdit.AnchorSideRight.Side := asrRight;
  FSearchEdit.BorderSpacing.Top := 22;
  FSearchEdit.BorderSpacing.Right := 16;
  FSearchEdit.TextHint := 'Search terms and definitions';
  FSearchEdit.OnChange := @SearchChanged;

  FSearchLabel := TLabel.Create(Self);
  FSearchLabel.Parent := FHeaderPanel;
  FSearchLabel.Caption := 'Search';
  FSearchLabel.Anchors := [akTop, akRight];
  FSearchLabel.AnchorSideTop.Control := FSearchEdit;
  FSearchLabel.AnchorSideTop.Side := asrCenter;
  FSearchLabel.AnchorSideRight.Control := FSearchEdit;
  FSearchLabel.AnchorSideRight.Side := asrLeft;
  FSearchLabel.BorderSpacing.Right := 8;

  FTermList := TListBox.Create(Self);
  FTermList.Parent := Self;
  FTermList.Align := alLeft;
  FTermList.Width := 300;
  FTermList.BorderSpacing.Left := 10;
  FTermList.BorderSpacing.Bottom := 10;
  FTermList.OnSelectionChange := @TermSelectionChanged;

  FReadingPanel := TPanel.Create(Self);
  FReadingPanel.Parent := Self;
  FReadingPanel.Align := alClient;
  FReadingPanel.BevelOuter := bvNone;

  FTermLabel := TLabel.Create(Self);
  FTermLabel.Parent := FReadingPanel;
  FTermLabel.Align := alTop;
  FTermLabel.Font.Style := [fsBold];
  FTermLabel.Font.Height := -17;
  FTermLabel.BorderSpacing.Left := 20;
  FTermLabel.BorderSpacing.Top := 6;
  FTermLabel.BorderSpacing.Right := 20;
  FTermLabel.WordWrap := True;

  FDefinitionLabel := TLabel.Create(Self);
  FDefinitionLabel.Parent := FReadingPanel;
  FDefinitionLabel.Align := alTop;
  FDefinitionLabel.AutoSize := True;
  FDefinitionLabel.WordWrap := True;
  FDefinitionLabel.BorderSpacing.Left := 20;
  FDefinitionLabel.BorderSpacing.Top := 10;
  FDefinitionLabel.BorderSpacing.Right := 40;

  FRelatedHeading := TLabel.Create(Self);
  FRelatedHeading.Parent := FReadingPanel;
  FRelatedHeading.Align := alTop;
  FRelatedHeading.Caption := 'Related terms';
  FRelatedHeading.Font.Style := [fsBold];
  FRelatedHeading.BorderSpacing.Left := 20;
  FRelatedHeading.BorderSpacing.Top := 18;

  FRelatedPanel := TPanel.Create(Self);
  FRelatedPanel.Parent := FReadingPanel;
  FRelatedPanel.Align := alTop;
  FRelatedPanel.BevelOuter := bvNone;
  FRelatedPanel.Height := 40;
  FRelatedPanel.BorderSpacing.Left := 20;
  FRelatedPanel.BorderSpacing.Top := 4;
  FRelatedPanel.ChildSizing.Layout := cclLeftToRightThenTopToBottom;
  FRelatedPanel.ChildSizing.ControlsPerLine := MaximumRelatedTerms;
  FRelatedPanel.ChildSizing.HorizontalSpacing := 8;

  for I := 0 to MaximumRelatedTerms - 1 do
  begin
    FRelatedButtons[I] := TButton.Create(Self);
    FRelatedButtons[I].Parent := FRelatedPanel;
    FRelatedButtons[I].AutoSize := True;
    FRelatedButtons[I].Visible := False;
    FRelatedButtons[I].OnClick := @RelatedTermClicked;
  end;

  FSourceLabel := TLabel.Create(Self);
  FSourceLabel.Parent := FReadingPanel;
  FSourceLabel.Align := alBottom;
  FSourceLabel.Caption :=
    'Source: GLOSSARY.md (bundled with the application)';
  FSourceLabel.Font.Color := clGrayText;
  FSourceLabel.BorderSpacing.Left := 20;
  FSourceLabel.BorderSpacing.Bottom := 10;

  { Fix alTop stacking order with well-separated sort keys: title,
    definition, related heading, chips. }
  FTermLabel.Top := 0;
  FDefinitionLabel.Top := 100;
  FRelatedHeading.Top := 400;
  FRelatedPanel.Top := 500;

  RefreshTermList(0);
end;

procedure TKnowledgeBaseFrame.RefreshTermList(APreferredEntry: Integer);
var
  I, SelectAt: Integer;
begin
  FVisibleEntries := FGlossary.Filter(FSearchEdit.Text);
  FTermList.Items.BeginUpdate;
  try
    FTermList.Items.Clear;
    SelectAt := -1;
    for I := 0 to High(FVisibleEntries) do
    begin
      FTermList.Items.Add(FGlossary.Term(FVisibleEntries[I]));
      if FVisibleEntries[I] = APreferredEntry then
        SelectAt := I;
    end;
    if (SelectAt < 0) and (FTermList.Items.Count > 0) then
      SelectAt := 0;
    FTermList.ItemIndex := SelectAt;
  finally
    FTermList.Items.EndUpdate;
  end;
  RefreshReadingPane;
end;

procedure TKnowledgeBaseFrame.RefreshReadingPane;
var
  EntryIndex, I: Integer;
  Related: TIntegerArray;
begin
  EntryIndex := -1;
  if (FTermList.ItemIndex >= 0) and
    (FTermList.ItemIndex <= High(FVisibleEntries)) then
    EntryIndex := FVisibleEntries[FTermList.ItemIndex];
  if EntryIndex < 0 then
  begin
    FTermLabel.Caption := 'No matching term';
    FDefinitionLabel.Caption :=
      'No glossary entry matches the current search.';
    FRelatedHeading.Visible := False;
    FRelatedPanel.Visible := False;
    for I := 0 to MaximumRelatedTerms - 1 do
      FRelatedButtons[I].Visible := False;
    Exit;
  end;
  FTermLabel.Caption := FGlossary.Term(EntryIndex);
  FDefinitionLabel.Caption := FGlossary.Definition(EntryIndex);
  Related := FGlossary.RelatedTerms(EntryIndex, MaximumRelatedTerms);
  FRelatedHeading.Visible := Length(Related) > 0;
  FRelatedPanel.Visible := Length(Related) > 0;
  for I := 0 to MaximumRelatedTerms - 1 do
    if I <= High(Related) then
    begin
      FRelatedButtons[I].Caption := FGlossary.Term(Related[I]);
      FRelatedButtons[I].Tag := Related[I];
      FRelatedButtons[I].Visible := True;
    end
    else
      FRelatedButtons[I].Visible := False;
end;

procedure TKnowledgeBaseFrame.SearchChanged(Sender: TObject);
begin
  RefreshTermList(-1);
end;

procedure TKnowledgeBaseFrame.TermSelectionChanged(Sender: TObject;
  User: Boolean);
begin
  RefreshReadingPane;
end;

procedure TKnowledgeBaseFrame.RelatedTermClicked(Sender: TObject);
var
  Target: Integer;
begin
  Target := TComponent(Sender).Tag;
  FSearchEdit.OnChange := nil;
  try
    FSearchEdit.Text := '';
  finally
    FSearchEdit.OnChange := @SearchChanged;
  end;
  RefreshTermList(Target);
end;

procedure TKnowledgeBaseFrame.Activate;
begin
  if FSearchEdit.CanSetFocus then
    FSearchEdit.SetFocus;
end;

procedure TKnowledgeBaseFrame.Deactivate;
begin
  { No transient state to release. }
end;

function TKnowledgeBaseFrame.TermCount: Integer;
begin
  Result := FGlossary.Count;
end;

end.
