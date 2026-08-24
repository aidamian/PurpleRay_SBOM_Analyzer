{ Sprint 11 shell-redesign regressions: embedded glossary model and
  dashboard statistics. Tests are deterministic, offline, and LCL-free. }

function S11GlossarySourceFileName: string;
begin
  Result := ExpandFileName('docs' + DirectorySeparator + 'GLOSSARY.md');
  if not FileExists(Result) then
    Result := ExpandFileName('..' + DirectorySeparator + 'docs' +
      DirectorySeparator + 'GLOSSARY.md');
end;

procedure TestGlossaryEmbeddedContentInSync;
var
  Source: TStringList;
  FileText: string;
begin
  Source := TStringList.Create;
  try
    AssertTrue(FileExists(S11GlossarySourceFileName),
      'docs/GLOSSARY.md is missing from the repository checkout');
    Source.LoadFromFile(S11GlossarySourceFileName);
    FileText := TrimRight(Source.Text);
    AssertEqual(TrimRight(GlossaryMarkdown),
      StringReplace(FileText, #13#10, #10, [rfReplaceAll]),
      'uGlossaryContent.pas is out of sync with docs/GLOSSARY.md; run ' +
      'scripts/regenerate-glossary-unit.sh');
  finally
    Source.Free;
  end;
end;

procedure TestGlossaryParsing;
var
  Glossary: TGlossary;
  AdvisoryIndex: Integer;
begin
  Glossary := TGlossary.Create;
  try
    Glossary.LoadFromMarkdown(GlossaryMarkdown);
    AssertEqual(108, Glossary.Count,
      'embedded glossary should parse every documented term');
    AssertEqual('ABI (Application Binary Interface)', Glossary.Term(0),
      'first glossary term should follow document order');
    AdvisoryIndex := Glossary.IndexOfTerm('Advisory and advisory ID');
    AssertTrue(AdvisoryIndex >= 0,
      'advisory term should be present in the glossary');
    AssertTrue(Pos('OSV', Glossary.Definition(AdvisoryIndex)) > 0,
      'advisory definition should keep its wrapped body text');
    AssertTrue(Pos(#10, Glossary.Definition(AdvisoryIndex)) = 0,
      'definitions should be unwrapped to single-line text');
  finally
    Glossary.Free;
  end;
end;

procedure TestGlossarySearchFilter;
var
  Glossary: TGlossary;
  Hits: TIntegerArray;
begin
  Glossary := TGlossary.Create;
  try
    Glossary.LoadFromMarkdown(GlossaryMarkdown);
    Hits := Glossary.Filter('');
    AssertEqual(Glossary.Count, Length(Hits),
      'an empty query should select every glossary entry');
    Hits := Glossary.Filter('advisory');
    AssertTrue(Length(Hits) > 0, 'advisory search should match entries');
    AssertTrue(Pos('advisory', LowerCase(Glossary.Term(Hits[0]))) > 0,
      'term matches should be ordered before definition-only matches');
    Hits := Glossary.Filter('no-such-term-anywhere-xyz');
    AssertEqual(0, Length(Hits),
      'an unmatched query should select nothing');
  finally
    Glossary.Free;
  end;
end;

procedure TestGlossaryRelatedTerms;
var
  Glossary: TGlossary;
  Related: TIntegerArray;
  I: Integer;
begin
  Glossary := TGlossary.Create;
  try
    Glossary.LoadFromMarkdown(
      '**Alpha term** ' + #$E2#$80#$94 + ' Works with the beta term ' +
      'and mentions gamma widget handling.' + #10#10 +
      '**Beta term** ' + #$E2#$80#$94 + ' Stands alone.' + #10#10 +
      '**Gamma widget** ' + #$E2#$80#$94 + ' Mentions alpha term.' +
      #10#10 +
      '**Delta** ' + #$E2#$80#$94 + ' Unrelated.' + #10);
    AssertEqual(4, Glossary.Count, 'related-terms fixture should parse');
    Related := Glossary.RelatedTerms(0, 4);
    AssertEqual(2, Length(Related),
      'alpha should relate to beta term and gamma widget only');
    AssertEqual('Beta term', Glossary.Term(Related[0]),
      'related terms should keep document order');
    AssertEqual('Gamma widget', Glossary.Term(Related[1]),
      'related terms should include multi-word matches');
    for I := 0 to High(Related) do
      AssertTrue(Related[I] <> 0, 'an entry never relates to itself');
    Related := Glossary.RelatedTerms(0, 1);
    AssertEqual(1, Length(Related),
      'related terms should honor the requested maximum');
  finally
    Glossary.Free;
  end;
end;

procedure TestDashboardStatsAggregation;
var
  Tasks: TObjectList;
  Task: TScanTask;
  Stats: TDashboardStats;
begin
  Tasks := TObjectList.Create(True);
  try
    Stats := ComputeDashboardStats(nil);
    AssertEqual(0, Stats.ScanCount, 'nil task list should count as empty');
    Stats := ComputeDashboardStats(Tasks);
    AssertEqual(0, Stats.ScanCount, 'empty history should yield zeros');

    Task := TScanTask.Create;
    Task.Status := tsCompleted;
    Task.ComponentsIdentified := 23;
    Task.ArtifactsDetected := 5;
    Task.FilesInspected := 1204;
    Task.KnownIssueCheck.AddMatch(
      S10NewMatch('pkg:pypi/flask@3.0.3', 'GHSA-aaaa', '2026-01-01'));
    Task.KnownIssueCheck.AddMatch(
      S10NewMatch('pkg:pypi/flask@3.0.3', 'GHSA-bbbb', '2026-01-01'));
    Tasks.Add(Task);

    Task := TScanTask.Create;
    Task.Status := tsFailed;
    Task.ComponentsIdentified := 7;
    Task.ArtifactsDetected := 2;
    Task.FilesInspected := 30;
    Task.KnownIssueCheck.AddMatch(
      S10NewMatch('pkg:pypi/requests@2.32.3', 'GHSA-aaaa', '2026-01-01'));
    Tasks.Add(Task);

    Task := TScanTask.Create;
    Task.Status := tsRunning;
    Tasks.Add(Task);

    Stats := ComputeDashboardStats(Tasks);
    AssertEqual(3, Stats.ScanCount, 'every task should be counted');
    AssertEqual(1, Stats.CompletedScanCount,
      'completed tasks should be counted separately');
    AssertEqual(1, Stats.RunningScanCount,
      'running tasks should be counted separately');
    AssertEqual(1, Stats.FailedScanCount,
      'failed tasks should be counted separately');
    AssertEqual(30, Integer(Stats.ComponentsDiscovered),
      'component totals should sum across the history');
    AssertEqual(7, Integer(Stats.ArtifactsInspected),
      'artifact totals should sum across the history');
    AssertEqual(1234, Integer(Stats.FilesInspected),
      'file totals should sum across the history');
    AssertEqual(2, Stats.UniqueAdvisoryCount,
      'advisories repeated across tasks should be counted once');
  finally
    Tasks.Free;
  end;
end;

procedure RunSprint11RegressionTests;
begin
  RunTest('embedded glossary content sync',
    @TestGlossaryEmbeddedContentInSync);
  RunTest('glossary parsing', @TestGlossaryParsing);
  RunTest('glossary search filter', @TestGlossarySearchFilter);
  RunTest('glossary related terms', @TestGlossaryRelatedTerms);
  RunTest('dashboard statistics aggregation',
    @TestDashboardStatsAggregation);
end;
