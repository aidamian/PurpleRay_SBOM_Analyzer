(**
  PurpleRay SBOM Analyzer glossary model.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  LCL-free parser and query model for the bundled glossary markdown.
  Terms use the documented shape "**Term** - definition" with wrapped
  continuation lines and blank-line separators. Related terms are
  derived deterministically by finding other term names inside a
  definition; nothing is guessed or fetched.

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
unit uGlossary;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TIntegerArray = array of Integer;

  TGlossary = class
  private
    FTerms: TStringList;
    FDefinitions: TStringList;
    FShortNames: TStringList;

    {**
      Extracts the search key used for related-term matching.

      Parameters
      ----------
      ATerm
        Full display term, possibly with a parenthesized expansion.

      Returns
      -------
      string
        Lowercased term text before any " (" suffix, trimmed.

      Raises
      ------
      None
    }
    class function ShortNameFor(const ATerm: string): string;

    {**
      Tests whether a lowercase needle occurs with word boundaries.

      Parameters
      ----------
      AHaystackLower
        Lowercased text to search.
      ANeedleLower
        Lowercased term name; empty never matches.

      Returns
      -------
      Boolean
        True when the needle occurs and neither neighbor is a letter
        or digit, preventing matches inside larger words.

      Raises
      ------
      None
    }
    class function ContainsWord(const AHaystackLower,
      ANeedleLower: string): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    {**
      Parses glossary markdown into ordered term/definition pairs.

      Parameters
      ----------
      AText
        Markdown where each entry starts with "**Term**" followed by a
        separator and a definition that may wrap across lines until a
        blank line.

      Returns
      -------
      None

      Raises
      ------
      None
    }
    procedure LoadFromMarkdown(const AText: string);

    {**
      Returns the number of parsed glossary entries.

      Parameters
      ----------
      None

      Returns
      -------
      Integer
        Entry count in document order.

      Raises
      ------
      None
    }
    function Count: Integer;

    {**
      Returns the display term at a position.

      Parameters
      ----------
      AIndex
        Zero-based entry index.

      Returns
      -------
      string
        Term text, or an empty string for an out-of-range index.

      Raises
      ------
      None
    }
    function Term(AIndex: Integer): string;

    {**
      Returns the definition at a position.

      Parameters
      ----------
      AIndex
        Zero-based entry index.

      Returns
      -------
      string
        Single-line definition text, or an empty string when out of
        range.

      Raises
      ------
      None
    }
    function Definition(AIndex: Integer): string;

    {**
      Finds an entry by its exact display term.

      Parameters
      ----------
      ATerm
        Term text compared case-insensitively.

      Returns
      -------
      Integer
        Entry index, or -1 when the term is not present.

      Raises
      ------
      None
    }
    function IndexOfTerm(const ATerm: string): Integer;

    {**
      Filters entries by a case-insensitive substring.

      Parameters
      ----------
      AQuery
        Search text; an empty or blank query selects every entry.

      Returns
      -------
      TIntegerArray
        Matching entry indices with term matches ordered before
        definition-only matches, each group in document order.

      Raises
      ------
      None
    }
    function Filter(const AQuery: string): TIntegerArray;

    {**
      Derives related entries referenced inside one definition.

      Parameters
      ----------
      AIndex
        Entry whose definition is scanned.
      AMaximum
        Upper bound on returned indices; values below one yield none.

      Returns
      -------
      TIntegerArray
        Indices of other entries whose term name occurs in the
        definition, in document order.

      Raises
      ------
      None
    }
    function RelatedTerms(AIndex, AMaximum: Integer): TIntegerArray;
  end;

implementation

const
  TermMarker = '**';

constructor TGlossary.Create;
begin
  inherited Create;
  FTerms := TStringList.Create;
  FDefinitions := TStringList.Create;
  FShortNames := TStringList.Create;
end;

destructor TGlossary.Destroy;
begin
  FShortNames.Free;
  FDefinitions.Free;
  FTerms.Free;
  inherited Destroy;
end;

class function TGlossary.ShortNameFor(const ATerm: string): string;
var
  CutAt: Integer;
begin
  Result := Trim(ATerm);
  CutAt := Pos(' (', Result);
  if CutAt > 0 then
    Result := Copy(Result, 1, CutAt - 1);
  Result := LowerCase(Result);
end;

class function TGlossary.ContainsWord(const AHaystackLower,
  ANeedleLower: string): Boolean;
var
  FoundAt, After: Integer;
  Before, Following: Char;
begin
  Result := False;
  if ANeedleLower = '' then
    Exit;
  FoundAt := Pos(ANeedleLower, AHaystackLower);
  while FoundAt > 0 do
  begin
    Before := ' ';
    if FoundAt > 1 then
      Before := AHaystackLower[FoundAt - 1];
    After := FoundAt + Length(ANeedleLower);
    Following := ' ';
    if After <= Length(AHaystackLower) then
      Following := AHaystackLower[After];
    if not (Before in ['a'..'z', '0'..'9']) and
      not (Following in ['a'..'z', '0'..'9']) then
      Exit(True);
    FoundAt := Pos(ANeedleLower, AHaystackLower, FoundAt + 1);
  end;
end;

procedure TGlossary.LoadFromMarkdown(const AText: string);
var
  Lines: TStringList;
  I, CloseAt: Integer;
  Line, TermText, DefinitionText: string;

  procedure CommitEntry;
  begin
    if TermText = '' then
      Exit;
    FTerms.Add(TermText);
    FDefinitions.Add(Trim(DefinitionText));
    FShortNames.Add(ShortNameFor(TermText));
    TermText := '';
    DefinitionText := '';
  end;

begin
  FTerms.Clear;
  FDefinitions.Clear;
  FShortNames.Clear;
  TermText := '';
  DefinitionText := '';
  Lines := TStringList.Create;
  try
    Lines.Text := AText;
    for I := 0 to Lines.Count - 1 do
    begin
      Line := TrimRight(Lines[I]);
      if Trim(Line) = '' then
      begin
        CommitEntry;
        Continue;
      end;
      if Copy(Line, 1, Length(TermMarker)) = TermMarker then
      begin
        CommitEntry;
        CloseAt := Pos(TermMarker, Line, Length(TermMarker) + 1);
        if CloseAt <= 0 then
          Continue;
        TermText := Trim(Copy(Line, Length(TermMarker) + 1,
          CloseAt - Length(TermMarker) - 1));
        DefinitionText := Trim(Copy(Line, CloseAt + Length(TermMarker),
          MaxInt));
        { Strip the leading separator: an em dash or hyphen run. }
        while (DefinitionText <> '') and
          (DefinitionText[1] in ['-', ' ']) do
          Delete(DefinitionText, 1, 1);
        if Copy(DefinitionText, 1, 3) = #$E2#$80#$94 then
        begin
          Delete(DefinitionText, 1, 3);
          DefinitionText := TrimLeft(DefinitionText);
        end;
      end
      else if TermText <> '' then
      begin
        { Rejoin wrapped lines; a trailing hyphen marks a split word. }
        if (DefinitionText <> '') and
          (DefinitionText[Length(DefinitionText)] <> '-') then
          DefinitionText := DefinitionText + ' ';
        DefinitionText := DefinitionText + Trim(Line);
      end;
    end;
    CommitEntry;
  finally
    Lines.Free;
  end;
end;

function TGlossary.Count: Integer;
begin
  Result := FTerms.Count;
end;

function TGlossary.Term(AIndex: Integer): string;
begin
  Result := '';
  if (AIndex >= 0) and (AIndex < FTerms.Count) then
    Result := FTerms[AIndex];
end;

function TGlossary.Definition(AIndex: Integer): string;
begin
  Result := '';
  if (AIndex >= 0) and (AIndex < FDefinitions.Count) then
    Result := FDefinitions[AIndex];
end;

function TGlossary.IndexOfTerm(const ATerm: string): Integer;
var
  I: Integer;
begin
  for I := 0 to FTerms.Count - 1 do
    if SameText(FTerms[I], ATerm) then
      Exit(I);
  Result := -1;
end;

function TGlossary.Filter(const AQuery: string): TIntegerArray;
var
  Query: string;
  TermHits, DefinitionHits: TIntegerArray;
  TermCount, DefinitionCount, I: Integer;
begin
  Query := LowerCase(Trim(AQuery));
  if Query = '' then
  begin
    SetLength(Result, FTerms.Count);
    for I := 0 to FTerms.Count - 1 do
      Result[I] := I;
    Exit;
  end;
  SetLength(TermHits, FTerms.Count);
  SetLength(DefinitionHits, FTerms.Count);
  TermCount := 0;
  DefinitionCount := 0;
  for I := 0 to FTerms.Count - 1 do
    if Pos(Query, LowerCase(FTerms[I])) > 0 then
    begin
      TermHits[TermCount] := I;
      Inc(TermCount);
    end
    else if Pos(Query, LowerCase(FDefinitions[I])) > 0 then
    begin
      DefinitionHits[DefinitionCount] := I;
      Inc(DefinitionCount);
    end;
  SetLength(Result, TermCount + DefinitionCount);
  for I := 0 to TermCount - 1 do
    Result[I] := TermHits[I];
  for I := 0 to DefinitionCount - 1 do
    Result[TermCount + I] := DefinitionHits[I];
end;

function TGlossary.RelatedTerms(AIndex, AMaximum: Integer): TIntegerArray;
var
  DefinitionLower: string;
  I, Found: Integer;
begin
  SetLength(Result, 0);
  if (AIndex < 0) or (AIndex >= FTerms.Count) or (AMaximum < 1) then
    Exit;
  DefinitionLower := LowerCase(FDefinitions[AIndex]);
  Found := 0;
  SetLength(Result, AMaximum);
  for I := 0 to FTerms.Count - 1 do
  begin
    if I = AIndex then
      Continue;
    if Length(FShortNames[I]) < 3 then
      Continue;
    if ContainsWord(DefinitionLower, FShortNames[I]) then
    begin
      Result[Found] := I;
      Inc(Found);
      if Found = AMaximum then
        Break;
    end;
  end;
  SetLength(Result, Found);
end;

end.
