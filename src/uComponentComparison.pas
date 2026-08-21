(**
  PurpleRay SBOM Analyzer component-comparison unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Compares the normalized component inventories retained by two scan tasks.
  Matching uses version-independent Package URL coordinates when available and
  a conservative field fallback with explicit warnings when coordinate
  evidence is absent. Known ambiguous coordinates are never conflated. Results
  own copied scalar values, remain independent of task lifetime, and are
  ordered deterministically without modifying either input task.

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
unit uComponentComparison;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels;

type
  {** Directional component-inventory classifications emitted by comparison. *}
  TComponentChangeKind = (ccAdded, ccRemoved, ccVersionChanged);

  {**
    One immutable-by-convention, scalar-only comparison row.

    ``Before`` values describe the baseline task and ``After`` values describe
    the current task. Added rows have no before values, removed rows have no
    after values, and version-changed rows retain both. ``IdentityKey`` and
    ``RowKey`` are opaque deterministic keys intended for matching and UI state,
    not user-edited package coordinates.
  *}
  TComponentChange = class
  public
    Kind: TComponentChangeKind;
    RowKey: string;
    IdentityKey: string;
    Name: string;
    Ecosystem: string;
    ComponentType: string;
    BeforeVersion: string;
    AfterVersion: string;
    BeforePackageURL: string;
    AfterPackageURL: string;
    BeforeScope: string;
    AfterScope: string;
  end;

  {**
    Caller-owned comparison result containing owned change rows and sorted,
    duplicate-free diagnostics.
  *}
  TComponentComparison = class
  public
    Changes: TObjectList;
    Warnings: TStringList;
    AddedCount: Integer;
    RemovedCount: Integer;
    VersionChangedCount: Integer;
    UnchangedCount: Integer;

    {**
      Creates an empty comparison with owned change and warning collections.

      Parameters
      ----------
      None

      Returns
      -------
      TComponentComparison
        Newly initialized comparison result.

      Raises
      ------
      EOutOfMemory
        Propagated when either owned collection cannot be allocated.
    }
    constructor Create;

    {**
      Releases all owned change records and diagnostic strings.

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
    destructor Destroy; override;
  end;

{**
  Compares two task component inventories without modifying either task.

  Parameters
  ----------
  ABaseline
    Earlier or otherwise operator-selected baseline task.
  ACurrent
    Later or otherwise operator-selected current task.

  Returns
  -------
  TComponentComparison
    Newly allocated, caller-owned deterministic comparison result. Every
    change contains copied scalar values and remains valid after either task is
    released.

  Raises
  ------
  EArgumentNilException
    Raised when either task is nil.
  EOutOfMemory
    Propagated if snapshots, identity indexes, or result records cannot be
    allocated.
}
function CompareComponentTasks(ABaseline, ACurrent: TScanTask):
  TComponentComparison;

implementation

type
  TComponentSnapshot = class
  public
    Name: string;
    Version: string;
    Ecosystem: string;
    ComponentType: string;
    PackageURL: string;
    Scope: string;
    SourceArtifact: string;
    SourceParser: string;
    SHA256: string;
    StrongKey: string;
    WeakKey: string;
    AssignedIdentity: string;
  end;

  TWeakIdentityInfo = class
  public
    StrongKeys: TStringList;
    HasMissingStrongKey: Boolean;

    {**
      Creates the deterministic set of strong identities observed for a weak
      field identity.

      Parameters
      ----------
      None

      Returns
      -------
      TWeakIdentityInfo
        Newly initialized weak-identity record.

      Raises
      ------
      EOutOfMemory
        Propagated when the strong-key set cannot be allocated.
    }
    constructor Create;

    {**
      Releases the owned strong-identity set.

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
    destructor Destroy; override;
  end;

  TIdentityGroup = class
  public
    BeforeItems: TObjectList;
    AfterItems: TObjectList;

    {**
      Creates non-owning baseline and current snapshot collections.

      Parameters
      ----------
      None

      Returns
      -------
      TIdentityGroup
        Newly initialized identity group.

      Raises
      ------
      EOutOfMemory
        Propagated when either collection cannot be allocated.
    }
    constructor Create;

    {**
      Releases the non-owning snapshot collections without releasing snapshots.

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
    destructor Destroy; override;
  end;

{**
  Converts ASCII uppercase letters to lowercase without locale-sensitive rules.

  Parameters
  ----------
  AValue
    Text whose ASCII letters should be folded.

  Returns
  -------
  string
    Text with bytes A through Z converted to a through z and all other bytes
    preserved exactly.

  Raises
  ------
  EOutOfMemory
    Propagated if the result string cannot be allocated.
}
function FoldASCII(const AValue: string): string;
var
  I: SizeInt;
begin
  Result := AValue;
  for I := 1 to Length(Result) do
    if Result[I] in ['A'..'Z'] then
      Result[I] := Chr(Ord(Result[I]) + Ord('a') - Ord('A'));
end;

{**
  Encodes one arbitrary string as an unambiguous identity-key field.

  Parameters
  ----------
  AValue
    Field value to encode.

  Returns
  -------
  string
    Decimal byte length, a colon, and the original field value.

  Raises
  ------
  EOutOfMemory
    Propagated if the encoded field cannot be allocated.
}
function KeyPart(const AValue: string): string;
begin
  Result := IntToStr(Length(AValue)) + ':' + AValue;
end;

{**
  Replaces control bytes and bounds diagnostic excerpts retained in warnings.

  Parameters
  ----------
  AValue
    Potentially malformed persisted value.

  Returns
  -------
  string
    Printable text no longer than 120 bytes, with an ellipsis when truncated.

  Raises
  ------
  EOutOfMemory
    Propagated if the excerpt cannot be allocated.
}
function DiagnosticExcerpt(const AValue: string): string;
var
  I: SizeInt;
begin
  Result := AValue;
  for I := 1 to Length(Result) do
    if (Ord(Result[I]) < 32) or (Ord(Result[I]) = 127) then
      Result[I] := '?';
  if Length(Result) > 120 then
    Result := Copy(Result, 1, 117) + '...';
end;

{**
  Tests text for whitespace or control bytes forbidden inside a Package URL.

  Parameters
  ----------
  AValue
    Trimmed Package URL candidate.

  Returns
  -------
  Boolean
    True when a byte is ASCII whitespace, another control, or DEL.

  Raises
  ------
  None
}
function HasForbiddenPURLByte(const AValue: string): Boolean;
var
  I: SizeInt;
begin
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) <= 32) or (Ord(AValue[I]) = 127) then
      Exit(True);
  Result := False;
end;

{**
  Counts occurrences of one ASCII marker in a string.

  Parameters
  ----------
  AValue
    Text to inspect.
  AMarker
    Marker byte to count.

  Returns
  -------
  Integer
    Number of exact marker occurrences.

  Raises
  ------
  None
}
function CountMarker(const AValue: string; AMarker: Char): Integer;
var
  I: SizeInt;
begin
  Result := 0;
  for I := 1 to Length(AValue) do
    if AValue[I] = AMarker then
      Inc(Result);
end;

{**
  Converts one hexadecimal digit to its numeric value.

  Parameters
  ----------
  AValue
    Candidate ASCII hexadecimal digit.

  Returns
  -------
  Integer
    Value from zero through fifteen, or -1 for a non-hexadecimal byte.

  Raises
  ------
  None
}
function PURLHexValue(AValue: Char): Integer;
begin
  if AValue in ['0'..'9'] then
    Result := Ord(AValue) - Ord('0')
  else if AValue in ['A'..'F'] then
    Result := Ord(AValue) - Ord('A') + 10
  else if AValue in ['a'..'f'] then
    Result := Ord(AValue) - Ord('a') + 10
  else
    Result := -1;
end;

{**
  Tests one byte for the unreserved characters retained literally in a PURL.

  Parameters
  ----------
  AValue
    Candidate byte.

  Returns
  -------
  Boolean
    True for ASCII letters, digits, period, dash, underscore, or tilde.

  Raises
  ------
  None
}
function IsPURLUnreserved(AValue: Byte): Boolean;
begin
  Result := (AValue in [Ord('A')..Ord('Z'), Ord('a')..Ord('z'),
    Ord('0')..Ord('9')]) or
    (AValue in [Ord('.'), Ord('-'), Ord('_'), Ord('~')]);
end;

{**
  Validates a byte string as shortest-form UTF-8 without surrogate codepoints.

  Parameters
  ----------
  AValue
    Percent-decoded component bytes.

  Returns
  -------
  Boolean
    True only for complete, scalar-value UTF-8 sequences.

  Raises
  ------
  None
}
function IsValidPURLUTF8(const AValue: string): Boolean;
var
  I: SizeInt;
  Byte1, Byte2, Byte3, Byte4: Byte;
begin
  I := 1;
  while I <= Length(AValue) do
  begin
    Byte1 := Byte(AValue[I]);
    if Byte1 <= $7F then
      Inc(I)
    else if (Byte1 >= $C2) and (Byte1 <= $DF) then
    begin
      if I + 1 > Length(AValue) then
        Exit(False);
      Byte2 := Byte(AValue[I + 1]);
      if not (Byte2 in [$80..$BF]) then
        Exit(False);
      Inc(I, 2);
    end
    else if (Byte1 >= $E0) and (Byte1 <= $EF) then
    begin
      if I + 2 > Length(AValue) then
        Exit(False);
      Byte2 := Byte(AValue[I + 1]);
      Byte3 := Byte(AValue[I + 2]);
      if not (Byte3 in [$80..$BF]) then
        Exit(False);
      if Byte1 = $E0 then
      begin
        if not (Byte2 in [$A0..$BF]) then
          Exit(False);
      end
      else if Byte1 = $ED then
      begin
        if not (Byte2 in [$80..$9F]) then
          Exit(False);
      end
      else if not (Byte2 in [$80..$BF]) then
        Exit(False);
      Inc(I, 3);
    end
    else if (Byte1 >= $F0) and (Byte1 <= $F4) then
    begin
      if I + 3 > Length(AValue) then
        Exit(False);
      Byte2 := Byte(AValue[I + 1]);
      Byte3 := Byte(AValue[I + 2]);
      Byte4 := Byte(AValue[I + 3]);
      if not (Byte3 in [$80..$BF]) or not (Byte4 in [$80..$BF]) then
        Exit(False);
      if Byte1 = $F0 then
      begin
        if not (Byte2 in [$90..$BF]) then
          Exit(False);
      end
      else if Byte1 = $F4 then
      begin
        if not (Byte2 in [$80..$8F]) then
          Exit(False);
      end
      else if not (Byte2 in [$80..$BF]) then
        Exit(False);
      Inc(I, 4);
    end
    else
      Exit(False);
  end;
  Result := True;
end;

{**
  Validates and canonicalizes one percent-encoded PURL data component.

  Parameters
  ----------
  AValue
    Encoded component text without structural separators.
  AForbidDecodedSlash
    True for path segments, whose decoded content may not contain a slash.
  ACanonical
    Receives canonical ASCII text with uppercase escapes and needless escapes
    of unreserved bytes or colons removed.

  Returns
  -------
  Boolean
    True only for permitted ASCII text that decodes to valid, control-free
    UTF-8.

  Raises
  ------
  EOutOfMemory
    Propagated while constructing decoded and canonical strings.
}
function TryCanonicalPURLData(const AValue: string;
  AForbidDecodedSlash: Boolean; out ACanonical: string): Boolean;
const
  HexDigits = '0123456789ABCDEF';
var
  Decoded: string;
  I, HighValue, LowValue: SizeInt;
  ByteValue: Byte;
begin
  Result := False;
  ACanonical := '';
  Decoded := '';
  I := 1;
  while I <= Length(AValue) do
  begin
    if AValue[I] = '%' then
    begin
      if I + 2 > Length(AValue) then
        Exit;
      HighValue := PURLHexValue(AValue[I + 1]);
      LowValue := PURLHexValue(AValue[I + 2]);
      if (HighValue < 0) or (LowValue < 0) then
        Exit;
      ByteValue := Byte((HighValue shl 4) or LowValue);
      Inc(I, 3);
    end
    else
    begin
      ByteValue := Byte(AValue[I]);
      if (ByteValue > $7F) or
        (not IsPURLUnreserved(ByteValue) and (ByteValue <> Ord(':'))) then
        Exit;
      Inc(I);
    end;
    if (ByteValue < 32) or (ByteValue = 127) or
      (AForbidDecodedSlash and (ByteValue = Ord('/'))) then
      Exit;
    Decoded := Decoded + Char(ByteValue);
    if IsPURLUnreserved(ByteValue) or (ByteValue = Ord(':')) then
      ACanonical := ACanonical + Char(ByteValue)
    else
      ACanonical := ACanonical + '%' + HexDigits[(ByteValue shr 4) + 1] +
        HexDigits[(ByteValue and $0F) + 1];
  end;
  Result := IsValidPURLUTF8(Decoded);
end;

{**
  Canonicalizes slash-delimited package-path or subpath segments.

  Parameters
  ----------
  AValue
    Encoded segments whose insignificant leading and trailing slashes are
    removed; empty segments inside the value remain invalid.
  ARejectDotSegments
    True for subpaths, where dot and dot-dot segments are forbidden and every
    decoded slash is invalid. False for a package path, whose final name
    segment may contain a percent-encoded slash while namespace segments may
    not.
  ACanonical
    Receives canonical segments joined by literal slashes.

  Returns
  -------
  Boolean
    True only when every segment is non-empty and valid.

  Raises
  ------
  EOutOfMemory
    Propagated while canonicalizing or joining segments.
}
function TryCanonicalPURLSegments(const AValue: string;
  ARejectDotSegments: Boolean; out ACanonical: string): Boolean;
var
  I, SegmentStart: SizeInt;
  NormalizedValue, SegmentValue, CanonicalSegment: string;
  ForbidDecodedSlash: Boolean;
begin
  Result := False;
  ACanonical := '';
  NormalizedValue := AValue;
  while (NormalizedValue <> '') and (NormalizedValue[1] = '/') do
    Delete(NormalizedValue, 1, 1);
  while (NormalizedValue <> '') and
    (NormalizedValue[Length(NormalizedValue)] = '/') do
    Delete(NormalizedValue, Length(NormalizedValue), 1);
  if NormalizedValue = '' then
    Exit;
  SegmentStart := 1;
  for I := 1 to Length(NormalizedValue) + 1 do
    if (I > Length(NormalizedValue)) or (NormalizedValue[I] = '/') then
    begin
      if I = SegmentStart then
        Exit;
      SegmentValue := Copy(NormalizedValue, SegmentStart, I - SegmentStart);
      ForbidDecodedSlash := ARejectDotSegments or
        (I <= Length(NormalizedValue));
      if not TryCanonicalPURLData(SegmentValue, ForbidDecodedSlash,
        CanonicalSegment) then
        Exit;
      if ARejectDotSegments and
        ((CanonicalSegment = '.') or (CanonicalSegment = '..')) then
        Exit;
      if ACanonical <> '' then
        ACanonical := ACanonical + '/';
      ACanonical := ACanonical + CanonicalSegment;
      SegmentStart := I + 1;
    end;
  Result := True;
end;

{**
  Parses, validates, and sorts the qualifier map of a Package URL.

  Parameters
  ----------
  AValue
    Ampersand-delimited key=value pairs without the leading question mark.
  ACanonical
    Receives unique qualifiers sorted by their lowercase ordinal keys.

  Returns
  -------
  Boolean
    True only for a non-empty, structurally valid qualifier map.

  Raises
  ------
  EOutOfMemory
    Propagated while storing and sorting qualifier pairs.
}
function TryCanonicalPURLQualifiers(const AValue: string;
  out ACanonical: string): Boolean;
var
  Pairs, Keys: TStringList;
  I, PairStart, EqualsAt, CharacterIndex: SizeInt;
  PairValue, KeyValue, ValueValue, CanonicalValue: string;
begin
  Result := False;
  ACanonical := '';
  if AValue = '' then
    Exit;
  Pairs := TStringList.Create;
  Keys := TStringList.Create;
  try
    Pairs.Sorted := True;
    Pairs.CaseSensitive := True;
    Pairs.UseLocale := False;
    Pairs.Duplicates := dupError;
    Keys.Sorted := True;
    Keys.CaseSensitive := True;
    Keys.UseLocale := False;
    Keys.Duplicates := dupError;
    PairStart := 1;
    for I := 1 to Length(AValue) + 1 do
      if (I > Length(AValue)) or (AValue[I] = '&') then
      begin
        if I = PairStart then
          Exit;
        PairValue := Copy(AValue, PairStart, I - PairStart);
        EqualsAt := Pos('=', PairValue);
        if (EqualsAt <= 1) or (EqualsAt = Length(PairValue)) or
          (CountMarker(PairValue, '=') <> 1) then
          Exit;
        KeyValue := Copy(PairValue, 1, EqualsAt - 1);
        if not (KeyValue[1] in ['a'..'z']) then
          Exit;
        for CharacterIndex := 1 to Length(KeyValue) do
          if not (KeyValue[CharacterIndex] in
            ['a'..'z', '0'..'9', '.', '-', '_']) then
            Exit;
        if Keys.IndexOf(KeyValue) >= 0 then
          Exit;
        ValueValue := Copy(PairValue, EqualsAt + 1, MaxInt);
        if not TryCanonicalPURLData(ValueValue, False,
          CanonicalValue) or (CanonicalValue = '') then
          Exit;
        Keys.Add(KeyValue);
        Pairs.Add(KeyValue + '=' + CanonicalValue);
        PairStart := I + 1;
      end;
    for I := 0 to Pairs.Count - 1 do
    begin
      if ACanonical <> '' then
        ACanonical := ACanonical + '&';
      ACanonical := ACanonical + Pairs[I];
    end;
    Result := ACanonical <> '';
  finally
    Keys.Free;
    Pairs.Free;
  end;
end;

{**
  Builds a version-independent strong identity from a conservative Package URL.

  Parameters
  ----------
  APURL
    Package URL candidate. Blank input means no strong identity and is not an
    error.
  AKey
    Receives the Package URL coordinate with only its version segment removed.
    Scheme and type are ASCII-folded, percent escapes are normalized, and the
    case-sensitive package path, qualifiers, and subpath remain identity-bearing.

  Returns
  -------
  Boolean
    True for a structurally usable Package URL; False for blank or malformed
    input.

  Raises
  ------
  EOutOfMemory
    Propagated while constructing the coordinate key.
}
function TryVersionlessPURLIdentity(const APURL: string;
  out AKey: string): Boolean;
var
  Value, CoreValue, TypeValue, PathValue, VersionValue, QueryValue,
    FragmentValue, CanonicalPathValue, CanonicalVersion,
    CanonicalQualifiers, CanonicalSubpath: string;
  QueryAt, FragmentAt, SlashAt, VersionAt, I: SizeInt;
begin
  Result := False;
  AKey := '';
  CanonicalVersion := '';
  Value := Trim(APURL);
  if Value = '' then
    Exit;
  if HasForbiddenPURLByte(Value) or
    (Copy(FoldASCII(Value), 1, 4) <> 'pkg:') then
    Exit;
  Delete(Value, 1, 4);
  while (Value <> '') and (Value[1] = '/') do
    Delete(Value, 1, 1);
  if Value = '' then
    Exit;
  if (CountMarker(Value, '?') > 1) or
    (CountMarker(Value, '#') > 1) then
    Exit;
  QueryAt := Pos('?', Value);
  FragmentAt := Pos('#', Value);
  if (QueryAt > 0) and (FragmentAt > 0) and (QueryAt > FragmentAt) then
    Exit;
  CoreValue := Value;
  FragmentValue := '';
  if FragmentAt > 0 then
  begin
    FragmentValue := Copy(CoreValue, FragmentAt + 1, MaxInt);
    Delete(CoreValue, FragmentAt, MaxInt);
    if FragmentValue = '' then
      Exit;
  end;
  QueryValue := '';
  QueryAt := Pos('?', CoreValue);
  if QueryAt > 0 then
  begin
    QueryValue := Copy(CoreValue, QueryAt + 1, MaxInt);
    Delete(CoreValue, QueryAt, MaxInt);
    if QueryValue = '' then
      Exit;
  end;
  SlashAt := Pos('/', CoreValue);
  if (SlashAt <= 1) or (SlashAt = Length(CoreValue)) then
    Exit;
  TypeValue := Copy(CoreValue, 1, SlashAt - 1);
  if not (TypeValue[1] in ['A'..'Z', 'a'..'z']) then
    Exit;
  for I := 1 to Length(TypeValue) do
    if not (TypeValue[I] in
      ['A'..'Z', 'a'..'z', '0'..'9', '.', '-']) then
      Exit;
  TypeValue := FoldASCII(TypeValue);
  PathValue := Copy(CoreValue, SlashAt + 1, MaxInt);
  if CountMarker(PathValue, '@') > 1 then
    Exit;
  VersionAt := Pos('@', PathValue);
  if VersionAt > 0 then
  begin
    VersionValue := Copy(PathValue, VersionAt + 1, MaxInt);
    Delete(PathValue, VersionAt, MaxInt);
    if (VersionValue = '') or
      not TryCanonicalPURLData(VersionValue, False, CanonicalVersion) or
      (CanonicalVersion = '') then
      Exit;
  end;
  if not TryCanonicalPURLSegments(PathValue, False,
    CanonicalPathValue) then
    Exit;
  CanonicalQualifiers := '';
  if (QueryValue <> '') and not TryCanonicalPURLQualifiers(QueryValue,
    CanonicalQualifiers) then
    Exit;
  CanonicalSubpath := '';
  if (FragmentValue <> '') and not TryCanonicalPURLSegments(FragmentValue,
    True, CanonicalSubpath) then
    Exit;
  AKey := 'purl:pkg:' + TypeValue + '/' + CanonicalPathValue;
  if CanonicalQualifiers <> '' then
    AKey := AKey + '?' + CanonicalQualifiers;
  if CanonicalSubpath <> '' then
    AKey := AKey + '#' + CanonicalSubpath;
  Result := True;
end;

{**
  Builds the version-independent fallback identity for one component.

  Parameters
  ----------
  AComponent
    Component whose ecosystem, name, type, and exceptional empty-name source
    are inspected.

  Returns
  -------
  string
    Length-delimited field identity. Controlled ecosystem and component-type
    tokens are ASCII-folded, while package names and source artifacts retain
    ordinal case so a conservative fallback cannot conflate case-distinct
    components. Source artifact participates only when the component name is
    empty, preventing unrelated malformed entries from collapsing.

  Raises
  ------
  EArgumentNilException
    Raised when AComponent is nil.
  EOutOfMemory
    Propagated while building the identity.
}
function BuildWeakIdentity(AComponent: TComponent): string;
var
  EcosystemValue, NameValue, TypeValue, SourceValue: string;
begin
  if AComponent = nil then
    raise EArgumentNilException.Create('Component must not be nil');
  EcosystemValue := FoldASCII(Trim(AComponent.Ecosystem));
  NameValue := Trim(AComponent.Name);
  TypeValue := FoldASCII(Trim(AComponent.ComponentType));
  if NameValue = '' then
  begin
    SourceValue := Trim(AComponent.SourceArtifact);
    Result := 'invalid-fields:' + KeyPart(EcosystemValue) +
      KeyPart(TypeValue) + KeyPart(SourceValue);
  end
  else
    Result := 'fields:' + KeyPart(EcosystemValue) + KeyPart(NameValue) +
      KeyPart(TypeValue);
end;

constructor TWeakIdentityInfo.Create;
begin
  inherited Create;
  StrongKeys := TStringList.Create;
  StrongKeys.Sorted := True;
  StrongKeys.CaseSensitive := True;
  StrongKeys.UseLocale := False;
  StrongKeys.Duplicates := dupIgnore;
end;

destructor TWeakIdentityInfo.Destroy;
begin
  StrongKeys.Free;
  inherited Destroy;
end;

constructor TIdentityGroup.Create;
begin
  inherited Create;
  BeforeItems := TObjectList.Create(False);
  AfterItems := TObjectList.Create(False);
end;

destructor TIdentityGroup.Destroy;
begin
  AfterItems.Free;
  BeforeItems.Free;
  inherited Destroy;
end;

constructor TComponentComparison.Create;
begin
  inherited Create;
  Changes := TObjectList.Create(True);
  Warnings := TStringList.Create;
  Warnings.Sorted := True;
  Warnings.CaseSensitive := True;
  Warnings.UseLocale := False;
  Warnings.Duplicates := dupIgnore;
end;

destructor TComponentComparison.Destroy;
begin
  Warnings.Free;
  Changes.Free;
  inherited Destroy;
end;

{**
  Frees every object stored in the Objects slots of a string index.

  Parameters
  ----------
  AIndex
    String index whose associated objects are exclusively owned by the index.

  Returns
  -------
  None

  Raises
  ------
  None
}
procedure FreeIndexedObjects(AIndex: TStringList);
var
  I: Integer;
begin
  if AIndex = nil then
    Exit;
  for I := 0 to AIndex.Count - 1 do
    AIndex.Objects[I].Free;
  AIndex.Free;
end;

{**
  Creates an owned scalar snapshot from a component model.

  Parameters
  ----------
  AComponent
    Source component whose ownership and fields remain unchanged.
  ASideName
    Human-readable side name used in diagnostics.
  AWarnings
    Sorted comparison warning set.

  Returns
  -------
  TComponentSnapshot
    Newly allocated caller-owned snapshot.

  Raises
  ------
  EArgumentNilException
    Raised when AComponent or AWarnings is nil.
  EOutOfMemory
    Propagated while copying fields or constructing identity keys.
}
function CreateSnapshot(AComponent: TComponent; const ASideName: string;
  AWarnings: TStrings): TComponentSnapshot;
begin
  if AComponent = nil then
    raise EArgumentNilException.Create('Component must not be nil');
  if AWarnings = nil then
    raise EArgumentNilException.Create('Warning collection must not be nil');
  Result := TComponentSnapshot.Create;
  try
    Result.Name := Trim(AComponent.Name);
    Result.Version := Trim(AComponent.Version);
    Result.Ecosystem := Trim(AComponent.Ecosystem);
    Result.ComponentType := Trim(AComponent.ComponentType);
    Result.PackageURL := Trim(AComponent.PackageURL);
    Result.Scope := Trim(AComponent.DependencyScope);
    Result.SourceArtifact := Trim(AComponent.SourceArtifact);
    Result.SourceParser := Trim(AComponent.SourceParser);
    Result.SHA256 := Trim(AComponent.SHA256);
    Result.WeakKey := BuildWeakIdentity(AComponent);
    if Result.Name = '' then
      AWarnings.Add(ASideName + ' contains a component without a name; its ' +
        'source artifact was retained in a conservative fallback identity.');
    if (Result.PackageURL <> '') and not TryVersionlessPURLIdentity(
      Result.PackageURL, Result.StrongKey) then
      AWarnings.Add(ASideName + ' component Package URL "' +
        DiagnosticExcerpt(Result.PackageURL) + '" is malformed; field ' +
        'identity was used conservatively.');
  except
    Result.Free;
    raise;
  end;
end;

{**
  Copies every valid task component into an owned snapshot list.

  Parameters
  ----------
  ATask
    Task whose component collection is read without mutation.
  ASideName
    Baseline or current label used in warnings.
  AWarnings
    Sorted comparison warning set.

  Returns
  -------
  TObjectList
    Newly allocated list owning TComponentSnapshot entries.

  Raises
  ------
  EArgumentNilException
    Raised when ATask or AWarnings is nil.
  EOutOfMemory
    Propagated while allocating snapshots.
}
function SnapshotTask(ATask: TScanTask; const ASideName: string;
  AWarnings: TStrings): TObjectList;
var
  I: Integer;
  Snapshot: TComponentSnapshot;
begin
  if ATask = nil then
    raise EArgumentNilException.Create('Task must not be nil');
  if AWarnings = nil then
    raise EArgumentNilException.Create('Warning collection must not be nil');
  Result := TObjectList.Create(True);
  try
    if ATask.Components = nil then
    begin
      AWarnings.Add(ASideName + ' task has no component collection.');
      Exit;
    end;
    for I := 0 to ATask.Components.Count - 1 do
      if ATask.Components[I] is TComponent then
      begin
        Snapshot := CreateSnapshot(TComponent(ATask.Components[I]), ASideName,
          AWarnings);
        try
          Result.Add(Snapshot);
          Snapshot := nil;
        finally
          Snapshot.Free;
        end;
      end
      else
        AWarnings.Add(ASideName + ' contains an invalid component entry; it ' +
          'was skipped.');
  except
    Result.Free;
    raise;
  end;
end;

{**
  Returns or creates the weak-identity metadata stored in a sorted index.

  Parameters
  ----------
  AIndex
    Sorted index owning TWeakIdentityInfo objects.
  AWeakKey
    Version-independent fallback identity.

  Returns
  -------
  TWeakIdentityInfo
    Borrowed metadata object associated with AWeakKey.

  Raises
  ------
  EArgumentNilException
    Raised when AIndex is nil.
  EOutOfMemory
    Propagated if the key or metadata object cannot be allocated.
}
function EnsureWeakIdentityInfo(AIndex: TStringList;
  const AWeakKey: string): TWeakIdentityInfo;
var
  Index: Integer;
begin
  if AIndex = nil then
    raise EArgumentNilException.Create('Weak identity index must not be nil');
  if AIndex.Find(AWeakKey, Index) then
    Exit(TWeakIdentityInfo(AIndex.Objects[Index]));
  Result := TWeakIdentityInfo.Create;
  try
    AIndex.AddObject(AWeakKey, Result);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Records strong-key availability for all snapshots on one comparison side.

  Parameters
  ----------
  ASnapshots
    List containing TComponentSnapshot objects.
  AWeakIndex
    Sorted index receiving strong keys grouped by weak key.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when either collection is nil.
  EOutOfMemory
    Propagated while extending the index.
}
procedure IndexWeakIdentities(ASnapshots: TObjectList;
  AWeakIndex: TStringList);
var
  I: Integer;
  Snapshot: TComponentSnapshot;
  Info: TWeakIdentityInfo;
begin
  if ASnapshots = nil then
    raise EArgumentNilException.Create('Snapshot list must not be nil');
  if AWeakIndex = nil then
    raise EArgumentNilException.Create('Weak identity index must not be nil');
  for I := 0 to ASnapshots.Count - 1 do
  begin
    Snapshot := TComponentSnapshot(ASnapshots[I]);
    Info := EnsureWeakIdentityInfo(AWeakIndex, Snapshot.WeakKey);
    if Snapshot.StrongKey <> '' then
      Info.StrongKeys.Add(Snapshot.StrongKey)
    else
      Info.HasMissingStrongKey := True;
  end;
end;

{**
  Assigns one effective identity to each snapshot using cross-side evidence.

  Parameters
  ----------
  ASnapshots
    Snapshot list to annotate with assigned identities.
  AWeakIndex
    Complete weak-to-strong identity index built from both tasks.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when either collection is nil.
}
procedure AssignSnapshotIdentities(ASnapshots: TObjectList;
  AWeakIndex: TStringList);
var
  I, Index: Integer;
  Snapshot: TComponentSnapshot;
  Info: TWeakIdentityInfo;
begin
  if ASnapshots = nil then
    raise EArgumentNilException.Create('Snapshot list must not be nil');
  if AWeakIndex = nil then
    raise EArgumentNilException.Create('Weak identity index must not be nil');
  for I := 0 to ASnapshots.Count - 1 do
  begin
    Snapshot := TComponentSnapshot(ASnapshots[I]);
    if Snapshot.StrongKey <> '' then
      Snapshot.AssignedIdentity := Snapshot.StrongKey
    else if AWeakIndex.Find(Snapshot.WeakKey, Index) then
    begin
      Info := TWeakIdentityInfo(AWeakIndex.Objects[Index]);
      if Info.StrongKeys.Count = 1 then
        Snapshot.AssignedIdentity := Info.StrongKeys[0]
      else
        Snapshot.AssignedIdentity := Snapshot.WeakKey;
    end
    else
      Snapshot.AssignedIdentity := Snapshot.WeakKey;
  end;
end;

{**
  Adds deterministic diagnostics for weak identities that lack strong evidence.

  Parameters
  ----------
  AWeakIndex
    Complete weak-to-strong identity index.
  AWarnings
    Sorted comparison warning set.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when either collection is nil.
  EOutOfMemory
    Propagated while adding a warning.
}
procedure AddFallbackWarnings(AWeakIndex: TStringList; AWarnings: TStrings);
var
  I, FieldOnlyCount: Integer;
  Info: TWeakIdentityInfo;
begin
  if AWeakIndex = nil then
    raise EArgumentNilException.Create('Weak identity index must not be nil');
  if AWarnings = nil then
    raise EArgumentNilException.Create('Warning collection must not be nil');
  FieldOnlyCount := 0;
  for I := 0 to AWeakIndex.Count - 1 do
  begin
    Info := TWeakIdentityInfo(AWeakIndex.Objects[I]);
    if not Info.HasMissingStrongKey then
      Continue;
    if Info.StrongKeys.Count = 0 then
      Inc(FieldOnlyCount)
    else if Info.StrongKeys.Count = 1 then
      AWarnings.Add('Component identity "' + DiagnosticExcerpt(
        AWeakIndex[I]) + '" used an unambiguous field fallback because one ' +
        'or more records had no usable Package URL.')
    else if Info.StrongKeys.Count > 1 then
      AWarnings.Add('Component identity "' + DiagnosticExcerpt(
        AWeakIndex[I]) + '" maps to multiple Package URL coordinates; ' +
        'records without a Package URL were kept separate.');
  end;
  if FieldOnlyCount > 0 then
    AWarnings.Add(IntToStr(FieldOnlyCount) + ' component identity field ' +
      'fallback(s) had no usable Package URL on either scan; matches use ' +
      'case-sensitive package names with ecosystem and component type.');
end;

{**
  Returns or creates a non-owning comparison group for an assigned identity.

  Parameters
  ----------
  AGroups
    Sorted group index owning TIdentityGroup instances.
  AIdentity
    Assigned strong or fallback identity.

  Returns
  -------
  TIdentityGroup
    Borrowed group associated with AIdentity.

  Raises
  ------
  EArgumentNilException
    Raised when AGroups is nil.
  EOutOfMemory
    Propagated if the group cannot be allocated.
}
function EnsureIdentityGroup(AGroups: TStringList;
  const AIdentity: string): TIdentityGroup;
var
  Index: Integer;
begin
  if AGroups = nil then
    raise EArgumentNilException.Create('Identity group index must not be nil');
  if AGroups.Find(AIdentity, Index) then
    Exit(TIdentityGroup(AGroups.Objects[Index]));
  Result := TIdentityGroup.Create;
  try
    AGroups.AddObject(AIdentity, Result);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Adds every snapshot on one side to its effective identity group.

  Parameters
  ----------
  ASnapshots
    Snapshot list whose entries already have AssignedIdentity values.
  AGroups
    Sorted identity-group index.
  ABaselineSide
    True to append to baseline lists; False for current lists.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when a collection is nil.
  EOutOfMemory
    Propagated while allocating a missing group.
}
procedure GroupSnapshots(ASnapshots: TObjectList; AGroups: TStringList;
  ABaselineSide: Boolean);
var
  I: Integer;
  Snapshot: TComponentSnapshot;
  Group: TIdentityGroup;
begin
  if ASnapshots = nil then
    raise EArgumentNilException.Create('Snapshot list must not be nil');
  if AGroups = nil then
    raise EArgumentNilException.Create('Identity group index must not be nil');
  for I := 0 to ASnapshots.Count - 1 do
  begin
    Snapshot := TComponentSnapshot(ASnapshots[I]);
    Group := EnsureIdentityGroup(AGroups, Snapshot.AssignedIdentity);
    if ABaselineSide then
      Group.BeforeItems.Add(Snapshot)
    else
      Group.AfterItems.Add(Snapshot);
  end;
end;

{**
  Builds the deterministic tie-break key for duplicate component snapshots.

  Parameters
  ----------
  ASnapshot
    Snapshot whose copied fields participate in representative selection.

  Returns
  -------
  string
    Length-delimited ordinal key preferring richer Package URL evidence.

  Raises
  ------
  EArgumentNilException
    Raised when ASnapshot is nil.
  EOutOfMemory
    Propagated while constructing the key.
}
function SnapshotTieKey(ASnapshot: TComponentSnapshot): string;
var
  StrongPreference: string;
begin
  if ASnapshot = nil then
    raise EArgumentNilException.Create('Snapshot must not be nil');
  if ASnapshot.StrongKey <> '' then
    StrongPreference := '0'
  else
    StrongPreference := '1';
  Result := StrongPreference + KeyPart(ASnapshot.PackageURL) +
    KeyPart(ASnapshot.Name) + KeyPart(ASnapshot.Ecosystem) +
    KeyPart(ASnapshot.ComponentType) + KeyPart(ASnapshot.Scope) +
    KeyPart(ASnapshot.SourceArtifact) + KeyPart(ASnapshot.SourceParser) +
    KeyPart(ASnapshot.SHA256);
end;

{**
  Collapses duplicate versions within one assigned component identity.

  Parameters
  ----------
  AItems
    Non-owning snapshots belonging to one assigned identity and one side.
  ASideName
    Baseline or current label used in duplicate diagnostics.
  AIdentity
    Assigned identity being reconciled.
  AWarnings
    Sorted comparison warning set.

  Returns
  -------
  TStringList
    Newly allocated caller-owned sorted version index whose Objects are borrowed
    snapshot references.

  Raises
  ------
  EArgumentNilException
    Raised when an input collection is nil.
  EOutOfMemory
    Propagated while allocating the index or tie keys.
}
function BuildUniqueVersionIndex(AItems: TObjectList; const ASideName,
  AIdentity: string; AWarnings: TStrings): TStringList;
var
  I, Index: Integer;
  Snapshot, Existing: TComponentSnapshot;
begin
  if AItems = nil then
    raise EArgumentNilException.Create('Identity item list must not be nil');
  if AWarnings = nil then
    raise EArgumentNilException.Create('Warning collection must not be nil');
  Result := TStringList.Create;
  try
    Result.Sorted := True;
    Result.CaseSensitive := True;
    Result.UseLocale := False;
    Result.Duplicates := dupError;
    for I := 0 to AItems.Count - 1 do
    begin
      Snapshot := TComponentSnapshot(AItems[I]);
      if Result.Find(Snapshot.Version, Index) then
      begin
        Existing := TComponentSnapshot(Result.Objects[Index]);
        if CompareStr(SnapshotTieKey(Snapshot), SnapshotTieKey(Existing)) < 0 then
          Result.Objects[Index] := Snapshot;
        AWarnings.Add(ASideName + ' contains duplicate component identity "' +
          DiagnosticExcerpt(AIdentity) + '" at version "' +
          DiagnosticExcerpt(Snapshot.Version) + '"; duplicate records were ' +
          'collapsed.');
      end
      else
        Result.AddObject(Snapshot.Version, Snapshot);
    end;
  except
    Result.Free;
    raise;
  end;
end;

{**
  Creates the stable row key for one comparison change.

  Parameters
  ----------
  AKind
    Added, removed, or version-changed classification.
  AIdentity, ABeforeVersion, AAfterVersion
    Identity and directional version values uniquely describing the row.

  Returns
  -------
  string
    Opaque, deterministic length-delimited row key.

  Raises
  ------
  EOutOfMemory
    Propagated while constructing the key.
}
function BuildRowKey(AKind: TComponentChangeKind; const AIdentity,
  ABeforeVersion, AAfterVersion: string): string;
begin
  Result := IntToStr(Ord(AKind)) + ':' + KeyPart(AIdentity) +
    KeyPart(ABeforeVersion) + KeyPart(AAfterVersion);
end;

{**
  Appends one scalar-owning result row and updates its classification counter.

  Parameters
  ----------
  AResult
    Comparison result receiving the owned row.
  AKind
    Row classification.
  AIdentity
    Effective version-independent identity.
  ABefore, AAfter
    Optional baseline and current snapshots. At least one must be non-nil.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when AResult is nil or both snapshots are nil.
  EOutOfMemory
    Propagated if the change record or copied fields cannot be allocated.
}
procedure AddChange(AResult: TComponentComparison;
  AKind: TComponentChangeKind; const AIdentity: string;
  ABefore, AAfter: TComponentSnapshot);
var
  Change: TComponentChange;
begin
  if AResult = nil then
    raise EArgumentNilException.Create('Comparison result must not be nil');
  if (ABefore = nil) and (AAfter = nil) then
    raise EArgumentNilException.Create('A comparison change needs a snapshot');
  Change := TComponentChange.Create;
  try
    Change.Kind := AKind;
    Change.IdentityKey := AIdentity;
    if ABefore <> nil then
    begin
      Change.Name := ABefore.Name;
      Change.Ecosystem := ABefore.Ecosystem;
      Change.ComponentType := ABefore.ComponentType;
      Change.BeforeVersion := ABefore.Version;
      Change.BeforePackageURL := ABefore.PackageURL;
      Change.BeforeScope := ABefore.Scope;
    end;
    if AAfter <> nil then
    begin
      if (AAfter.Name <> '') or (Change.Name = '') then
        Change.Name := AAfter.Name;
      if (AAfter.Ecosystem <> '') or (Change.Ecosystem = '') then
        Change.Ecosystem := AAfter.Ecosystem;
      if (AAfter.ComponentType <> '') or (Change.ComponentType = '') then
        Change.ComponentType := AAfter.ComponentType;
      Change.AfterVersion := AAfter.Version;
      Change.AfterPackageURL := AAfter.PackageURL;
      Change.AfterScope := AAfter.Scope;
    end;
    Change.RowKey := BuildRowKey(AKind, AIdentity, Change.BeforeVersion,
      Change.AfterVersion);
    AResult.Changes.Add(Change);
    Change := nil;
    case AKind of
      ccAdded: Inc(AResult.AddedCount);
      ccRemoved: Inc(AResult.RemovedCount);
      ccVersionChanged: Inc(AResult.VersionChangedCount);
    end;
  except
    Change.Free;
    raise;
  end;
end;

{**
  Reconciles one identity's version sets into unchanged and directional rows.

  Parameters
  ----------
  AIdentity
    Assigned strong or fallback identity.
  AGroup
    Baseline/current snapshots associated with the identity.
  AResult
    Comparison receiving owned rows, counts, and duplicate diagnostics.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when AGroup or AResult is nil.
  EOutOfMemory
    Propagated while constructing version indexes or rows.

  Notes
  -----
  Exact versions cancel first. A version-change row is emitted only when each
  original side has exactly one unique version. Residual entries from any
  multi-version identity remain explicit additions and removals rather than
  being paired speculatively.
}
procedure ReconcileIdentity(const AIdentity: string; AGroup: TIdentityGroup;
  AResult: TComponentComparison);
var
  BeforeVersions, AfterVersions: TStringList;
  BeforeOriginalCount, AfterOriginalCount, I, MatchIndex: Integer;
begin
  if AGroup = nil then
    raise EArgumentNilException.Create('Identity group must not be nil');
  if AResult = nil then
    raise EArgumentNilException.Create('Comparison result must not be nil');
  BeforeVersions := BuildUniqueVersionIndex(AGroup.BeforeItems, 'Baseline',
    AIdentity, AResult.Warnings);
  AfterVersions := BuildUniqueVersionIndex(AGroup.AfterItems, 'Current',
    AIdentity, AResult.Warnings);
  try
    BeforeOriginalCount := BeforeVersions.Count;
    AfterOriginalCount := AfterVersions.Count;
    for I := BeforeVersions.Count - 1 downto 0 do
      if AfterVersions.Find(BeforeVersions[I], MatchIndex) then
      begin
        Inc(AResult.UnchangedCount);
        BeforeVersions.Delete(I);
        AfterVersions.Delete(MatchIndex);
      end;

    if (BeforeOriginalCount = 1) and (AfterOriginalCount = 1) and
      (BeforeVersions.Count = 1) and (AfterVersions.Count = 1) then
      AddChange(AResult, ccVersionChanged, AIdentity,
        TComponentSnapshot(BeforeVersions.Objects[0]),
        TComponentSnapshot(AfterVersions.Objects[0]))
    else
    begin
      for I := 0 to BeforeVersions.Count - 1 do
        AddChange(AResult, ccRemoved, AIdentity,
          TComponentSnapshot(BeforeVersions.Objects[I]), nil);
      for I := 0 to AfterVersions.Count - 1 do
        AddChange(AResult, ccAdded, AIdentity, nil,
          TComponentSnapshot(AfterVersions.Objects[I]));
    end;
  finally
    AfterVersions.Free;
    BeforeVersions.Free;
  end;
end;

{**
  Orders change rows by classification and ordinal identity/version fields.

  Parameters
  ----------
  Item1, Item2
    Pointers to TComponentChange instances supplied by TObjectList.Sort.

  Returns
  -------
  Integer
    Negative, zero, or positive according to deterministic row order.

  Raises
  ------
  None
}
function CompareChanges(Item1, Item2: Pointer): Integer;
var
  Left, Right: TComponentChange;
begin
  Left := TComponentChange(Item1);
  Right := TComponentChange(Item2);
  Result := Ord(Left.Kind) - Ord(Right.Kind);
  if Result = 0 then
    Result := CompareStr(Left.IdentityKey, Right.IdentityKey);
  if Result = 0 then
    Result := CompareStr(Left.BeforeVersion, Right.BeforeVersion);
  if Result = 0 then
    Result := CompareStr(Left.AfterVersion, Right.AfterVersion);
  if Result = 0 then
    Result := CompareStr(Left.Ecosystem, Right.Ecosystem);
  if Result = 0 then
    Result := CompareStr(Left.Name, Right.Name);
  if Result = 0 then
    Result := CompareStr(Left.ComponentType, Right.ComponentType);
  if Result = 0 then
    Result := CompareStr(Left.RowKey, Right.RowKey);
end;

function CompareComponentTasks(ABaseline, ACurrent: TScanTask):
  TComponentComparison;
var
  BeforeSnapshots, AfterSnapshots: TObjectList;
  WeakIndex, Groups: TStringList;
  I: Integer;
begin
  if ABaseline = nil then
    raise EArgumentNilException.Create('Baseline task must not be nil');
  if ACurrent = nil then
    raise EArgumentNilException.Create('Current task must not be nil');
  Result := TComponentComparison.Create;
  BeforeSnapshots := nil;
  AfterSnapshots := nil;
  WeakIndex := nil;
  Groups := nil;
  try
    try
      BeforeSnapshots := SnapshotTask(ABaseline, 'Baseline', Result.Warnings);
      AfterSnapshots := SnapshotTask(ACurrent, 'Current', Result.Warnings);

      WeakIndex := TStringList.Create;
      WeakIndex.Sorted := True;
      WeakIndex.CaseSensitive := True;
      WeakIndex.UseLocale := False;
      WeakIndex.Duplicates := dupError;
      IndexWeakIdentities(BeforeSnapshots, WeakIndex);
      IndexWeakIdentities(AfterSnapshots, WeakIndex);
      AddFallbackWarnings(WeakIndex, Result.Warnings);
      AssignSnapshotIdentities(BeforeSnapshots, WeakIndex);
      AssignSnapshotIdentities(AfterSnapshots, WeakIndex);

      Groups := TStringList.Create;
      Groups.Sorted := True;
      Groups.CaseSensitive := True;
      Groups.UseLocale := False;
      Groups.Duplicates := dupError;
      GroupSnapshots(BeforeSnapshots, Groups, True);
      GroupSnapshots(AfterSnapshots, Groups, False);
      for I := 0 to Groups.Count - 1 do
        ReconcileIdentity(Groups[I], TIdentityGroup(Groups.Objects[I]), Result);
      Result.Changes.Sort(@CompareChanges);
    except
      Result.Free;
      Result := nil;
      raise;
    end;
  finally
    FreeIndexedObjects(Groups);
    FreeIndexedObjects(WeakIndex);
    AfterSnapshots.Free;
    BeforeSnapshots.Free;
  end;
end;

end.
