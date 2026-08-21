(**
  PurpleRay SBOM Analyzer PE VERSIONINFO inspection unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Reads fixed file/product versions plus CompanyName and ProductName directly
  from a bounded PE resource tree. The parser consumes a caller-owned verified
  stream and never asks Windows to reopen the scanned pathname.

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
unit uPEVersionInfo;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TPEVersionInfoEvidence = record
    FixedFileVersion: string;
    FixedProductVersion: string;
    CompanyName: string;
    ProductName: string;
  end;

{**
  Parses one already bounded raw VS_VERSION_INFO resource blob.

  Parameters
  ----------
  AData
    Complete resource bytes capped by the caller.
  AEvidence
    Receives fixed versions and a same-StringTable company/product pair.

  Returns
  -------
  Boolean
    True when at least one supported value is present.

  Raises
  ------
  EOutOfMemory
    Propagated if bounded key/value storage cannot be allocated.
*}
function ParsePEVersionInfoResource(const AData: TBytes;
  out AEvidence: TPEVersionInfoEvidence): Boolean;

{**
  Extracts bounded, stream-native PE VERSIONINFO evidence.

  Parameters
  ----------
  AStream
    Caller-owned verified and bounded PE stream.
  AEvidence
    Receives fixed numeric versions and selected string-table fields.

  Returns
  -------
  Boolean
    True when at least one supported VERSIONINFO value is present.

  Raises
  ------
  EArgumentNilException, EStreamError
    Propagated for nil input or an in-range stream read failure.
  EOutOfMemory
    Propagated if the capped resource buffer cannot be allocated.
*}
function InspectPEVersionInfo(AStream: TStream;
  out AEvidence: TPEVersionInfoEvidence): Boolean;

implementation

uses
  uBoundedBinaryReader;

const
  MaximumPEHeaderOffset = 16 * 1024 * 1024;
  MaximumPESections = 4096;
  MaximumResourceDirectorySize = 64 * 1024 * 1024;
  MaximumResourceEntries = 8192;
  MaximumVersionResourceSize = 1024 * 1024;
  MaximumVersionBlocks = 4096;
  MaximumVersionKeyCharacters = 256;
  MaximumVersionValueCharacters = 2048;

type
  TPESection = record
    VirtualAddress: QWord;
    VirtualSize: QWord;
    RawOffset: QWord;
    RawSize: QWord;
  end;
  TPESections = array of TPESection;

  TVersionBlock = record
    BlockStart: Integer;
    BlockEnd: Integer;
    ValueOffset: Integer;
    ValueLength: Integer;
    ChildrenOffset: Integer;
    ValueType: Word;
    Key: UnicodeString;
  end;

{**
  Maps one PE relative virtual address to a checked file offset.

  Parameters
  ----------
  ARVA
    Relative virtual address to map.
  ASizeOfHeaders
    PE SizeOfHeaders value.
  ASections
    Parsed section table.
  AOffset
    Receives the corresponding file offset.

  Returns
  -------
  Boolean
    True when the RVA identifies raw bytes in headers or one section.

  Raises
  ------
  None
*}
function PERvaToOffset(ARVA, ASizeOfHeaders: QWord;
  const ASections: TPESections; out AOffset: QWord): Boolean;
var
  I: Integer;
  Span, Delta: QWord;
begin
  if ARVA < ASizeOfHeaders then
  begin
    AOffset := ARVA;
    Exit(True);
  end;
  for I := 0 to High(ASections) do
  begin
    Span := ASections[I].VirtualSize;
    if ASections[I].RawSize > Span then
      Span := ASections[I].RawSize;
    if (ARVA >= ASections[I].VirtualAddress) and
      (ARVA - ASections[I].VirtualAddress < Span) then
    begin
      Delta := ARVA - ASections[I].VirtualAddress;
      if (Delta >= ASections[I].RawSize) or
        (ASections[I].RawOffset > High(QWord) - Delta) then
        Exit(False);
      AOffset := ASections[I].RawOffset + Delta;
      Exit(True);
    end;
  end;
  Result := False;
end;

{**
  Parses only the PE layout required to locate the resource data directory.

  Parameters
  ----------
  AReader
    Range-checking reader for the complete verified file.
  AResourceRVA
    Receives the resource-directory RVA.
  AResourceSize
    Receives the declared resource-directory size.
  ASizeOfHeaders
    Receives the PE SizeOfHeaders value.
  ASections
    Receives the bounded section mapping table.

  Returns
  -------
  Boolean
    True for a supported PE32 or PE32+ layout with a resource directory.

  Raises
  ------
  EStreamError
    Propagated when an in-range read fails.
  EOutOfMemory
    Propagated if the bounded section table cannot be allocated.
*}
function TryReadPELayout(AReader: TBoundedBinaryReader;
  out AResourceRVA, AResourceSize, ASizeOfHeaders: QWord;
  out ASections: TPESections): Boolean;
var
  HeaderOffsetValue, Value32, NumberOfDirectories: UInt32;
  HeaderOffset, OptionalOffset, SectionOffset, DirectoryOffset: QWord;
  NumberOfSections, OptionalSize, Magic: Word;
  DOSMagic: array[0..1] of Byte;
  Signature: array[0..3] of Byte;
  I: Integer;
begin
  Result := False;
  AResourceRVA := 0;
  AResourceSize := 0;
  ASizeOfHeaders := 0;
  SetLength(ASections, 0);
  if not AReader.ReadBuffer(0, DOSMagic, SizeOf(DOSMagic)) or
    (DOSMagic[0] <> Ord('M')) or (DOSMagic[1] <> Ord('Z')) or
    not AReader.ReadUInt32($3C, False, HeaderOffsetValue) then
    Exit;
  HeaderOffset := HeaderOffsetValue;
  if (HeaderOffset > MaximumPEHeaderOffset) or
    not AReader.ContainsRange(HeaderOffset, 24) or
    not AReader.ReadBuffer(HeaderOffset, Signature, SizeOf(Signature)) or
    (Signature[0] <> Ord('P')) or (Signature[1] <> Ord('E')) or
    (Signature[2] <> 0) or (Signature[3] <> 0) or
    not AReader.ReadUInt16(HeaderOffset + 6, False, NumberOfSections) or
    not AReader.ReadUInt16(HeaderOffset + 20, False, OptionalSize) or
    (NumberOfSections = 0) or (NumberOfSections > MaximumPESections) then
    Exit;
  OptionalOffset := HeaderOffset + 24;
  if not AReader.ContainsRange(OptionalOffset, OptionalSize) or
    not AReader.ReadUInt16(OptionalOffset, False, Magic) or
    not AReader.ReadUInt32(OptionalOffset + 60, False, Value32) then
    Exit;
  ASizeOfHeaders := Value32;
  case Magic of
    $010B:
      begin
        if (OptionalSize < 120) or
          not AReader.ReadUInt32(OptionalOffset + 92, False,
            NumberOfDirectories) then
          Exit;
        DirectoryOffset := OptionalOffset + 96;
      end;
    $020B:
      begin
        if (OptionalSize < 136) or
          not AReader.ReadUInt32(OptionalOffset + 108, False,
            NumberOfDirectories) then
          Exit;
        DirectoryOffset := OptionalOffset + 112;
      end;
  else
    Exit;
  end;
  if NumberOfDirectories <= 2 then
    Exit;
  if not AReader.ReadUInt32(DirectoryOffset + 16, False, Value32) then
    Exit;
  AResourceRVA := Value32;
  if not AReader.ReadUInt32(DirectoryOffset + 20, False, Value32) then
    Exit;
  AResourceSize := Value32;
  if (AResourceRVA = 0) or (AResourceSize = 0) or
    (AResourceSize > MaximumResourceDirectorySize) then
    Exit;
  SectionOffset := OptionalOffset + OptionalSize;
  if not AReader.ContainsRange(SectionOffset,
    QWord(NumberOfSections) * 40) then
    Exit;
  SetLength(ASections, NumberOfSections);
  for I := 0 to NumberOfSections - 1 do
  begin
    if not AReader.ReadUInt32(SectionOffset + QWord(I) * 40 + 8, False,
      Value32) then Exit;
    ASections[I].VirtualSize := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I) * 40 + 12, False,
      Value32) then Exit;
    ASections[I].VirtualAddress := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I) * 40 + 16, False,
      Value32) then Exit;
    ASections[I].RawSize := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I) * 40 + 20, False,
      Value32) then Exit;
    ASections[I].RawOffset := Value32;
  end;
  Result := True;
end;

{**
  Tests and resolves a resource-directory-relative byte range.

  Parameters
  ----------
  AReader
    Reader for the complete PE file.
  ARootOffset
    File offset corresponding to the resource-directory root.
  AResourceSize
    Declared resource-directory extent.
  ARelativeOffset
    Offset relative to the resource root.
  ACount
    Required byte count.
  AFileOffset
    Receives the absolute file offset.

  Returns
  -------
  Boolean
    True when the range lies in both the resource extent and the file.

  Raises
  ------
  None
*}
function ResourceRange(AReader: TBoundedBinaryReader; ARootOffset,
  AResourceSize, ARelativeOffset, ACount: QWord;
  out AFileOffset: QWord): Boolean;
begin
  Result := (ARelativeOffset <= AResourceSize) and
    (ACount <= AResourceSize - ARelativeOffset) and
    (ARootOffset <= High(QWord) - ARelativeOffset);
  if not Result then
    Exit;
  AFileOffset := ARootOffset + ARelativeOffset;
  Result := AReader.ContainsRange(AFileOffset, ACount);
end;

{**
  Walks the bounded resource tree to its first deterministic data entry.

  Parameters
  ----------
  AReader
    Reader for the complete PE file.
  ARootOffset
    File offset corresponding to resource-relative zero.
  AResourceSize
    Declared resource-directory extent.
  ADirectoryRelative
    Relative offset of the directory being visited.
  ADepth
    Current directory depth.
  ABudget
    Shared remaining-entry budget, decremented for every examined entry.
  ADataRVA
    Receives the selected resource data RVA.
  ADataSize
    Receives its declared size.

  Returns
  -------
  Boolean
    True when a bounded data entry is found.

  Raises
  ------
  EStreamError
    Propagated when an in-range read fails.
*}
function FindResourceData(AReader: TBoundedBinaryReader; ARootOffset,
  AResourceSize, ADirectoryRelative: QWord; ADepth: Integer;
  var ABudget: Integer; out ADataRVA, ADataSize: QWord): Boolean;
var
  DirectoryOffset, EntryOffset, ChildOffset: QWord;
  NamedCount, IDCount: Word;
  NameValue, TargetValue, Value32: UInt32;
  EntryCount, I: Integer;
begin
  Result := False;
  if (ADepth > 2) or not ResourceRange(AReader, ARootOffset,
    AResourceSize, ADirectoryRelative, 16, DirectoryOffset) or
    not AReader.ReadUInt16(DirectoryOffset + 12, False, NamedCount) or
    not AReader.ReadUInt16(DirectoryOffset + 14, False, IDCount) then
    Exit;
  EntryCount := Integer(NamedCount) + Integer(IDCount);
  if (EntryCount <= 0) or (EntryCount > ABudget) or
    not ResourceRange(AReader, ARootOffset, AResourceSize,
      ADirectoryRelative + 16, QWord(EntryCount) * 8, EntryOffset) then
    Exit;
  for I := 0 to EntryCount - 1 do
  begin
    if ABudget <= 0 then
      Exit(False);
    Dec(ABudget);
    if not AReader.ReadUInt32(EntryOffset + QWord(I) * 8, False,
      NameValue) or not AReader.ReadUInt32(EntryOffset + QWord(I) * 8 + 4,
      False, TargetValue) then
      Exit(False);
    if ADepth = 0 then
    begin
      if ((NameValue and $80000000) <> 0) or
        ((NameValue and $FFFF) <> 16) then
        Continue;
      if (TargetValue and $80000000) = 0 then
        Exit(False);
    end;
    ChildOffset := TargetValue and $7FFFFFFF;
    if ADepth < 2 then
    begin
      if (TargetValue and $80000000) = 0 then
        Continue;
      if FindResourceData(AReader, ARootOffset, AResourceSize, ChildOffset,
        ADepth + 1, ABudget, ADataRVA, ADataSize) then
        Exit(True);
    end
    else
    begin
      if (TargetValue and $80000000) <> 0 then
        Continue;
      if not ResourceRange(AReader, ARootOffset, AResourceSize, ChildOffset,
        16, DirectoryOffset) or
        not AReader.ReadUInt32(DirectoryOffset, False, Value32) then
        Continue;
      ADataRVA := Value32;
      if not AReader.ReadUInt32(DirectoryOffset + 4, False, Value32) then
        Continue;
      ADataSize := Value32;
      if (ADataSize > 0) and
        (ADataSize <= MaximumVersionResourceSize) then
        Exit(True);
    end;
  end;
end;

{**
  Reads one little-endian word from an in-memory version-resource blob.

  Parameters
  ----------
  AData
    Resource bytes.
  AOffset
    Zero-based byte offset.
  AValue
    Receives the decoded word.

  Returns
  -------
  Boolean
    True when the complete scalar lies in AData.

  Raises
  ------
  None
*}
function BlobUInt16(const AData: TBytes; AOffset: Integer;
  out AValue: Word): Boolean;
begin
  Result := (AOffset >= 0) and (AOffset <= Length(AData) - 2);
  if Result then
    AValue := Word(AData[AOffset]) or (Word(AData[AOffset + 1]) shl 8)
  else
    AValue := 0;
end;

{**
  Reads one little-endian double word from a version-resource blob.

  Parameters
  ----------
  AData
    Resource bytes.
  AOffset
    Zero-based byte offset.
  AValue
    Receives the decoded value.

  Returns
  -------
  Boolean
    True when the complete scalar lies in AData.

  Raises
  ------
  None
*}
function BlobUInt32(const AData: TBytes; AOffset: Integer;
  out AValue: UInt32): Boolean;
begin
  Result := (AOffset >= 0) and (AOffset <= Length(AData) - 4);
  if Result then
    AValue := UInt32(AData[AOffset]) or
      (UInt32(AData[AOffset + 1]) shl 8) or
      (UInt32(AData[AOffset + 2]) shl 16) or
      (UInt32(AData[AOffset + 3]) shl 24)
  else
    AValue := 0;
end;

{**
  Aligns a blob offset to four bytes under an explicit upper bound.

  Parameters
  ----------
  AOffset
    Offset to align.
  ALimit
    Exclusive upper bound.
  AAligned
    Receives the aligned offset.

  Returns
  -------
  Boolean
    True when the aligned offset does not exceed ALimit.

  Raises
  ------
  None
*}
function AlignBlobOffset(AOffset, ALimit: Integer;
  out AAligned: Integer): Boolean;
begin
  Result := (AOffset >= 0) and (AOffset <= High(Integer) - 3);
  if Result then
  begin
    AAligned := (AOffset + 3) and not 3;
    Result := AAligned <= ALimit;
  end
  else
    AAligned := 0;
end;

{**
  Reads a null-terminated UTF-16LE key within one VERSIONINFO block.

  Parameters
  ----------
  AData
    Resource bytes.
  AOffset
    Offset of the first UTF-16 code unit; advanced past the terminator.
  ALimit
    Exclusive block boundary.
  AValue
    Receives the Unicode key.

  Returns
  -------
  Boolean
    True when a capped terminator is found within the block.

  Raises
  ------
  EOutOfMemory
    Propagated if the capped Unicode value cannot be allocated.
*}
function ReadUTF16Key(const AData: TBytes; var AOffset: Integer;
  ALimit: Integer; out AValue: UnicodeString): Boolean;
var
  Value: Word;
  Count: Integer;
begin
  Result := False;
  AValue := '';
  Count := 0;
  while (AOffset <= ALimit - 2) and
    (Count < MaximumVersionKeyCharacters) do
  begin
    if not BlobUInt16(AData, AOffset, Value) then
      Exit;
    Inc(AOffset, 2);
    if Value = 0 then
      Exit(True);
    Inc(Count);
    SetLength(AValue, Count);
    AValue[Count] := WideChar(Value);
  end;
end;

{**
  Parses one bounded VERSIONINFO block header and its value/child offsets.

  Parameters
  ----------
  AData
    Resource bytes.
  AOffset
    Block start offset.
  AParentEnd
    Exclusive containing-block boundary.
  ABlock
    Receives validated block metadata.

  Returns
  -------
  Boolean
    True when lengths, key, value, and child offsets are structurally valid.

  Raises
  ------
  EOutOfMemory
    Propagated if the capped key cannot be allocated.
*}
function ParseVersionBlock(const AData: TBytes; AOffset, AParentEnd: Integer;
  out ABlock: TVersionBlock): Boolean;
var
  BlockLength, ValueLength, ValueType: Word;
  Cursor, ValueBytes: Integer;
begin
  ABlock.BlockStart := 0;
  ABlock.BlockEnd := 0;
  ABlock.ValueOffset := 0;
  ABlock.ValueLength := 0;
  ABlock.ChildrenOffset := 0;
  ABlock.ValueType := 0;
  ABlock.Key := '';
  Result := False;
  if not BlobUInt16(AData, AOffset, BlockLength) or
    not BlobUInt16(AData, AOffset + 2, ValueLength) or
    not BlobUInt16(AData, AOffset + 4, ValueType) or
    (BlockLength < 6) or (AOffset > AParentEnd - BlockLength) then
    Exit;
  ABlock.BlockStart := AOffset;
  ABlock.BlockEnd := AOffset + BlockLength;
  ABlock.ValueType := ValueType;
  Cursor := AOffset + 6;
  if not ReadUTF16Key(AData, Cursor, ABlock.BlockEnd, ABlock.Key) or
    not AlignBlobOffset(Cursor, ABlock.BlockEnd, ABlock.ValueOffset) then
    Exit;
  if ValueType = 1 then
    ValueBytes := Integer(ValueLength) * 2
  else
    ValueBytes := ValueLength;
  if (ABlock.ValueOffset > ABlock.BlockEnd - ValueBytes) or
    not AlignBlobOffset(ABlock.ValueOffset + ValueBytes,
      ABlock.BlockEnd, ABlock.ChildrenOffset) then
    Exit;
  ABlock.ValueLength := ValueLength;
  Result := True;
end;

{**
  Decodes and sanitizes one UTF-16LE VERSIONINFO string value.

  Parameters
  ----------
  AData
    Resource bytes.
  AOffset
    First UTF-16 code unit.
  ACharacterCount
    Declared number of UTF-16 code units, including an optional terminator.
  ALimit
    Exclusive block boundary.
  AValue
    Receives trimmed UTF-8 text.

  Returns
  -------
  Boolean
    True for nonempty, bounded text without control characters.

  Raises
  ------
  EOutOfMemory
    Propagated if the capped string cannot be allocated.
*}
function DecodeVersionString(const AData: TBytes; AOffset,
  ACharacterCount, ALimit: Integer; out AValue: string): Boolean;
var
  TextValue: UnicodeString;
  CodeUnit: Word;
  I, Count: Integer;
begin
  Result := False;
  AValue := '';
  if (ACharacterCount <= 0) or
    (ACharacterCount > MaximumVersionValueCharacters) or
    (AOffset > ALimit - ACharacterCount * 2) then
    Exit;
  Count := ACharacterCount;
  SetLength(TextValue, Count);
  for I := 0 to Count - 1 do
  begin
    if not BlobUInt16(AData, AOffset + I * 2, CodeUnit) then
      Exit;
    if CodeUnit = 0 then
    begin
      SetLength(TextValue, I);
      Break;
    end;
    if (CodeUnit < 32) or (CodeUnit = 127) then
      Exit;
    TextValue[I + 1] := WideChar(CodeUnit);
  end;
  AValue := Trim(UTF8Encode(TextValue));
  Result := AValue <> '';
end;

{**
  Validates the canonical eight-hex-digit VERSIONINFO StringTable key.

  Parameters
  ----------
  AKey
    Candidate language/codepage key.

  Returns
  -------
  Boolean
    True only for exactly eight ASCII hexadecimal characters.

  Raises
  ------
  None
*}
function IsVersionStringTableKey(const AKey: UnicodeString): Boolean;
var
  I: Integer;
begin
  Result := Length(AKey) = 8;
  if not Result then
    Exit;
  for I := 1 to Length(AKey) do
    if not (AKey[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
end;

{**
  Selects the ordinally lowest nonempty string-table value.

  Parameters
  ----------
  ATarget
    Current selected value, updated in place.
  ACandidate
    Additional nonempty evidence value.

  Returns
  -------
  None

  Raises
  ------
  None
*}
procedure SelectStableString(var ATarget: string; const ACandidate: string);
begin
  if (ATarget = '') or ((ACandidate <> '') and
    (CompareStr(ACandidate, ATarget) < 0)) then
    ATarget := ACandidate;
end;

{**
  Parses CompanyName and ProductName only from one StringTable block.

  Parameters
  ----------
  AData
    Resource bytes.
  ATable
    Validated eight-hex-key StringTable block.
  ABudget
    Shared remaining-block budget.
  ACompanyName, AProductName
    Receive independently selected values from this table only.

  Returns
  -------
  Boolean
    True only when this one table contains both supported values.

  Raises
  ------
  EOutOfMemory
    Propagated if bounded keys or values cannot be allocated.
*}
function ParseVersionStringTable(const AData: TBytes;
  const ATable: TVersionBlock; var ABudget: Integer;
  out ACompanyName, AProductName: string): Boolean;
var
  Block: TVersionBlock;
  Cursor, NextOffset: Integer;
  Value: string;
begin
  Result := False;
  ACompanyName := '';
  AProductName := '';
  Cursor := ATable.ChildrenOffset;
  while (Cursor <= ATable.BlockEnd - 6) and (ABudget > 0) do
  begin
    Dec(ABudget);
    if not ParseVersionBlock(AData, Cursor, ATable.BlockEnd, Block) then
      Exit(False);
    if (Block.ValueType = 1) and
      DecodeVersionString(AData, Block.ValueOffset, Block.ValueLength,
        Block.BlockEnd, Value) then
    begin
      if SameText(UTF8Encode(Block.Key), 'CompanyName') then
        SelectStableString(ACompanyName, Value)
      else if SameText(UTF8Encode(Block.Key), 'ProductName') then
        SelectStableString(AProductName, Value);
    end;
    if not AlignBlobOffset(Block.BlockEnd, ATable.BlockEnd, NextOffset) or
      (NextOffset <= Cursor) then
      Exit(False);
    Cursor := NextOffset;
  end;
  Result := (ACompanyName <> '') and (AProductName <> '');
end;

{**
  Selects a complete company/product pair from canonical StringFileInfo tables.

  Parameters
  ----------
  AData
    Resource bytes.
  ARoot
    Parsed VS_VERSION_INFO root block.
  ABudget
    Shared remaining-block budget.
  AEvidence
    Receives both strings from one deterministically selected table.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if bounded keys or values cannot be allocated.
*}
procedure ParseVersionStringTables(const AData: TBytes;
  const ARoot: TVersionBlock; var ABudget: Integer;
  var AEvidence: TPEVersionInfoEvidence);
var
  FileInfo, Table: TVersionBlock;
  RootCursor, TableCursor, NextOffset: Integer;
  CompanyName, ProductName, SelectionKey, CandidateKey: string;
begin
  SelectionKey := '';
  RootCursor := ARoot.ChildrenOffset;
  while (RootCursor <= ARoot.BlockEnd - 6) and (ABudget > 0) do
  begin
    Dec(ABudget);
    if not ParseVersionBlock(AData, RootCursor, ARoot.BlockEnd,
      FileInfo) then
      Exit;
    if SameText(UTF8Encode(FileInfo.Key), 'StringFileInfo') then
    begin
      TableCursor := FileInfo.ChildrenOffset;
      while (TableCursor <= FileInfo.BlockEnd - 6) and (ABudget > 0) do
      begin
        Dec(ABudget);
        if not ParseVersionBlock(AData, TableCursor, FileInfo.BlockEnd,
          Table) then
          Break;
        if IsVersionStringTableKey(Table.Key) and
          ParseVersionStringTable(AData, Table, ABudget, CompanyName,
            ProductName) then
        begin
          CandidateKey := LowerCase(UTF8Encode(Table.Key)) + #1 +
            CompanyName + #1 + ProductName;
          if (SelectionKey = '') or
            (CompareStr(CandidateKey, SelectionKey) < 0) then
          begin
            SelectionKey := CandidateKey;
            AEvidence.CompanyName := CompanyName;
            AEvidence.ProductName := ProductName;
          end;
        end;
        if not AlignBlobOffset(Table.BlockEnd, FileInfo.BlockEnd,
          NextOffset) or (NextOffset <= TableCursor) then
          Break;
        TableCursor := NextOffset;
      end;
    end;
    if not AlignBlobOffset(FileInfo.BlockEnd, ARoot.BlockEnd,
      NextOffset) or (NextOffset <= RootCursor) then
      Exit;
    RootCursor := NextOffset;
  end;
end;

{**
  Tests whether one fixed version pair contains useful nonzero evidence.

  Parameters
  ----------
  AMS, ALS
    Most- and least-significant fixed version double words.

  Returns
  -------
  Boolean
    True when at least one of the four numeric fields is nonzero.

  Raises
  ------
  None
*}
function FixedVersionIsUseful(AMS, ALS: UInt32): Boolean;
begin
  Result := (AMS <> 0) or (ALS <> 0);
end;

{**
  Formats one fixed 64-bit PE version pair as four decimal segments.

  Parameters
  ----------
  AMS
    Most-significant fixed-file-info double word.
  ALS
    Least-significant fixed-file-info double word.

  Returns
  -------
  string
    major.minor.patch.build with unsigned 16-bit segments.

  Raises
  ------
  None
*}
function FormatFixedVersion(AMS, ALS: UInt32): string;
begin
  Result := Format('%d.%d.%d.%d', [AMS shr 16, AMS and $FFFF,
    ALS shr 16, ALS and $FFFF]);
end;

{**
  Parses fixed and string evidence from a complete VERSIONINFO resource blob.

  Parameters
  ----------
  AData
    Capped resource bytes.
  AEvidence
    Receives supported values.

  Returns
  -------
  Boolean
    True when at least one supported value is present.

  Raises
  ------
  EOutOfMemory
    Propagated if bounded key/value storage cannot be allocated.
*}
function ParsePEVersionInfoResource(const AData: TBytes;
  out AEvidence: TPEVersionInfoEvidence): Boolean;
const
  FixedInfoSize = 52;
  FixedInfoSignature = $FEEF04BD;
var
  Root: TVersionBlock;
  Signature, FileMS, FileLS, ProductMS, ProductLS: UInt32;
  Budget: Integer;
begin
  AEvidence.FixedFileVersion := '';
  AEvidence.FixedProductVersion := '';
  AEvidence.CompanyName := '';
  AEvidence.ProductName := '';
  Root.BlockStart := 0;
  Root.BlockEnd := 0;
  Root.ValueOffset := 0;
  Root.ValueLength := 0;
  Root.ChildrenOffset := 0;
  Root.ValueType := 0;
  Root.Key := '';
  Result := False;
  if not ParseVersionBlock(AData, 0, Length(AData), Root) or
    not SameText(UTF8Encode(Root.Key), 'VS_VERSION_INFO') then
    Exit;
  if (Root.ValueLength >= FixedInfoSize) and
    (Root.ValueOffset <= Root.BlockEnd - FixedInfoSize) and
    BlobUInt32(AData, Root.ValueOffset, Signature) and
    (Signature = FixedInfoSignature) and
    BlobUInt32(AData, Root.ValueOffset + 8, FileMS) and
    BlobUInt32(AData, Root.ValueOffset + 12, FileLS) and
    BlobUInt32(AData, Root.ValueOffset + 16, ProductMS) and
    BlobUInt32(AData, Root.ValueOffset + 20, ProductLS) then
  begin
    if FixedVersionIsUseful(FileMS, FileLS) then
      AEvidence.FixedFileVersion := FormatFixedVersion(FileMS, FileLS);
    if FixedVersionIsUseful(ProductMS, ProductLS) then
      AEvidence.FixedProductVersion := FormatFixedVersion(ProductMS, ProductLS);
  end;
  Budget := MaximumVersionBlocks;
  if Root.ChildrenOffset < Root.BlockEnd then
    ParseVersionStringTables(AData, Root, Budget, AEvidence);
  Result := (AEvidence.FixedFileVersion <> '') or
    (AEvidence.FixedProductVersion <> '') or
    (AEvidence.CompanyName <> '') or (AEvidence.ProductName <> '');
end;

function InspectPEVersionInfo(AStream: TStream;
  out AEvidence: TPEVersionInfoEvidence): Boolean;
var
  Reader: TBoundedBinaryReader;
  ResourceRVA, ResourceSize, SizeOfHeaders, RootOffset,
    VersionRVA, VersionSize, VersionOffset: QWord;
  Sections: TPESections;
  EntryBudget: Integer;
  Data: TBytes;
begin
  AEvidence.FixedFileVersion := '';
  AEvidence.FixedProductVersion := '';
  AEvidence.CompanyName := '';
  AEvidence.ProductName := '';
  if AStream = nil then
    raise EArgumentNilException.Create('PE version-info input stream is nil');
  Reader := TBoundedBinaryReader.Create(AStream);
  try
    if not TryReadPELayout(Reader, ResourceRVA, ResourceSize,
      SizeOfHeaders, Sections) or
      not PERvaToOffset(ResourceRVA, SizeOfHeaders, Sections, RootOffset) or
      not Reader.ContainsRange(RootOffset, ResourceSize) then
      Exit(False);
    EntryBudget := MaximumResourceEntries;
    if not FindResourceData(Reader, RootOffset, ResourceSize, 0, 0,
      EntryBudget, VersionRVA, VersionSize) or
      (VersionSize = 0) or (VersionSize > MaximumVersionResourceSize) or
      not PERvaToOffset(VersionRVA, SizeOfHeaders, Sections, VersionOffset) or
      not Reader.ContainsRange(VersionOffset, VersionSize) then
      Exit(False);
    SetLength(Data, Integer(VersionSize));
    if not Reader.ReadBuffer(VersionOffset, Data[0], Length(Data)) then
      Exit(False);
    Result := ParsePEVersionInfoResource(Data, AEvidence);
  finally
    Reader.Free;
  end;
end;

end.
