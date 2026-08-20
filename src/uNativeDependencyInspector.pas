(**
  PurpleRay SBOM Analyzer native-dependency inspection unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Reads bounded ELF dynamic entries, PE import tables, and Mach-O load commands
  directly from untrusted binaries without loading or executing them.

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
unit uNativeDependencyInspector;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

{**
  Extracts direct native-library declarations using bounded static parsing.

  Parameters
  ----------
  AFileName
    PE, ELF, thin Mach-O, or universal Mach-O file to inspect.
  AFormatName
    Format previously established by TBinaryInfo.
  ADependencies
    Caller-owned list augmented with unique import or load declarations.

  Returns
  -------
  Boolean
    True when at least one new dependency declaration is added.

  Raises
  ------
  EFOpenError, EReadError
    Propagated when the target file cannot be opened or read. Malformed binary
    structures otherwise return False without executing the target.
}
function InspectNativeDependencies(const AFileName, AFormatName: string;
  ADependencies: TStrings): Boolean;

{**
  Extracts a version only when a native library declaration explicitly uses a
  recognized versioned-filename convention.

  Parameters
  ----------
  ADeclaration
    Native loader declaration, such as an ELF SONAME or Mach-O install name.

  Returns
  -------
  string
    Numeric product-version evidence, or an empty string when no unambiguous
    version is present. A single numeric ELF ``.so`` suffix is treated as an
    ABI level rather than a component version; existing Mach-O install-name
    extraction remains supported.

  Raises
  ------
  None
}
function NativeDependencyVersion(const ADeclaration: string): string;

implementation

const
  MaximumDependencies = 4096;
  MaximumDependencyName = 1024;
  MaximumMachCommands = 4096;
  MaximumProgramHeaders = 1024;
  MaximumDynamicEntries = 16384;

type
  {**
    Random-access reader that range-checks every request against file size.

    Notes
    -----
    Scalar methods return False for truncated or out-of-range structures rather
    than raising parser-specific exceptions. File-open/read exceptions from the
    underlying TFileStream may still propagate.
  }
  TBinaryReader = class
  private
    FStream: TFileStream;
  public
    {**
      Opens a binary for bounded random-access inspection.

      Parameters
      ----------
      AFileName
        Binary file to open read-only.

      Returns
      -------
      TBinaryReader
        Initialized reader owned by the caller.

      Raises
      ------
      EFOpenError
        Raised when the file cannot be opened.
    }
    constructor Create(const AFileName: string);

    {**
      Releases the underlying file stream.

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

    {**
      Returns the opened file size.

      Parameters
      ----------
      None

      Returns
      -------
      QWord
        File length in bytes.

      Raises
      ------
      None
    }
    function Size: QWord;

    {**
      Reads an exact byte range after validating it against the file length.

      Parameters
      ----------
      AOffset
        Zero-based file offset.
      ABuffer
        Caller-provided destination buffer.
      ACount
        Number of bytes requested.

      Returns
      -------
      Boolean
        True only when the complete in-range request is read.

      Raises
      ------
      EStreamError
        May propagate from an underlying seek or read failure.
    }
    function ReadBuffer(AOffset: QWord; var ABuffer; ACount: Integer): Boolean;

    {**
      Reads one endian-aware 16-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based file offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when two bytes were available.

      Raises
      ------
      EStreamError
        May propagate from an underlying seek or read failure.
    }
    function ReadUInt16(AOffset: QWord; ABigEndian: Boolean;
      out AValue: Word): Boolean;

    {**
      Reads one endian-aware 32-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based file offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when four bytes were available.

      Raises
      ------
      EStreamError
        May propagate from an underlying seek or read failure.
    }
    function ReadUInt32(AOffset: QWord; ABigEndian: Boolean;
      out AValue: UInt32): Boolean;

    {**
      Reads one endian-aware 64-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based file offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when eight bytes were available.

      Raises
      ------
      EStreamError
        May propagate from an underlying seek or read failure.
    }
    function ReadUInt64(AOffset: QWord; ABigEndian: Boolean;
      out AValue: QWord): Boolean;

    {**
      Reads a bounded null-terminated dependency name.

      Parameters
      ----------
      AOffset
        Zero-based file offset at the first string byte.
      AMaximumLength
        Hard upper bound for the decoded byte string.
      AValue
        Receives the decoded string on success.

      Returns
      -------
      Boolean
        True when a terminator is found within the permitted range.

      Raises
      ------
      EStreamError
        May propagate from an underlying seek or read failure.
    }
    function ReadCString(AOffset: QWord; AMaximumLength: Integer;
      out AValue: string): Boolean;
  end;

  TPESection = record
    VirtualAddress: QWord;
    VirtualSize: QWord;
    RawOffset: QWord;
    RawSize: QWord;
  end;
  TPESections = array of TPESection;

  TLoadSegment = record
    FileOffset: QWord;
    VirtualAddress: QWord;
    FileSize: QWord;
  end;
  TLoadSegments = array of TLoadSegment;
  TQWordValues = array of QWord;

{**
  Checks that a version candidate contains only nonempty numeric segments.

  Parameters
  ----------
  AValue
    Candidate containing one or more numeric segments separated by dots.

  Returns
  -------
  Boolean
    True for a bare numeric segment or a well-formed numeric dotted sequence.

  Raises
  ------
  None
}
function IsNumericDottedVersion(const AValue: string): Boolean;
var
  I: Integer;
  PreviousWasDot: Boolean;
begin
  Result := AValue <> '';
  PreviousWasDot := True;
  for I := 1 to Length(AValue) do
  begin
    if AValue[I] = '.' then
    begin
      if PreviousWasDot then
        Exit(False);
      PreviousWasDot := True;
    end
    else if AValue[I] in ['0'..'9'] then
      PreviousWasDot := False
    else
      Exit(False);
  end;
  Result := Result and not PreviousWasDot;
end;

function NativeDependencyVersion(const ADeclaration: string): string;
var
  FileNameValue, LowerName, Stem, Candidate: string;
  Marker, SeparatorAt: SizeInt;
  RequireDottedCandidate: Boolean;
begin
  Result := '';
  FileNameValue := ExtractFileName(StringReplace(Trim(ADeclaration), '\',
    DirectorySeparator, [rfReplaceAll]));
  LowerName := LowerCase(FileNameValue);
  Candidate := '';
  RequireDottedCandidate := False;

  Marker := Pos('.so.', LowerName);
  if Marker > 0 then
  begin
    Candidate := Copy(FileNameValue, Marker + Length('.so.'), MaxInt);
    RequireDottedCandidate := True;
  end
  else if (Length(LowerName) > Length('.dylib')) and
    (Copy(LowerName, Length(LowerName) - Length('.dylib') + 1,
      MaxInt) = '.dylib') then
  begin
    Stem := Copy(FileNameValue, 1, Length(FileNameValue) - Length('.dylib'));
    SeparatorAt := LastDelimiter('.', Stem);
    if SeparatorAt > 0 then
      Candidate := Copy(Stem, SeparatorAt + 1, MaxInt);
  end;
  { DLL suffixes are deliberately not interpreted. Names such as
    api-ms-win-core-file-l1-1-0.dll contain numeric tokens that are not a
    component version; the Windows version-resource API is authoritative. }
  { A bare ELF suffix is an ABI level. The caller retains it in the complete
    SONAME component name, so suppressing Version does not discard evidence. }

  if IsNumericDottedVersion(Candidate) and
    (not RequireDottedCandidate or (Pos('.', Candidate) > 0)) then
    Result := Candidate;
end;

constructor TBinaryReader.Create(const AFileName: string);
begin
  inherited Create;
  FStream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
end;

destructor TBinaryReader.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

function TBinaryReader.Size: QWord;
begin
  Result := QWord(FStream.Size);
end;

function TBinaryReader.ReadBuffer(AOffset: QWord; var ABuffer;
  ACount: Integer): Boolean;
begin
  Result := (ACount >= 0) and (AOffset <= QWord(High(Int64))) and
    (QWord(ACount) <= Size) and (AOffset <= Size - QWord(ACount));
  if not Result or (ACount = 0) then
    Exit;
  FStream.Position := Int64(AOffset);
  Result := FStream.Read(ABuffer, ACount) = ACount;
end;

function TBinaryReader.ReadUInt16(AOffset: QWord; ABigEndian: Boolean;
  out AValue: Word): Boolean;
var
  Buffer: array[0..1] of Byte;
begin
  AValue := 0;
  Result := ReadBuffer(AOffset, Buffer, SizeOf(Buffer));
  if not Result then
    Exit;
  if ABigEndian then
    AValue := (Word(Buffer[0]) shl 8) or Word(Buffer[1])
  else
    AValue := Word(Buffer[0]) or (Word(Buffer[1]) shl 8);
end;

function TBinaryReader.ReadUInt32(AOffset: QWord; ABigEndian: Boolean;
  out AValue: UInt32): Boolean;
var
  Buffer: array[0..3] of Byte;
begin
  AValue := 0;
  Result := ReadBuffer(AOffset, Buffer, SizeOf(Buffer));
  if not Result then
    Exit;
  if ABigEndian then
    AValue := (UInt32(Buffer[0]) shl 24) or
      (UInt32(Buffer[1]) shl 16) or (UInt32(Buffer[2]) shl 8) or Buffer[3]
  else
    AValue := UInt32(Buffer[0]) or (UInt32(Buffer[1]) shl 8) or
      (UInt32(Buffer[2]) shl 16) or (UInt32(Buffer[3]) shl 24);
end;

function TBinaryReader.ReadUInt64(AOffset: QWord; ABigEndian: Boolean;
  out AValue: QWord): Boolean;
var
  First, Second: UInt32;
begin
  AValue := 0;
  Result := ReadUInt32(AOffset, ABigEndian, First) and
    ReadUInt32(AOffset + 4, ABigEndian, Second);
  if not Result then
    Exit;
  if ABigEndian then
    AValue := (QWord(First) shl 32) or Second
  else
    AValue := QWord(First) or (QWord(Second) shl 32);
end;

function TBinaryReader.ReadCString(AOffset: QWord; AMaximumLength: Integer;
  out AValue: string): Boolean;
var
  Buffer: array of Byte;
  Available: QWord;
  Count, I: Integer;
  RawValue: RawByteString;
begin
  Result := False;
  AValue := '';
  if (AMaximumLength <= 0) or (AOffset >= Size) then
    Exit;
  Available := Size - AOffset;
  Count := AMaximumLength;
  if Available < QWord(Count) then
    Count := Integer(Available);
  SetLength(Buffer, Count);
  if (Count = 0) or not ReadBuffer(AOffset, Buffer[0], Count) then
    Exit;
  I := 0;
  while (I < Count) and (Buffer[I] <> 0) do
  begin
    if Buffer[I] < 32 then
      Exit;
    Inc(I);
  end;
  if (I = 0) or (I = Count) then
    Exit;
  SetLength(RawValue, I);
  Move(Buffer[0], RawValue[1], I);
  AValue := string(RawValue);
  Result := True;
end;

procedure AddDependency(ADependencies: TStrings; const AValue: string);
var
  Value: string;
begin
  Value := Trim(AValue);
  if (Value <> '') and (Length(Value) <= MaximumDependencyName) and
    (ADependencies.IndexOf(Value) < 0) and
    (ADependencies.Count < MaximumDependencies) then
    ADependencies.Add(Value);
end;

function PERvaToOffset(ARva, ASizeOfHeaders: QWord;
  const ASections: TPESections; out AOffset: QWord): Boolean;
var
  I: Integer;
  Span, Delta: QWord;
begin
  if ARva < ASizeOfHeaders then
  begin
    AOffset := ARva;
    Exit(True);
  end;
  for I := 0 to High(ASections) do
  begin
    Span := ASections[I].VirtualSize;
    if ASections[I].RawSize > Span then
      Span := ASections[I].RawSize;
    if (ARva >= ASections[I].VirtualAddress) and
      (ARva - ASections[I].VirtualAddress < Span) then
    begin
      Delta := ARva - ASections[I].VirtualAddress;
      if (Delta >= ASections[I].RawSize) or
        (ASections[I].RawOffset > High(QWord) - Delta) then
        Exit(False);
      AOffset := ASections[I].RawOffset + Delta;
      Exit(True);
    end;
  end;
  Result := False;
end;

procedure ParsePEImportDirectory(AReader: TBinaryReader; ADirectoryRVA,
  ADirectorySize, ASizeOfHeaders, AImageBase: QWord;
  ADelayImport: Boolean; const ASections: TPESections;
  ADependencies: TStrings);
var
  DirectoryOffset, DescriptorOffset, NameOffset, NameValue: QWord;
  Attributes, NameRVA, FirstValue: UInt32;
  DescriptorSize, Limit, I: Integer;
  DependencyName: string;
begin
  if (ADirectoryRVA = 0) or not PERvaToOffset(ADirectoryRVA,
    ASizeOfHeaders, ASections, DirectoryOffset) then
    Exit;
  if ADelayImport then
    DescriptorSize := 32
  else
    DescriptorSize := 20;
  Limit := MaximumDependencies;
  if (ADirectorySize > 0) and
    (ADirectorySize div QWord(DescriptorSize) < QWord(Limit)) then
    Limit := Integer(ADirectorySize div QWord(DescriptorSize));
  for I := 0 to Limit - 1 do
  begin
    DescriptorOffset := DirectoryOffset + QWord(I * DescriptorSize);
    if ADelayImport then
    begin
      if not AReader.ReadUInt32(DescriptorOffset, False, Attributes) or
        not AReader.ReadUInt32(DescriptorOffset + 4, False, NameRVA) then
        Exit;
      if (Attributes = 0) and (NameRVA = 0) then
        Exit;
      NameValue := NameRVA;
      if ((Attributes and 1) = 0) and (NameValue >= AImageBase) then
        Dec(NameValue, AImageBase);
    end
    else
    begin
      if not AReader.ReadUInt32(DescriptorOffset, False, FirstValue) or
        not AReader.ReadUInt32(DescriptorOffset + 12, False, NameRVA) then
        Exit;
      if (FirstValue = 0) and (NameRVA = 0) then
        Exit;
      NameValue := NameRVA;
    end;
    if PERvaToOffset(NameValue, ASizeOfHeaders, ASections, NameOffset) and
      AReader.ReadCString(NameOffset, MaximumDependencyName, DependencyName) then
      AddDependency(ADependencies, DependencyName);
  end;
end;

{**
  Reads PE normal and delay-load import descriptors.

  Parameters
  ----------
  AReader
    Range-checking reader positioned logically at the complete PE file.
  ADependencies
    List augmented with unique DLL declarations.

  Returns
  -------
  Boolean
    True when at least one dependency is added.

  Raises
  ------
  None
    Malformed offsets, headers, and descriptors return False.
}
function InspectPEDependencies(AReader: TBinaryReader;
  ADependencies: TStrings): Boolean;
var
  PEOffset, OptionalOffset, SectionOffset, DataDirectoryOffset: QWord;
  ImportRVA, ImportSize, DelayRVA, DelaySize, SizeOfHeaders: UInt32;
  ImageBase32: UInt32;
  ImageBase: QWord;
  Signature: array[0..3] of Byte;
  NumberOfSections, OptionalSize, Magic: Word;
  NumberOfDirectories, Value32: UInt32;
  Sections: TPESections;
  I, InitialCount: Integer;
begin
  Result := False;
  InitialCount := ADependencies.Count;
  if not AReader.ReadUInt32($3C, False, Value32) then
    Exit;
  PEOffset := Value32;
  if (PEOffset > AReader.Size) or (AReader.Size - PEOffset < 24) or
    not AReader.ReadBuffer(PEOffset, Signature, SizeOf(Signature)) or
    (Signature[0] <> Ord('P')) or (Signature[1] <> Ord('E')) or
    (Signature[2] <> 0) or (Signature[3] <> 0) or
    not AReader.ReadUInt16(PEOffset + 6, False, NumberOfSections) or
    not AReader.ReadUInt16(PEOffset + 20, False, OptionalSize) then
    Exit;
  if (NumberOfSections = 0) or (NumberOfSections > 4096) then
    Exit;
  OptionalOffset := PEOffset + 24;
  if (OptionalSize > AReader.Size - OptionalOffset) then
    Exit;
  if not AReader.ReadUInt16(OptionalOffset, False, Magic) or
    not AReader.ReadUInt32(OptionalOffset + 60, False, SizeOfHeaders) then
    Exit;
  ImageBase := 0;
  case Magic of
    $010B:
      begin
        DataDirectoryOffset := OptionalOffset + 96;
        if (OptionalSize < 112) or
          not AReader.ReadUInt32(OptionalOffset + 28, False, ImageBase32) or
          not AReader.ReadUInt32(OptionalOffset + 92, False,
            NumberOfDirectories) then
          Exit;
        ImageBase := ImageBase32;
      end;
    $020B:
      begin
        DataDirectoryOffset := OptionalOffset + 112;
        if (OptionalSize < 128) or
          not AReader.ReadUInt64(OptionalOffset + 24, False, ImageBase) or
          not AReader.ReadUInt32(OptionalOffset + 108, False,
            NumberOfDirectories) then
          Exit;
      end;
  else
    Exit;
  end;
  SectionOffset := OptionalOffset + OptionalSize;
  if (QWord(NumberOfSections) * 40 > AReader.Size - SectionOffset) then
    Exit;
  SetLength(Sections, NumberOfSections);
  for I := 0 to NumberOfSections - 1 do
  begin
    if not AReader.ReadUInt32(SectionOffset + QWord(I * 40) + 8, False,
      Value32) then Exit;
    Sections[I].VirtualSize := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I * 40) + 12, False,
      Value32) then Exit;
    Sections[I].VirtualAddress := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I * 40) + 16, False,
      Value32) then Exit;
    Sections[I].RawSize := Value32;
    if not AReader.ReadUInt32(SectionOffset + QWord(I * 40) + 20, False,
      Value32) then Exit;
    Sections[I].RawOffset := Value32;
  end;

  if NumberOfDirectories > 1 then
    if AReader.ReadUInt32(DataDirectoryOffset + 8, False, ImportRVA) and
      AReader.ReadUInt32(DataDirectoryOffset + 12, False, ImportSize) then
      ParsePEImportDirectory(AReader, ImportRVA, ImportSize, SizeOfHeaders,
        ImageBase, False, Sections, ADependencies);
  if NumberOfDirectories > 13 then
    if AReader.ReadUInt32(DataDirectoryOffset + 13 * 8, False, DelayRVA) and
      AReader.ReadUInt32(DataDirectoryOffset + 13 * 8 + 4, False,
        DelaySize) then
      ParsePEImportDirectory(AReader, DelayRVA, DelaySize, SizeOfHeaders,
        ImageBase, True, Sections, ADependencies);
  Result := ADependencies.Count > InitialCount;
end;

{**
  Reads load-dylib commands from one bounded thin Mach-O slice.

  Parameters
  ----------
  AReader
    Reader for the containing file.
  ABaseOffset
    Slice start offset.
  ASliceSize
    Maximum bytes belonging to the slice.
  ADependencies
    List augmented with unique dylib install names.

  Returns
  -------
  Boolean
    True when at least one load declaration is added.

  Raises
  ------
  None
    Invalid command tables return False.
}
function ParseMachSlice(AReader: TBinaryReader; ABaseOffset, ASliceSize: QWord;
  ADependencies: TStrings): Boolean;
const
  LC_LOAD_DYLIB = $0000000C;
  LC_LOAD_WEAK_DYLIB = $80000018;
  LC_REEXPORT_DYLIB = $8000001F;
  LC_LAZY_LOAD_DYLIB = $00000020;
  LC_LOAD_UPWARD_DYLIB = $80000023;
var
  Magic, Command, CommandSize, NameOffset, NumberOfCommands,
    CommandsSize: UInt32;
  BigEndian, Is64Bit: Boolean;
  HeaderSize, CommandOffset, CommandsEnd: QWord;
  I, InitialCount, MaximumNameLength: Integer;
  DependencyName: string;
begin
  Result := False;
  InitialCount := ADependencies.Count;
  if not AReader.ReadUInt32(ABaseOffset, True, Magic) then
    Exit;
  case Magic of
    $FEEDFACE: begin BigEndian := True; Is64Bit := False; end;
    $FEEDFACF: begin BigEndian := True; Is64Bit := True; end;
    $CEFAEDFE: begin BigEndian := False; Is64Bit := False; end;
    $CFFAEDFE: begin BigEndian := False; Is64Bit := True; end;
  else
    Exit;
  end;
  if Is64Bit then HeaderSize := 32 else HeaderSize := 28;
  if not AReader.ReadUInt32(ABaseOffset + 16, BigEndian, NumberOfCommands) or
    not AReader.ReadUInt32(ABaseOffset + 20, BigEndian, CommandsSize) or
    (NumberOfCommands > MaximumMachCommands) then
    Exit;
  if (HeaderSize > ASliceSize) or
    (QWord(CommandsSize) > ASliceSize - HeaderSize) then
    Exit;
  CommandOffset := ABaseOffset + HeaderSize;
  CommandsEnd := CommandOffset + CommandsSize;
  for I := 0 to Integer(NumberOfCommands) - 1 do
  begin
    if (CommandOffset > CommandsEnd) or (CommandsEnd - CommandOffset < 8) or
      not AReader.ReadUInt32(CommandOffset, BigEndian, Command) or
      not AReader.ReadUInt32(CommandOffset + 4, BigEndian, CommandSize) or
      (CommandSize < 8) or (QWord(CommandSize) > CommandsEnd - CommandOffset) then
      Exit;
    if (Command = LC_LOAD_DYLIB) or (Command = LC_LOAD_WEAK_DYLIB) or
      (Command = LC_REEXPORT_DYLIB) or (Command = LC_LAZY_LOAD_DYLIB) or
      (Command = LC_LOAD_UPWARD_DYLIB) then
    begin
      if (CommandSize >= 24) and
        AReader.ReadUInt32(CommandOffset + 8, BigEndian, NameOffset) and
        (NameOffset >= 24) and (NameOffset < CommandSize) then
      begin
        MaximumNameLength := Integer(CommandSize - NameOffset);
        if MaximumNameLength > MaximumDependencyName then
          MaximumNameLength := MaximumDependencyName;
        if AReader.ReadCString(CommandOffset + NameOffset, MaximumNameLength,
          DependencyName) then
          AddDependency(ADependencies, DependencyName);
      end;
    end;
    Inc(CommandOffset, CommandSize);
  end;
  Result := ADependencies.Count > InitialCount;
end;

{**
  Dispatches thin or universal Mach-O dependency-table parsing.

  Parameters
  ----------
  AReader
    Reader for the complete Mach-O file.
  ADependencies
    List augmented across all valid architecture slices.

  Returns
  -------
  Boolean
    True when at least one dylib declaration is added.

  Raises
  ------
  None
    Malformed fat headers or slices return False.
}
function InspectMachDependencies(AReader: TBinaryReader;
  ADependencies: TStrings): Boolean;
var
  Magic, NumberOfArchitectures, Offset32, Size32: UInt32;
  Offset64, Size64, EntryOffset, EntrySize: QWord;
  BigEndian, Is64Bit: Boolean;
  I, InitialCount: Integer;
begin
  InitialCount := ADependencies.Count;
  if not AReader.ReadUInt32(0, True, Magic) then
    Exit(False);
  if (Magic = $FEEDFACE) or (Magic = $FEEDFACF) or
    (Magic = $CEFAEDFE) or (Magic = $CFFAEDFE) then
    Exit(ParseMachSlice(AReader, 0, AReader.Size, ADependencies));
  case Magic of
    $CAFEBABE: begin BigEndian := True; Is64Bit := False; end;
    $CAFEBABF: begin BigEndian := True; Is64Bit := True; end;
    $BEBAFECA: begin BigEndian := False; Is64Bit := False; end;
    $BFBAFECA: begin BigEndian := False; Is64Bit := True; end;
  else
    Exit(False);
  end;
  if not AReader.ReadUInt32(4, BigEndian, NumberOfArchitectures) or
    (NumberOfArchitectures = 0) or (NumberOfArchitectures > 128) then
    Exit(False);
  if Is64Bit then EntrySize := 32 else EntrySize := 20;
  if QWord(NumberOfArchitectures) * EntrySize > AReader.Size - 8 then
    Exit(False);
  for I := 0 to Integer(NumberOfArchitectures) - 1 do
  begin
    EntryOffset := 8 + QWord(I) * EntrySize;
    if Is64Bit then
    begin
      if not AReader.ReadUInt64(EntryOffset + 8, BigEndian, Offset64) or
        not AReader.ReadUInt64(EntryOffset + 16, BigEndian, Size64) then
        Break;
    end
    else
    begin
      if not AReader.ReadUInt32(EntryOffset + 8, BigEndian, Offset32) or
        not AReader.ReadUInt32(EntryOffset + 12, BigEndian, Size32) then
        Break;
      Offset64 := Offset32;
      Size64 := Size32;
    end;
    if (Offset64 <= AReader.Size) and (Size64 <= AReader.Size - Offset64) then
      ParseMachSlice(AReader, Offset64, Size64, ADependencies);
  end;
  Result := ADependencies.Count > InitialCount;
end;

{**
  Maps an ELF dynamic string table and reads bounded DT_NEEDED entries.

  Parameters
  ----------
  AReader
    Reader for a 32-bit or 64-bit, little- or big-endian ELF file.
  ADependencies
    List augmented with unique shared-object declarations.

  Returns
  -------
  Boolean
    True when at least one dependency is added.

  Raises
  ------
  None
    Unsupported, truncated, extended, or malformed structures return False.
}
function InspectELFDependencies(AReader: TBinaryReader;
  ADependencies: TStrings): Boolean;
var
  Ident: array[0..15] of Byte;
  Is64Bit, BigEndian: Boolean;
  ProgramOffset, HeaderOffset, DynamicOffset, DynamicSize, StringAddress,
    StringSize, StringOffset, Tag, Value, EntrySize: QWord;
  ProgramEntrySize, ProgramCount: Word;
  ProgramType, Value32: UInt32;
  Segments: TLoadSegments;
  Needed: TQWordValues;
  I, SegmentCount, NeededCount, InitialCount, NameLimit: Integer;
  DynamicEntryCount: QWord;
  FoundStringOffset: Boolean;
  DependencyName: string;
begin
  Result := False;
  InitialCount := ADependencies.Count;
  if not AReader.ReadBuffer(0, Ident, SizeOf(Ident)) or
    (Ident[0] <> $7F) or (Ident[1] <> Ord('E')) or
    (Ident[2] <> Ord('L')) or (Ident[3] <> Ord('F')) or
    not (Ident[4] in [1, 2]) or not (Ident[5] in [1, 2]) then
    Exit;
  Is64Bit := Ident[4] = 2;
  BigEndian := Ident[5] = 2;
  if Is64Bit then
  begin
    if not AReader.ReadUInt64(32, BigEndian, ProgramOffset) or
      not AReader.ReadUInt16(54, BigEndian, ProgramEntrySize) or
      not AReader.ReadUInt16(56, BigEndian, ProgramCount) then Exit;
    EntrySize := 16;
  end
  else
  begin
    if not AReader.ReadUInt32(28, BigEndian, Value32) then Exit;
    ProgramOffset := Value32;
    if not AReader.ReadUInt16(42, BigEndian, ProgramEntrySize) or
      not AReader.ReadUInt16(44, BigEndian, ProgramCount) then Exit;
    EntrySize := 8;
  end;
  if (ProgramCount = 0) or (ProgramCount > MaximumProgramHeaders) or
    (ProgramEntrySize = 0) then Exit;
  if (Is64Bit and (ProgramEntrySize < 56)) or
    ((not Is64Bit) and (ProgramEntrySize < 32)) or
    (ProgramOffset > AReader.Size) or
    (QWord(ProgramCount) * ProgramEntrySize > AReader.Size - ProgramOffset) then
    Exit;
  SetLength(Segments, ProgramCount);
  SegmentCount := 0;
  DynamicOffset := 0;
  DynamicSize := 0;
  for I := 0 to ProgramCount - 1 do
  begin
    HeaderOffset := ProgramOffset + QWord(I) * ProgramEntrySize;
    if not AReader.ReadUInt32(HeaderOffset, BigEndian, ProgramType) then Exit;
    if Is64Bit then
    begin
      if not AReader.ReadUInt64(HeaderOffset + 8, BigEndian, Value) then Exit;
      if ProgramType = 1 then Segments[SegmentCount].FileOffset := Value;
      if ProgramType = 2 then DynamicOffset := Value;
      if not AReader.ReadUInt64(HeaderOffset + 16, BigEndian, Tag) then Exit;
      if ProgramType = 1 then Segments[SegmentCount].VirtualAddress := Tag;
      if not AReader.ReadUInt64(HeaderOffset + 32, BigEndian, Value) then Exit;
    end
    else
    begin
      if not AReader.ReadUInt32(HeaderOffset + 4, BigEndian, Value32) then Exit;
      Value := Value32;
      if ProgramType = 1 then Segments[SegmentCount].FileOffset := Value;
      if ProgramType = 2 then DynamicOffset := Value;
      if not AReader.ReadUInt32(HeaderOffset + 8, BigEndian, Value32) then Exit;
      Tag := Value32;
      if ProgramType = 1 then Segments[SegmentCount].VirtualAddress := Tag;
      if not AReader.ReadUInt32(HeaderOffset + 16, BigEndian, Value32) then Exit;
      Value := Value32;
    end;
    if ProgramType = 1 then
    begin
      Segments[SegmentCount].FileSize := Value;
      Inc(SegmentCount);
    end
    else if ProgramType = 2 then
      DynamicSize := Value;
  end;
  SetLength(Segments, SegmentCount);
  if (DynamicSize = 0) or (DynamicOffset >= AReader.Size) then Exit;
  if DynamicSize > AReader.Size - DynamicOffset then
    DynamicSize := AReader.Size - DynamicOffset;
  SetLength(Needed, MaximumDependencies);
  NeededCount := 0;
  StringAddress := 0;
  StringSize := 0;
  DynamicEntryCount := DynamicSize div EntrySize;
  if DynamicEntryCount > MaximumDynamicEntries then
    DynamicEntryCount := MaximumDynamicEntries;
  for I := 0 to Integer(DynamicEntryCount) - 1 do
  begin
    HeaderOffset := DynamicOffset + QWord(I) * EntrySize;
    if Is64Bit then
    begin
      if not AReader.ReadUInt64(HeaderOffset, BigEndian, Tag) or
        not AReader.ReadUInt64(HeaderOffset + 8, BigEndian, Value) then Break;
    end
    else
    begin
      if not AReader.ReadUInt32(HeaderOffset, BigEndian, Value32) then Break;
      Tag := Value32;
      if not AReader.ReadUInt32(HeaderOffset + 4, BigEndian, Value32) then Break;
      Value := Value32;
    end;
    if Tag = 0 then Break;
    case Tag of
      1: if NeededCount < MaximumDependencies then
        begin Needed[NeededCount] := Value; Inc(NeededCount); end;
      5: StringAddress := Value;
      10: StringSize := Value;
    end;
  end;
  if (StringAddress = 0) or (NeededCount = 0) then Exit;
  StringOffset := 0;
  FoundStringOffset := False;
  for I := 0 to High(Segments) do
    if (StringAddress >= Segments[I].VirtualAddress) and
      (StringAddress - Segments[I].VirtualAddress < Segments[I].FileSize) then
    begin
      Value := StringAddress - Segments[I].VirtualAddress;
      if Segments[I].FileOffset > High(QWord) - Value then
        Exit;
      StringOffset := Segments[I].FileOffset + Value;
      FoundStringOffset := True;
      Break;
    end;
  if not FoundStringOffset then Exit;
  for I := 0 to NeededCount - 1 do
  begin
    if (StringSize > 0) and (Needed[I] >= StringSize) then Continue;
    NameLimit := MaximumDependencyName;
    if (StringSize > Needed[I]) and
      (StringSize - Needed[I] < QWord(NameLimit)) then
      NameLimit := Integer(StringSize - Needed[I]);
    if (StringOffset > High(QWord) - Needed[I]) then Continue;
    if AReader.ReadCString(StringOffset + Needed[I], NameLimit,
      DependencyName) then
      AddDependency(ADependencies, DependencyName);
  end;
  Result := ADependencies.Count > InitialCount;
end;

function InspectNativeDependencies(const AFileName, AFormatName: string;
  ADependencies: TStrings): Boolean;
var
  Reader: TBinaryReader;
begin
  Result := False;
  if ADependencies = nil then
    Exit;
  Reader := TBinaryReader.Create(AFileName);
  try
    if SameText(AFormatName, 'PE') then
      Result := InspectPEDependencies(Reader, ADependencies)
    else if SameText(AFormatName, 'ELF') then
      Result := InspectELFDependencies(Reader, ADependencies)
    else if Pos('Mach-O', AFormatName) = 1 then
      Result := InspectMachDependencies(Reader, ADependencies);
  finally
    Reader.Free;
  end;
end;

end.
