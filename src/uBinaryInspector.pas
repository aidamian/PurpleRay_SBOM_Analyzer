(**
  PurpleRay SBOM Analyzer native-binary header unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Detects PE, ELF, thin Mach-O, and universal Mach-O files and reports their
  architecture and broad binary classification without executing them.

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
unit uBinaryInspector;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TBinaryInfo = record
    FormatName: string;
    Architecture: string;
    Classification: string;
    Diagnostic: string;
  end;

{**
  Inspects a binary header without loading or executing the target.

  Parameters
  ----------
  AFileName
    File to open and inspect.
  AInfo
    Receives the format, architecture, and binary classification.

  Returns
  -------
  Boolean
    True when a PE, ELF, Mach-O, or universal Mach-O header is recognized.

  Raises
  ------
  EFOpenError, EReadError
    Propagated when the file cannot be opened or its header cannot be read.
}
function InspectBinary(const AFileName: string; out AInfo: TBinaryInfo): Boolean;
  overload;

{**
  Inspects a binary header from an already verified, bounded stream.

  Parameters
  ----------
  AStream
    Caller-owned seekable input; inspection starts at offset zero.
  ADisplayName
    Retained for source compatibility; classification is entirely structural.
  AInfo
    Receives format, architecture, classification, and any fail-closed
    candidate diagnostic.

  Returns
  -------
  Boolean
    True when a supported binary or a visible MZ/ELF candidate is recognized.

  Raises
  ------
  EReadError, EStreamError
    Propagated when the bounded stream cannot be read or rewound.
*}
function InspectBinary(AStream: TStream; const ADisplayName: string;
  out AInfo: TBinaryInfo): Boolean; overload;

implementation

uses
  uBoundedBinaryReader;

const
  MaximumPEHeaderOffset = 16 * 1024 * 1024;
  MaximumELFProgramHeaders = 1024;
  MaximumMachArchitectures = 128;

function PEMachineName(Value: Word): string;
begin
  case Value of
    $014C: Result := 'x86';
    $8664: Result := 'x86_64';
    $01C0, $01C2, $01C4: Result := 'ARM';
    $AA64: Result := 'ARM64';
    $0200: Result := 'IA-64';
  else
    Result := 'unknown-' + IntToHex(Value, 4);
  end;
end;

function ELFMachineName(Value: Word): string;
begin
  case Value of
    3: Result := 'x86';
    8: Result := 'MIPS';
    20: Result := 'PowerPC';
    21: Result := 'PowerPC64';
    40: Result := 'ARM';
    62: Result := 'x86_64';
    183: Result := 'ARM64';
    243: Result := 'RISC-V';
  else
    Result := 'unknown-' + IntToStr(Value);
  end;
end;

function MachCPUName(Value: UInt32): string;
const
  CPU_ARCH_ABI64 = $01000000;
begin
  case Value of
    7: Result := 'x86';
    7 or CPU_ARCH_ABI64: Result := 'x86_64';
    12: Result := 'ARM';
    12 or CPU_ARCH_ABI64: Result := 'ARM64';
    18: Result := 'PowerPC';
    18 or CPU_ARCH_ABI64: Result := 'PowerPC64';
  else
    Result := 'unknown-' + IntToHex(Value, 8);
  end;
end;

{**
  Recognizes a PE header and maps its machine and DLL characteristics.

  Parameters
  ----------
  AReader
    Range-checking reader for the complete verified file.
  AInfo
    Receives PE metadata, or candidate classification and a failure diagnostic.

  Returns
  -------
  Boolean
    True for a valid PE or any MZ candidate requiring visible diagnostics.

  Raises
  ------
  None
}
function InspectPE(AReader: TBoundedBinaryReader;
  out AInfo: TBinaryInfo): Boolean;
var
  HeaderOffsetValue: UInt32;
  HeaderOffset: QWord;
  Characteristics, Machine: Word;
  DOSMagic: array[0..1] of Byte;
  Signature: array[0..3] of Byte;
begin
  Result := False;
  if not AReader.ReadBuffer(0, DOSMagic, SizeOf(DOSMagic)) or
    (DOSMagic[0] <> Ord('M')) or (DOSMagic[1] <> Ord('Z')) then
    Exit;
  AInfo.FormatName := 'PE';
  AInfo.Architecture := 'unknown';
  AInfo.Classification := 'binary';
  if not AReader.ReadUInt32($3C, False, HeaderOffsetValue) then
  begin
    AInfo.Diagnostic := 'PE candidate has a truncated DOS header';
    Exit(True);
  end;
  HeaderOffset := HeaderOffsetValue;
  if HeaderOffset > MaximumPEHeaderOffset then
  begin
    AInfo.Diagnostic := 'PE header offset exceeds the 16 MiB safety limit';
    Exit(True);
  end;
  if not AReader.ContainsRange(HeaderOffset, 24) then
  begin
    AInfo.Diagnostic := 'PE candidate has a truncated targeted header';
    Exit(True);
  end;
  if not AReader.ReadBuffer(HeaderOffset, Signature, SizeOf(Signature)) or
    (Signature[0] <> Ord('P')) or (Signature[1] <> Ord('E')) or
    (Signature[2] <> 0) or (Signature[3] <> 0) then
  begin
    AInfo.Diagnostic := 'PE candidate has an invalid targeted signature';
    Exit(True);
  end;
  if not AReader.ReadUInt16(HeaderOffset + 4, False, Machine) or
    not AReader.ReadUInt16(HeaderOffset + 22, False, Characteristics) then
  begin
    AInfo.Diagnostic := 'PE candidate has a truncated COFF header';
    Exit(True);
  end;
  AInfo.Architecture := PEMachineName(Machine);
  if (Characteristics and $2000) <> 0 then
    AInfo.Classification := 'library'
  else
    AInfo.Classification := 'executable';
  Result := True;
end;

type
  TELFInterpreterState = (eisIndeterminate, eisAbsent, eisPresent);

{**
  Validates one complete bounded PT_INTERP payload.

  Parameters
  ----------
  AReader
    Range-checking reader for the verified ELF file.
  AOffset, ASize
    Declared PT_INTERP file range, already capped by the caller.
  APath
    Receives the printable interpreter path.

  Returns
  -------
  Boolean
    True for one nonempty NUL-terminated path followed only by zero padding.

  Raises
  ------
  EStreamError
    Propagated when an in-range stream read fails.
  EOutOfMemory
    Propagated if the at-most-4096-byte buffer cannot be allocated.
*}
function ReadELFInterpreterPayload(AReader: TBoundedBinaryReader;
  AOffset, ASize: QWord; out APath: string): Boolean;
var
  Buffer: array of Byte;
  RawPath: RawByteString;
  I, TerminatorAt: Integer;
begin
  Result := False;
  APath := '';
  if (ASize = 0) or (ASize > 4096) or
    not AReader.ContainsRange(AOffset, ASize) then
    Exit;
  SetLength(Buffer, Integer(ASize));
  if not AReader.ReadBuffer(AOffset, Buffer[0], Length(Buffer)) then
    Exit;
  TerminatorAt := -1;
  for I := 0 to High(Buffer) do
  begin
    if Buffer[I] = 0 then
    begin
      TerminatorAt := I;
      Break;
    end;
    if (Buffer[I] < 32) or (Buffer[I] = $7F) then
      Exit;
  end;
  if TerminatorAt <= 0 then
    Exit;
  for I := TerminatorAt + 1 to High(Buffer) do
    if Buffer[I] <> 0 then
      Exit;
  SetLength(RawPath, TerminatorAt);
  Move(Buffer[0], RawPath[1], TerminatorAt);
  APath := string(RawPath);
  Result := True;
end;

{**
  Detects PT_INTERP in a bounded ELF program-header table.

  Parameters
  ----------
  AReader
    Range-checking reader for the complete verified file.
  AIs64Bit
    Selects the ELF64 header and program-header layout.
  ABigEndian
    Selects big-endian scalar decoding.
  ADiagnostic
    Receives a deterministic explanation for indeterminate structure.

  Returns
  -------
  TELFInterpreterState
    Present for one valid bounded payload, absent after a complete valid table,
    or indeterminate for malformed, truncated, duplicate, or over-cap data.

  Raises
  ------
  EStreamError
    Propagated when an in-range stream read fails.
}
function ELFInterpreterState(AReader: TBoundedBinaryReader;
  AIs64Bit, ABigEndian: Boolean; out ADiagnostic: string):
  TELFInterpreterState;
var
  ProgramOffset, HeaderOffset, InterpreterOffset, InterpreterSize: QWord;
  Offset32, Size32, ProgramType: UInt32;
  ProgramEntrySize, ProgramCount: Word;
  I: Integer;
  InterpreterPath: string;
  FoundInterpreter: Boolean;
begin
  Result := eisIndeterminate;
  ADiagnostic := '';
  if AIs64Bit then
  begin
    if not AReader.ReadUInt64(32, ABigEndian, ProgramOffset) or
      not AReader.ReadUInt16(54, ABigEndian, ProgramEntrySize) or
      not AReader.ReadUInt16(56, ABigEndian, ProgramCount) then
    begin
      ADiagnostic := 'ELF program-header metadata is truncated';
      Exit;
    end;
  end
  else
  begin
    if not AReader.ReadUInt32(28, ABigEndian, Offset32) or
      not AReader.ReadUInt16(42, ABigEndian, ProgramEntrySize) or
      not AReader.ReadUInt16(44, ABigEndian, ProgramCount) then
    begin
      ADiagnostic := 'ELF program-header metadata is truncated';
      Exit;
    end;
    ProgramOffset := Offset32;
  end;
  if ProgramCount = 0 then
  begin
    ADiagnostic := 'ELF ET_DYN has no program-header table';
    Exit(eisIndeterminate);
  end;
  if AIs64Bit and (ProgramEntrySize < 56) then
  begin
    ADiagnostic := 'ELF64 program-header entry size is invalid';
    Exit;
  end;
  if (not AIs64Bit) and (ProgramEntrySize < 32) then
  begin
    ADiagnostic := 'ELF32 program-header entry size is invalid';
    Exit;
  end;
  if ProgramCount > MaximumELFProgramHeaders then
  begin
    ADiagnostic := 'ELF program-header count exceeds the safety limit';
    Exit;
  end;
  if not AReader.ContainsRange(ProgramOffset,
    QWord(ProgramCount) * ProgramEntrySize) then
  begin
    ADiagnostic := 'ELF program-header table is out of range';
    Exit;
  end;
  FoundInterpreter := False;
  for I := 0 to ProgramCount - 1 do
  begin
    HeaderOffset := ProgramOffset + QWord(I) * ProgramEntrySize;
    if not AReader.ReadUInt32(HeaderOffset, ABigEndian, ProgramType) then
    begin
      ADiagnostic := 'ELF program-header table could not be read';
      Exit(eisIndeterminate);
    end;
    if ProgramType = 3 then
    begin
      if FoundInterpreter then
      begin
        ADiagnostic := 'ELF contains multiple PT_INTERP declarations';
        Exit(eisIndeterminate);
      end;
      if AIs64Bit then
      begin
        if not AReader.ReadUInt64(HeaderOffset + 8, ABigEndian,
          InterpreterOffset) or
          not AReader.ReadUInt64(HeaderOffset + 32, ABigEndian,
            InterpreterSize) then
        begin
          ADiagnostic := 'ELF PT_INTERP header is truncated';
          Exit(eisIndeterminate);
        end;
      end
      else
      begin
        if not AReader.ReadUInt32(HeaderOffset + 4, ABigEndian, Offset32) or
          not AReader.ReadUInt32(HeaderOffset + 16, ABigEndian, Size32) then
        begin
          ADiagnostic := 'ELF PT_INTERP header is truncated';
          Exit(eisIndeterminate);
        end;
        InterpreterOffset := Offset32;
        InterpreterSize := Size32;
      end;
      if not ReadELFInterpreterPayload(AReader, InterpreterOffset,
        InterpreterSize, InterpreterPath) then
      begin
        ADiagnostic := 'ELF PT_INTERP payload is invalid or exceeds 4096 bytes';
        Exit(eisIndeterminate);
      end;
      FoundInterpreter := True;
    end;
  end;
  if FoundInterpreter then
    Result := eisPresent
  else
    Result := eisAbsent;
end;

{**
  Recognizes an ELF header and classifies ET_DYN using PT_INTERP evidence.

  Parameters
  ----------
  AReader
    Range-checking reader for the complete verified file.
  AInfo
    Receives ELF format, architecture, and classification.

  Returns
  -------
  Boolean
    True for a recognizable ELF header and supported encoding.

  Raises
  ------
  EStreamError
    Propagated when an in-range stream read fails.
}
function InspectELF(AReader: TBoundedBinaryReader;
  out AInfo: TBinaryInfo): Boolean;
var
  Ident: array[0..19] of Byte;
  Is64Bit, BigEndian: Boolean;
  Machine, FileType: Word;
  InterpreterState: TELFInterpreterState;
begin
  Result := False;
  if not AReader.ReadBuffer(0, Ident, SizeOf(Ident)) or
    (Ident[0] <> $7F) or (Ident[1] <> Ord('E')) or
    (Ident[2] <> Ord('L')) or (Ident[3] <> Ord('F')) or
    not (Ident[4] in [1, 2]) or not (Ident[5] in [1, 2]) then
    Exit;
  Is64Bit := Ident[4] = 2;
  BigEndian := Ident[5] = 2;
  if not AReader.ReadUInt16(16, BigEndian, FileType) or
    not AReader.ReadUInt16(18, BigEndian, Machine) then
    Exit;
  AInfo.FormatName := 'ELF';
  AInfo.Architecture := ELFMachineName(Machine);
  if FileType = 2 then
    AInfo.Classification := 'executable'
  else if FileType = 3 then
  begin
    InterpreterState := ELFInterpreterState(AReader, Is64Bit, BigEndian,
      AInfo.Diagnostic);
    case InterpreterState of
      eisPresent: AInfo.Classification := 'executable';
      eisAbsent: AInfo.Classification := 'library';
      eisIndeterminate: AInfo.Classification := 'binary';
    end;
  end
  else
    AInfo.Classification := 'object';
  Result := True;
end;

{**
  Recognizes thin and universal Mach-O headers without parsing load commands.

  Parameters
  ----------
  AReader
    Range-checking reader for the complete verified file.
  AInfo
    Receives Mach-O metadata on success.

  Returns
  -------
  Boolean
    True for a recognizable Mach-O magic and header.

  Raises
  ------
  None
}
function InspectMachO(AReader: TBoundedBinaryReader;
  out AInfo: TBinaryInfo): Boolean;
var
  Magic, CPUType, FileType, NumberOfArchitectures: UInt32;
  ArchitectureEntrySize: QWord;
  BigEndian, Is64Bit: Boolean;
begin
  Result := False;
  if not AReader.ReadUInt32(0, True, Magic) then
    Exit;
  if (Magic = $CAFEBABE) or (Magic = $CAFEBABF) or
    (Magic = $BEBAFECA) or (Magic = $BFBAFECA) then
  begin
    BigEndian := (Magic = $CAFEBABE) or (Magic = $CAFEBABF);
    Is64Bit := (Magic = $CAFEBABF) or (Magic = $BFBAFECA);
    if not AReader.ReadUInt32(4, BigEndian, NumberOfArchitectures) or
      (NumberOfArchitectures = 0) or
      (NumberOfArchitectures > MaximumMachArchitectures) then
      Exit(False);
    if Is64Bit then
      ArchitectureEntrySize := 32
    else
      ArchitectureEntrySize := 20;
    if not AReader.ContainsRange(8,
      QWord(NumberOfArchitectures) * ArchitectureEntrySize) then
      Exit(False);
    AInfo.FormatName := 'Mach-O universal';
    AInfo.Architecture := 'universal';
    AInfo.Classification := 'binary';
    Exit(True);
  end;
  if (Magic <> $FEEDFACE) and (Magic <> $FEEDFACF) and
    (Magic <> $CEFAEDFE) and (Magic <> $CFFAEDFE) then
    Exit;
  BigEndian := (Magic = $FEEDFACE) or (Magic = $FEEDFACF);
  if not AReader.ReadUInt32(4, BigEndian, CPUType) or
    not AReader.ReadUInt32(12, BigEndian, FileType) then
    Exit;
  AInfo.FormatName := 'Mach-O';
  AInfo.Architecture := MachCPUName(CPUType);
  case FileType of
    2: AInfo.Classification := 'executable';
    6, 8: AInfo.Classification := 'library';
  else
    AInfo.Classification := 'object';
  end;
  Result := True;
end;

function InspectBinary(AStream: TStream; const ADisplayName: string;
  out AInfo: TBinaryInfo): Boolean;
var
  Reader: TBoundedBinaryReader;
begin
  AInfo.FormatName := '';
  AInfo.Architecture := '';
  AInfo.Classification := '';
  AInfo.Diagnostic := '';
  if AStream = nil then
    raise EArgumentNilException.Create('Binary input stream is nil');
  Reader := TBoundedBinaryReader.Create(AStream);
  try
    Result := InspectPE(Reader, AInfo) or InspectELF(Reader, AInfo) or
      InspectMachO(Reader, AInfo);
  finally
    Reader.Free;
  end;
end;

function InspectBinary(const AFileName: string;
  out AInfo: TBinaryInfo): Boolean;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    Result := InspectBinary(Stream, AFileName, AInfo);
  finally
    Stream.Free;
  end;
end;

end.
