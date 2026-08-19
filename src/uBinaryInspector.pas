(**
  SBOM Analyzer native-binary header unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Detects PE, ELF, thin Mach-O, and universal Mach-O files and reports their
  architecture and broad binary classification without executing them.

  Citation request
  ----------------
  Please retain this notice and cite the project as follows:

  @misc{damian2026sbomanalyzer,
    author = {Andrei Ionut Damian},
    title  = {{SBOM Analyzer}},
    year   = {2026},
    url    = {https://github.com/aidamian/SBOM_Analyzer}
  }
*)
unit uBinaryInspector;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  TBinaryInfo = record
    FormatName: string;
    Architecture: string;
    Classification: string;
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

implementation

uses
  Classes;

function ReadUInt16LE(const Buffer: array of Byte; Offset: Integer): Word;
begin
  Result := Word(Buffer[Offset]) or (Word(Buffer[Offset + 1]) shl 8);
end;

function ReadUInt16BE(const Buffer: array of Byte; Offset: Integer): Word;
begin
  Result := (Word(Buffer[Offset]) shl 8) or Word(Buffer[Offset + 1]);
end;

function ReadUInt32LE(const Buffer: array of Byte; Offset: Integer): UInt32;
begin
  Result := UInt32(Buffer[Offset]) or (UInt32(Buffer[Offset + 1]) shl 8) or
    (UInt32(Buffer[Offset + 2]) shl 16) or (UInt32(Buffer[Offset + 3]) shl 24);
end;

function ReadUInt32BE(const Buffer: array of Byte; Offset: Integer): UInt32;
begin
  Result := (UInt32(Buffer[Offset]) shl 24) or
    (UInt32(Buffer[Offset + 1]) shl 16) or
    (UInt32(Buffer[Offset + 2]) shl 8) or UInt32(Buffer[Offset + 3]);
end;

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
  Buffer
    Initial file bytes.
  Count
    Number of valid bytes in Buffer.
  AInfo
    Receives PE metadata on success.

  Returns
  -------
  Boolean
    True for a structurally recognizable PE header.

  Raises
  ------
  None
}
function InspectPE(const Buffer: array of Byte; Count: Integer;
  out AInfo: TBinaryInfo): Boolean;
var
  HeaderOffset: UInt32;
  Characteristics: Word;
begin
  Result := False;
  if (Count < 64) or (Buffer[0] <> Ord('M')) or (Buffer[1] <> Ord('Z')) then
    Exit;
  HeaderOffset := ReadUInt32LE(Buffer, $3C);
  if (HeaderOffset > UInt32(Count - 24)) or
    (Buffer[HeaderOffset] <> Ord('P')) or
    (Buffer[HeaderOffset + 1] <> Ord('E')) or
    (Buffer[HeaderOffset + 2] <> 0) or (Buffer[HeaderOffset + 3] <> 0) then
    Exit;
  AInfo.FormatName := 'PE';
  AInfo.Architecture := PEMachineName(ReadUInt16LE(Buffer, HeaderOffset + 4));
  Characteristics := ReadUInt16LE(Buffer, HeaderOffset + 22);
  if (Characteristics and $2000) <> 0 then
    AInfo.Classification := 'library'
  else
    AInfo.Classification := 'executable';
  Result := True;
end;

{**
  Recognizes an ELF header and maps machine, type, and filename hints.

  Parameters
  ----------
  Buffer
    Initial file bytes.
  Count
    Number of valid bytes in Buffer.
  AFileName
    Filename used only to distinguish shared-object naming.
  AInfo
    Receives ELF metadata on success.

  Returns
  -------
  Boolean
    True for a recognizable ELF header.

  Raises
  ------
  None
}
function InspectELF(const Buffer: array of Byte; Count: Integer;
  const AFileName: string; out AInfo: TBinaryInfo): Boolean;
var
  BigEndian: Boolean;
  Machine, FileType: Word;
  LowerName: string;
begin
  Result := False;
  if (Count < 20) or (Buffer[0] <> $7F) or (Buffer[1] <> Ord('E')) or
    (Buffer[2] <> Ord('L')) or (Buffer[3] <> Ord('F')) then
    Exit;
  BigEndian := Buffer[5] = 2;
  if BigEndian then
  begin
    FileType := ReadUInt16BE(Buffer, 16);
    Machine := ReadUInt16BE(Buffer, 18);
  end
  else
  begin
    FileType := ReadUInt16LE(Buffer, 16);
    Machine := ReadUInt16LE(Buffer, 18);
  end;
  AInfo.FormatName := 'ELF';
  AInfo.Architecture := ELFMachineName(Machine);
  LowerName := LowerCase(ExtractFileName(AFileName));
  if (FileType = 3) and ((Pos('.so', LowerName) > 0) or
    (Pos('.dylib', LowerName) > 0)) then
    AInfo.Classification := 'library'
  else if FileType in [2, 3] then
    AInfo.Classification := 'executable'
  else
    AInfo.Classification := 'object';
  Result := True;
end;

{**
  Recognizes thin and universal Mach-O headers without parsing load commands.

  Parameters
  ----------
  Buffer
    Initial file bytes.
  Count
    Number of valid bytes in Buffer.
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
function InspectMachO(const Buffer: array of Byte; Count: Integer;
  out AInfo: TBinaryInfo): Boolean;
var
  Magic, CPUType, FileType: UInt32;
  BigEndian: Boolean;
begin
  Result := False;
  if Count < 16 then
    Exit;
  Magic := ReadUInt32BE(Buffer, 0);
  if (Magic = $CAFEBABE) or (Magic = $CAFEBABF) or
    (Magic = $BEBAFECA) or (Magic = $BFBAFECA) then
  begin
    AInfo.FormatName := 'Mach-O universal';
    AInfo.Architecture := 'universal';
    AInfo.Classification := 'binary';
    Exit(True);
  end;
  if (Magic <> $FEEDFACE) and (Magic <> $FEEDFACF) and
    (Magic <> $CEFAEDFE) and (Magic <> $CFFAEDFE) then
    Exit;
  BigEndian := (Magic = $FEEDFACE) or (Magic = $FEEDFACF);
  if BigEndian then
  begin
    CPUType := ReadUInt32BE(Buffer, 4);
    FileType := ReadUInt32BE(Buffer, 12);
  end
  else
  begin
    CPUType := ReadUInt32LE(Buffer, 4);
    FileType := ReadUInt32LE(Buffer, 12);
  end;
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

function InspectBinary(const AFileName: string; out AInfo: TBinaryInfo): Boolean;
const
  HeaderSize = 4096;
var
  Stream: TFileStream;
  Buffer: array[0..HeaderSize - 1] of Byte;
  Count: Integer;
begin
  AInfo.FormatName := '';
  AInfo.Architecture := '';
  AInfo.Classification := '';
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    Count := Stream.Read(Buffer, SizeOf(Buffer));
  finally
    Stream.Free;
  end;
  Result := InspectPE(Buffer, Count, AInfo) or InspectELF(Buffer, Count,
    AFileName, AInfo) or InspectMachO(Buffer, Count, AInfo);
end;

end.
