(**
  PurpleRay SBOM Analyzer bounded binary-reader unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Provides overflow-safe, exact random-access reads over a caller-owned
  seekable stream whose size is captured once at construction. Binary parsers
  use this unit to consume the verified file object without reopening a path.

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
unit uBoundedBinaryReader;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TBoundedBinaryReader = class
  private
    FStream: TStream;
    FSize: QWord;
  public
    {**
      Captures the readable extent of a caller-owned seekable stream.

      Parameters
      ----------
      AStream
        Verified bounded stream that must outlive this reader.

      Returns
      -------
      TBoundedBinaryReader
        Newly initialized non-owning reader.

      Raises
      ------
      EArgumentNilException
        Raised when AStream is nil.
      EStreamError
        Raised when the stream reports a negative size.
    *}
    constructor Create(AStream: TStream);

    {**
      Tests whether a byte range lies within the captured stream extent.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      ACount
        Requested number of bytes.

      Returns
      -------
      Boolean
        True when the complete range is within the captured extent.

      Raises
      ------
      None
    *}
    function ContainsRange(AOffset, ACount: QWord): Boolean;

    {**
      Reads an exact byte range after checking it against the captured size.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      ABuffer
        Caller-provided destination buffer.
      ACount
        Number of bytes to read; negative values are rejected.

      Returns
      -------
      Boolean
        True only when the complete in-range request is read.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
    *}
    function ReadBuffer(AOffset: QWord; var ABuffer;
      ACount: Integer): Boolean;

    {**
      Reads one byte from a checked offset.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      AValue
        Receives the byte on success.

      Returns
      -------
      Boolean
        True when the byte is available.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
    *}
    function ReadByte(AOffset: QWord; out AValue: Byte): Boolean;

    {**
      Reads one endian-aware 16-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when two bytes are available.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
    *}
    function ReadUInt16(AOffset: QWord; ABigEndian: Boolean;
      out AValue: Word): Boolean;

    {**
      Reads one endian-aware 32-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when four bytes are available.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
    *}
    function ReadUInt32(AOffset: QWord; ABigEndian: Boolean;
      out AValue: UInt32): Boolean;

    {**
      Reads one endian-aware 64-bit unsigned integer.

      Parameters
      ----------
      AOffset
        Zero-based byte offset.
      ABigEndian
        Selects big-endian decoding when True.
      AValue
        Receives the decoded value on success.

      Returns
      -------
      Boolean
        True when eight bytes are available.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
    *}
    function ReadUInt64(AOffset: QWord; ABigEndian: Boolean;
      out AValue: QWord): Boolean;

    {**
      Reads a printable, null-terminated byte string under a hard cap.

      Parameters
      ----------
      AOffset
        Offset of the first string byte.
      AMaximumLength
        Maximum bytes inspected, including the terminator.
      AValue
        Receives the decoded byte string on success.

      Returns
      -------
      Boolean
        True when a nonempty printable string terminates within the cap.

      Raises
      ------
      EStreamError
        Propagated when the underlying stream cannot seek or read.
      EOutOfMemory
        Propagated if the bounded temporary buffer cannot be allocated.
    *}
    function ReadCString(AOffset: QWord; AMaximumLength: Integer;
      out AValue: string): Boolean;

    property Size: QWord read FSize;
  end;

implementation

constructor TBoundedBinaryReader.Create(AStream: TStream);
var
  StreamSize: Int64;
begin
  inherited Create;
  if AStream = nil then
    raise EArgumentNilException.Create('Bounded binary input stream is nil');
  StreamSize := AStream.Size;
  if StreamSize < 0 then
    raise EStreamError.Create('Bounded binary input has a negative size');
  FStream := AStream;
  FSize := QWord(StreamSize);
end;

function TBoundedBinaryReader.ContainsRange(AOffset, ACount: QWord): Boolean;
begin
  Result := (AOffset <= FSize) and (ACount <= FSize - AOffset);
end;

function TBoundedBinaryReader.ReadBuffer(AOffset: QWord; var ABuffer;
  ACount: Integer): Boolean;
var
  Destination: PByte;
  ReadCount, TotalRead: Integer;
begin
  Result := (ACount >= 0) and ContainsRange(AOffset, QWord(ACount)) and
    (AOffset <= QWord(High(Int64)));
  if not Result or (ACount = 0) then
    Exit;
  FStream.Position := Int64(AOffset);
  Destination := @ABuffer;
  TotalRead := 0;
  while TotalRead < ACount do
  begin
    ReadCount := FStream.Read(Destination[TotalRead], ACount - TotalRead);
    if ReadCount <= 0 then
      Exit(False);
    Inc(TotalRead, ReadCount);
  end;
  Result := True;
end;

function TBoundedBinaryReader.ReadByte(AOffset: QWord;
  out AValue: Byte): Boolean;
begin
  AValue := 0;
  Result := ReadBuffer(AOffset, AValue, SizeOf(AValue));
end;

function TBoundedBinaryReader.ReadUInt16(AOffset: QWord;
  ABigEndian: Boolean; out AValue: Word): Boolean;
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

function TBoundedBinaryReader.ReadUInt32(AOffset: QWord;
  ABigEndian: Boolean; out AValue: UInt32): Boolean;
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

function TBoundedBinaryReader.ReadUInt64(AOffset: QWord;
  ABigEndian: Boolean; out AValue: QWord): Boolean;
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

function TBoundedBinaryReader.ReadCString(AOffset: QWord;
  AMaximumLength: Integer; out AValue: string): Boolean;
var
  Buffer: array of Byte;
  Available: QWord;
  Count, I: Integer;
  RawValue: RawByteString;
begin
  Result := False;
  AValue := '';
  if (AMaximumLength <= 0) or (AOffset >= FSize) then
    Exit;
  Available := FSize - AOffset;
  Count := AMaximumLength;
  if Available < QWord(Count) then
    Count := Integer(Available);
  SetLength(Buffer, Count);
  if (Count = 0) or not ReadBuffer(AOffset, Buffer[0], Count) then
    Exit;
  I := 0;
  while (I < Count) and (Buffer[I] <> 0) do
  begin
    if (Buffer[I] < 32) or (Buffer[I] = $7F) then
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

end.
