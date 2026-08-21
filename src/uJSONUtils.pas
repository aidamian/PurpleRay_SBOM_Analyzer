(**
  PurpleRay SBOM Analyzer JSON utility unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Provides defensive typed JSON accessors and UTF-8 file helpers shared by
  settings, history, manifest parsing, and SBOM generation.

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
unit uJSONUtils;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpjson;

const
  { Upper bound used by persistent settings and task-history readers when a
    caller does not provide a narrower format-specific limit. }
  DefaultMaximumJSONBytes = Int64(64) * 1024 * 1024;
  MaximumJSONNestingDepth = 128;
  MaximumJSONNodeCount = 262144;
  MaximumJSONTokenCount = 1048576;

{**
  Reads a string member with type checking and a caller-supplied fallback.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned when the member is absent or not a JSON string.

  Returns
  -------
  string
    Stored value or ADefault.

  Raises
  ------
  None
}
function JSONString(AObject: TJSONObject; const AName: string;
  const ADefault: string = ''): string;

{**
  Reads a Boolean member with type checking.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned for a missing or incompatible member.

  Returns
  -------
  Boolean
    Stored value or ADefault.

  Raises
  ------
  None
}
function JSONBoolean(AObject: TJSONObject; const AName: string;
  ADefault: Boolean = False): Boolean;

{**
  Reads an integer member as Int64 with type checking.

  Parameters
  ----------
  AObject
    Object to inspect; nil is accepted.
  AName
    Member name.
  ADefault
    Value returned for a missing or incompatible member.

  Returns
  -------
  Int64
    Stored integer or ADefault.

  Raises
  ------
  None
}
function JSONInt64(AObject: TJSONObject; const AName: string;
  ADefault: Int64 = 0): Int64;

{**
  Returns a named child only when it is a JSON object.

  Parameters
  ----------
  AObject
    Parent object; nil is accepted.
  AName
    Child member name.

  Returns
  -------
  TJSONObject
    Borrowed child reference, or nil when absent or incompatible.

  Raises
  ------
  None
}
function JSONObject(AObject: TJSONObject; const AName: string): TJSONObject;

{**
  Returns a named child only when it is a JSON array.

  Parameters
  ----------
  AObject
    Parent object; nil is accepted.
  AName
    Child member name.

  Returns
  -------
  TJSONArray
    Borrowed child reference, or nil when absent or incompatible.

  Raises
  ------
  None
}
function JSONArray(AObject: TJSONObject; const AName: string): TJSONArray;

{**
  Validates raw bytes according to RFC 3629 UTF-8 scalar-value rules.

  Parameters
  ----------
  AContent
    Exact bytes to validate.

  Returns
  -------
  Boolean
    True only for shortest-form UTF-8 excluding surrogate code points and
    values above U+10FFFF.

  Raises
  ------
  None
}
function IsValidUTF8Bytes(const AContent: RawByteString): Boolean;

{**
  Reads the remaining bytes of a stream under an explicit hard limit.

  Parameters
  ----------
  AStream
    Caller-owned stream read from its current position through end of stream.
  AMaximumBytes
    Maximum accepted byte count. The function probes one byte beyond this
    boundary so an exactly full stream is distinguished from an oversized one.

  Returns
  -------
  RawByteString
    Exact source bytes without code-page conversion.

  Raises
  ------
  EArgumentNilException, EArgumentOutOfRangeException
    Raised for nil input or a nonpositive bound.
  EReadError, EStreamError
    Raised for oversized input or an underlying stream failure.
  EOutOfMemory
    Propagated if the bounded result buffer cannot be allocated.
}
function ReadBoundedRawBytes(AStream: TStream;
  AMaximumBytes: Int64): RawByteString;

{**
  Parses one complete strict JSON document from validated UTF-8 bytes.

  Parameters
  ----------
  AContent
    Complete raw JSON document. A UTF-8 byte-order mark is not accepted.

  Returns
  -------
  TJSONData
    Newly allocated JSON tree owned by the caller.

  Raises
  ------
  EJSONParser, EScannerError, EJSON
    Raised for invalid UTF-8, malformed escapes or surrogate pairs, duplicate
    object members, trailing non-whitespace data, or other invalid JSON.
  EOutOfMemory
    Propagated if normalization or parsed-tree storage cannot be allocated.

  Notes
  -----
  Unicode escapes are normalized to verified raw UTF-8 before invoking FPC
  3.2.2 with ``joStrict`` and without ``joUTF8``. This avoids its lossy
  system-code-page conversion and its incorrect pairing of adjacent
  ``\\uXXXX`` escapes.
}
function ParseStrictUTF8JSON(const AContent: RawByteString): TJSONData;

{**
  Reads and parses one bounded strict UTF-8 JSON document from a stream.

  Parameters
  ----------
  AStream
    Caller-owned stream read from its current position.
  AMaximumBytes
    Maximum accepted raw byte count.

  Returns
  -------
  TJSONData
    Newly allocated JSON tree owned by the caller.

  Raises
  ------
  EArgumentNilException, EArgumentOutOfRangeException, EReadError,
  EStreamError, EJSONParser, EScannerError, EJSON, EOutOfMemory
    Propagated from bounded reading and strict parsing.
}
function ReadJSONStream(AStream: TStream;
  AMaximumBytes: Int64 = DefaultMaximumJSONBytes): TJSONData;

{**
  Reads and parses one UTF-8 JSON document from disk.

  Parameters
  ----------
  AFileName
    JSON file to open.
  AMaximumBytes
    Maximum accepted raw byte count.

  Returns
  -------
  TJSONData
    Newly allocated JSON tree owned by the caller.

  Raises
  ------
  EFOpenError, EReadError, EStreamError, EArgumentOutOfRangeException,
  EJSONParser, EScannerError, EJSON, EOutOfMemory
    Propagated for file access, bounded reading, strict parsing, or allocation
    failure.
}
function ReadJSONFile(const AFileName: string;
  AMaximumBytes: Int64 = DefaultMaximumJSONBytes): TJSONData;

{**
  Serializes a JSON tree directly to deterministic UTF-8 bytes.

  Parameters
  ----------
  AData
    JSON tree to serialize; ownership remains with the caller.
  AOptions
    FPC JSON formatting options.
  AIndentSize
    Number of spaces per indentation level.
  AAppendFinalLineFeed
    True to terminate the document with exactly one additional LF.

  Returns
  -------
  UTF8String
    Valid UTF-8 JSON with CRLF and bare CR formatting separators normalized to
    LF, without a system-code-page round trip.

  Raises
  ------
  EArgumentNilException, EArgumentOutOfRangeException, EJSON
    Raised for nil input, a negative indent, or invalid serialized UTF-8.
  EOutOfMemory
    Propagated if serialization or normalization storage cannot be allocated.
}
function SerializeJSONUTF8(AData: TJSONData;
  const AOptions: TFormatOptions; AIndentSize: Integer;
  AAppendFinalLineFeed: Boolean): UTF8String;

{**
  Writes exact UTF-8 bytes to a newly created or replaced file.

  Parameters
  ----------
  AFileName
    Destination filename.
  AContent
    UTF-8 bytes to write.

  Returns
  -------
  None

  Raises
  ------
  EFCreateError, EWriteError
    Propagated when the file cannot be created or fully written.
}
procedure WriteUTF8File(const AFileName: string; const AContent: UTF8String);

{**
  Converts CRLF and bare CR sequences to line-feed JSON line endings.

  Parameters
  ----------
  AValue
    Text to normalize.

  Returns
  -------
  string
    Text containing only LF line separators.

  Raises
  ------
  None
}
function NormalizeJSONLineEndings(const AValue: string): string;

implementation

uses
  jsonparser, jsonscanner;

const
  { A private, injective transport protocol is needed only for JSON escapes
    representing U+0000..U+001F. Raw control bytes cannot be handed to the FPC
    scanner, and FPC 3.2.2 drops U+0000. Every literal U+FDD0 in a JSON string
    is doubled; U+FDD0 followed by U+E000..U+E01F transports one control byte.
    The parsed tree is decoded immediately, so callers never observe markers. }
  ControlMarkerUTF8: RawByteString = #$EF#$B7#$90; { U+FDD0 }

{**
  Tests whether one byte has the RFC 3629 continuation-byte prefix.

  Parameters
  ----------
  AValue
    Byte to classify.

  Returns
  -------
  Boolean
    True when the two high bits are ``10``.

  Raises
  ------
  None
*}
function IsContinuationByte(AValue: Byte): Boolean; inline;
begin
  Result := (AValue and $C0) = $80;
end;

function IsValidUTF8Bytes(const AContent: RawByteString): Boolean;
var
  First, Second, Third, Fourth: Byte;
  I: SizeInt;
begin
  I := 1;
  while I <= Length(AContent) do
  begin
    First := Byte(AContent[I]);
    if First <= $7F then
    begin
      Inc(I);
      Continue;
    end;
    if (First >= $C2) and (First <= $DF) then
    begin
      if (I + 1 > Length(AContent)) or
        not IsContinuationByte(Byte(AContent[I + 1])) then
        Exit(False);
      Inc(I, 2);
      Continue;
    end;
    if (First >= $E0) and (First <= $EF) then
    begin
      if I + 2 > Length(AContent) then
        Exit(False);
      Second := Byte(AContent[I + 1]);
      Third := Byte(AContent[I + 2]);
      if not IsContinuationByte(Third) then
        Exit(False);
      case First of
        $E0:
          if (Second < $A0) or (Second > $BF) then
            Exit(False);
        $ED:
          if (Second < $80) or (Second > $9F) then
            Exit(False);
      else
        if not IsContinuationByte(Second) then
          Exit(False);
      end;
      Inc(I, 3);
      Continue;
    end;
    if (First >= $F0) and (First <= $F4) then
    begin
      if I + 3 > Length(AContent) then
        Exit(False);
      Second := Byte(AContent[I + 1]);
      Third := Byte(AContent[I + 2]);
      Fourth := Byte(AContent[I + 3]);
      if not IsContinuationByte(Third) or
        not IsContinuationByte(Fourth) then
        Exit(False);
      case First of
        $F0:
          if (Second < $90) or (Second > $BF) then
            Exit(False);
        $F4:
          if (Second < $80) or (Second > $8F) then
            Exit(False);
      else
        if not IsContinuationByte(Second) then
          Exit(False);
      end;
      Inc(I, 4);
      Continue;
    end;
    Exit(False);
  end;
  Result := True;
end;

function ReadBoundedRawBytes(AStream: TStream;
  AMaximumBytes: Int64): RawByteString;
const
  ReadBufferSize = 8192;
var
  Buffer: array[0..ReadBufferSize - 1] of Byte;
  BytesRead, Capacity, RequiredCapacity: SizeInt;
  TotalBytes: Int64;
begin
  if AStream = nil then
    raise EArgumentNilException.Create('JSON input stream is nil');
  if AMaximumBytes <= 0 then
    raise EArgumentOutOfRangeException.Create(
      'Maximum JSON byte count must be positive');
  {$IFNDEF CPU64}
  if AMaximumBytes > High(SizeInt) then
    raise EArgumentOutOfRangeException.Create(
      'Maximum JSON byte count exceeds the addressable string size');
  {$ENDIF}
  Result := '';
  Buffer[0] := 0;
  Capacity := 0;
  TotalBytes := 0;
  repeat
    if TotalBytes = AMaximumBytes then
    begin
      BytesRead := AStream.Read(Buffer[0], 1);
      if BytesRead <> 0 then
        raise EReadError.CreateFmt('JSON input exceeds the %d-byte limit',
          [AMaximumBytes]);
      Break;
    end;
    RequiredCapacity := ReadBufferSize;
    if AMaximumBytes - TotalBytes < RequiredCapacity then
      RequiredCapacity := SizeInt(AMaximumBytes - TotalBytes);
    BytesRead := AStream.Read(Buffer[0], RequiredCapacity);
    if BytesRead < 0 then
      raise EReadError.Create('JSON input stream returned an invalid byte count');
    if BytesRead = 0 then
      Break;
    if TotalBytes + BytesRead > AMaximumBytes then
      raise EReadError.CreateFmt('JSON input exceeds the %d-byte limit',
        [AMaximumBytes]);
    RequiredCapacity := SizeInt(TotalBytes) + BytesRead;
    if RequiredCapacity > Capacity then
    begin
      if Capacity = 0 then
      begin
        Capacity := ReadBufferSize;
        if Capacity > SizeInt(AMaximumBytes) then
          Capacity := SizeInt(AMaximumBytes);
      end;
      while Capacity < RequiredCapacity do
      begin
        if Capacity > SizeInt(AMaximumBytes) div 2 then
          Capacity := SizeInt(AMaximumBytes)
        else
          Capacity := Capacity * 2;
      end;
      SetLength(Result, Capacity);
    end;
    Move(Buffer[0], Result[SizeInt(TotalBytes) + 1], BytesRead);
    Inc(TotalBytes, BytesRead);
  until False;
  SetLength(Result, SizeInt(TotalBytes));
end;

{**
  Converts one ASCII hexadecimal digit to its numeric value.

  Parameters
  ----------
  AValue
    Candidate ASCII digit.

  Returns
  -------
  Integer
    Value from zero through fifteen, or minus one for a nondigit.

  Raises
  ------
  None
*}
function HexDigitValue(AValue: AnsiChar): Integer; inline;
begin
  case AValue of
    '0'..'9': Result := Ord(AValue) - Ord('0');
    'A'..'F': Result := Ord(AValue) - Ord('A') + 10;
    'a'..'f': Result := Ord(AValue) - Ord('a') + 10;
  else
    Result := -1;
  end;
end;

{**
  Decodes one complete JSON ``\\uXXXX`` escape without advancing input.

  Parameters
  ----------
  AContent
    Complete raw JSON bytes containing the candidate escape.
  ASlashIndex
    One-based index of the candidate backslash.
  AValue
    Receives the decoded 16-bit code unit on success; its value is unspecified
    after a malformed partial escape.

  Returns
  -------
  Boolean
    True only when all six bytes form a valid Unicode escape.

  Raises
  ------
  None
*}
function TryReadUnicodeEscape(const AContent: RawByteString;
  ASlashIndex: SizeInt; out AValue: Cardinal): Boolean;
var
  Digit, I: Integer;
begin
  AValue := 0;
  Result := (ASlashIndex >= 1) and
    (ASlashIndex + 5 <= Length(AContent)) and
    (AContent[ASlashIndex] = '\') and
    (AContent[ASlashIndex + 1] = 'u');
  if not Result then
    Exit;
  for I := ASlashIndex + 2 to ASlashIndex + 5 do
  begin
    Digit := HexDigitValue(AContent[I]);
    if Digit < 0 then
      Exit(False);
    AValue := (AValue shl 4) or Cardinal(Digit);
  end;
end;

{**
  Appends exact bytes to a preallocated normalization buffer.

  Parameters
  ----------
  ABuffer
    Destination buffer whose allocated length covers the append.
  ALength
    Used-byte count, advanced by the appended length.
  AValue
    Exact bytes to append.

  Returns
  -------
  None

  Raises
  ------
  None
    Buffer capacity is guaranteed by the owning normalizer.
*}
procedure AppendRawBytes(var ABuffer: RawByteString; var ALength: SizeInt;
  const AValue: RawByteString); inline;
begin
  if Length(AValue) = 0 then
    Exit;
  Move(AValue[1], ABuffer[ALength + 1], Length(AValue));
  Inc(ALength, Length(AValue));
end;

{**
  Appends one byte to a preallocated normalization buffer.

  Parameters
  ----------
  ABuffer
    Destination buffer whose allocated length covers the append.
  ALength
    Used-byte count, advanced by one.
  AValue
    Byte to append.

  Returns
  -------
  None

  Raises
  ------
  None
    Buffer capacity is guaranteed by the owning normalizer.
*}
procedure AppendRawByte(var ABuffer: RawByteString; var ALength: SizeInt;
  AValue: Byte); inline;
begin
  Inc(ALength);
  ABuffer[ALength] := AnsiChar(AValue);
end;

{**
  Encodes one verified Unicode scalar into a preallocated UTF-8 buffer.

  Parameters
  ----------
  ABuffer
    Destination normalization buffer.
  ALength
    Used-byte count advanced by the encoded length.
  AValue
    Unicode scalar no greater than U+10FFFF and outside the surrogate range.

  Returns
  -------
  None

  Raises
  ------
  None
    Scalar validity and buffer capacity are guaranteed by the caller.
*}
procedure AppendUTF8Scalar(var ABuffer: RawByteString; var ALength: SizeInt;
  AValue: Cardinal);
begin
  if AValue <= $7F then
    AppendRawByte(ABuffer, ALength, AValue)
  else if AValue <= $7FF then
  begin
    AppendRawByte(ABuffer, ALength, $C0 or (AValue shr 6));
    AppendRawByte(ABuffer, ALength, $80 or (AValue and $3F));
  end
  else if AValue <= $FFFF then
  begin
    AppendRawByte(ABuffer, ALength, $E0 or (AValue shr 12));
    AppendRawByte(ABuffer, ALength, $80 or ((AValue shr 6) and $3F));
    AppendRawByte(ABuffer, ALength, $80 or (AValue and $3F));
  end
  else
  begin
    AppendRawByte(ABuffer, ALength, $F0 or (AValue shr 18));
    AppendRawByte(ABuffer, ALength, $80 or ((AValue shr 12) and $3F));
    AppendRawByte(ABuffer, ALength, $80 or ((AValue shr 6) and $3F));
    AppendRawByte(ABuffer, ALength, $80 or (AValue and $3F));
  end;
end;

{**
  Emits an escaped scalar using UTF-8 or the private control transport.

  Parameters
  ----------
  ABuffer
    Destination normalization buffer.
  ALength
    Used-byte count advanced by the emitted bytes.
  AValue
    Verified Unicode scalar decoded from JSON escape syntax.
  AUsedControlProtocol
    Set True when control or marker transport bytes are emitted.

  Returns
  -------
  None

  Raises
  ------
  None
    Scalar validity and buffer capacity are guaranteed by the caller.
*}
procedure AppendNormalizedEscapedScalar(var ABuffer: RawByteString;
  var ALength: SizeInt; AValue: Cardinal; var AUsedControlProtocol: Boolean);
begin
  if AValue <= $1F then
  begin
    AppendRawBytes(ABuffer, ALength, ControlMarkerUTF8);
    AppendRawByte(ABuffer, ALength, $EE);
    AppendRawByte(ABuffer, ALength, $80);
    AppendRawByte(ABuffer, ALength, $80 + Byte(AValue));
    AUsedControlProtocol := True;
    Exit;
  end;
  case AValue of
    Ord('"'):
      AppendRawBytes(ABuffer, ALength, '\"');
    Ord('\'):
      AppendRawBytes(ABuffer, ALength, '\\');
    $FDD0:
      begin
        AppendRawBytes(ABuffer, ALength, ControlMarkerUTF8);
        AppendRawBytes(ABuffer, ALength, ControlMarkerUTF8);
        AUsedControlProtocol := True;
      end;
  else
    AppendUTF8Scalar(ABuffer, ALength, AValue);
  end;
end;

{**
  Validates UTF-8 and normalizes JSON Unicode escapes for FPC strict parsing.

  Parameters
  ----------
  AContent
    Complete raw JSON bytes.
  AUsedControlProtocol
    Receives True when an escaped control or literal marker required private
    reversible transport through the FPC parser.

  Returns
  -------
  RawByteString
    Validated JSON bytes with Unicode escapes converted to safe UTF-8 or
    private transport sequences.

  Raises
  ------
  EJSONParser
    Raised for invalid UTF-8, raw controls, malformed escapes, isolated
    surrogates, or input too large for bounded normalization.
  EOutOfMemory
    Propagated if the bounded output buffer cannot be allocated.
*}
function NormalizeUnicodeEscapes(const AContent: RawByteString;
  out AUsedControlProtocol: Boolean): RawByteString;
var
  FirstValue, LowValue, ScalarValue: Cardinal;
  I, OutputLength: SizeInt;
  InString: Boolean;
  Value: Byte;
begin
  if not IsValidUTF8Bytes(AContent) then
    raise EJSONParser.Create('JSON input is not valid RFC 3629 UTF-8');
  if Length(AContent) > (High(SizeInt) - 8) div 2 then
    raise EJSONParser.Create('JSON input is too large to normalize safely');
  SetLength(Result, Length(AContent) * 2 + 8);
  OutputLength := 0;
  AUsedControlProtocol := False;
  InString := False;
  I := 1;
  while I <= Length(AContent) do
  begin
    Value := Byte(AContent[I]);
    if not InString then
    begin
      if (Value < $20) and not (Value in [$09, $0A, $0D]) then
        raise EJSONParser.Create('JSON input contains an invalid raw control byte');
      AppendRawByte(Result, OutputLength, Value);
      if Value = Ord('"') then
        InString := True;
      Inc(I);
      Continue;
    end;

    if Value = Ord('"') then
    begin
      AppendRawByte(Result, OutputLength, Value);
      InString := False;
      Inc(I);
      Continue;
    end;
    if Value < $20 then
      raise EJSONParser.Create('JSON string contains an unescaped control byte');
    if Value <> Ord('\') then
    begin
      if (I + 2 <= Length(AContent)) and
        (Copy(AContent, I, 3) = ControlMarkerUTF8) then
      begin
        AppendRawBytes(Result, OutputLength, ControlMarkerUTF8);
        AppendRawBytes(Result, OutputLength, ControlMarkerUTF8);
        AUsedControlProtocol := True;
        Inc(I, 3);
      end
      else
      begin
        AppendRawByte(Result, OutputLength, Value);
        Inc(I);
      end;
      Continue;
    end;

    if I = Length(AContent) then
      raise EJSONParser.Create('JSON string ends with an incomplete escape');
    if AContent[I + 1] <> 'u' then
    begin
      AppendRawByte(Result, OutputLength, Value);
      AppendRawByte(Result, OutputLength, Byte(AContent[I + 1]));
      Inc(I, 2);
      Continue;
    end;
    if not TryReadUnicodeEscape(AContent, I, FirstValue) then
      raise EJSONParser.Create('JSON string contains a malformed Unicode escape');
    if (FirstValue >= $D800) and (FirstValue <= $DBFF) then
    begin
      if (I + 11 > Length(AContent)) or
        not TryReadUnicodeEscape(AContent, I + 6, LowValue) or
        (LowValue < $DC00) or (LowValue > $DFFF) then
        raise EJSONParser.Create(
          'JSON string contains an isolated high surrogate');
      ScalarValue := $10000 + ((FirstValue - $D800) shl 10) +
        (LowValue - $DC00);
      AppendNormalizedEscapedScalar(Result, OutputLength, ScalarValue,
        AUsedControlProtocol);
      Inc(I, 12);
      Continue;
    end;
    if (FirstValue >= $DC00) and (FirstValue <= $DFFF) then
      raise EJSONParser.Create('JSON string contains an isolated low surrogate');
    AppendNormalizedEscapedScalar(Result, OutputLength, FirstValue,
      AUsedControlProtocol);
    Inc(I, 6);
  end;
  SetLength(Result, OutputLength);
end;

{**
  Applies conservative token, potential-node, and nesting caps before parsing.

  Parameters
  ----------
  AContent
    Normalized JSON bytes whose string boundaries and structural tokens are
    counted without constructing a tree.

  Returns
  -------
  None

  Raises
  ------
  EJSONParser
    Raised when token, potential-node, or container-depth limits are exceeded.
*}
procedure PreflightJSONResources(const AContent: RawByteString);
var
  Depth, PotentialNodes, Tokens: Integer;
  Escaped, InAtom, InString: Boolean;
  I: SizeInt;
  Value: Byte;

  {**
    Accounts for one preflight token and optionally one potential JSON node.

    Parameters
    ----------
    ACanBeNode
      True when this token can create a scalar or container tree node.

    Returns
    -------
    None

    Raises
    ------
    EJSONParser
      Raised when either enclosing resource counter exceeds its hard limit.
  *}
  procedure CountToken(ACanBeNode: Boolean);
  begin
    Inc(Tokens);
    if Tokens > MaximumJSONTokenCount then
      raise EJSONParser.Create('JSON input exceeds the token-count limit');
    if ACanBeNode then
    begin
      Inc(PotentialNodes);
      if PotentialNodes > MaximumJSONNodeCount then
        raise EJSONParser.Create('JSON input exceeds the node-count limit');
    end;
  end;

begin
  Depth := 0;
  PotentialNodes := 0;
  Tokens := 0;
  Escaped := False;
  InAtom := False;
  InString := False;
  I := 1;
  while I <= Length(AContent) do
  begin
    Value := Byte(AContent[I]);
    if InString then
    begin
      if Escaped then
        Escaped := False
      else if Value = Ord('\') then
        Escaped := True
      else if Value = Ord('"') then
        InString := False;
      Inc(I);
      Continue;
    end;

    case Value of
      $09, $0A, $0D, $20:
        InAtom := False;
      Ord('"'):
        begin
          InAtom := False;
          InString := True;
          CountToken(True);
        end;
      Ord('{'), Ord('['):
        begin
          InAtom := False;
          CountToken(True);
          Inc(Depth);
          if Depth > MaximumJSONNestingDepth then
            raise EJSONParser.Create('JSON input exceeds the nesting-depth limit');
        end;
      Ord('}'), Ord(']'):
        begin
          InAtom := False;
          CountToken(False);
          if Depth > 0 then
            Dec(Depth);
        end;
      Ord(','), Ord(':'):
        begin
          InAtom := False;
          CountToken(False);
        end;
    else
      if not InAtom then
      begin
        InAtom := True;
        CountToken(True);
      end;
    end;
    Inc(I);
  end;
end;

{**
  Reverses the private transport used for escaped JSON control characters.

  Parameters
  ----------
  AValue
    Parsed UTF-8 string containing doubled markers or marker/control pairs.

  Returns
  -------
  UTF8String
    Original UTF-8 bytes with transported controls restored.

  Raises
  ------
  EJSONParser
    Raised when a private marker is not followed by a valid transport payload.
  EOutOfMemory
    Propagated if the decoded output buffer cannot be allocated.
*}
function DecodeControlProtocolString(const AValue: UTF8String): UTF8String;
var
  Input: RawByteString;
  I, OutputLength: SizeInt;
begin
  Input := RawByteString(AValue);
  SetLength(Result, Length(Input));
  I := 1;
  OutputLength := 0;
  while I <= Length(Input) do
  begin
    if (I + 2 <= Length(Input)) and
      (Copy(Input, I, 3) = ControlMarkerUTF8) then
    begin
      if (I + 5 <= Length(Input)) and
        (Copy(Input, I + 3, 3) = ControlMarkerUTF8) then
      begin
        Inc(OutputLength, 3);
        Move(ControlMarkerUTF8[1], Result[OutputLength - 2], 3);
        Inc(I, 6);
        Continue;
      end;
      if (I + 5 <= Length(Input)) and
        (Byte(Input[I + 3]) = $EE) and
        (Byte(Input[I + 4]) = $80) and
        (Byte(Input[I + 5]) in [$80..$9F]) then
      begin
        Inc(OutputLength);
        Result[OutputLength] := AnsiChar(Byte(Input[I + 5]) - $80);
        Inc(I, 6);
        Continue;
      end;
      raise EJSONParser.Create('Internal JSON control marker is malformed');
    end;
    Inc(OutputLength);
    Result[OutputLength] := Input[I];
    Inc(I);
  end;
  SetLength(Result, OutputLength);
end;

{**
  Clones a parsed JSON tree while reversing private control transport strings.

  Parameters
  ----------
  AData
    Non-nil parsed JSON node whose ownership remains with the caller.

  Returns
  -------
  TJSONData
    Newly allocated decoded tree owned by the caller.

  Raises
  ------
  EAccessViolation
    Raised when AData is nil.
  EJSONParser
    Propagated for malformed private marker sequences.
  EOutOfMemory
    Propagated if the cloned tree cannot be allocated.
*}
function DecodeControlProtocolTree(AData: TJSONData): TJSONData;
var
  ArrayValue: TJSONArray;
  I: Integer;
  ObjectValue: TJSONObject;
begin
  case AData.JSONType of
    jtString:
      Result := TJSONString.Create(DecodeControlProtocolString(AData.AsString));
    jtArray:
      begin
        ArrayValue := TJSONArray.Create;
        try
          for I := 0 to TJSONArray(AData).Count - 1 do
            ArrayValue.Add(DecodeControlProtocolTree(
              TJSONArray(AData).Items[I]));
          Result := ArrayValue;
        except
          ArrayValue.Free;
          raise;
        end;
      end;
    jtObject:
      begin
        ObjectValue := TJSONObject.Create;
        try
          for I := 0 to TJSONObject(AData).Count - 1 do
            ObjectValue.Add(DecodeControlProtocolString(
              TJSONObject(AData).Names[I]), DecodeControlProtocolTree(
              TJSONObject(AData).Items[I]));
          Result := ObjectValue;
        except
          ObjectValue.Free;
          raise;
        end;
      end;
  else
    Result := AData.Clone;
  end;
end;

{**
  Recursively verifies post-parse node, depth, and UTF-8 invariants.

  Parameters
  ----------
  AData
    Node to validate; nil returns False.
  AContainerDepth
    Number of containers surrounding AData.
  ANodeCount
    Shared node counter incremented for every visited node.

  Returns
  -------
  Boolean
    True when the subtree remains within all hard bounds and every key and
    string value contains valid UTF-8.

  Raises
  ------
  None
*}
function ValidateJSONTreeBounds(AData: TJSONData; AContainerDepth: Integer;
  var ANodeCount: Integer): Boolean;
var
  ChildDepth, I: Integer;
begin
  Result := (AData <> nil) and (ANodeCount < MaximumJSONNodeCount);
  if not Result then
    Exit;
  Inc(ANodeCount);
  ChildDepth := AContainerDepth;
  if AData.JSONType in [jtArray, jtObject] then
  begin
    Inc(ChildDepth);
    if ChildDepth > MaximumJSONNestingDepth then
      Exit(False);
  end;
  case AData.JSONType of
    jtString:
      Result := IsValidUTF8Bytes(RawByteString(AData.AsString));
    jtArray:
      for I := 0 to TJSONArray(AData).Count - 1 do
        if not ValidateJSONTreeBounds(TJSONArray(AData).Items[I], ChildDepth,
          ANodeCount) then
          Exit(False);
    jtObject:
      for I := 0 to TJSONObject(AData).Count - 1 do
      begin
        if not IsValidUTF8Bytes(RawByteString(TJSONObject(AData).Names[I])) or
          not ValidateJSONTreeBounds(TJSONObject(AData).Items[I], ChildDepth,
          ANodeCount) then
          Exit(False);
      end;
  end;
end;

function ParseStrictUTF8JSON(const AContent: RawByteString): TJSONData;
var
  NodeCount: Integer;
  Normalized: RawByteString;
  Parsed: TJSONData;
  Parser: TJSONParser;
  UsedControlProtocol: Boolean;
begin
  Result := nil;
  Normalized := NormalizeUnicodeEscapes(AContent, UsedControlProtocol);
  PreflightJSONResources(Normalized);
  Parser := TJSONParser.Create(Normalized, [joStrict]);
  try
    Parsed := Parser.Parse;
  finally
    Parser.Free;
  end;
  if Parsed = nil then
    raise EJSONParser.Create('JSON input does not contain a value');
  if not UsedControlProtocol then
    Result := Parsed
  else
  begin
    try
      Result := DecodeControlProtocolTree(Parsed);
    finally
      Parsed.Free;
    end;
  end;
  NodeCount := 0;
  if not ValidateJSONTreeBounds(Result, 0, NodeCount) then
  begin
    FreeAndNil(Result);
    raise EJSONParser.Create(
      'Parsed JSON exceeds the node, depth, or UTF-8 limits');
  end;
end;

function ReadJSONStream(AStream: TStream;
  AMaximumBytes: Int64): TJSONData;
var
  Content: RawByteString;
begin
  Content := ReadBoundedRawBytes(AStream, AMaximumBytes);
  Result := ParseStrictUTF8JSON(Content);
end;

function JSONString(AObject: TJSONObject; const AName: string;
  const ADefault: string): string;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsString;
end;

function JSONBoolean(AObject: TJSONObject; const AName: string;
  ADefault: Boolean): Boolean;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsBoolean;
end;

function JSONInt64(AObject: TJSONObject; const AName: string;
  ADefault: Int64): Int64;
var
  Data: TJSONData;
begin
  Result := ADefault;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType <> jtNull) then
    Result := Data.AsInt64;
end;

function JSONObject(AObject: TJSONObject; const AName: string): TJSONObject;
var
  Data: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType = jtObject) then
    Result := TJSONObject(Data);
end;

function JSONArray(AObject: TJSONObject; const AName: string): TJSONArray;
var
  Data: TJSONData;
begin
  Result := nil;
  if AObject = nil then
    Exit;
  Data := AObject.Find(AName);
  if (Data <> nil) and (Data.JSONType = jtArray) then
    Result := TJSONArray(Data);
end;

function ReadJSONFile(const AFileName: string;
  AMaximumBytes: Int64): TJSONData;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := ReadJSONStream(Stream, AMaximumBytes);
  finally
    Stream.Free;
  end;
end;

{**
  Normalizes CRLF and bare CR bytes without a text-code-page conversion.

  Parameters
  ----------
  AValue
    Raw serialized UTF-8 bytes.

  Returns
  -------
  RawByteString
    Exact input bytes except that every line separator is one LF.

  Raises
  ------
  EOutOfMemory
    Propagated if the output buffer cannot be allocated.
*}
function NormalizeUTF8LineEndings(
  const AValue: RawByteString): RawByteString;
var
  I, OutputLength: SizeInt;
begin
  SetLength(Result, Length(AValue));
  I := 1;
  OutputLength := 0;
  while I <= Length(AValue) do
  begin
    Inc(OutputLength);
    if AValue[I] = #13 then
    begin
      Result[OutputLength] := #10;
      if (I < Length(AValue)) and (AValue[I + 1] = #10) then
        Inc(I);
    end
    else
      Result[OutputLength] := AValue[I];
    Inc(I);
  end;
  SetLength(Result, OutputLength);
end;

function SerializeJSONUTF8(AData: TJSONData;
  const AOptions: TFormatOptions; AIndentSize: Integer;
  AAppendFinalLineFeed: Boolean): UTF8String;
var
  Bytes: RawByteString;
  Formatted: UTF8String;
begin
  if AData = nil then
    raise EArgumentNilException.Create('JSON value to serialize is nil');
  if AIndentSize < 0 then
    raise EArgumentOutOfRangeException.Create(
      'JSON indentation size must not be negative');
  Formatted := AData.FormatJSON(AOptions, AIndentSize);
  Bytes := NormalizeUTF8LineEndings(RawByteString(Formatted));
  if AAppendFinalLineFeed then
    Bytes := Bytes + #10;
  if not IsValidUTF8Bytes(Bytes) then
    raise EJSON.Create('Serialized JSON contains invalid UTF-8');
  SetCodePage(Bytes, CP_UTF8, False);
  Result := UTF8String(Bytes);
end;

procedure WriteUTF8File(const AFileName: string; const AContent: UTF8String);
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmCreate);
  try
    if Length(AContent) > 0 then
      Stream.WriteBuffer(AContent[1], Length(AContent));
  finally
    Stream.Free;
  end;
end;

function NormalizeJSONLineEndings(const AValue: string): string;
begin
  Result := StringReplace(AValue, #13#10, #10, [rfReplaceAll]);
  Result := StringReplace(Result, #13, #10, [rfReplaceAll]);
end;

end.
