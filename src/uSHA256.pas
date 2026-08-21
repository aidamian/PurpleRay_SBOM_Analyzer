(**
  PurpleRay SBOM Analyzer SHA-256 unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Implements incremental SHA-256 hashing for memory strings and files with
  cooperative cancellation and progress reporting.

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
unit uSHA256;

{$mode objfpc}{$H+}{$Q-}

interface

uses
  Classes, SysUtils;

type
  TCancelCheck = function: Boolean of object;
  THashProgress = procedure(ABytesRead: Int64) of object;

{**
  Calculates SHA-256 over the exact bytes of a raw string.

  Parameters
  ----------
  AValue
    Byte string to hash; text encoding is not altered.

  Returns
  -------
  string
    Lowercase 64-character hexadecimal digest.

  Raises
  ------
  None
}
function SHA256String(const AValue: RawByteString): string;

{**
  Calculates SHA-256 over one stream's exact size snapshot.

  Parameters
  ----------
  AStream
    Caller-owned seekable stream. Hashing starts at offset zero.
  ADigest
    Receives the lowercase digest on success, or an empty string on cancel.
  ACancelCheck
    Optional callback polled between input chunks.
  AProgress
    Optional callback receiving cumulative bytes read.

  Returns
  -------
  Boolean
    True when exactly the initial stream size was hashed; False on cancellation.

  Raises
  ------
  EArgumentNilException
    Raised when AStream is nil.
  EReadError, EStreamError
    Raised for a negative size, premature EOF, or an underlying stream
    read/seek failure.
*}
function SHA256Stream(AStream: TStream; out ADigest: string;
  ACancelCheck: TCancelCheck = nil; AProgress: THashProgress = nil): Boolean;

{**
  Calculates SHA-256 for a file with cancellation and progress callbacks.

  Parameters
  ----------
  AFileName
    File to open and hash sequentially.
  ADigest
    Receives the lowercase digest on success, or an empty string on cancel.
  ACancelCheck
    Optional callback polled between input chunks.
  AProgress
    Optional callback receiving cumulative bytes read.

  Returns
  -------
  Boolean
    True when the entire file was hashed; False when cancellation was requested.

  Raises
  ------
  EFOpenError, EReadError
    Propagated when the file cannot be opened or read.
}
function SHA256File(const AFileName: string; out ADigest: string;
  ACancelCheck: TCancelCheck = nil; AProgress: THashProgress = nil): Boolean;

implementation

type
  TSHA256Context = record
    State: array[0..7] of UInt32;
    Buffer: array[0..63] of Byte;
    BufferLength: Integer;
    ProcessedBits: QWord;
  end;

const
  K: array[0..63] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1,
    $923F82A4, $AB1C5ED5, $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174, $E49B69C1, $EFBE4786,
    $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147,
    $06CA6351, $14292967, $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85, $A2BFE8A1, $A81A664B,
    $C24B8B70, $C76C51A3, $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A,
    $5B9CCA4F, $682E6FF3, $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

function RotateRight(AValue: UInt32; ACount: Byte): UInt32; inline;
begin
  Result := (AValue shr ACount) or (AValue shl (32 - ACount));
end;

{**
  Adds up to five SHA-256 words with explicit modulo-2^32 reduction.

  Parameters
  ----------
  AFirst, ASecond
    Required 32-bit words.
  AThird, AFourth, AFifth
    Optional additional words, defaulting to zero.

  Returns
  -------
  UInt32
    Low 32 bits of the unsigned sum.

  Raises
  ------
  None
    The wider intermediate prevents checked Debug builds from treating the
    algorithm's required modular reduction as a range error.
}
function AddMod32(AFirst, ASecond: UInt32; AThird: UInt32 = 0;
  AFourth: UInt32 = 0; AFifth: UInt32 = 0): UInt32; inline;
begin
  Result := UInt32((QWord(AFirst) + QWord(ASecond) + QWord(AThird) +
    QWord(AFourth) + QWord(AFifth)) and QWord($FFFFFFFF));
end;

procedure Initialize(var AContext: TSHA256Context);
begin
  FillChar(AContext, SizeOf(AContext), 0);
  AContext.State[0] := $6A09E667;
  AContext.State[1] := $BB67AE85;
  AContext.State[2] := $3C6EF372;
  AContext.State[3] := $A54FF53A;
  AContext.State[4] := $510E527F;
  AContext.State[5] := $9B05688C;
  AContext.State[6] := $1F83D9AB;
  AContext.State[7] := $5BE0CD19;
end;

procedure Transform(var AContext: TSHA256Context);
var
  W: array[0..63] of UInt32;
  A, B, C, D, E, F, G, H, S0, S1, Choice, Majority, T1, T2: UInt32;
  I: Integer;
begin
  for I := 0 to 15 do
    W[I] := (UInt32(AContext.Buffer[I * 4]) shl 24) or
      (UInt32(AContext.Buffer[I * 4 + 1]) shl 16) or
      (UInt32(AContext.Buffer[I * 4 + 2]) shl 8) or
      UInt32(AContext.Buffer[I * 4 + 3]);
  for I := 16 to 63 do
  begin
    S0 := RotateRight(W[I - 15], 7) xor RotateRight(W[I - 15], 18) xor
      (W[I - 15] shr 3);
    S1 := RotateRight(W[I - 2], 17) xor RotateRight(W[I - 2], 19) xor
      (W[I - 2] shr 10);
    W[I] := AddMod32(W[I - 16], S0, W[I - 7], S1);
  end;

  A := AContext.State[0];
  B := AContext.State[1];
  C := AContext.State[2];
  D := AContext.State[3];
  E := AContext.State[4];
  F := AContext.State[5];
  G := AContext.State[6];
  H := AContext.State[7];

  for I := 0 to 63 do
  begin
    S1 := RotateRight(E, 6) xor RotateRight(E, 11) xor RotateRight(E, 25);
    Choice := (E and F) xor ((not E) and G);
    T1 := AddMod32(H, S1, Choice, K[I], W[I]);
    S0 := RotateRight(A, 2) xor RotateRight(A, 13) xor RotateRight(A, 22);
    Majority := (A and B) xor (A and C) xor (B and C);
    T2 := AddMod32(S0, Majority);
    H := G;
    G := F;
    F := E;
    E := AddMod32(D, T1);
    D := C;
    C := B;
    B := A;
    A := AddMod32(T1, T2);
  end;

  AContext.State[0] := AddMod32(AContext.State[0], A);
  AContext.State[1] := AddMod32(AContext.State[1], B);
  AContext.State[2] := AddMod32(AContext.State[2], C);
  AContext.State[3] := AddMod32(AContext.State[3], D);
  AContext.State[4] := AddMod32(AContext.State[4], E);
  AContext.State[5] := AddMod32(AContext.State[5], F);
  AContext.State[6] := AddMod32(AContext.State[6], G);
  AContext.State[7] := AddMod32(AContext.State[7], H);
end;

procedure Update(var AContext: TSHA256Context; const AData; ALength: SizeInt);
var
  Source: PByte;
begin
  Source := @AData;
  while ALength > 0 do
  begin
    AContext.Buffer[AContext.BufferLength] := Source^;
    Inc(AContext.BufferLength);
    Inc(Source);
    Dec(ALength);
    if AContext.BufferLength = SizeOf(AContext.Buffer) then
    begin
      Transform(AContext);
      Inc(AContext.ProcessedBits, 512);
      AContext.BufferLength := 0;
    end;
  end;
end;

function FinalizeDigest(var AContext: TSHA256Context): string;
var
  TotalBits: QWord;
  I: Integer;
begin
  TotalBits := AContext.ProcessedBits + QWord(AContext.BufferLength) * 8;
  AContext.Buffer[AContext.BufferLength] := $80;
  Inc(AContext.BufferLength);
  if AContext.BufferLength > 56 then
  begin
    while AContext.BufferLength < 64 do
    begin
      AContext.Buffer[AContext.BufferLength] := 0;
      Inc(AContext.BufferLength);
    end;
    Transform(AContext);
    AContext.BufferLength := 0;
  end;
  while AContext.BufferLength < 56 do
  begin
    AContext.Buffer[AContext.BufferLength] := 0;
    Inc(AContext.BufferLength);
  end;
  for I := 0 to 7 do
    AContext.Buffer[63 - I] := Byte((TotalBits shr (I * 8)) and $FF);
  Transform(AContext);

  Result := '';
  for I := 0 to 7 do
    Result := Result + LowerCase(IntToHex(AContext.State[I], 8));
end;

function SHA256String(const AValue: RawByteString): string;
var
  Context: TSHA256Context;
begin
  Initialize(Context);
  if Length(AValue) > 0 then
    Update(Context, AValue[1], Length(AValue));
  Result := FinalizeDigest(Context);
end;

function SHA256Stream(AStream: TStream; out ADigest: string;
  ACancelCheck: TCancelCheck; AProgress: THashProgress): Boolean;
const
  BufferSize = 64 * 1024;
var
  Context: TSHA256Context;
  Buffer: array[0..BufferSize - 1] of Byte;
  Count, Requested: LongInt;
  Total, ExpectedSize, Remaining: Int64;
begin
  Result := False;
  ADigest := '';
  if AStream = nil then
    raise EArgumentNilException.Create('SHA-256 input stream is nil');
  Initialize(Context);
  ExpectedSize := AStream.Size;
  if ExpectedSize < 0 then
    raise EReadError.Create('SHA-256 input has an invalid negative size');
  AStream.Position := 0;
  Total := 0;
  while Total < ExpectedSize do
  begin
    if Assigned(ACancelCheck) and ACancelCheck() then
      Exit;
    Remaining := ExpectedSize - Total;
    Requested := SizeOf(Buffer);
    if Remaining < Requested then
      Requested := LongInt(Remaining);
    Count := AStream.Read(Buffer, Requested);
    if Count <= 0 then
      raise EReadError.CreateFmt(
        'SHA-256 input ended early after %d of %d bytes',
        [Total, ExpectedSize]);
    Update(Context, Buffer[0], Count);
    Inc(Total, Count);
    if Assigned(AProgress) then
      AProgress(Total);
  end;
  ADigest := FinalizeDigest(Context);
  Result := True;
end;

function SHA256File(const AFileName: string; out ADigest: string;
  ACancelCheck: TCancelCheck; AProgress: THashProgress): Boolean;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    Result := SHA256Stream(Stream, ADigest, ACancelCheck, AProgress);
  finally
    Stream.Free;
  end;
end;

end.
