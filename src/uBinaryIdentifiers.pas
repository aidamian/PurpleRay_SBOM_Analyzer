(**
  PurpleRay SBOM Analyzer binary-identifier unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Constructs conservative inventory identifiers only from exact binary
  evidence. Generic Package URLs require name, fixed version, and SHA-256;
  candidate CPEs require both PE CompanyName and ProductName. Neither form is
  a package-registry or CPE-dictionary resolution.

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
unit uBinaryIdentifiers;

{$mode objfpc}{$H+}

interface

{**
  Builds a checksum-qualified generic Package URL from exact binary evidence.

  Parameters
  ----------
  AName
    Binary filename or stable product name.
  AVersion
    Exact dotted-numeric version, normally from fixed PE VERSIONINFO.
  ASHA256
    Exact 64-hexadecimal-character SHA-256 of the verified input.

  Returns
  -------
  string
    ``pkg:generic`` identifier, or an empty string when any requirement fails.

  Raises
  ------
  EOutOfMemory
    Propagated if identifier construction cannot be allocated.
*}
function BuildGenericBinaryPackageURL(const AName, AVersion,
  ASHA256: string): string;

{**
  Builds a conservative CPE 2.3 inventory candidate from PE string evidence.

  Parameters
  ----------
  ACompanyName
    CompanyName read from the binary's VERSIONINFO resource.
  AProductName
    ProductName read from the same resource.
  AVersion
    Optional exact dotted-numeric fixed product version.

  Returns
  -------
  string
    A syntactically conservative application CPE, or empty when company or
    product evidence cannot be represented without loss.

  Raises
  ------
  EOutOfMemory
    Propagated if normalized fields cannot be allocated.
*}
function BuildEvidenceCPE(const ACompanyName, AProductName,
  AVersion: string): string;

{**
  Tests the exact version shape accepted for binary identifiers.

  Parameters
  ----------
  AVersion
    Candidate fixed numeric version.

  Returns
  -------
  Boolean
    True for two through eight nonempty decimal segments with at least one
    nonzero digit.

  Raises
  ------
  None
*}
function IsExactBinaryVersion(const AVersion: string): Boolean;

implementation

uses
  SysUtils;

{**
  Percent-encodes one Package URL component byte-for-byte as UTF-8.

  Parameters
  ----------
  AValue
    UTF-8 text stored in an Object Pascal string.

  Returns
  -------
  string
    Package URL data component with uppercase percent escapes.

  Raises
  ------
  EOutOfMemory
    Propagated if the encoded result cannot be allocated.
*}
function PercentEncode(const AValue: string): string;
const
  HexChars = '0123456789ABCDEF';
var
  I: Integer;
  B: Byte;
begin
  Result := '';
  for I := 1 to Length(AValue) do
  begin
    B := Byte(AValue[I]);
    if B in [Ord('a')..Ord('z'), Ord('A')..Ord('Z'), Ord('0')..Ord('9'),
      Ord('.'), Ord('_'), Ord('-'), Ord('~')] then
      Result := Result + Char(B)
    else
      Result := Result + '%' + HexChars[(B shr 4) + 1] +
        HexChars[(B and $0F) + 1];
  end;
end;

function IsExactBinaryVersion(const AVersion: string): Boolean;
var
  Value: string;
  I, SegmentCount: Integer;
  SegmentHasDigit, HasNonZeroDigit: Boolean;
begin
  Value := Trim(AVersion);
  Result := Value <> '';
  if not Result then
    Exit;
  SegmentCount := 1;
  SegmentHasDigit := False;
  HasNonZeroDigit := False;
  for I := 1 to Length(Value) do
  begin
    if Value[I] in ['0'..'9'] then
    begin
      SegmentHasDigit := True;
      if Value[I] <> '0' then
        HasNonZeroDigit := True;
    end
    else if Value[I] = '.' then
    begin
      if not SegmentHasDigit then
        Exit(False);
      Inc(SegmentCount);
      if SegmentCount > 8 then
        Exit(False);
      SegmentHasDigit := False;
    end
    else
      Exit(False);
  end;
  Result := SegmentHasDigit and HasNonZeroDigit and (SegmentCount >= 2);
end;

{**
  Verifies one lowercase or uppercase SHA-256 hexadecimal digest.

  Parameters
  ----------
  AValue
    Candidate digest without an algorithm prefix.

  Returns
  -------
  Boolean
    True only for exactly 64 hexadecimal characters.

  Raises
  ------
  None
*}
function IsSHA256(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := Length(AValue) = 64;
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['0'..'9', 'a'..'f', 'A'..'F']) then
      Exit(False);
end;

{**
  Rejects blank or control-bearing Package URL source names.

  Parameters
  ----------
  AValue
    Candidate binary name.

  Returns
  -------
  Boolean
    True when trimmed text contains no ASCII control character.

  Raises
  ------
  None
*}
function IsUsableName(const AValue: string): Boolean;
var
  I: Integer;
begin
  Result := Trim(AValue) <> '';
  if not Result then
    Exit;
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(False);
end;

function BuildGenericBinaryPackageURL(const AName, AVersion,
  ASHA256: string): string;
var
  NameValue, VersionValue, HashValue: string;
begin
  Result := '';
  NameValue := Trim(AName);
  VersionValue := Trim(AVersion);
  HashValue := LowerCase(Trim(ASHA256));
  if not IsUsableName(NameValue) or
    not IsExactBinaryVersion(VersionValue) or not IsSHA256(HashValue) then
    Exit;
  Result := 'pkg:generic/' + PercentEncode(NameValue) + '@' +
    PercentEncode(VersionValue) + '?checksum=sha256:' + HashValue;
end;

{**
  Converts one ASCII company or product string into a conservative CPE part.

  Parameters
  ----------
  AValue
    VERSIONINFO evidence to normalize.
  APart
    Receives lowercase alphanumeric words joined with underscores.

  Returns
  -------
  Boolean
    True when the value is nonempty, ASCII, and retains at least one word.

  Raises
  ------
  EOutOfMemory
    Propagated if the normalized part cannot be allocated.
*}
function TryNormalizeCPEPart(const AValue: string; out APart: string): Boolean;
var
  Value: string;
  I: Integer;
  SeparatorPending: Boolean;
begin
  APart := '';
  Value := LowerCase(Trim(AValue));
  SeparatorPending := False;
  for I := 1 to Length(Value) do
  begin
    if Ord(Value[I]) > 127 then
      Exit(False);
    if Value[I] in ['a'..'z', '0'..'9'] then
    begin
      if SeparatorPending and (APart <> '') then
        APart := APart + '_';
      APart := APart + Value[I];
      SeparatorPending := False;
    end
    else if Value[I] in [' ', #9, '.', ',', '-', '_', '/', '\',
      '(', ')', '[', ']', '{', '}', '+', '&'] then
      SeparatorPending := APart <> ''
    else
      Exit(False);
  end;
  Result := APart <> '';
end;

function BuildEvidenceCPE(const ACompanyName, AProductName,
  AVersion: string): string;
var
  VendorPart, ProductPart, VersionPart: string;
begin
  Result := '';
  if not TryNormalizeCPEPart(ACompanyName, VendorPart) or
    not TryNormalizeCPEPart(AProductName, ProductPart) then
    Exit;
  if IsExactBinaryVersion(Trim(AVersion)) then
    VersionPart := Trim(AVersion)
  else
    VersionPart := '*';
  Result := 'cpe:2.3:a:' + VendorPart + ':' + ProductPart + ':' +
    VersionPart + ':*:*:*:*:*:*:*';
end;

end.
