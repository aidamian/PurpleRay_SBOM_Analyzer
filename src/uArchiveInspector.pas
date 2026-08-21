(**
  PurpleRay SBOM Analyzer bounded archive-inspection unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Inspects Java JAR, WAR, and EAR metadata and identifies static ar libraries
  through one verified, size-bounded input without extracting to disk,
  following nested archives, invoking external tools, or executing content.

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
unit uArchiveInspector;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels, uSHA256, uVerifiedInput;

const
  MaximumJavaArchiveBytes: Int64 = 1024 * 1024 * 1024;
  MaximumZipEntries = 32768;
  MaximumCentralDirectoryBytes = 16 * 1024 * 1024;
  MaximumArchiveNameBytes = 4096;
  MaximumMetadataEntries = 128;
  MaximumManifestBytes = 256 * 1024;
  MaximumPomPropertiesBytes = 64 * 1024;
  MaximumCompressedMetadataBytes = 1024 * 1024;
  MaximumTotalMetadataBytes = 2 * 1024 * 1024;
  MaximumArchivePassReadBytes: Int64 = 40 * 1024 * 1024;
  MaximumMetadataLineBytes = 8192;
  MaximumCoordinateBytes = 512;

type
  TJavaArchiveKind = (jakJAR, jakWAR, jakEAR);
  TArchiveInspectionResult = (airCompleted, airCancelled);

{**
  Recognizes a Java archive candidate from its final filename extension.

  Parameters
  ----------
  AFileName
    Filename or path whose final extension is checked case-insensitively.
  AKind
    Receives the JAR, WAR, or EAR kind on success.

  Returns
  -------
  Boolean
    True only for ``.jar``, ``.war``, or ``.ear``.

  Raises
  ------
  None
*}
function TryJavaArchiveKind(const AFileName: string;
  out AKind: TJavaArchiveKind): Boolean;

{**
  Recognizes a static-library filename candidate.

  Parameters
  ----------
  AFileName
    Filename or path whose final extension is checked case-insensitively.

  Returns
  -------
  Boolean
    True only for ``.a`` or ``.lib`` candidates. Content must still carry the
    ar global signature before it is accepted as a static library.

  Raises
  ------
  None
*}
function IsStaticLibraryFileName(const AFileName: string): Boolean;

{**
  Builds an exact Maven Package URL from literal archive metadata.

  Parameters
  ----------
  AGroupID
    Literal Maven group identifier.
  AArtifactID
    Literal Maven artifact identifier.
  AVersion
    Exact resolved Maven version.

  Returns
  -------
  string
    Canonical percent-encoded Maven purl, or an empty string when any
    coordinate is missing, unsafe, or not exact.

  Raises
  ------
  None
*}
function BuildMavenPackageURL(const AGroupID, AArtifactID,
  AVersion: string): string;

{**
  Inspects bounded top-level Java archive metadata from one pinned input.

  Parameters
  ----------
  AInput
    Verified input that remains alive for the complete inspection.
  AKind
    Candidate archive kind selected from the filename extension.
  ARelativePath
    Root-relative outer archive path retained as component evidence.
  AFileSHA256
    Optional SHA-256 of the complete verified outer archive.
  AArtifact
    Existing artifact record updated with type, parser, status, diagnostics,
    and component count.
  AComponents
    Owned list receiving newly allocated components transactionally.
  ACancelCheck
    Optional callback polled during archive reads and decompressed writes.

  Returns
  -------
  TArchiveInspectionResult
    ``airCompleted`` for a parsed or failed artifact, and ``airCancelled``
    only when cooperative cancellation interrupted the inspection.

  Raises
  ------
  None
    Structural, bound, decompression, and metadata errors are converted into
    artifact status and diagnostics. Newly produced components are rolled back
    on fatal failure or cancellation.
*}
function InspectJavaArchive(AInput: TVerifiedInput; AKind: TJavaArchiveKind;
  const ARelativePath, AFileSHA256: string; AArtifact: TArtifact;
  AComponents: TObjectList; ACancelCheck: TCancelCheck = nil):
  TArchiveInspectionResult;

{**
  Identifies one static ar library through its exact global signature.

  Parameters
  ----------
  AInput
    Verified input supplying the first eight bounded bytes.
  ARelativePath
    Root-relative static-library path.
  AFileSHA256
    Optional SHA-256 of the complete verified file.
  AArtifact
    Existing artifact record updated with status and evidence.
  AComponents
    Owned list receiving one native library component on success.
  ACancelCheck
    Optional callback checked before and after the bounded signature read.

  Returns
  -------
  TArchiveInspectionResult
    ``airCompleted`` after recognition or deterministic rejection, and
    ``airCancelled`` when cancellation was requested.

  Raises
  ------
  None
    Stream and allocation failures become a failed artifact diagnostic.
*}
function InspectStaticLibrary(AInput: TVerifiedInput;
  const ARelativePath, AFileSHA256: string; AArtifact: TArtifact;
  AComponents: TObjectList; ACancelCheck: TCancelCheck = nil):
  TArchiveInspectionResult;

implementation

uses
  zipper, uManifestParsers;

const
  MaximumArchiveDiagnostics = 16;
  EndOfCentralDirectoryBytes = 22;
  MaximumZipCommentBytes = 65535;
  ZipLocalHeaderSignature: array[0..3] of Byte = ($50, $4B, $03, $04);
  ArGlobalSignature: array[0..7] of Byte = ($21, $3C, $61, $72,
    $63, $68, $3E, $0A);

type
  EArchiveInspectionError = class(Exception);
  EArchiveInspectionCancelled = class(EArchiveInspectionError);
  EArchiveInspectionLimit = class(EArchiveInspectionError);

  TMetadataKind = (mkManifest, mkPomProperties);

  {**
    Holds one selected central-directory entry and its bounded content.

    Ownership
    ---------
    Instances are owned by ``TArchiveInspectionSession.FEntries``. Their
    content never exceeds the per-entry and aggregate metadata caps.
  *}
  TMetadataEntry = class
  public
    ArchiveName: string;
    Kind: TMetadataKind;
    DeclaredSize: Int64;
    CompressedSize: QWord;
    CRC32: LongWord;
    CompressionMethod: Word;
    UnZipperCompressionMethod: Word;
    BitFlags: Word;
    LocalHeaderOffset: QWord;
    PathGroupID: string;
    PathArtifactID: string;
    Content: RawByteString;
    Extracted: Boolean;
  end;

  {**
    Stores one exact Maven coordinate extracted from pom.properties.
  *}
  TMavenCoordinate = class
  public
    GroupID: string;
    ArtifactID: string;
    Version: string;
    PackageURL: string;
  end;

  {**
    Stores conservative identity fields from the manifest main section.
  *}
  TManifestIdentity = record
    Title: string;
    Version: string;
    Vendor: string;
    ImplementationTitle: string;
    ImplementationVersion: string;
    BundleTitle: string;
    BundleVersion: string;
    ModuleName: string;
    SpecificationVersion: string;
    Present: Boolean;
    Invalid: Boolean;
  end;

  {**
    Wraps a verified stream and rejects reads beyond a cumulative pass budget.

    The wrapper owns its source stream. TUnZipper owns and frees the wrapper
    supplied through OnOpenInputStream.
  *}
  TReadBudgetStream = class(TStream)
  private
    FSource: TStream;
    FLimit: Int64;
    FRead: Int64;
    FCancelCheck: TCancelCheck;
  public
    constructor Create(ASource: TStream; ALimit: Int64;
      ACancelCheck: TCancelCheck);
    destructor Destroy; override;
    function Read(var Buffer; Count: LongInt): LongInt; override;
    function Write(const Buffer; Count: LongInt): LongInt; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

  {**
    Captures one decompressed metadata entry without permitting cap overflow.
  *}
  TBoundedCaptureStream = class(TMemoryStream)
  private
    FEntry: TMetadataEntry;
    FLimit: Int64;
    FCancelCheck: TCancelCheck;
  public
    constructor Create(AEntry: TMetadataEntry; ALimit: Int64;
      ACancelCheck: TCancelCheck);
    function Write(const Buffer; Count: LongInt): LongInt; override;
    property Entry: TMetadataEntry read FEntry;
  end;

  {**
    Coordinates TUnZipper callbacks while retaining strict stream ownership.
  *}
  TArchiveInspectionSession = class
  private
    FInput: TVerifiedInput;
    FCancelCheck: TCancelCheck;
    FUnZipper: TUnZipper;
    FEntries: TObjectList;
    FEntryIndex: TStringList;
    FTotalMetadataBytes: Int64;
    FCallbackError: string;
    FNextEntryIndex: Integer;
    procedure OpenInputStream(Sender: TObject; var AStream: TStream);
    procedure CreateOutputStream(Sender: TObject; var AStream: TStream;
      AItem: TFullZipFileEntry);
    procedure FinishOutputStream(Sender: TObject; var AStream: TStream;
      AItem: TFullZipFileEntry);
    procedure DiscoverEntries(AExpectedEntryCount: Integer;
      ACentralOffset, ACentralSize: Int64);
    procedure ValidateLocalHeaders;
    procedure ExtractEntries;
  public
    constructor Create(AInput: TVerifiedInput;
      ACancelCheck: TCancelCheck);
    destructor Destroy; override;
    procedure Execute(AExpectedEntryCount: Integer;
      ACentralOffset, ACentralSize: Int64);
    property Entries: TObjectList read FEntries;
  end;

{**
  Returns whether cooperative cancellation is currently requested.

  Parameters
  ----------
  ACancelCheck
    Optional cancellation callback.

  Returns
  -------
  Boolean
    True only when the callback is assigned and returns True.

  Raises
  ------
  None
*}
function IsCancelled(ACancelCheck: TCancelCheck): Boolean;
begin
  Result := Assigned(ACancelCheck) and ACancelCheck();
end;

{**
  Removes control characters and caps an exception-derived diagnostic.

  Parameters
  ----------
  AValue
    Diagnostic text that may originate in an underlying stream or parser.

  Returns
  -------
  string
    Single-line text no longer than 512 characters.

  Raises
  ------
  None
*}
function SafeDiagnostic(const AValue: string): string;
var
  I: Integer;
begin
  Result := Trim(AValue);
  for I := 1 to Length(Result) do
    if (Ord(Result[I]) < 32) or (Ord(Result[I]) = 127) then
      Result[I] := ' ';
  Result := Trim(Result);
  if Length(Result) > 512 then
    Result := Copy(Result, 1, 509) + '...';
  if Result = '' then
    Result := 'unspecified archive inspection error';
end;

{**
  Rolls an owned component list back to its entry count.

  Parameters
  ----------
  AComponents
    Owned component list to truncate.
  AInitialCount
    Count captured before archive inspection began.

  Returns
  -------
  None

  Raises
  ------
  None
*}
procedure RollBackComponents(AComponents: TObjectList; AInitialCount: Integer);
begin
  if AComponents = nil then
    Exit;
  while AComponents.Count > AInitialCount do
    AComponents.Delete(AComponents.Count - 1);
end;

{**
  Adds one bounded unique archive diagnostic in ordinal order.

  Parameters
  ----------
  ADiagnostics
    Sorted diagnostic set.
  AValue
    Message to sanitize and retain.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the retained diagnostic cannot be allocated.
*}
procedure AddDiagnostic(ADiagnostics: TStringList; const AValue: string);
begin
  if (ADiagnostics = nil) or
    (ADiagnostics.Count >= MaximumArchiveDiagnostics) then
    Exit;
  ADiagnostics.Add(SafeDiagnostic(AValue));
end;

{**
  Joins bounded sorted diagnostics into one stable sentence fragment.

  Parameters
  ----------
  ADiagnostics
    Sorted diagnostics to join.

  Returns
  -------
  string
    Semicolon-delimited text, or an empty string for no diagnostics.

  Raises
  ------
  EOutOfMemory
    Propagated while allocating the result.
*}
function JoinedDiagnostics(ADiagnostics: TStringList): string;
var
  I: Integer;
begin
  Result := '';
  if ADiagnostics = nil then
    Exit;
  for I := 0 to ADiagnostics.Count - 1 do
  begin
    if Result <> '' then
      Result := Result + '; ';
    Result := Result + ADiagnostics[I];
  end;
end;

function TryJavaArchiveKind(const AFileName: string;
  out AKind: TJavaArchiveKind): Boolean;
var
  ExtensionValue: string;
begin
  ExtensionValue := LowerCase(ExtractFileExt(AFileName));
  if ExtensionValue = '.jar' then
    AKind := jakJAR
  else if ExtensionValue = '.war' then
    AKind := jakWAR
  else if ExtensionValue = '.ear' then
    AKind := jakEAR
  else
    Exit(False);
  Result := True;
end;

function IsStaticLibraryFileName(const AFileName: string): Boolean;
var
  ExtensionValue: string;
begin
  ExtensionValue := LowerCase(ExtractFileExt(AFileName));
  Result := (ExtensionValue = '.a') or (ExtensionValue = '.lib');
end;

{**
  Tests whether a coordinate contains placeholders or unsafe control data.

  Parameters
  ----------
  AValue
    Literal coordinate candidate.
  AAllowVersionPunctuation
    True for a version; False for group and artifact identifiers.

  Returns
  -------
  Boolean
    True only for a bounded literal value safe to percent-encode.

  Raises
  ------
  None
*}
function IsLiteralCoordinate(const AValue: string;
  AAllowVersionPunctuation: Boolean): Boolean;
var
  I: Integer;
  Value: string;
begin
  Value := Trim(AValue);
  Result := (Value <> '') and (Length(Value) <= MaximumCoordinateBytes) and
    (Pos('${', Value) = 0) and (Pos('#{', Value) = 0) and
    (Pos('@', Value) = 0);
  if not Result then
    Exit;
  for I := 1 to Length(Value) do
  begin
    if (Ord(Value[I]) < 32) or (Ord(Value[I]) = 127) then
      Exit(False);
    if not AAllowVersionPunctuation and
      (Value[I] in ['/', '\', ':', '=', ' ', #9]) then
      Exit(False);
    if AAllowVersionPunctuation and (Value[I] in ['\', ' ']) then
      Exit(False);
  end;
end;

{**
  Percent-encodes one Package URL segment using its UTF-8 bytes.

  Parameters
  ----------
  AValue
    Segment to encode.

  Returns
  -------
  string
    Purl-safe segment using uppercase hexadecimal escapes.

  Raises
  ------
  EOutOfMemory
    Propagated while extending the result.
*}
function PercentEncodePURLSegment(const AValue: string): string;
const
  Hex = '0123456789ABCDEF';
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
      Result := Result + '%' + Hex[(B shr 4) + 1] + Hex[(B and $0F) + 1];
  end;
end;

function BuildMavenPackageURL(const AGroupID, AArtifactID,
  AVersion: string): string;
var
  GroupValue, ArtifactValue, VersionValue: string;
begin
  Result := '';
  GroupValue := Trim(AGroupID);
  ArtifactValue := Trim(AArtifactID);
  VersionValue := Trim(AVersion);
  if not IsLiteralCoordinate(GroupValue, False) or
    not IsLiteralCoordinate(ArtifactValue, False) or
    not IsLiteralCoordinate(VersionValue, True) or
    not IsExactVersion(VersionValue) then
    Exit;
  Result := 'pkg:maven/' + PercentEncodePURLSegment(GroupValue) + '/' +
    PercentEncodePURLSegment(ArtifactValue) + '@' +
    PercentEncodePURLSegment(VersionValue);
end;

{**
  Initializes a cumulative read-budget wrapper around one verified view.

  Parameters
  ----------
  ASource
    Stream owned by the wrapper after successful construction.
  ALimit
    Maximum cumulative bytes that may be returned by Read.
  ACancelCheck
    Optional callback polled before every read.

  Returns
  -------
  TReadBudgetStream
    New wrapper owned by its caller.

  Raises
  ------
  EArgumentNilException
    Raised when ASource is nil.
*}
constructor TReadBudgetStream.Create(ASource: TStream; ALimit: Int64;
  ACancelCheck: TCancelCheck);
begin
  inherited Create;
  if ASource = nil then
    raise EArgumentNilException.Create('Archive input stream is nil');
  FSource := ASource;
  FLimit := ALimit;
  FCancelCheck := ACancelCheck;
end;

{**
  Releases the owned verified stream view.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
*}
destructor TReadBudgetStream.Destroy;
begin
  FSource.Free;
  inherited Destroy;
end;

{**
  Reads through the wrapped stream within the cumulative byte budget.

  Parameters
  ----------
  Buffer
    Caller-provided destination.
  Count
    Maximum requested byte count.

  Returns
  -------
  LongInt
    Bytes returned by the wrapped stream.

  Raises
  ------
  EArchiveInspectionCancelled
    Raised when cancellation is requested.
  EArchiveInspectionLimit
    Raised before a read could exceed the pass budget.
*}
function TReadBudgetStream.Read(var Buffer; Count: LongInt): LongInt;
begin
  if IsCancelled(FCancelCheck) then
    raise EArchiveInspectionCancelled.Create('Archive inspection cancelled');
  if Count <= 0 then
    Exit(0);
  if (FRead > FLimit) or (Int64(Count) > FLimit - FRead) then
    raise EArchiveInspectionLimit.Create(
      'Archive read exceeds the bounded inspection budget');
  Result := FSource.Read(Buffer, Count);
  if Result > 0 then
    Inc(FRead, Result);
end;

{**
  Rejects writes to the read-only archive wrapper.

  Parameters
  ----------
  Buffer
    Ignored source buffer.
  Count
    Ignored requested byte count.

  Returns
  -------
  LongInt
    This method never returns normally.

  Raises
  ------
  EStreamError
    Always raised.
*}
function TReadBudgetStream.Write(const Buffer; Count: LongInt): LongInt;
begin
  Result := 0;
  raise EStreamError.Create('Archive inspection input is read-only');
end;

{**
  Delegates bounded random access to the verified source stream.

  Parameters
  ----------
  Offset
    Signed stream offset.
  Origin
    Beginning, current position, or end.

  Returns
  -------
  Int64
    New source position.

  Raises
  ------
  EStreamError
    Propagated for an invalid seek.
*}
function TReadBudgetStream.Seek(const Offset: Int64;
  Origin: TSeekOrigin): Int64;
begin
  Result := FSource.Seek(Offset, Origin);
end;

{**
  Creates an in-memory entry sink with a hard decompressed-byte cap.

  Parameters
  ----------
  AEntry
    Metadata entry receiving the completed content.
  ALimit
    Maximum bytes accepted by Write.
  ACancelCheck
    Optional callback polled before every write.

  Returns
  -------
  TBoundedCaptureStream
    New stream owned by the unzip callback.

  Raises
  ------
  EArgumentNilException
    Raised when AEntry is nil.
*}
constructor TBoundedCaptureStream.Create(AEntry: TMetadataEntry;
  ALimit: Int64; ACancelCheck: TCancelCheck);
begin
  inherited Create;
  if AEntry = nil then
    raise EArgumentNilException.Create('Archive metadata entry is nil');
  FEntry := AEntry;
  FLimit := ALimit;
  FCancelCheck := ACancelCheck;
end;

{**
  Appends decompressed bytes only while cancellation and size bounds allow it.

  Parameters
  ----------
  Buffer
    Decompressed bytes supplied by TUnZipper.
  Count
    Number of bytes to append.

  Returns
  -------
  LongInt
    Number of bytes appended.

  Raises
  ------
  EArchiveInspectionCancelled
    Raised when cancellation is requested.
  EArchiveInspectionLimit
    Raised before the actual output could exceed the entry cap.
*}
function TBoundedCaptureStream.Write(const Buffer;
  Count: LongInt): LongInt;
begin
  if IsCancelled(FCancelCheck) then
    raise EArchiveInspectionCancelled.Create('Archive inspection cancelled');
  if Count <= 0 then
    Exit(0);
  if (Position > FLimit) or (Int64(Count) > FLimit - Position) then
    raise EArchiveInspectionLimit.Create(
      'Decompressed archive metadata exceeds its size limit');
  Result := inherited Write(Buffer, Count);
end;

{**
  Computes the ZIP CRC-32 of captured metadata bytes.

  Parameters
  ----------
  AData
    Exact decompressed bytes.

  Returns
  -------
  LongWord
    Standard reflected ZIP CRC-32 value.

  Raises
  ------
  None
*}
function ZIPCRC32(const AData: RawByteString): LongWord;
const
  Polynomial: LongWord = $EDB88320;
var
  CRC: LongWord;
  I, BitIndex: Integer;
begin
  CRC := $FFFFFFFF;
  for I := 1 to Length(AData) do
  begin
    CRC := CRC xor Byte(AData[I]);
    for BitIndex := 0 to 7 do
      if (CRC and 1) <> 0 then
        CRC := (CRC shr 1) xor Polynomial
      else
        CRC := CRC shr 1;
  end;
  Result := not CRC;
end;

{**
  Copies one bounded memory stream into an exact raw byte string.

  Parameters
  ----------
  AStream
    Captured metadata stream.

  Returns
  -------
  RawByteString
    Exact stream bytes without text conversion.

  Raises
  ------
  EArchiveInspectionLimit
    Raised if the stream size cannot be represented safely.
*}
function CaptureBytes(AStream: TMemoryStream): RawByteString;
begin
  Result := '';
  if (AStream.Size < 0) or (AStream.Size > MaximumManifestBytes) then
    raise EArchiveInspectionLimit.Create(
      'Captured archive metadata has an invalid size');
  SetLength(Result, SizeInt(AStream.Size));
  if AStream.Size > 0 then
    Move(AStream.Memory^, Result[1], SizeInt(AStream.Size));
end;

{**
  Opens one new budgeted view for each TUnZipper archive pass.

  Parameters
  ----------
  Sender
    TUnZipper requesting its input.
  AStream
    Receives a wrapper owned and freed by TUnZipper.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory, EStreamError
    Propagated when the verified view or wrapper cannot be created.
*}
procedure TArchiveInspectionSession.OpenInputStream(Sender: TObject;
  var AStream: TStream);
begin
  AStream := TReadBudgetStream.Create(FInput.NewStream,
    MaximumArchivePassReadBytes, FCancelCheck);
end;

{**
  Supplies a non-file, hard-capped output stream for selected metadata.

  Parameters
  ----------
  Sender
    TUnZipper producing the entry.
  AStream
    Receives a non-nil memory stream, preventing disk extraction.
  AItem
    Entry after its local header has been read.

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError
    Raised after installing a safe sink when callback order or local metadata
    differs from the preserved central entry.
*}
procedure TArchiveInspectionSession.CreateOutputStream(Sender: TObject;
  var AStream: TStream; AItem: TFullZipFileEntry);
var
  Entry: TMetadataEntry;
  Limit: Int64;

  {**
    Installs a zero-capacity memory sink before reporting callback failure.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Raises
    ------
    EOutOfMemory
      Propagated if the defensive sink cannot be allocated.
  *}
  procedure InstallFailureSink;
  var
    DummyEntry: TMetadataEntry;
  begin
    { Never leave the stream nil: TUnZipper would otherwise create a file. }
    DummyEntry := TMetadataEntry.Create;
    try
      AStream := TBoundedCaptureStream.Create(DummyEntry, 0, FCancelCheck);
      TBoundedCaptureStream(AStream).FEntry := nil;
    finally
      DummyEntry.Free;
    end;
  end;

begin
  if FNextEntryIndex >= FEntries.Count then
  begin
    InstallFailureSink;
    raise EArchiveInspectionError.Create(
      'Archive produced more selected metadata entries than expected');
  end;
  Entry := TMetadataEntry(FEntries[FNextEntryIndex]);
  Inc(FNextEntryIndex);
  if (AItem.ArchiveFileName <> Entry.ArchiveName) or
    (AItem.CompressedSize <> Entry.CompressedSize) or
    (AItem.CRC32 <> Entry.CRC32) or
    (AItem.CompressMethod <> Entry.UnZipperCompressionMethod) or
    (AItem.BitFlags <> Entry.BitFlags) or
    (((Entry.BitFlags and (1 shl 3)) = 0) and
    (AItem.Size <> Entry.DeclaredSize)) or
    (((Entry.BitFlags and (1 shl 3)) <> 0) and (AItem.Size <> 0) and
    (AItem.Size <> Entry.DeclaredSize)) then
  begin
    InstallFailureSink;
    raise EArchiveInspectionError.Create(
      'Archive local metadata differs from the expected central entry');
  end;
  if Entry.Kind = mkManifest then
    Limit := MaximumManifestBytes
  else
    Limit := MaximumPomPropertiesBytes;
  AStream := TBoundedCaptureStream.Create(Entry, Limit, FCancelCheck);
end;

{**
  Validates, retains, and frees one decompressed metadata stream.

  Parameters
  ----------
  Sender
    TUnZipper completing the entry.
  AStream
    Owned output stream; this callback always frees and nils it.
  AItem
    Completed entry metadata.

  Returns
  -------
  None

  Raises
  ------
  None
    Callback validation failures are deferred in FCallbackError so stream
    ownership remains correct even while another exception is unwinding.
*}
procedure TArchiveInspectionSession.FinishOutputStream(Sender: TObject;
  var AStream: TStream; AItem: TFullZipFileEntry);
var
  Capture: TBoundedCaptureStream;
  Entry: TMetadataEntry;
  Data: RawByteString;
begin
  if not (AStream is TBoundedCaptureStream) then
  begin
    FCallbackError := 'Archive extraction returned an unexpected stream type';
    FreeAndNil(AStream);
    Exit;
  end;
  Capture := TBoundedCaptureStream(AStream);
  Entry := Capture.Entry;
  try
    if Entry = nil then
      Exit;
    if Entry.Extracted then
    begin
      FCallbackError := 'Archive metadata entry was extracted more than once';
      Exit;
    end;
    Data := CaptureBytes(Capture);
    if Length(Data) <> Entry.DeclaredSize then
    begin
      FCallbackError := 'Archive metadata size differs from its central ' +
        'directory declaration';
      Exit;
    end;
    if ZIPCRC32(Data) <> Entry.CRC32 then
    begin
      FCallbackError := 'Archive metadata CRC-32 verification failed';
      Exit;
    end;
    if (FTotalMetadataBytes > MaximumTotalMetadataBytes) or
      (Length(Data) > MaximumTotalMetadataBytes - FTotalMetadataBytes) then
    begin
      FCallbackError := 'Archive metadata exceeds the aggregate size limit';
      Exit;
    end;
    Inc(FTotalMetadataBytes, Length(Data));
    Entry.Content := Data;
    Entry.Extracted := True;
  finally
    FreeAndNil(AStream);
  end;
end;

{**
  Parses an eligible Maven metadata entry path without inferring coordinates.

  Parameters
  ----------
  AName
    Exact central-directory filename.
  AGroupID, AArtifactID
    Receive the two literal path segments.

  Returns
  -------
  Boolean
    True only for ``META-INF/maven/group/artifact/pom.properties`` with no
    additional path segment.

  Raises
  ------
  None
*}
function TryPomPropertiesPath(const AName: string;
  out AGroupID, AArtifactID: string): Boolean;
const
  Prefix = 'META-INF/maven/';
  Suffix = '/pom.properties';
var
  Middle: string;
  SlashAt: Integer;
begin
  Result := False;
  AGroupID := '';
  AArtifactID := '';
  if (Copy(AName, 1, Length(Prefix)) <> Prefix) or
    (Length(AName) <= Length(Prefix) + Length(Suffix)) or
    (Copy(AName, Length(AName) - Length(Suffix) + 1,
      Length(Suffix)) <> Suffix) then
    Exit;
  Middle := Copy(AName, Length(Prefix) + 1,
    Length(AName) - Length(Prefix) - Length(Suffix));
  SlashAt := Pos('/', Middle);
  if (SlashAt <= 1) or (SlashAt >= Length(Middle)) or
    (Pos('/', Copy(Middle, SlashAt + 1, MaxInt)) > 0) then
    Exit;
  AGroupID := Copy(Middle, 1, SlashAt - 1);
  AArtifactID := Copy(Middle, SlashAt + 1, MaxInt);
  Result := IsLiteralCoordinate(AGroupID, False) and
    IsLiteralCoordinate(AArtifactID, False);
end;

{**
  Discovers and validates all bounded metadata entries in the central index.

  Parameters
  ----------
  AExpectedEntryCount
    Entry count validated independently from the EOCD record.
  ACentralOffset, ACentralSize
    Exact bounded central-directory interval from the EOCD record.

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError, EArchiveInspectionLimit,
  EArchiveInspectionCancelled
    Raised for structural disagreement, duplicates, unsupported compression,
    encryption, links, cancellation, or a metadata bound violation.
*}
procedure TArchiveInspectionSession.DiscoverEntries(
  AExpectedEntryCount: Integer; ACentralOffset, ACentralSize: Int64);
const
  CentralHeaderBytes = 46;
  CentralHeaderSignature = $02014B50;
var
  I, ExistingIndex: Integer;
  Item: TFullZipFileEntry;
  Entry: TMetadataEntry;
  NameValue, GroupValue, ArtifactValue: string;
  NameBytes: RawByteString;
  MetadataKind: TMetadataKind;
  IsMetadata: Boolean;
  EntryLimit, TotalDeclared, CentralEnd, RemainingRecord: Int64;
  CentralStream: TStream;
  Header: array[0..CentralHeaderBytes - 1] of Byte;
  BitFlags, CompressionMethod, NameLength, ExtraLength, CommentLength,
    StartDisk: Word;
  CRCValue, CompressedSize, UncompressedSize, LocalHeaderOffset: LongWord;

  {**
    Decodes one little-endian word from the fixed central-header buffer.

    Parameters
    ----------
    AOffset
      Valid offset of a two-byte field.

    Returns
    -------
    Word
      Decoded unsigned value.

    Raises
    ------
    None
  *}
  function HeaderWord(AOffset: Integer): Word;
  begin
    Result := Word(Header[AOffset]) or
      (Word(Header[AOffset + 1]) shl 8);
  end;

  {**
    Decodes one little-endian double word from the central-header buffer.

    Parameters
    ----------
    AOffset
      Valid offset of a four-byte field.

    Returns
    -------
    LongWord
      Decoded unsigned value.

    Raises
    ------
    None
  *}
  function HeaderDWord(AOffset: Integer): LongWord;
  begin
    Result := LongWord(Header[AOffset]) or
      (LongWord(Header[AOffset + 1]) shl 8) or
      (LongWord(Header[AOffset + 2]) shl 16) or
      (LongWord(Header[AOffset + 3]) shl 24);
  end;

begin
  FUnZipper.Examine;
  if FUnZipper.Entries.Count <> AExpectedEntryCount then
    raise EArchiveInspectionError.Create(
      'ZIP entry count differs from the bounded preflight result');
  TotalDeclared := 0;
  CentralEnd := ACentralOffset + ACentralSize;
  FillChar(Header, SizeOf(Header), 0);
  NameBytes := '';
  CentralStream := FInput.NewStream;
  try
    CentralStream.Position := ACentralOffset;
    for I := 0 to FUnZipper.Entries.Count - 1 do
    begin
      if IsCancelled(FCancelCheck) then
        raise EArchiveInspectionCancelled.Create(
          'Archive inspection cancelled');
      if (CentralStream.Position > CentralEnd - CentralHeaderBytes) then
        raise EArchiveInspectionError.Create(
          'ZIP central directory ends inside an entry header');
      CentralStream.ReadBuffer(Header, SizeOf(Header));
      if HeaderDWord(0) <> CentralHeaderSignature then
        raise EArchiveInspectionError.Create(
          'ZIP central directory contains an invalid entry signature');
      BitFlags := HeaderWord(8);
      CompressionMethod := HeaderWord(10);
      CRCValue := HeaderDWord(16);
      CompressedSize := HeaderDWord(20);
      UncompressedSize := HeaderDWord(24);
      NameLength := HeaderWord(28);
      ExtraLength := HeaderWord(30);
      CommentLength := HeaderWord(32);
      StartDisk := HeaderWord(34);
      LocalHeaderOffset := HeaderDWord(42);
      if StartDisk <> 0 then
        raise EArchiveInspectionError.Create(
          'Multi-disk Java archive entries are unsupported');
      if (CompressedSize = $FFFFFFFF) or
        (UncompressedSize = $FFFFFFFF) or
        (LocalHeaderOffset = $FFFFFFFF) then
        raise EArchiveInspectionError.Create(
          'ZIP64 Java archive entries are outside the bounded profile');
      if NameLength > MaximumArchiveNameBytes then
        raise EArchiveInspectionLimit.Create(
          'ZIP entry filename exceeds the bounded name limit');
      RemainingRecord := Int64(NameLength) + Int64(ExtraLength) +
        Int64(CommentLength);
      if (CentralStream.Position > CentralEnd) or
        (RemainingRecord > CentralEnd - CentralStream.Position) then
        raise EArchiveInspectionError.Create(
          'ZIP central directory entry exceeds its declared bounds');
      NameBytes := '';
      SetLength(NameBytes, NameLength);
      if NameLength > 0 then
        CentralStream.ReadBuffer(NameBytes[1], NameLength);
      if (ExtraLength <> 0) or (CommentLength <> 0) then
        CentralStream.Seek(Int64(ExtraLength) + Int64(CommentLength),
          soCurrent);
      NameValue := string(NameBytes);
      Item := FUnZipper.Entries[I];
      IsMetadata := False;
      GroupValue := '';
      ArtifactValue := '';
      if NameValue = 'META-INF/MANIFEST.MF' then
      begin
        MetadataKind := mkManifest;
        IsMetadata := True;
      end
      else if TryPomPropertiesPath(NameValue, GroupValue,
        ArtifactValue) then
      begin
        MetadataKind := mkPomProperties;
        IsMetadata := True;
      end;
      if not IsMetadata then
        Continue;
      if (Item.ArchiveFileName <> NameValue) or
        (Item.BitFlags <> BitFlags) or (Item.Size <> UncompressedSize) or
        (Item.CompressedSize <> CompressedSize) or (Item.CRC32 <> CRCValue) then
        raise EArchiveInspectionError.Create(
          'ZIP parser disagrees with the selected central entry');
      if FEntryIndex.Find(NameValue, ExistingIndex) then
        raise EArchiveInspectionError.Create(
          'Java archive contains a duplicate selected metadata entry');
      if FEntries.Count >= MaximumMetadataEntries then
        raise EArchiveInspectionLimit.Create(
          'Java archive contains too many metadata entries');
      if Item.IsDirectory or Item.IsLink then
        raise EArchiveInspectionError.Create(
          'Selected Java metadata is not a regular archive entry');
      if (BitFlags and 1) <> 0 then
        raise EArchiveInspectionError.Create(
          'Encrypted Java metadata entries are unsupported');
      if (BitFlags and (1 shl 5)) <> 0 then
        raise EArchiveInspectionError.Create(
          'Patched Java metadata entries are unsupported');
      if not (CompressionMethod in [0, 8]) then
        raise EArchiveInspectionError.Create(
          'Java metadata uses an unsupported ZIP compression method');
      if MetadataKind = mkManifest then
        EntryLimit := MaximumManifestBytes
      else
        EntryLimit := MaximumPomPropertiesBytes;
      if UncompressedSize > EntryLimit then
        raise EArchiveInspectionLimit.Create(
          'Java archive metadata entry exceeds its decompressed size limit');
      if CompressedSize > MaximumCompressedMetadataBytes then
        raise EArchiveInspectionLimit.Create(
          'Java archive metadata entry exceeds its compressed size limit');
      if (TotalDeclared > MaximumTotalMetadataBytes) or
        (UncompressedSize > MaximumTotalMetadataBytes - TotalDeclared) then
        raise EArchiveInspectionLimit.Create(
          'Java archive metadata exceeds the aggregate size limit');
      Inc(TotalDeclared, UncompressedSize);
      Entry := TMetadataEntry.Create;
      try
        Entry.ArchiveName := NameValue;
        Entry.Kind := MetadataKind;
        Entry.DeclaredSize := UncompressedSize;
        Entry.CompressedSize := CompressedSize;
        Entry.CRC32 := CRCValue;
        Entry.CompressionMethod := CompressionMethod;
        Entry.UnZipperCompressionMethod := Item.CompressMethod;
        Entry.BitFlags := BitFlags;
        Entry.LocalHeaderOffset := LocalHeaderOffset;
        Entry.PathGroupID := GroupValue;
        Entry.PathArtifactID := ArtifactValue;
        FEntries.Add(Entry);
        FEntryIndex.AddObject(NameValue, Entry);
      except
        if FEntries.IndexOf(Entry) < 0 then
          Entry.Free;
        raise;
      end;
    end;
    if CentralStream.Position <> CentralEnd then
      raise EArchiveInspectionError.Create(
        'ZIP central directory size differs from its entry records');
  finally
    CentralStream.Free;
  end;
end;

{**
  Confirms selected local headers against their preserved central records.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError, EArchiveInspectionLimit,
  EArchiveInspectionCancelled
    Raised for an invalid offset, signature, filename, flags, compression
    method, CRC, size declaration, or cancellation.
*}
procedure TArchiveInspectionSession.ValidateLocalHeaders;
const
  LocalHeaderBytes = 30;
  LocalHeaderSignature = $04034B50;
var
  I: Integer;
  Entry: TMetadataEntry;
  Stream: TStream;
  Header: array[0..LocalHeaderBytes - 1] of Byte;
  NameBytes: RawByteString;
  BitFlags, CompressionMethod, NameLength, ExtraLength: Word;
  CRCValue, CompressedSize, UncompressedSize: LongWord;

  {**
    Decodes one little-endian word from the fixed local-header buffer.

    Parameters
    ----------
    AOffset
      Valid offset of a two-byte field.

    Returns
    -------
    Word
      Decoded unsigned value.

    Raises
    ------
    None
  *}
  function HeaderWord(AOffset: Integer): Word;
  begin
    Result := Word(Header[AOffset]) or
      (Word(Header[AOffset + 1]) shl 8);
  end;

  {**
    Decodes one little-endian double word from the local-header buffer.

    Parameters
    ----------
    AOffset
      Valid offset of a four-byte field.

    Returns
    -------
    LongWord
      Decoded unsigned value.

    Raises
    ------
    None
  *}
  function HeaderDWord(AOffset: Integer): LongWord;
  begin
    Result := LongWord(Header[AOffset]) or
      (LongWord(Header[AOffset + 1]) shl 8) or
      (LongWord(Header[AOffset + 2]) shl 16) or
      (LongWord(Header[AOffset + 3]) shl 24);
  end;

begin
  FillChar(Header, SizeOf(Header), 0);
  NameBytes := '';
  Stream := FInput.NewStream;
  try
    for I := 0 to FEntries.Count - 1 do
    begin
      if IsCancelled(FCancelCheck) then
        raise EArchiveInspectionCancelled.Create(
          'Archive inspection cancelled');
      Entry := TMetadataEntry(FEntries[I]);
      if (FInput.Size < LocalHeaderBytes) or
        (Entry.LocalHeaderOffset > QWord(FInput.Size - LocalHeaderBytes)) then
        raise EArchiveInspectionError.Create(
          'Selected Java metadata has an invalid local-header offset');
      Stream.Position := Int64(Entry.LocalHeaderOffset);
      Stream.ReadBuffer(Header, SizeOf(Header));
      if HeaderDWord(0) <> LocalHeaderSignature then
        raise EArchiveInspectionError.Create(
          'Selected Java metadata has an invalid local-header signature');
      BitFlags := HeaderWord(6);
      CompressionMethod := HeaderWord(8);
      CRCValue := HeaderDWord(14);
      CompressedSize := HeaderDWord(18);
      UncompressedSize := HeaderDWord(22);
      NameLength := HeaderWord(26);
      ExtraLength := HeaderWord(28);
      if NameLength > MaximumArchiveNameBytes then
        raise EArchiveInspectionLimit.Create(
          'ZIP local filename exceeds the bounded name limit');
      if (Stream.Position > FInput.Size) or
        (Int64(NameLength) + Int64(ExtraLength) >
        FInput.Size - Stream.Position) then
        raise EArchiveInspectionError.Create(
          'Selected Java metadata local header exceeds the archive bounds');
      NameBytes := '';
      SetLength(NameBytes, NameLength);
      if NameLength > 0 then
        Stream.ReadBuffer(NameBytes[1], NameLength);
      if string(NameBytes) <> Entry.ArchiveName then
        raise EArchiveInspectionError.Create(
          'Archive local filename differs from its central entry');
      if (BitFlags <> Entry.BitFlags) or
        (CompressionMethod <> Entry.CompressionMethod) then
        raise EArchiveInspectionError.Create(
          'Archive local flags or compression method differ from the central entry');
      if (BitFlags and (1 shl 3)) = 0 then
      begin
        if (CRCValue <> Entry.CRC32) or
          (CompressedSize <> Entry.CompressedSize) or
          (UncompressedSize <> Entry.DeclaredSize) then
          raise EArchiveInspectionError.Create(
            'Archive local size or CRC differs from the central entry');
      end
      else if ((CRCValue <> 0) and (CRCValue <> Entry.CRC32)) or
        ((CompressedSize <> 0) and
        (CompressedSize <> Entry.CompressedSize)) or
        ((UncompressedSize <> 0) and
        (UncompressedSize <> Entry.DeclaredSize)) then
        raise EArchiveInspectionError.Create(
          'Archive local data-descriptor fields conflict with the central entry');
    end;
  finally
    Stream.Free;
  end;
end;

{**
  Decompresses only the selected metadata entries into bounded memory streams.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError, EArchiveInspectionLimit,
  EArchiveInspectionCancelled
    Raised for callback validation, bounds, cancellation, or incomplete
    extraction.
*}
procedure TArchiveInspectionSession.ExtractEntries;
var
  Names: TStringList;
  I: Integer;
  Entry: TMetadataEntry;
begin
  if FEntries.Count = 0 then
    Exit;
  Names := TStringList.Create;
  try
    Names.Sorted := True;
    Names.CaseSensitive := True;
    Names.Duplicates := dupError;
    for I := 0 to FEntries.Count - 1 do
      Names.Add(TMetadataEntry(FEntries[I]).ArchiveName);
    FCallbackError := '';
    FNextEntryIndex := 0;
    FUnZipper.OnCreateStream := @CreateOutputStream;
    FUnZipper.OnDoneStream := @FinishOutputStream;
    if FUnZipper.Files is TStringList then
      TStringList(FUnZipper.Files).CaseSensitive := True;
    FUnZipper.UnZipFiles(Names);
    if FCallbackError <> '' then
      raise EArchiveInspectionError.Create(FCallbackError);
    if FNextEntryIndex <> FEntries.Count then
      raise EArchiveInspectionError.Create(
        'Archive produced fewer selected metadata entries than expected');
    for I := 0 to FEntries.Count - 1 do
    begin
      Entry := TMetadataEntry(FEntries[I]);
      if not Entry.Extracted then
        raise EArchiveInspectionError.Create(
          'A selected Java metadata entry was not extracted');
    end;
  finally
    Names.Free;
  end;
end;

{**
  Creates a bounded archive session over one caller-owned verified input.

  Parameters
  ----------
  AInput
    Verified input that must outlive the session.
  ACancelCheck
    Optional cooperative cancellation callback.

  Returns
  -------
  TArchiveInspectionSession
    New session owned by its caller.

  Raises
  ------
  EArgumentNilException
    Raised when AInput is nil.
*}
constructor TArchiveInspectionSession.Create(AInput: TVerifiedInput;
  ACancelCheck: TCancelCheck);
begin
  inherited Create;
  if AInput = nil then
    raise EArgumentNilException.Create('Verified archive input is nil');
  FInput := AInput;
  FCancelCheck := ACancelCheck;
  FEntries := TObjectList.Create(True);
  FEntryIndex := TStringList.Create;
  FEntryIndex.Sorted := True;
  FEntryIndex.CaseSensitive := True;
  FEntryIndex.Duplicates := dupError;
  FUnZipper := TUnZipper.Create;
  FUnZipper.UseUTF8 := False;
  FUnZipper.OnOpenInputStream := @OpenInputStream;
end;

{**
  Releases the unzipper, selected metadata records, and lookup index.

  Parameters
  ----------
  None

  Returns
  -------
  None

  Raises
  ------
  None
*}
destructor TArchiveInspectionSession.Destroy;
begin
  FUnZipper.Free;
  FEntryIndex.Free;
  FEntries.Free;
  inherited Destroy;
end;

{**
  Examines the central directory and extracts only selected metadata.

  Parameters
  ----------
  AExpectedEntryCount
    EOCD entry count independently checked before TUnZipper is invoked.
  ACentralOffset, ACentralSize
    Bounded central-directory interval retained from preflight.

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError, EArchiveInspectionLimit,
  EArchiveInspectionCancelled
    Raised when discovery or bounded extraction cannot complete safely.
*}
procedure TArchiveInspectionSession.Execute(AExpectedEntryCount: Integer;
  ACentralOffset, ACentralSize: Int64);
begin
  DiscoverEntries(AExpectedEntryCount, ACentralOffset, ACentralSize);
  ValidateLocalHeaders;
  ExtractEntries;
end;

{**
  Reads an unsigned little-endian 16-bit value from a one-based byte string.

  Parameters
  ----------
  AData
    Source bytes.
  AIndex
    One-based first byte index.

  Returns
  -------
  Word
    Decoded value.

  Raises
  ------
  ERangeError
    Raised if the caller supplies an invalid index while range checks are on.
*}
function ReadUInt16LE(const AData: RawByteString; AIndex: Integer): Word;
begin
  Result := Word(Byte(AData[AIndex])) or
    (Word(Byte(AData[AIndex + 1])) shl 8);
end;

{**
  Reads an unsigned little-endian 32-bit value from a one-based byte string.

  Parameters
  ----------
  AData
    Source bytes.
  AIndex
    One-based first byte index.

  Returns
  -------
  LongWord
    Decoded value.

  Raises
  ------
  ERangeError
    Raised if the caller supplies an invalid index while range checks are on.
*}
function ReadUInt32LE(const AData: RawByteString; AIndex: Integer): LongWord;
begin
  Result := LongWord(Byte(AData[AIndex])) or
    (LongWord(Byte(AData[AIndex + 1])) shl 8) or
    (LongWord(Byte(AData[AIndex + 2])) shl 16) or
    (LongWord(Byte(AData[AIndex + 3])) shl 24);
end;

{**
  Validates Java ZIP framing and resource bounds before TUnZipper allocation.

  Parameters
  ----------
  AInput
    Verified, size-bounded archive input.
  AEntryCount
    Receives the validated non-ZIP64 central entry count.
  ACentralOffset, ACentralSize
    Receive the exact central-directory interval.

  Returns
  -------
  None

  Raises
  ------
  EArchiveInspectionError, EArchiveInspectionLimit
    Raised for invalid magic, missing or inconsistent EOCD data, ZIP64,
    multi-disk archives, and declared resource-bound violations.
*}
procedure PreflightJavaArchive(AInput: TVerifiedInput;
  out AEntryCount: Integer; out ACentralOffset, ACentralSize: Int64);
var
  Stream: TStream;
  Header: array[0..3] of Byte;
  Tail: RawByteString;
  TailLength, TailStart, EOCDOffset: Int64;
  I, FoundAt: Integer;
  DiskNumber, StartDisk, EntriesThisDisk, TotalEntries: Word;
  CentralSizeValue, CentralOffsetValue: LongWord;
begin
  AEntryCount := 0;
  ACentralOffset := 0;
  ACentralSize := 0;
  FillChar(Header, SizeOf(Header), 0);
  Tail := '';
  if AInput = nil then
    raise EArgumentNilException.Create('Verified Java archive input is nil');
  if AInput.Size > MaximumJavaArchiveBytes then
    raise EArchiveInspectionLimit.Create(
      'Java archive exceeds the maximum container size');
  if AInput.Size < EndOfCentralDirectoryBytes + Length(ZipLocalHeaderSignature) then
    raise EArchiveInspectionError.Create('Java archive is too small');
  Stream := AInput.NewStream;
  try
    Stream.Position := 0;
    Stream.ReadBuffer(Header, SizeOf(Header));
    if CompareByte(Header, ZipLocalHeaderSignature,
      SizeOf(ZipLocalHeaderSignature)) <> 0 then
      raise EArchiveInspectionError.Create(
        'Java archive does not begin with the ZIP local-header signature');
    TailLength := EndOfCentralDirectoryBytes + MaximumZipCommentBytes;
    if TailLength > AInput.Size then
      TailLength := AInput.Size;
    TailStart := AInput.Size - TailLength;
    SetLength(Tail, SizeInt(TailLength));
    Stream.Position := TailStart;
    Stream.ReadBuffer(Tail[1], Length(Tail));
  finally
    Stream.Free;
  end;
  FoundAt := 0;
  for I := Length(Tail) - EndOfCentralDirectoryBytes + 1 downto 1 do
    if (Byte(Tail[I]) = $50) and (Byte(Tail[I + 1]) = $4B) and
      (Byte(Tail[I + 2]) = $05) and (Byte(Tail[I + 3]) = $06) and
      (TailStart + I - 1 + EndOfCentralDirectoryBytes +
      ReadUInt16LE(Tail, I + 20) = AInput.Size) then
    begin
      FoundAt := I;
      Break;
    end;
  if FoundAt = 0 then
    raise EArchiveInspectionError.Create(
      'Java archive has no valid end-of-central-directory record');
  DiskNumber := ReadUInt16LE(Tail, FoundAt + 4);
  StartDisk := ReadUInt16LE(Tail, FoundAt + 6);
  EntriesThisDisk := ReadUInt16LE(Tail, FoundAt + 8);
  TotalEntries := ReadUInt16LE(Tail, FoundAt + 10);
  CentralSizeValue := ReadUInt32LE(Tail, FoundAt + 12);
  CentralOffsetValue := ReadUInt32LE(Tail, FoundAt + 16);
  EOCDOffset := TailStart + FoundAt - 1;
  if (DiskNumber <> 0) or (StartDisk <> 0) or
    (EntriesThisDisk <> TotalEntries) then
    raise EArchiveInspectionError.Create(
      'Multi-disk Java archives are unsupported');
  if (TotalEntries = $FFFF) or (CentralSizeValue = $FFFFFFFF) or
    (CentralOffsetValue = $FFFFFFFF) then
    raise EArchiveInspectionError.Create(
      'ZIP64 Java archives are outside the bounded inspection profile');
  if TotalEntries = 0 then
    raise EArchiveInspectionError.Create('Java archive contains no entries');
  if TotalEntries > MaximumZipEntries then
    raise EArchiveInspectionLimit.Create(
      'Java archive contains too many ZIP entries');
  if CentralSizeValue > MaximumCentralDirectoryBytes then
    raise EArchiveInspectionLimit.Create(
      'Java archive central directory exceeds its size limit');
  if QWord(CentralOffsetValue) + QWord(CentralSizeValue) <>
    QWord(EOCDOffset) then
    raise EArchiveInspectionError.Create(
      'Java archive central-directory bounds are inconsistent');
  AEntryCount := TotalEntries;
  ACentralOffset := CentralOffsetValue;
  ACentralSize := CentralSizeValue;
end;

{**
  Returns the next physical line from raw metadata without encoding changes.

  Parameters
  ----------
  AData
    Raw metadata bytes.
  APosition
    One-based cursor updated past CR, LF, or CRLF.
  ALine
    Receives bytes before the line terminator.

  Returns
  -------
  Boolean
    True when a physical line was returned.

  Raises
  ------
  None
*}
function NextRawLine(const AData: RawByteString; var APosition: Integer;
  out ALine: RawByteString): Boolean;
var
  StartAt: Integer;
begin
  ALine := '';
  if APosition > Length(AData) then
    Exit(False);
  StartAt := APosition;
  while (APosition <= Length(AData)) and
    not (AData[APosition] in [#10, #13]) do
    Inc(APosition);
  ALine := Copy(AData, StartAt, APosition - StartAt);
  if APosition <= Length(AData) then
  begin
    if (AData[APosition] = #13) and (APosition < Length(AData)) and
      (AData[APosition + 1] = #10) then
      Inc(APosition);
    Inc(APosition);
  end;
  Result := True;
end;

{**
  Reports whether a metadata line contains a forbidden control byte.

  Parameters
  ----------
  AValue
    Line or field value to inspect.

  Returns
  -------
  Boolean
    True for NUL or another control byte except horizontal tab.

  Raises
  ------
  None
*}
function HasForbiddenControl(const AValue: string): Boolean;
var
  I: Integer;
begin
  for I := 1 to Length(AValue) do
    if ((Ord(AValue[I]) < 32) and (AValue[I] <> #9)) or
      (Ord(AValue[I]) = 127) then
      Exit(True);
  Result := False;
end;

{**
  Assigns one properties identity key and detects conflicting duplicates.

  Parameters
  ----------
  ADestination
    Existing value, updated by the first occurrence.
  AValue
    New literal value.
  AConflict
    Set True when a later value differs.

  Returns
  -------
  None

  Raises
  ------
  None
*}
procedure AssignPropertyValue(var ADestination: string; const AValue: string;
  var AConflict: Boolean);
begin
  if ADestination = '' then
    ADestination := AValue
  else if ADestination <> AValue then
    AConflict := True;
end;

{**
  Parses one conservative pom.properties identity record.

  Parameters
  ----------
  AEntry
    Extracted metadata entry and expected path coordinates.
  ACoordinate
    Receives a newly allocated exact coordinate on success, otherwise nil.
  AReason
    Receives a deterministic reason when no coordinate is accepted.

  Returns
  -------
  Boolean
    True only for complete, literal, path-consistent Maven coordinates.

  Raises
  ------
  EOutOfMemory
    Propagated when result allocation fails.
*}
function TryParsePomProperties(AEntry: TMetadataEntry;
  out ACoordinate: TMavenCoordinate; out AReason: string): Boolean;
var
  Data, Line: RawByteString;
  LineValue, KeyValue, ValueValue: string;
  Position, SeparatorAt, I, TrailingSlashes: Integer;
  GroupValue, ArtifactValue, VersionValue, PURL: string;
  Conflict: Boolean;
begin
  Result := False;
  ACoordinate := nil;
  AReason := '';
  GroupValue := '';
  ArtifactValue := '';
  VersionValue := '';
  Data := AEntry.Content;
  Line := '';
  if Copy(Data, 1, 3) = #$EF#$BB#$BF then
    Delete(Data, 1, 3);
  Position := 1;
  Conflict := False;
  while NextRawLine(Data, Position, Line) do
  begin
    if Length(Line) > MaximumMetadataLineBytes then
    begin
      AReason := 'pom.properties contains an overlong line';
      Exit;
    end;
    LineValue := Trim(string(Line));
    if (LineValue = '') or (LineValue[1] in ['#', '!']) then
      Continue;
    TrailingSlashes := 0;
    I := Length(LineValue);
    while (I > 0) and (LineValue[I] = '\') do
    begin
      Inc(TrailingSlashes);
      Dec(I);
    end;
    if (TrailingSlashes mod 2) <> 0 then
    begin
      AReason := 'pom.properties line continuations are not accepted';
      Exit;
    end;
    SeparatorAt := Pos('=', LineValue);
    if SeparatorAt = 0 then
      SeparatorAt := Pos(':', LineValue);
    if SeparatorAt = 0 then
      for I := 1 to Length(LineValue) do
        if LineValue[I] in [' ', #9] then
        begin
          SeparatorAt := I;
          Break;
        end;
    if SeparatorAt <= 1 then
      Continue;
    KeyValue := Trim(Copy(LineValue, 1, SeparatorAt - 1));
    ValueValue := Trim(Copy(LineValue, SeparatorAt + 1, MaxInt));
    if (KeyValue = 'groupId') or (KeyValue = 'artifactId') or
      (KeyValue = 'version') then
    begin
      if (Pos('\', KeyValue) > 0) or (Pos('\', ValueValue) > 0) or
        HasForbiddenControl(ValueValue) then
      begin
        AReason := 'pom.properties identity uses unsupported escaping';
        Exit;
      end;
      if KeyValue = 'groupId' then
        AssignPropertyValue(GroupValue, ValueValue, Conflict)
      else if KeyValue = 'artifactId' then
        AssignPropertyValue(ArtifactValue, ValueValue, Conflict)
      else
        AssignPropertyValue(VersionValue, ValueValue, Conflict);
    end;
  end;
  if Conflict then
  begin
    AReason := 'pom.properties contains conflicting duplicate identity keys';
    Exit;
  end;
  if (GroupValue = '') or (ArtifactValue = '') or (VersionValue = '') then
  begin
    AReason := 'pom.properties does not contain a complete Maven coordinate';
    Exit;
  end;
  if (GroupValue <> AEntry.PathGroupID) or
    (ArtifactValue <> AEntry.PathArtifactID) then
  begin
    AReason := 'pom.properties identity conflicts with its archive path';
    Exit;
  end;
  PURL := BuildMavenPackageURL(GroupValue, ArtifactValue, VersionValue);
  if PURL = '' then
  begin
    AReason := 'pom.properties does not contain a literal exact Maven version';
    Exit;
  end;
  ACoordinate := TMavenCoordinate.Create;
  ACoordinate.GroupID := GroupValue;
  ACoordinate.ArtifactID := ArtifactValue;
  ACoordinate.Version := VersionValue;
  ACoordinate.PackageURL := PURL;
  Result := True;
end;

{**
  Assigns one selected manifest attribute and detects conflicting duplicates.

  Parameters
  ----------
  AIdentity
    Manifest identity record to update.
  AKey, AValue
    Unfolded main-section attribute and value.

  Returns
  -------
  None

  Raises
  ------
  None
*}
procedure ApplyManifestAttribute(var AIdentity: TManifestIdentity;
  const AKey, AValue: string);
var
  KeyValue, Value: string;
  SeparatorAt: Integer;

  {**
    Assigns one captured manifest value or marks a conflicting duplicate.

    Parameters
    ----------
    ADestination
      Identity field to populate from the captured Value variable.

    Returns
    -------
    None

    Raises
    ------
    EOutOfMemory
      Propagated if the value copy cannot be allocated.
  *}
  procedure AssignIdentityValue(var ADestination: string);
  begin
    if ADestination = '' then
      ADestination := Value
    else if ADestination <> Value then
      AIdentity.Invalid := True;
  end;

begin
  KeyValue := LowerCase(Trim(AKey));
  Value := Trim(AValue);
  if Value = '' then
    Exit;
  if KeyValue = 'implementation-title' then
    AssignIdentityValue(AIdentity.ImplementationTitle)
  else if KeyValue = 'implementation-version' then
    AssignIdentityValue(AIdentity.ImplementationVersion)
  else if KeyValue = 'implementation-vendor' then
    AssignIdentityValue(AIdentity.Vendor)
  else if KeyValue = 'bundle-symbolicname' then
  begin
    SeparatorAt := Pos(';', Value);
    if SeparatorAt > 0 then
      Value := Trim(Copy(Value, 1, SeparatorAt - 1));
    AssignIdentityValue(AIdentity.BundleTitle);
  end
  else if KeyValue = 'automatic-module-name' then
    AssignIdentityValue(AIdentity.ModuleName)
  else if KeyValue = 'bundle-version' then
    AssignIdentityValue(AIdentity.BundleVersion)
  else if KeyValue = 'specification-version' then
    AssignIdentityValue(AIdentity.SpecificationVersion);
end;

{**
  Parses the bounded manifest main section for conservative owner metadata.

  Parameters
  ----------
  AData
    Exact decompressed MANIFEST.MF bytes.
  AIdentity
    Receives literal title, exact version, and vendor evidence.
  AReason
    Receives a deterministic nonfatal diagnostic for malformed input.

  Returns
  -------
  Boolean
    True when the main section was structurally usable.

  Raises
  ------
  EOutOfMemory
    Propagated while unfolding bounded attributes.
*}
function ParseManifestIdentity(const AData: RawByteString;
  out AIdentity: TManifestIdentity; out AReason: string): Boolean;
var
  Data, Line: RawByteString;
  Position, ColonAt: Integer;
  CurrentKey, CurrentValue, LineValue: string;

  {**
    Applies and clears the currently unfolded manifest attribute.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Raises
    ------
    EOutOfMemory
      Propagated if identity assignment or string clearing cannot allocate.
  *}
  procedure FlushAttribute;
  begin
    if CurrentKey <> '' then
      ApplyManifestAttribute(AIdentity, CurrentKey, CurrentValue);
    CurrentKey := '';
    CurrentValue := '';
  end;

begin
  AIdentity.Title := '';
  AIdentity.Version := '';
  AIdentity.Vendor := '';
  AIdentity.ImplementationTitle := '';
  AIdentity.ImplementationVersion := '';
  AIdentity.BundleTitle := '';
  AIdentity.BundleVersion := '';
  AIdentity.ModuleName := '';
  AIdentity.SpecificationVersion := '';
  AIdentity.Present := False;
  AIdentity.Invalid := False;
  AReason := '';
  Data := AData;
  Line := '';
  CurrentKey := '';
  CurrentValue := '';
  if Copy(Data, 1, 3) = #$EF#$BB#$BF then
    Delete(Data, 1, 3);
  Position := 1;
  while NextRawLine(Data, Position, Line) do
  begin
    if Length(Line) > MaximumMetadataLineBytes then
    begin
      AReason := 'MANIFEST.MF contains an overlong physical line';
      AIdentity.Invalid := True;
      Break;
    end;
    LineValue := string(Line);
    if LineValue = '' then
    begin
      FlushAttribute;
      Break;
    end;
    if LineValue[1] = ' ' then
    begin
      if CurrentKey = '' then
      begin
        AReason := 'MANIFEST.MF begins a continuation without an attribute';
        AIdentity.Invalid := True;
        Break;
      end;
      if HasForbiddenControl(Copy(LineValue, 2, MaxInt)) then
      begin
        AReason := 'MANIFEST.MF continuation contains forbidden control data';
        AIdentity.Invalid := True;
        Break;
      end;
      CurrentValue := CurrentValue + Copy(LineValue, 2, MaxInt);
      if Length(CurrentValue) > MaximumMetadataLineBytes then
      begin
        AReason := 'MANIFEST.MF contains an overlong unfolded attribute';
        AIdentity.Invalid := True;
        Break;
      end;
      Continue;
    end;
    FlushAttribute;
    ColonAt := Pos(':', LineValue);
    if ColonAt <= 1 then
    begin
      AReason := 'MANIFEST.MF contains a malformed main-section attribute';
      AIdentity.Invalid := True;
      Break;
    end;
    CurrentKey := Trim(Copy(LineValue, 1, ColonAt - 1));
    CurrentValue := Trim(Copy(LineValue, ColonAt + 1, MaxInt));
    if HasForbiddenControl(CurrentKey) or HasForbiddenControl(CurrentValue) then
    begin
      AReason := 'MANIFEST.MF contains forbidden control data';
      AIdentity.Invalid := True;
      Break;
    end;
  end;
  if not AIdentity.Invalid then
    FlushAttribute;
  if AIdentity.Invalid then
  begin
    AIdentity.Title := '';
    AIdentity.Version := '';
    AIdentity.Vendor := '';
    Exit(False);
  end;
  if AIdentity.ImplementationTitle <> '' then
    AIdentity.Title := AIdentity.ImplementationTitle
  else if AIdentity.BundleTitle <> '' then
    AIdentity.Title := AIdentity.BundleTitle
  else
    AIdentity.Title := AIdentity.ModuleName;
  if AIdentity.ImplementationVersion <> '' then
    AIdentity.Version := AIdentity.ImplementationVersion
  else if AIdentity.BundleVersion <> '' then
    AIdentity.Version := AIdentity.BundleVersion
  else
    AIdentity.Version := AIdentity.SpecificationVersion;
  if not IsLiteralCoordinate(AIdentity.Title, True) then
    AIdentity.Title := '';
  if not IsLiteralCoordinate(AIdentity.Version, True) or
    not IsExactVersion(AIdentity.Version) then
    AIdentity.Version := '';
  if (Length(AIdentity.Vendor) > MaximumCoordinateBytes) or
    HasForbiddenControl(AIdentity.Vendor) or
    (Pos('${', AIdentity.Vendor) > 0) then
    AIdentity.Vendor := '';
  AIdentity.Present := (AIdentity.Title <> '') or
    (AIdentity.Version <> '') or (AIdentity.Vendor <> '');
  Result := True;
end;

{**
  Returns the portable basename of one slash-normalized evidence path.

  Parameters
  ----------
  ARelativePath
    Root-relative path using either slash convention.

  Returns
  -------
  string
    Final path component.

  Raises
  ------
  None
*}
function RelativeBaseName(const ARelativePath: string): string;
var
  Normalized: string;
  SeparatorAt: Integer;
begin
  Normalized := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
  SeparatorAt := LastDelimiter('/', Normalized);
  if SeparatorAt > 0 then
    Result := Copy(Normalized, SeparatorAt + 1, MaxInt)
  else
    Result := Normalized;
end;

{**
  Maps a Java archive kind to a stable artifact label.

  Parameters
  ----------
  AKind
    JAR, WAR, or EAR selector.

  Returns
  -------
  string
    Human-readable artifact type.

  Raises
  ------
  None
*}
function JavaArtifactType(AKind: TJavaArchiveKind): string;
begin
  Result := 'Java archive';
  case AKind of
    jakJAR: Result := 'Java JAR archive';
    jakWAR: Result := 'Java WAR archive';
    jakEAR: Result := 'Java EAR archive';
  end;
end;

{**
  Maps a Java archive kind to its CycloneDX component type.

  Parameters
  ----------
  AKind
    JAR, WAR, or EAR selector.

  Returns
  -------
  string
    ``library`` for JAR and ``application`` for WAR or EAR.

  Raises
  ------
  None
*}
function JavaComponentType(AKind: TJavaArchiveKind): string;
begin
  if AKind = jakJAR then
    Result := 'library'
  else
    Result := 'application';
end;

{**
  Creates and appends one archive-derived component.

  Parameters
  ----------
  AComponents
    Owned destination list.
  AName, AVersion, AEcosystem, APURL
    Normalized component identity.
  ARelativePath, AParser, ASHA256
    Outer archive evidence and parser provenance.
  AComponentType
    CycloneDX component type.
  AVendor
    Optional explicit manifest publisher.

  Returns
  -------
  TComponent
    Added component owned by AComponents.

  Raises
  ------
  EOutOfMemory
    Propagated if allocation fails.
*}
function AddArchiveComponent(AComponents: TObjectList; const AName,
  AVersion, AEcosystem, APURL, ARelativePath, AParser, ASHA256,
  AComponentType, AVendor: string): TComponent;
begin
  Result := TComponent.Create;
  try
    Result.Name := AName;
    Result.Version := AVersion;
    Result.Ecosystem := AEcosystem;
    Result.PackageURL := APURL;
    Result.SourceArtifact := ARelativePath;
    Result.SourceParser := AParser;
    Result.DependencyScope := 'resolved';
    Result.SHA256 := ASHA256;
    Result.ComponentType := AComponentType;
    Result.EvidencePaths.Add(ARelativePath);
    if Trim(AVendor) <> '' then
      Result.DeclaredPublishers.Add(Trim(AVendor));
    AComponents.Add(Result);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Converts extracted Java metadata into deterministic component records.

  Parameters
  ----------
  ASession
    Completed bounded extraction session.
  AKind
    Outer archive kind.
  ARelativePath, AFileSHA256
    Outer archive evidence.
  AComponents
    Owned component list receiving results.
  ADiagnostics
    Sorted bounded set receiving nonfatal metadata diagnostics.

  Returns
  -------
  Integer
    Number of exact distinct Maven coordinates retained.

  Raises
  ------
  EOutOfMemory
    Propagated during parsing or component construction.
*}
function BuildJavaComponents(ASession: TArchiveInspectionSession;
  AKind: TJavaArchiveKind; const ARelativePath, AFileSHA256: string;
  AComponents: TObjectList; ADiagnostics: TStringList): Integer;
var
  CoordinateIndex: TStringList;
  CoordinateObjects: TObjectList;
  Entry: TMetadataEntry;
  Coordinate: TMavenCoordinate;
  ManifestIdentity: TManifestIdentity;
  ManifestSeen: Boolean;
  Reason, OuterName, OuterParser: string;
  I, Index: Integer;
begin
  CoordinateIndex := TStringList.Create;
  CoordinateObjects := TObjectList.Create(True);
  try
    CoordinateIndex.Sorted := True;
    CoordinateIndex.CaseSensitive := True;
    CoordinateIndex.Duplicates := dupError;
    ManifestIdentity.Title := '';
    ManifestIdentity.Version := '';
    ManifestIdentity.Vendor := '';
    ManifestIdentity.ImplementationTitle := '';
    ManifestIdentity.ImplementationVersion := '';
    ManifestIdentity.BundleTitle := '';
    ManifestIdentity.BundleVersion := '';
    ManifestIdentity.ModuleName := '';
    ManifestIdentity.SpecificationVersion := '';
    ManifestIdentity.Present := False;
    ManifestIdentity.Invalid := False;
    ManifestSeen := False;
    for I := 0 to ASession.Entries.Count - 1 do
    begin
      Entry := TMetadataEntry(ASession.Entries[I]);
      if Entry.Kind = mkManifest then
      begin
        ManifestSeen := True;
        if not ParseManifestIdentity(Entry.Content, ManifestIdentity,
          Reason) then
          AddDiagnostic(ADiagnostics, Reason);
        Continue;
      end;
      Coordinate := nil;
      if not TryParsePomProperties(Entry, Coordinate, Reason) then
      begin
        AddDiagnostic(ADiagnostics, Reason);
        Continue;
      end;
      if CoordinateIndex.Find(Coordinate.PackageURL, Index) then
        Coordinate.Free
      else
      begin
        CoordinateObjects.Add(Coordinate);
        CoordinateIndex.AddObject(Coordinate.PackageURL, Coordinate);
      end;
    end;
    Result := CoordinateIndex.Count;
    if CoordinateIndex.Count = 1 then
    begin
      Coordinate := TMavenCoordinate(CoordinateIndex.Objects[0]);
      AddArchiveComponent(AComponents, Coordinate.ArtifactID,
        Coordinate.Version, 'Maven', Coordinate.PackageURL, ARelativePath,
        'java-pom-properties', AFileSHA256, JavaComponentType(AKind),
        ManifestIdentity.Vendor);
      if ManifestIdentity.Present and
        (((ManifestIdentity.Title <> '') and
        (ManifestIdentity.Title <> Coordinate.ArtifactID)) or
        ((ManifestIdentity.Version <> '') and
        (ManifestIdentity.Version <> Coordinate.Version))) then
        AddDiagnostic(ADiagnostics,
          'Manifest identity differs from the exact Maven coordinate; ' +
          'pom.properties was retained');
    end
    else
    begin
      OuterName := ManifestIdentity.Title;
      if OuterName = '' then
        OuterName := RelativeBaseName(ARelativePath);
      if ManifestSeen and ManifestIdentity.Present then
        OuterParser := 'java-manifest'
      else
        OuterParser := 'java-archive-header';
      AddArchiveComponent(AComponents, OuterName, ManifestIdentity.Version,
        'Java', '', ARelativePath, OuterParser, AFileSHA256,
        JavaComponentType(AKind), ManifestIdentity.Vendor);
      for I := 0 to CoordinateIndex.Count - 1 do
      begin
        Coordinate := TMavenCoordinate(CoordinateIndex.Objects[I]);
        AddArchiveComponent(AComponents, Coordinate.ArtifactID,
          Coordinate.Version, 'Maven', Coordinate.PackageURL, ARelativePath,
          'java-pom-properties', '', 'library', '');
      end;
      if CoordinateIndex.Count > 1 then
        AddDiagnostic(ADiagnostics,
          'Multiple exact Maven coordinates were retained; archive ownership ' +
          'was not inferred');
    end;
  finally
    CoordinateIndex.Free;
    CoordinateObjects.Free;
  end;
end;

function InspectJavaArchive(AInput: TVerifiedInput; AKind: TJavaArchiveKind;
  const ARelativePath, AFileSHA256: string; AArtifact: TArtifact;
  AComponents: TObjectList; ACancelCheck: TCancelCheck):
  TArchiveInspectionResult;
var
  InitialCount, EntryCount, CoordinateCount: Integer;
  CentralOffset, CentralSize: Int64;
  Session: TArchiveInspectionSession;
  Diagnostics: TStringList;
  Detail: string;
begin
  Result := airCompleted;
  if (AArtifact = nil) or (AComponents = nil) then
    Exit;
  InitialCount := AComponents.Count;
  AArtifact.ArtifactType := JavaArtifactType(AKind);
  AArtifact.Ecosystem := 'Maven';
  AArtifact.ParserName := 'java-archive-metadata';
  AArtifact.Status := arsUnsupported;
  AArtifact.ComponentCount := 0;
  AArtifact.MessageText := '';
  Session := nil;
  Diagnostics := nil;
  try
    if IsCancelled(ACancelCheck) then
      raise EArchiveInspectionCancelled.Create('Archive inspection cancelled');
    PreflightJavaArchive(AInput, EntryCount, CentralOffset, CentralSize);
    Session := TArchiveInspectionSession.Create(AInput, ACancelCheck);
    Session.Execute(EntryCount, CentralOffset, CentralSize);
    Diagnostics := TStringList.Create;
    Diagnostics.Sorted := True;
    Diagnostics.CaseSensitive := True;
    Diagnostics.Duplicates := dupIgnore;
    CoordinateCount := BuildJavaComponents(Session, AKind, ARelativePath,
      AFileSHA256, AComponents, Diagnostics);
    AArtifact.ComponentCount := AComponents.Count - InitialCount;
    if Diagnostics.Count > 0 then
      AArtifact.Status := arsPartiallyParsed
    else
      AArtifact.Status := arsParsed;
    AArtifact.MessageText := 'Inspected bounded Java archive metadata; ' +
      IntToStr(CoordinateCount) + ' exact Maven coordinate';
    if CoordinateCount <> 1 then
      AArtifact.MessageText := AArtifact.MessageText + 's';
    AArtifact.MessageText := AArtifact.MessageText +
      '; nested archives were not inspected.';
    Detail := JoinedDiagnostics(Diagnostics);
    if Detail <> '' then
      AArtifact.MessageText := AArtifact.MessageText + ' ' + Detail + '.';
  except
    on E: EArchiveInspectionCancelled do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.ComponentCount := 0;
      AArtifact.Status := arsFailed;
      AArtifact.MessageText := 'Java archive inspection was cancelled.';
      Result := airCancelled;
    end;
    on E: EArchiveInspectionLimit do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.ComponentCount := 0;
      AArtifact.Status := arsFailed;
      AArtifact.MessageText := SafeDiagnostic(E.Message) + '.';
    end;
    on E: EArchiveInspectionError do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.ComponentCount := 0;
      AArtifact.Status := arsFailed;
      AArtifact.MessageText := SafeDiagnostic(E.Message) + '.';
    end;
    on E: EZipError do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.ComponentCount := 0;
      AArtifact.Status := arsFailed;
      AArtifact.MessageText :=
        'Java archive has a malformed or unsupported ZIP structure.';
    end;
    on E: Exception do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.ComponentCount := 0;
      AArtifact.Status := arsFailed;
      AArtifact.MessageText := 'Java archive inspection failed: ' +
        SafeDiagnostic(E.Message) + '.';
    end;
  end;
  Diagnostics.Free;
  Session.Free;
end;

function InspectStaticLibrary(AInput: TVerifiedInput;
  const ARelativePath, AFileSHA256: string; AArtifact: TArtifact;
  AComponents: TObjectList; ACancelCheck: TCancelCheck):
  TArchiveInspectionResult;
var
  InitialCount: Integer;
  Stream: TStream;
  Signature: array[0..7] of Byte;
begin
  Result := airCompleted;
  if (AArtifact = nil) or (AComponents = nil) then
    Exit;
  InitialCount := AComponents.Count;
  AArtifact.ArtifactType := 'ar static library';
  AArtifact.Ecosystem := 'native';
  AArtifact.ParserName := 'ar-header';
  AArtifact.Status := arsUnsupported;
  AArtifact.ComponentCount := 0;
  AArtifact.MessageText := '';
  Stream := nil;
  FillChar(Signature, SizeOf(Signature), 0);
  try
    if IsCancelled(ACancelCheck) then
      raise EArchiveInspectionCancelled.Create('Archive inspection cancelled');
    if AInput = nil then
      raise EArgumentNilException.Create('Verified static-library input is nil');
    if AInput.Size < SizeOf(Signature) then
      raise EArchiveInspectionError.Create(
        'Static-library candidate is too small for an ar signature');
    Stream := AInput.NewStream;
    Stream.ReadBuffer(Signature, SizeOf(Signature));
    FreeAndNil(Stream);
    if CompareByte(Signature, ArGlobalSignature,
      SizeOf(ArGlobalSignature)) <> 0 then
      raise EArchiveInspectionError.Create(
        'Static-library candidate does not carry the ar global signature');
    if IsCancelled(ACancelCheck) then
      raise EArchiveInspectionCancelled.Create('Archive inspection cancelled');
    AddArchiveComponent(AComponents, RelativeBaseName(ARelativePath), '',
      'native', '', ARelativePath, 'ar-header', AFileSHA256, 'library', '');
    AArtifact.Status := arsParsed;
    AArtifact.ComponentCount := 1;
    AArtifact.MessageText := 'Identified the ar static-library signature; ' +
      'archive members were not inspected.';
  except
    on E: EArchiveInspectionCancelled do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.Status := arsFailed;
      AArtifact.ComponentCount := 0;
      AArtifact.MessageText := 'Static-library inspection was cancelled.';
      Result := airCancelled;
    end;
    on E: Exception do
    begin
      RollBackComponents(AComponents, InitialCount);
      AArtifact.Status := arsFailed;
      AArtifact.ComponentCount := 0;
      AArtifact.MessageText := SafeDiagnostic(E.Message) + '.';
    end;
  end;
  Stream.Free;
end;

end.
