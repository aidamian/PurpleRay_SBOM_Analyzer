(**
  PurpleRay SBOM Analyzer verified rescan-cache unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Stores one bounded, profile-local snapshot of per-file analysis evidence.
  Cache hits require an exact scan context, relative path, native identity,
  and a freshly computed SHA-256 digest. Persistence is explicit and atomic;
  destroying or abandoning a cache session never writes staged evidence.

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
unit uScanCache;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Contnrs, uModels, uVerifiedInput, uPlatform;

const
  ScanCacheFormatVersion = 1;
  DefaultScanCacheFileName = 'scan-cache.json';
  MaximumScanCacheBytes = 16 * 1024 * 1024;
  MaximumScanCacheEntries = 4096;
  MaximumScanCacheComponentsPerEntry = 512;
  MaximumScanCacheComponents = 32768;
  MaximumScanCacheStringBytes = 4096;
  MaximumScanCacheListValues = 256;
  MaximumScanCacheJSONNodes = 262144;
  VerifiedFileIdentityHexLength = 9 * 16;

type
  (** Selects whether a scan ignores, consumes, or refreshes cache data. *)
  TScanCacheMode = (scmDisabled, scmUse, scmRefresh);

  (**
    Names the complete non-file context under which evidence was produced.

    ProfilePathSHA256, RootPathSHA256, and SettingsSHA256 are lowercase
    SHA-256 values supplied by the coordinator. RootIdentityToken is a bounded
    native directory identity chosen by the coordinator; no raw absolute path
    is retained.
  *)
  TScanCacheContext = record
    AnalysisContract: string;
    Platform: string;
    ProfilePathSHA256: string;
    RootPathSHA256: string;
    RootIdentityToken: string;
    SettingsSHA256: string;
  end;

  (**
    Caller-owned, path-independent cached evidence.

    Artifact and Components are borrowed for the lifetime of this instance.
    The artifact deliberately has an empty AbsolutePath. Clone creates another
    independently owned result suitable for a separate publication path.
  *)
  TScanCacheEvidence = class
  private
    FArtifact: TArtifact;
    FComponents: TObjectList;
    FInspectionTools: TStringList;
    FWarnings: TStringList;
  public
    (**
      Clones one path-independent evidence bundle into cache-owned storage.

      Parameters
      ----------
      AArtifact
        Optional borrowed artifact; its clone has no AbsolutePath.
      AComponents
        Required borrowed list of TComponent instances to clone.
      AInspectionTools
        Optional borrowed inspection-tool strings to copy.
      AWarnings
        Optional borrowed warning strings to copy.

      Returns
      -------
      TScanCacheEvidence
        Caller-owned independent evidence bundle.

      Raises
      ------
      EArgumentNilException
        Raised when AComponents is nil.
      EArgumentException
        Raised when AComponents contains a non-component object.
      EOutOfMemory
        Propagated if evidence cannot be cloned.
    *)
    constructor Create(AArtifact: TArtifact; AComponents: TObjectList;
      AInspectionTools: TStrings = nil; AWarnings: TStrings = nil);

    (**
      Frees all artifact, component, tool, and warning evidence still owned.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *)
    destructor Destroy; override;

    (**
      Creates an independent deep copy of this evidence bundle.

      Parameters
      ----------
      None

      Returns
      -------
      TScanCacheEvidence
        Caller-owned cloned evidence.

      Raises
      ------
      EOutOfMemory
        Propagated if cloning fails.
    *)
    function Clone: TScanCacheEvidence;

    (**
      Transfers the artifact out of this evidence bundle.

      Parameters
      ----------
      None

      Returns
      -------
      TArtifact
        Caller-owned artifact, or nil when absent or already released.

      Raises
      ------
      None
    *)
    function ReleaseArtifact: TArtifact;

    (**
      Transfers all components into a caller-owned object list.

      Parameters
      ----------
      ADestination
        Required destination that assumes ownership of each component.

      Returns
      -------
      None

      Raises
      ------
      EArgumentNilException
        Raised when ADestination is nil.
      EOutOfMemory
        Propagated if the destination cannot grow; the failed component is freed.
    *)
    procedure MoveComponentsTo(ADestination: TObjectList);
    property Artifact: TArtifact read FArtifact;
    property Components: TObjectList read FComponents;
    property InspectionTools: TStringList read FInspectionTools;
    property Warnings: TStringList read FWarnings;
  end;

  (**
    Owns one cache read/staging session for one scan context.

    Load never raises for an absent, unsafe, oversized, or malformed cache;
    such input is ignored and described through ADiagnostic. Stage clones all
    evidence. Commit is the only method that writes and must be called by the
    coordinator only after the complete SBOM has succeeded.
  *)
  TScanCache = class
  private
    FMode: TScanCacheMode;
    FProfileDirectory: string;
    FCacheFileName: string;
    FContext: TScanCacheContext;
    FProfilePin: TPinnedDirectory;
    FLoadedEntries: TObjectList;
    FLoadedLock: TRTLCriticalSection;
    FLoadedLockInitialized: Boolean;
    FStagedEntries: TObjectList;
    FStagingValid: Boolean;
    FStagedComponentCount: Integer;
    (**
      Pins the profile directory and verifies its context binding.

      Parameters
      ----------
      ACreateDirectory
        Creates a missing profile directory when True.
      ADiagnostic
        Receives a bounded reason when pinning fails.

      Returns
      -------
      Boolean
        True when a stable matching profile pin is available.

      Raises
      ------
      EOutOfMemory
        May propagate while path or diagnostic strings are prepared. Filesystem
        and pinning errors are otherwise converted into ADiagnostic.
    *)
    function EnsureProfilePin(ACreateDirectory: Boolean;
      out ADiagnostic: string): Boolean;

    (**
      Finds one exact relative path in an entry list.

      Parameters
      ----------
      AEntries
        Borrowed list of TScanCacheEntry objects, or nil.
      ARelativePath
        Exact case-sensitive path key.

      Returns
      -------
      TObject
        Borrowed matching entry, or nil.

      Raises
      ------
      None
    *)
    function FindEntry(AEntries: TObjectList; const ARelativePath: string):
      TObject;

    (**
      Serializes and bounds the complete staged snapshot.

      Parameters
      ----------
      AContent
        Receives strict UTF-8 JSON bytes on success.
      ADiagnostic
        Receives a bounded reason when serialization or validation fails.

      Returns
      -------
      Boolean
        True only for a valid snapshot within all cache bounds.

      Raises
      ------
      EOutOfMemory
        May propagate if the root JSON object cannot be created. Later
        serialization errors are converted into ADiagnostic.
    *)
    function BuildDocument(out AContent: UTF8String;
      out ADiagnostic: string): Boolean;
  public
    (**
      Creates one cache session bound to an explicit profile and scan context.

      Parameters
      ----------
      AMode
        Disabled, consuming, or refresh behavior for this session.
      AProfileDirectory
        Profile-local directory; required unless AMode is disabled.
      AContext
        Complete validated context that must match the profile path hash.
      ACacheFileName
        Safe single-leaf snapshot filename.

      Returns
      -------
      TScanCache
        Caller-owned cache session with empty loaded and staged state.

      Raises
      ------
      EArgumentException
        Raised for an invalid context, profile binding, or cache filename.
      EOutOfMemory
        Propagated if cache state cannot be allocated.
    *)
    constructor Create(AMode: TScanCacheMode;
      const AProfileDirectory: string; const AContext: TScanCacheContext;
      const ACacheFileName: string = DefaultScanCacheFileName);

    (**
      Frees loaded and staged evidence without writing a snapshot.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *)
    destructor Destroy; override;

    (**
      Loads one valid matching snapshot for exact subsequent lookups.

      Refresh and disabled modes bypass loading. Missing or context-mismatched
      snapshots are ordinary misses; malformed, unstable, or unsafe snapshots
      are ignored with a diagnostic.

      Parameters
      ----------
      ADiagnostic
        Receives a privacy-safe reason for rejected cache data.

      Returns
      -------
      Boolean
        True only when a matching valid snapshot was loaded.

      Raises
      ------
      EOutOfMemory
        May propagate while initial path or entry-list state is allocated. Cache
        read and parse failures are otherwise converted into ADiagnostic.
    *)
    function Load(out ADiagnostic: string): Boolean;

    (**
      Looks up an entry by exact path, native identity, and fresh digest.

      Parameters
      ----------
      ARelativePath
        Safe root-relative path key.
      AIdentity
        Fresh verified native file identity.
      AContentSHA256
        Fresh lowercase content digest from the same verified handle.
      AEvidence
        Receives a caller-owned deep clone on a hit, otherwise nil.

      Returns
      -------
      Boolean
        True only when every key field matches an entry in use mode.

      Raises
      ------
      EOutOfMemory
        Propagated if hit evidence cannot be cloned.
    *)
    function TryLookup(const ARelativePath: string;
      const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
      out AEvidence: TScanCacheEvidence): Boolean;

    (**
      Clones one per-file result into the pending snapshot.

      Parameters
      ----------
      ARelativePath
        Safe root-relative key shared by all supplied evidence.
      AIdentity
        Verified native identity for the analyzed bytes.
      AContentSHA256
        Fresh lowercase digest used as the private cache key.
      AArtifact
        Optional borrowed artifact; nil represents a negative entry.
      AComponents
        Required borrowed component list.
      ADiagnostic
        Receives a bounded reason when staging is rejected.

      Returns
      -------
      Boolean
        True when disabled or when a valid independent entry is staged.

      Raises
      ------
      EOutOfMemory
        May propagate while key or diagnostic strings are prepared. Evidence
        cloning failures invalidate staging and are converted into ADiagnostic.
    *)
    function Stage(const ARelativePath: string;
      const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
      AArtifact: TArtifact; AComponents: TObjectList;
      out ADiagnostic: string): Boolean; overload;

    (**
      Clones one per-file result plus tools and warnings into pending storage.

      Parameters
      ----------
      ARelativePath
        Safe root-relative key shared by all supplied evidence.
      AIdentity
        Verified native identity for the analyzed bytes.
      AContentSHA256
        Fresh lowercase digest used as the private cache key.
      AArtifact
        Optional borrowed artifact; nil represents a negative entry.
      AComponents
        Required borrowed component list.
      AInspectionTools
        Optional borrowed deterministic tool-name list.
      AWarnings
        Optional borrowed deterministic warning list.
      ADiagnostic
        Receives a bounded reason when staging is rejected.

      Returns
      -------
      Boolean
        True when disabled or when a valid independent entry is staged.

      Raises
      ------
      EOutOfMemory
        May propagate while key or diagnostic strings are prepared. Evidence
        cloning failures invalidate staging and are converted into ADiagnostic.
    *)
    function Stage(const ARelativePath: string;
      const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
      AArtifact: TArtifact; AComponents: TObjectList;
      AInspectionTools, AWarnings: TStrings;
      out ADiagnostic: string): Boolean; overload;

    (**
      Drops pending evidence without touching the last successful snapshot.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *)
    procedure ResetStaging;

    (**
      Atomically activates the complete pending snapshot.

      Parameters
      ----------
      ADiagnostic
        Receives a bounded reason when validation or activation fails.

      Returns
      -------
      Boolean
        True when disabled or durably committed; False without replacing the
        prior snapshot.

      Raises
      ------
      EOutOfMemory
        May propagate if initial document or diagnostic storage cannot be
        allocated. Filesystem activation failures are otherwise contained.
    *)
    function Commit(out ADiagnostic: string): Boolean;

    property Mode: TScanCacheMode read FMode;
    property ProfileDirectory: string read FProfileDirectory;
    property CacheFileName: string read FCacheFileName;
    property StagingValid: Boolean read FStagingValid;
  end;

(**
  Encodes every TVerifiedFileIdentity field as nine fixed-width hex words.

  An empty string is returned for an invalid identity or negative size. The
  first word is the Valid flag, followed by storage ID, file ID, size,
  modification seconds/nanoseconds, change seconds/nanoseconds, and link count.

  Parameters
  ----------
  AIdentity
    Native identity captured from a verified regular file.

  Returns
  -------
  string
    Fixed-width lowercase encoding, or an empty string for invalid input.

  Raises
  ------
  EOutOfMemory
    Propagated if the encoded result cannot be allocated.
*)
function EncodeVerifiedFileIdentity(
  const AIdentity: TVerifiedFileIdentity): string;

(**
  Initializes an explicit cache context without retaining caller storage.

  Parameters
  ----------
  AContext
    Receives independent copies of all supplied fields.
  AAnalysisContract
    Evidence-semantics contract token.
  APlatform
    Stable operating-system and CPU token.
  AProfilePathSHA256
    Lowercase digest binding the selected profile path.
  ARootPathSHA256
    Lowercase digest binding the canonical scan root path.
  ARootIdentityToken
    Native directory identity without a raw path.
  ASettingsSHA256
    Digest of evidence-affecting scan settings.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if field copies cannot be allocated.
*)
procedure InitializeScanCacheContext(out AContext: TScanCacheContext;
  const AAnalysisContract, APlatform, AProfilePathSHA256, ARootPathSHA256,
  ARootIdentityToken, ASettingsSHA256: string);

(**
  Hashes the canonical profile path without persisting its raw spelling.

  Parameters
  ----------
  AProfileDirectory
    Profile directory to expand and canonicalize.

  Returns
  -------
  string
    Lowercase SHA-256 binding, or an empty string for blank input.

  Raises
  ------
  EOutOfMemory
    Propagated if canonicalization or hash input allocation fails.
*)
function ScanCacheProfilePathSHA256(const AProfileDirectory: string): string;

implementation

uses
  fpjson, jsonparser, jsonscanner, uSHA256;

const
  ScanCacheFormatName = 'purpleray-scan-cache';
  MaximumJSONDepth = 16;
  MaximumAnalysisContractBytes = 128;
  MaximumPlatformBytes = 64;
  MaximumRootIdentityTokenBytes = 256;

type
  TScanCacheEntry = class
  private
    FRelativePath: string;
    FIdentityHex: string;
    FContentSHA256: string;
    FEvidence: TScanCacheEvidence;
  public
    (**
      Creates one cache entry and takes ownership of its evidence.

      Parameters
      ----------
      ARelativePath
        Exact root-relative lookup key.
      AIdentityHex
        Encoded verified native identity.
      AContentSHA256
        Fresh lowercase content digest.
      AEvidence
        Evidence transferred to the entry.

      Returns
      -------
      TScanCacheEntry
        Caller-owned cache entry.

      Raises
      ------
      EArgumentNilException
        Raised when AEvidence is nil.
      EOutOfMemory
        Propagated if entry fields cannot be allocated.
    *)
    constructor Create(const ARelativePath, AIdentityHex,
      AContentSHA256: string; AEvidence: TScanCacheEvidence);

    (**
      Frees the evidence still owned by this cache entry.

      Parameters
      ----------
      None

      Returns
      -------
      None

      Raises
      ------
      None
    *)
    destructor Destroy; override;

    (**
      Creates an independent deep copy of this cache entry.

      Parameters
      ----------
      None

      Returns
      -------
      TScanCacheEntry
        Caller-owned cloned entry.

      Raises
      ------
      EOutOfMemory
        Propagated if entry or evidence cloning fails.
    *)
    function Clone: TScanCacheEntry;
  end;

{**
  Formats one unsigned word as exactly 16 lowercase hexadecimal digits.

  Parameters
  ----------
  AValue
    Word to encode.

  Returns
  -------
  string
    Fixed-width lowercase hexadecimal text.

  Raises
  ------
  EOutOfMemory
    Propagated if the result cannot be allocated.
*}
function LowerHexWord(AValue: QWord): string;
begin
  Result := LowerCase(IntToHex(AValue, 16));
end;

function EncodeVerifiedFileIdentity(
  const AIdentity: TVerifiedFileIdentity): string;
begin
  Result := '';
  if (not AIdentity.Valid) or (AIdentity.Size < 0) then
    Exit;
  Result := LowerHexWord(1) + LowerHexWord(AIdentity.StorageID) +
    LowerHexWord(AIdentity.FileID) + LowerHexWord(QWord(AIdentity.Size)) +
    LowerHexWord(AIdentity.ModifiedSeconds) +
    LowerHexWord(AIdentity.ModifiedNanoseconds) +
    LowerHexWord(AIdentity.ChangedSeconds) +
    LowerHexWord(AIdentity.ChangedNanoseconds) +
    LowerHexWord(AIdentity.LinkCount);
end;

procedure InitializeScanCacheContext(out AContext: TScanCacheContext;
  const AAnalysisContract, APlatform, AProfilePathSHA256, ARootPathSHA256,
  ARootIdentityToken, ASettingsSHA256: string);
begin
  AContext.AnalysisContract := AAnalysisContract;
  AContext.Platform := APlatform;
  AContext.ProfilePathSHA256 := AProfilePathSHA256;
  AContext.RootPathSHA256 := ARootPathSHA256;
  AContext.RootIdentityToken := ARootIdentityToken;
  AContext.SettingsSHA256 := ASettingsSHA256;
end;

function ScanCacheProfilePathSHA256(const AProfileDirectory: string): string;
var
  CanonicalProfile: string;
begin
  if Trim(AProfileDirectory) = '' then
    Exit('');
  CanonicalProfile := CanonicalPath(ExpandFileName(AProfileDirectory));
  Result := SHA256String(RawByteString('purpleray-profile-path-v1'#0 +
    CanonicalProfile));
end;

{**
  Detects ASCII control bytes forbidden in bounded cache tokens.

  Parameters
  ----------
  AValue
    Byte string to inspect.

  Returns
  -------
  Boolean
    True when a C0 control or DEL byte is present.

  Raises
  ------
  None
*}
function HasForbiddenControl(const AValue: string): Boolean;
var
  I: Integer;
begin
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) < 32) or (Ord(AValue[I]) = 127) then
      Exit(True);
  Result := False;
end;

{**
  Validates raw bytes against the RFC 3629 UTF-8 scalar-value ranges.

  Parameters
  ----------
  AValue
    Raw byte sequence to validate without code-page conversion.

  Returns
  -------
  Boolean
    True for complete canonical UTF-8 without surrogate or out-of-range values.

  Raises
  ------
  None
*}
function IsValidUTF8Bytes(const AValue: RawByteString): Boolean;
var
  I, Count: SizeInt;
  First, Second, Third, Fourth: Byte;

  {**
    Tests whether one byte is an UTF-8 continuation byte.

    Parameters
    ----------
    AByte
      Byte to classify.

    Returns
    -------
    Boolean
      True for values from 0x80 through 0xBF.

    Raises
    ------
    None
  *}
  function Continuation(AByte: Byte): Boolean; inline;
  begin
    Result := (AByte >= $80) and (AByte <= $BF);
  end;

begin
  I := 1;
  Count := Length(AValue);
  while I <= Count do
  begin
    First := Byte(AValue[I]);
    if First <= $7F then
      Inc(I)
    else if (First >= $C2) and (First <= $DF) then
    begin
      if I > Count - 1 then
        Exit(False);
      Second := Byte(AValue[I + 1]);
      if not Continuation(Second) then
        Exit(False);
      Inc(I, 2);
    end
    else if (First >= $E0) and (First <= $EF) then
    begin
      if I > Count - 2 then
        Exit(False);
      Second := Byte(AValue[I + 1]);
      Third := Byte(AValue[I + 2]);
      if not Continuation(Third) then
        Exit(False);
      if First = $E0 then
      begin
        if (Second < $A0) or (Second > $BF) then
          Exit(False);
      end
      else if First = $ED then
      begin
        if (Second < $80) or (Second > $9F) then
          Exit(False);
      end
      else if not Continuation(Second) then
        Exit(False);
      Inc(I, 3);
    end
    else if (First >= $F0) and (First <= $F4) then
    begin
      if I > Count - 3 then
        Exit(False);
      Second := Byte(AValue[I + 1]);
      Third := Byte(AValue[I + 2]);
      Fourth := Byte(AValue[I + 3]);
      if not Continuation(Third) or not Continuation(Fourth) then
        Exit(False);
      if First = $F0 then
      begin
        if (Second < $90) or (Second > $BF) then
          Exit(False);
      end
      else if First = $F4 then
      begin
        if (Second < $80) or (Second > $8F) then
          Exit(False);
      end
      else if not Continuation(Second) then
        Exit(False);
      Inc(I, 4);
    end
    else
      Exit(False);
  end;
  Result := True;
end;

{**
  Retags already verified string bytes as UTF-8 without transcoding.

  Parameters
  ----------
  AValue
    String whose current bytes are valid UTF-8.

  Returns
  -------
  UTF8String
    Same bytes carrying the CP_UTF8 tag.

  Raises
  ------
  None
*}
function CacheUTF8(const AValue: string): UTF8String;
var
  RawValue: RawByteString;
begin
  RawValue := RawByteString(AValue);
  SetCodePage(RawValue, CP_UTF8, False);
  Result := UTF8String(RawValue);
end;

{**
  Extracts one JSON string while retaining its verified UTF-8 bytes and tag.

  Parameters
  ----------
  AValue
    Borrowed JSON string node.

  Returns
  -------
  string
    Extracted bytes tagged CP_UTF8.

  Raises
  ------
  EJSON
    Propagated when the node cannot be represented as a string.
  EOutOfMemory
    Propagated if extraction cannot allocate storage.
*}
function CacheString(AValue: TJSONData): string;
var
  RawValue: RawByteString;
begin
  RawValue := RawByteString(AValue.AsString);
  SetCodePage(RawValue, CP_UTF8, False);
  Result := string(RawValue);
end;

{**
  Adds one explicitly UTF-8 string member to a JSON object.

  Parameters
  ----------
  AObject
    Borrowed destination object.
  AName
    Member name whose bytes are valid UTF-8.
  AValue
    Member value whose bytes are valid UTF-8.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the node or object storage cannot be allocated.
*}
procedure AddCacheString(AObject: TJSONObject; const AName, AValue: string);
begin
  AObject.Add(UTF8String(AName), TJSONString.Create(CacheUTF8(AValue)));
end;

{**
  Appends one explicitly UTF-8 string value to a JSON array.

  Parameters
  ----------
  AArray
    Borrowed destination array.
  AValue
    Value whose bytes are valid UTF-8.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if the node or array storage cannot be allocated.
*}
procedure AddCacheString(AArray: TJSONArray; const AValue: string);
begin
  AArray.Add(TJSONString.Create(CacheUTF8(AValue)));
end;

{**
  Validates one UTF-8 cache token against length, emptiness, and control rules.

  Parameters
  ----------
  AValue
    Candidate byte string.
  AMaximumLength
    Maximum accepted byte count.
  AAllowEmpty
    Permits the empty value when True.

  Returns
  -------
  Boolean
    True only when every token constraint is satisfied.

  Raises
  ------
  None
*}
function IsBoundedToken(const AValue: string; AMaximumLength: Integer;
  AAllowEmpty: Boolean = False): Boolean;
begin
  Result := ((AAllowEmpty and (AValue = '')) or (AValue <> '')) and
    (Length(AValue) <= AMaximumLength) and
    IsValidUTF8Bytes(RawByteString(AValue)) and
    not HasForbiddenControl(AValue);
end;

{**
  Tests for exact-length lowercase hexadecimal text.

  Parameters
  ----------
  AValue
    Candidate text.
  ALength
    Required character count.

  Returns
  -------
  Boolean
    True only for the requested number of lowercase hexadecimal digits.

  Raises
  ------
  None
*}
function IsLowerHex(const AValue: string; ALength: Integer): Boolean;
var
  I: Integer;
begin
  if Length(AValue) <> ALength then
    Exit(False);
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['0'..'9', 'a'..'f']) then
      Exit(False);
  Result := True;
end;

{**
  Tests the canonical textual shape of a SHA-256 digest.

  Parameters
  ----------
  AValue
    Candidate digest.

  Returns
  -------
  Boolean
    True for exactly 64 lowercase hexadecimal characters.

  Raises
  ------
  None
*}
function IsSHA256(const AValue: string): Boolean;
begin
  Result := IsLowerHex(AValue, 64);
end;

{**
  Validates a complete encoded verified-file identity.

  Parameters
  ----------
  AValue
    Candidate fixed-width identity encoding.

  Returns
  -------
  Boolean
    True for a valid flag, nonnegative size, and lowercase hexadecimal fields.

  Raises
  ------
  EOutOfMemory
    Propagated if the validity-flag slice cannot be allocated.
*}
function IsIdentityHex(const AValue: string): Boolean;
begin
  Result := IsLowerHex(AValue, VerifiedFileIdentityHexLength) and
    (Copy(AValue, 1, 16) = '0000000000000001') and
    not (AValue[49] in ['8'..'9', 'a'..'f']);
end;

{**
  Parses one exact 16-digit lowercase hexadecimal word.

  Parameters
  ----------
  AValue
    Candidate fixed-width word.
  AResult
    Receives the decoded value, or zero on failure.

  Returns
  -------
  Boolean
    True when all 16 digits are canonical and decoded.

  Raises
  ------
  None
*}
function TryHexWord(const AValue: string; out AResult: QWord): Boolean;
var
  I: Integer;
  Digit: Byte;
begin
  AResult := 0;
  if Length(AValue) <> 16 then
    Exit(False);
  for I := 1 to 16 do
  begin
    case AValue[I] of
      '0'..'9': Digit := Ord(AValue[I]) - Ord('0');
      'a'..'f': Digit := Ord(AValue[I]) - Ord('a') + 10;
    else
      Exit(False);
    end;
    AResult := (AResult shl 4) or Digit;
  end;
  Result := True;
end;

{**
  Extracts the nonnegative file size from an encoded verified identity.

  Parameters
  ----------
  AIdentityHex
    Complete encoded identity.
  ASize
    Receives the decoded size, or zero on failure.

  Returns
  -------
  Boolean
    True when the identity and signed size field are valid.

  Raises
  ------
  EOutOfMemory
    Propagated if the encoded size field cannot be sliced.
*}
function IdentitySize(const AIdentityHex: string; out ASize: Int64): Boolean;
var
  Value: QWord;
begin
  Result := IsIdentityHex(AIdentityHex) and
    TryHexWord(Copy(AIdentityHex, 49, 16), Value) and
    ((Value and (QWord(1) shl 63)) = 0);
  if Result then
    ASize := Int64(Value)
  else
    ASize := 0;
end;

{**
  Validates a bounded relative cache key without traversal or drive syntax.

  Parameters
  ----------
  AValue
    Candidate root-relative path.

  Returns
  -------
  Boolean
    True for valid UTF-8 segments containing no empty, dot, or dot-dot element.

  Raises
  ------
  EOutOfMemory
    Propagated if a path segment cannot be allocated for validation.
*}
function IsSafeRelativePath(const AValue: string): Boolean;
var
  I, SegmentStart: Integer;
  Segment: string;
begin
  Result := False;
  if (AValue = '') or (Length(AValue) > MaximumScanCacheStringBytes) or
    not IsValidUTF8Bytes(RawByteString(AValue)) or
    HasForbiddenControl(AValue) or (AValue[1] in ['/', '\']) then
    Exit;
  if (Length(AValue) >= 2) and (AValue[1] in ['A'..'Z', 'a'..'z']) and
    (AValue[2] = ':') then
    Exit;

  SegmentStart := 1;
  for I := 1 to Length(AValue) + 1 do
    if (I > Length(AValue)) or (AValue[I] in ['/', '\']) then
    begin
      Segment := Copy(AValue, SegmentStart, I - SegmentStart);
      if (Segment = '') or (Segment = '.') or (Segment = '..') then
        Exit;
      SegmentStart := I + 1;
    end;
  Result := True;
end;

{**
  Enforces all format, digest, and privacy constraints on a cache context.

  Parameters
  ----------
  AContext
    Context to validate before cache construction or serialization.

  Returns
  -------
  None

  Raises
  ------
  EArgumentException
    Raised when any token, digest, or root identity is invalid.
*}
procedure RequireValidContext(const AContext: TScanCacheContext);
begin
  if not IsBoundedToken(AContext.AnalysisContract,
    MaximumAnalysisContractBytes) then
    raise EArgumentException.Create('Invalid scan-cache analysis contract');
  if not IsBoundedToken(AContext.Platform, MaximumPlatformBytes) then
    raise EArgumentException.Create('Invalid scan-cache platform');
  if not IsSHA256(AContext.ProfilePathSHA256) then
    raise EArgumentException.Create('Invalid scan-cache profile-path SHA-256');
  if not IsSHA256(AContext.RootPathSHA256) then
    raise EArgumentException.Create('Invalid scan-cache root-path SHA-256');
  if not IsBoundedToken(AContext.RootIdentityToken,
    MaximumRootIdentityTokenBytes) or
    (Pos('/', AContext.RootIdentityToken) > 0) or
    (Pos('\', AContext.RootIdentityToken) > 0) then
    raise EArgumentException.Create('Invalid scan-cache root identity token');
  if not IsSHA256(AContext.SettingsSHA256) then
    raise EArgumentException.Create('Invalid scan-cache settings SHA-256');
end;

{**
  Compares every cache-context field exactly and case-sensitively.

  Parameters
  ----------
  ALeft
    First context.
  ARight
    Second context.

  Returns
  -------
  Boolean
    True only when all six fields are byte-identical.

  Raises
  ------
  None
*}
function ContextsEqual(const ALeft, ARight: TScanCacheContext): Boolean;
begin
  Result := (ALeft.AnalysisContract = ARight.AnalysisContract) and
    (ALeft.Platform = ARight.Platform) and
    (ALeft.ProfilePathSHA256 = ARight.ProfilePathSHA256) and
    (ALeft.RootPathSHA256 = ARight.RootPathSHA256) and
    (ALeft.RootIdentityToken = ARight.RootIdentityToken) and
    (ALeft.SettingsSHA256 = ARight.SettingsSHA256);
end;

{**
  Validates one bounded cache filename with no directory or stream syntax.

  Parameters
  ----------
  AValue
    Candidate filename.

  Returns
  -------
  Boolean
    True for one non-dot leaf name.

  Raises
  ------
  None
*}
function IsSingleLeafName(const AValue: string): Boolean;
begin
  Result := IsBoundedToken(AValue, 200) and (AValue <> '.') and
    (AValue <> '..') and (Pos('/', AValue) = 0) and
    (Pos('\', AValue) = 0) and (Pos(':', AValue) = 0);
end;

{**
  Creates a collision-resistant temporary leaf for one cache snapshot.

  Parameters
  ----------
  ACacheFileName
    Valid final cache leaf used as the prefix.

  Returns
  -------
  string
    Final leaf followed by a lowercase GUID suffix.

  Raises
  ------
  Exception
    Raised when the platform cannot create a GUID.
  EOutOfMemory
    Propagated if the leaf cannot be allocated.
*}
function NewCacheTemporaryLeaf(const ACacheFileName: string): string;
var
  Identifier: TGUID;
  Suffix: string;
begin
  if CreateGUID(Identifier) <> 0 then
    raise Exception.Create('Unable to create a rescan-cache identifier');
  Suffix := LowerCase(GUIDToString(Identifier));
  if (Length(Suffix) >= 2) and (Suffix[1] = '{') then
    Suffix := Copy(Suffix, 2, Length(Suffix) - 2);
  Result := ACacheFileName + '.tmp-' + Suffix;
end;

{**
  Writes, flushes, and atomically activates one cache snapshot under a pin.

  Parameters
  ----------
  APinnedDirectory
    Required stable profile-directory pin.
  ACacheFileName
    Safe final cache leaf.
  AContent
    Complete validated UTF-8 snapshot bytes.

  Returns
  -------
  None

  Raises
  ------
  EArgumentNilException
    Raised when APinnedDirectory is nil.
  EInOutError
    Raised when creation, flushing, pin verification, or activation fails.
  EOutOfMemory
    Propagated if temporary state cannot be allocated.
*}
procedure WriteAtomicCache(APinnedDirectory: TPinnedDirectory;
  const ACacheFileName: string; const AContent: UTF8String);
var
  TemporaryLeaf: string;
  HandleValue: THandle;
  Stream: THandleStream;
begin
  if APinnedDirectory = nil then
    raise EArgumentNilException.Create('Cache profile pin must not be nil');
  TemporaryLeaf := NewCacheTemporaryLeaf(ACacheFileName);
  HandleValue := feInvalidHandle;
  try
    HandleValue := APinnedDirectory.CreateFileExclusive(TemporaryLeaf);
    try
      Stream := THandleStream.Create(HandleValue);
      try
        if Length(AContent) > 0 then
          Stream.WriteBuffer(AContent[1], Length(AContent));
        FlushFileHandle(HandleValue);
      finally
        Stream.Free;
      end;
    finally
      FileClose(HandleValue);
      HandleValue := feInvalidHandle;
    end;
    { ReplaceFileAtomically verifies the profile immediately before its
      descriptor-relative activation. A failed activation leaves the previous
      cache untouched. We deliberately do not turn a later pathname rebind
      into a reported commit failure: the completed rename remains confined to
      the pinned original profile and can never populate the replacement. }
    if not APinnedDirectory.ReplaceFileAtomically(TemporaryLeaf,
      ACacheFileName) then
      raise EInOutError.Create('Unable to activate the rescan-cache snapshot');
    TemporaryLeaf := '';
  finally
    if HandleValue <> feInvalidHandle then
      FileClose(HandleValue);
    if TemporaryLeaf <> '' then
      APinnedDirectory.DeleteFile(TemporaryLeaf);
  end;
end;

{**
  Deep-clones a borrowed list containing only components.

  Parameters
  ----------
  AComponents
    Required borrowed TObjectList of TComponent instances.

  Returns
  -------
  TObjectList
    Caller-owned list that owns all cloned components.

  Raises
  ------
  EArgumentNilException
    Raised when AComponents is nil.
  EArgumentException
    Raised when an element is not a TComponent.
  EOutOfMemory
    Propagated if the list or a clone cannot be allocated.
*}
function CloneComponentList(AComponents: TObjectList): TObjectList;
var
  I: Integer;
begin
  if AComponents = nil then
    raise EArgumentNilException.Create('Cache component list must not be nil');
  Result := TObjectList.Create(True);
  try
    for I := 0 to AComponents.Count - 1 do
    begin
      if not (AComponents[I] is TComponent) then
        raise EArgumentException.Create('Cache component list contains an ' +
          'incompatible object');
      Result.Add(TComponent(AComponents[I]).Clone);
    end;
  except
    Result.Free;
    raise;
  end;
end;

constructor TScanCacheEvidence.Create(AArtifact: TArtifact;
  AComponents: TObjectList; AInspectionTools: TStrings; AWarnings: TStrings);
begin
  inherited Create;
  if AArtifact <> nil then
  begin
    FArtifact := AArtifact.Clone;
    FArtifact.AbsolutePath := '';
  end;
  try
    FComponents := CloneComponentList(AComponents);
    FInspectionTools := TStringList.Create;
    FInspectionTools.Sorted := True;
    FInspectionTools.Duplicates := dupIgnore;
    if AInspectionTools <> nil then
      FInspectionTools.Assign(AInspectionTools);
    FWarnings := TStringList.Create;
    if AWarnings <> nil then
      FWarnings.Assign(AWarnings);
  except
    FreeAndNil(FWarnings);
    FreeAndNil(FInspectionTools);
    FreeAndNil(FComponents);
    FreeAndNil(FArtifact);
    raise;
  end;
end;

destructor TScanCacheEvidence.Destroy;
begin
  FWarnings.Free;
  FInspectionTools.Free;
  FComponents.Free;
  FArtifact.Free;
  inherited Destroy;
end;

function TScanCacheEvidence.Clone: TScanCacheEvidence;
begin
  Result := TScanCacheEvidence.Create(FArtifact, FComponents,
    FInspectionTools, FWarnings);
end;

function TScanCacheEvidence.ReleaseArtifact: TArtifact;
begin
  Result := FArtifact;
  FArtifact := nil;
end;

procedure TScanCacheEvidence.MoveComponentsTo(ADestination: TObjectList);
var
  Component: TObject;
begin
  if ADestination = nil then
    raise EArgumentNilException.Create('Component destination must not be nil');
  while FComponents.Count > 0 do
  begin
    Component := FComponents.Extract(FComponents[0]);
    try
      ADestination.Add(Component);
    except
      Component.Free;
      raise;
    end;
  end;
end;

constructor TScanCacheEntry.Create(const ARelativePath, AIdentityHex,
  AContentSHA256: string; AEvidence: TScanCacheEvidence);
begin
  inherited Create;
  if AEvidence = nil then
    raise EArgumentNilException.Create('Cache evidence must not be nil');
  FRelativePath := ARelativePath;
  FIdentityHex := AIdentityHex;
  FContentSHA256 := AContentSHA256;
  FEvidence := AEvidence;
end;

destructor TScanCacheEntry.Destroy;
begin
  FEvidence.Free;
  inherited Destroy;
end;

function TScanCacheEntry.Clone: TScanCacheEntry;
begin
  Result := TScanCacheEntry.Create(FRelativePath, FIdentityHex,
    FContentSHA256, FEvidence.Clone);
end;

{**
  Rejects duplicate or unknown members in one JSON object.

  Parameters
  ----------
  AObject
    Borrowed object to inspect.
  AAllowed
    Exact case-sensitive member-name allowlist.

  Returns
  -------
  Boolean
    True when every member occurs once and appears in AAllowed.

  Raises
  ------
  None
*}
function ObjectHasOnlyMembers(AObject: TJSONObject;
  const AAllowed: array of string): Boolean;
var
  I, J, Previous: Integer;
  Found: Boolean;
begin
  if AObject = nil then
    Exit(False);
  for I := 0 to AObject.Count - 1 do
  begin
    for Previous := 0 to I - 1 do
      if AObject.Names[Previous] = AObject.Names[I] then
        Exit(False);
    Found := False;
    for J := Low(AAllowed) to High(AAllowed) do
      if AObject.Names[I] = AAllowed[J] then
      begin
        Found := True;
        Break;
      end;
    if not Found then
      Exit(False);
  end;
  Result := True;
end;

{**
  Reads one optional or required string member with its UTF-8 tag preserved.

  Parameters
  ----------
  AObject
    Borrowed source object.
  AName
    Exact member name.
  ARequired
    Rejects an absent member when True.
  AValue
    Receives the string, or an empty value when absent.

  Returns
  -------
  Boolean
    True when presence and type satisfy the request.

  Raises
  ------
  EOutOfMemory
    Propagated if string extraction cannot allocate storage.
*}
function ReadJSONString(AObject: TJSONObject; const AName: string;
  ARequired: Boolean; out AValue: string): Boolean;
var
  Data: TJSONData;
begin
  AValue := '';
  if AObject = nil then
    Exit(False);
  Data := AObject.Find(AName);
  if Data = nil then
    Exit(not ARequired);
  Result := Data.JSONType = jtString;
  if Result then
    AValue := CacheString(Data);
end;

{**
  Reads one required canonical decimal Int64 JSON member.

  Parameters
  ----------
  AObject
    Borrowed source object.
  AName
    Exact member name.
  AValue
    Receives the decoded integer, or zero on failure.

  Returns
  -------
  Boolean
    True only when the JSON spelling exactly matches the decoded integer.

  Raises
  ------
  None
    Numeric conversion errors are reported as False.
*}
function ReadJSONInteger(AObject: TJSONObject; const AName: string;
  out AValue: Int64): Boolean;
var
  Data: TJSONData;
begin
  AValue := 0;
  if AObject = nil then
    Exit(False);
  Data := AObject.Find(AName);
  if (Data = nil) or (Data.JSONType <> jtNumber) then
    Exit(False);
  try
    AValue := Data.AsInt64;
    Result := Data.AsJSON = IntToStr(AValue);
  except
    Result := False;
  end;
end;

{**
  Borrows one required object-valued JSON member.

  Parameters
  ----------
  AObject
    Borrowed source object.
  AName
    Exact member name.
  AValue
    Receives the borrowed child object, or nil on failure.

  Returns
  -------
  Boolean
    True when the named member exists and is an object.

  Raises
  ------
  None
*}
function ReadJSONObject(AObject: TJSONObject; const AName: string;
  out AValue: TJSONObject): Boolean;
var
  Data: TJSONData;
begin
  AValue := nil;
  if AObject = nil then
    Exit(False);
  Data := AObject.Find(AName);
  Result := (Data <> nil) and (Data.JSONType = jtObject);
  if Result then
    AValue := TJSONObject(Data);
end;

{**
  Borrows one required array-valued JSON member.

  Parameters
  ----------
  AObject
    Borrowed source object.
  AName
    Exact member name.
  AValue
    Receives the borrowed child array, or nil on failure.

  Returns
  -------
  Boolean
    True when the named member exists and is an array.

  Raises
  ------
  None
*}
function ReadJSONArray(AObject: TJSONObject; const AName: string;
  out AValue: TJSONArray): Boolean;
var
  Data: TJSONData;
begin
  AValue := nil;
  if AObject = nil then
    Exit(False);
  Data := AObject.Find(AName);
  Result := (Data <> nil) and (Data.JSONType = jtArray);
  if Result then
    AValue := TJSONArray(Data);
end;

{**
  Recursively enforces cache JSON depth, node, name, string, and UTF-8 bounds.

  Parameters
  ----------
  AData
    Borrowed node to validate.
  ADepth
    Current zero-based container depth.
  ANodeCount
    Running node count updated for every accepted node.

  Returns
  -------
  Boolean
    True when this subtree remains within every configured bound.

  Raises
  ------
  EOutOfMemory
    Propagated if the JSON library must materialize a string value.
*}
function ValidateJSONBounds(AData: TJSONData; ADepth: Integer;
  var ANodeCount: Integer): Boolean;
var
  I: Integer;
begin
  if (AData = nil) or (ADepth > MaximumJSONDepth) or
    (ANodeCount >= MaximumScanCacheJSONNodes) then
    Exit(False);
  Inc(ANodeCount);
  case AData.JSONType of
    jtString:
      Result := (Length(AData.AsString) <= MaximumScanCacheStringBytes) and
        IsValidUTF8Bytes(RawByteString(AData.AsString));
    jtArray:
      begin
        Result := TJSONArray(AData).Count <=
          MaximumScanCacheJSONNodes - ANodeCount;
        if Result then
          for I := 0 to TJSONArray(AData).Count - 1 do
            if not ValidateJSONBounds(TJSONArray(AData).Items[I], ADepth + 1,
              ANodeCount) then
              Exit(False);
      end;
    jtObject:
      begin
        Result := TJSONObject(AData).Count <=
          MaximumScanCacheJSONNodes - ANodeCount;
        if Result then
          for I := 0 to TJSONObject(AData).Count - 1 do
          begin
            if (Length(TJSONObject(AData).Names[I]) > 128) or
              not IsValidUTF8Bytes(
                RawByteString(TJSONObject(AData).Names[I])) then
              Exit(False);
            if not ValidateJSONBounds(TJSONObject(AData).Items[I],
              ADepth + 1, ANodeCount) then
              Exit(False);
          end;
      end;
  else
    Result := True;
  end;
end;

{**
  Preflights raw JSON structure before allocating a parser tree.

  Parameters
  ----------
  AContent
    Complete verified UTF-8 cache bytes.

  Returns
  -------
  Boolean
    True when delimiters, strings, depth, and token count satisfy cache rules.

  Raises
  ------
  None
*}
function PreflightRawJSON(const AContent: RawByteString): Boolean;
var
  Stack: array[1..MaximumJSONDepth] of AnsiChar;
  Depth, I, TokenCount: Integer;
  Value, Expected: AnsiChar;
  InString, Escaped, InPrimitive: Boolean;
begin
  Result := False;
  FillChar(Stack, SizeOf(Stack), 0);
  if AContent = '' then
    Exit;
  Depth := 0;
  InString := False;
  Escaped := False;
  InPrimitive := False;
  TokenCount := 0;
  for I := 1 to Length(AContent) do
  begin
    Value := AContent[I];
    if InString then
    begin
      if Escaped then
      begin
        { FPC 3.2.2's JSON reader performs a lossy system-codepage conversion
          for Unicode escapes even when raw UTF-8 input has already been
          verified. This cache's writer emits non-ASCII text as raw UTF-8, so
          reject \u escapes rather than accepting ambiguous reconstructed
          evidence. The strict parser still validates all other escapes. }
        if Value = 'u' then
          Exit;
        Escaped := False;
        Continue;
      end;
      if Value = '\' then
      begin
        Escaped := True;
        Continue;
      end;
      if Value = '"' then
      begin
        InString := False;
        Continue;
      end;
      if Ord(Value) < 32 then
        Exit;
      Continue;
    end;

    if Value = '"' then
    begin
      if TokenCount >= MaximumScanCacheJSONNodes then
        Exit;
      Inc(TokenCount);
      InString := True
    end
    else if (Value = '{') or (Value = '[') then
    begin
      if TokenCount >= MaximumScanCacheJSONNodes then
        Exit;
      Inc(TokenCount);
      if Depth >= MaximumJSONDepth then
        Exit;
      Inc(Depth);
      Stack[Depth] := Value;
      InPrimitive := False;
    end
    else if (Value = '}') or (Value = ']') then
    begin
      if Depth = 0 then
        Exit;
      if Value = '}' then
        Expected := '{'
      else
        Expected := '[';
      if Stack[Depth] <> Expected then
        Exit;
      Dec(Depth);
      InPrimitive := False;
    end
    else if Ord(Value) < 32 then
    begin
      if not (Value in [#9, #10, #13]) then
        Exit;
      InPrimitive := False;
    end
    else if Value in [' ', ',', ':'] then
      InPrimitive := False
    else if not InPrimitive then
    begin
      if TokenCount >= MaximumScanCacheJSONNodes then
        Exit;
      Inc(TokenCount);
      InPrimitive := True;
    end;
  end;
  Result := (Depth = 0) and not InString and not Escaped;
end;

{**
  Reads one verified cache input exactly under the file-size bound.

  Parameters
  ----------
  AInput
    Borrowed verified input.
  AContent
    Receives exact raw bytes, or an empty value on rejection.

  Returns
  -------
  Boolean
    True only when the complete bounded input is read.

  Raises
  ------
  EStreamError
    Propagated when an in-range verified read fails.
  EOutOfMemory
    Propagated when the bounded destination cannot be allocated.
*}
function ReadVerifiedJSONBytes(AInput: TVerifiedInput;
  out AContent: RawByteString): Boolean;
var
  Stream: TStream;
begin
  Result := False;
  AContent := '';
  if (AInput = nil) or (AInput.Size < 0) or
    (AInput.Size > MaximumScanCacheBytes) then
    Exit;
  SetLength(AContent, SizeInt(AInput.Size));
  Stream := AInput.NewStream;
  try
    if Length(AContent) > 0 then
      Stream.ReadBuffer(AContent[1], Length(AContent));
    Result := Stream.Position = Stream.Size;
  finally
    Stream.Free;
  end;
end;

{**
  Parses prevalidated UTF-8 bytes with FPC strict JSON syntax enabled.

  Parameters
  ----------
  AContent
    Complete raw JSON document already checked for UTF-8 and resource bounds.

  Returns
  -------
  TJSONData
    Caller-owned parsed tree.

  Raises
  ------
  EJSONParser
    Propagated for invalid strict JSON syntax.
  EOutOfMemory
    Propagated if parser state or the tree cannot be allocated.
*}
function ParseStrictUTF8JSON(const AContent: RawByteString): TJSONData;
var
  Memory: TMemoryStream;
  Parser: TJSONParser;
begin
  Result := nil;
  Memory := TMemoryStream.Create;
  try
    if Length(AContent) > 0 then
      Memory.WriteBuffer(AContent[1], Length(AContent));
    Memory.Position := 0;
    { Raw bytes were validated as UTF-8 before this call. FPC 3.2.2's joUTF8
      path decodes through the current system code page and can replace valid
      non-ASCII evidence. joStrict alone preserves those verified bytes. }
    Parser := TJSONParser.Create(Memory, [joStrict]);
    try
      Result := Parser.Parse;
    finally
      Parser.Free;
    end;
  finally
    Memory.Free;
  end;
end;

{**
  Validates a bounded JSON array containing only cache-safe strings.

  Parameters
  ----------
  AArray
    Borrowed array to inspect.

  Returns
  -------
  Boolean
    True when the count and every string satisfy cache bounds.

  Raises
  ------
  EOutOfMemory
    Propagated if string extraction cannot allocate storage.
*}
function ValidateStringListJSON(AArray: TJSONArray): Boolean;
var
  I: Integer;
  Value: string;
begin
  if (AArray = nil) or (AArray.Count > MaximumScanCacheListValues) then
    Exit(False);
  for I := 0 to AArray.Count - 1 do
  begin
    if AArray.Items[I].JSONType <> jtString then
      Exit(False);
    Value := CacheString(AArray.Items[I]);
    if not IsBoundedToken(Value, MaximumScanCacheStringBytes, True) then
      Exit(False);
  end;
  Result := True;
end;

{**
  Validates an optional in-memory string list before cache staging.

  Parameters
  ----------
  AStrings
    Borrowed list, or nil.
  AMaximumCount
    Maximum accepted number of values.

  Returns
  -------
  Boolean
    True when absent or when all list values satisfy cache bounds.

  Raises
  ------
  None
*}
function ValidateCachedStrings(AStrings: TStrings;
  AMaximumCount: Integer): Boolean;
var
  I: Integer;
begin
  Result := (AStrings = nil) or (AStrings.Count <= AMaximumCount);
  if not Result or (AStrings = nil) then
    Exit;
  for I := 0 to AStrings.Count - 1 do
    if not IsBoundedToken(AStrings[I], MaximumScanCacheStringBytes, True) then
      Exit(False);
end;

{**
  Replaces one string list with UTF-8 values from a validated JSON array.

  Parameters
  ----------
  AArray
    Borrowed validated string array.
  AStrings
    Borrowed destination list to clear and refill.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if extraction or destination growth fails.
*}
procedure JSONStringsToList(AArray: TJSONArray; AStrings: TStrings);
var
  I: Integer;
begin
  AStrings.Clear;
  for I := 0 to AArray.Count - 1 do
    AStrings.Add(CacheString(AArray.Items[I]));
end;

{**
  Appends an optional string list to a JSON array as explicit UTF-8 values.

  Parameters
  ----------
  AStrings
    Borrowed source list, or nil.
  AArray
    Borrowed destination array.

  Returns
  -------
  None

  Raises
  ------
  EOutOfMemory
    Propagated if JSON values cannot be allocated.
*}
procedure StringsToJSONArray(AStrings: TStrings; AArray: TJSONArray);
var
  I: Integer;
begin
  if AStrings = nil then
    Exit;
  for I := 0 to AStrings.Count - 1 do
    AddCacheString(AArray, AStrings[I]);
end;

{**
  Serializes one validated artifact without its transient absolute path.

  Parameters
  ----------
  AArtifact
    Borrowed artifact already validated for cache staging.

  Returns
  -------
  TJSONObject
    Caller-owned JSON object containing path-independent artifact evidence.

  Raises
  ------
  EOutOfMemory
    Propagated if the object cannot be allocated.
*}
function ArtifactToCacheJSON(AArtifact: TArtifact): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    AddCacheString(Result, 'relative_path', AArtifact.RelativePath);
    AddCacheString(Result, 'artifact_type', AArtifact.ArtifactType);
    AddCacheString(Result, 'ecosystem', AArtifact.Ecosystem);
    AddCacheString(Result, 'status', ArtifactStatusToString(AArtifact.Status));
    AddCacheString(Result, 'parser', AArtifact.ParserName);
    Result.Add('file_size', AArtifact.FileSize);
    if AArtifact.SHA256 <> '' then
      AddCacheString(Result, 'sha256', AArtifact.SHA256);
    if AArtifact.MessageText <> '' then
      AddCacheString(Result, 'message', AArtifact.MessageText);
    Result.Add('component_count', AArtifact.ComponentCount);
  except
    Result.Free;
    raise;
  end;
end;

{**
  Serializes one validated component and its bounded evidence lists.

  Parameters
  ----------
  AComponent
    Borrowed component already validated for cache staging.

  Returns
  -------
  TJSONObject
    Caller-owned JSON object containing the component model.

  Raises
  ------
  EOutOfMemory
    Propagated if the object or child arrays cannot be allocated.
*}
function ComponentToCacheJSON(AComponent: TComponent): TJSONObject;
var
  Values: TJSONArray;
begin
  Result := TJSONObject.Create;
  try
    AddCacheString(Result, 'component_type', AComponent.ComponentType);
    AddCacheString(Result, 'name', AComponent.Name);
    if AComponent.Version <> '' then
      AddCacheString(Result, 'version', AComponent.Version);
    AddCacheString(Result, 'ecosystem', AComponent.Ecosystem);
    if AComponent.PackageURL <> '' then
      AddCacheString(Result, 'package_url', AComponent.PackageURL);
    if AComponent.CPE <> '' then
      AddCacheString(Result, 'cpe', AComponent.CPE);
    if AComponent.CPEEvidence <> '' then
      AddCacheString(Result, 'cpe_evidence', AComponent.CPEEvidence);
    if AComponent.CompanyName <> '' then
      AddCacheString(Result, 'company_name', AComponent.CompanyName);
    if AComponent.ProductName <> '' then
      AddCacheString(Result, 'product_name', AComponent.ProductName);
    if AComponent.NativeSONAME <> '' then
      AddCacheString(Result, 'native_soname', AComponent.NativeSONAME);
    if AComponent.NativeBuildID <> '' then
      AddCacheString(Result, 'native_build_id', AComponent.NativeBuildID);
    AddCacheString(Result, 'source_artifact', AComponent.SourceArtifact);
    AddCacheString(Result, 'source_parser', AComponent.SourceParser);
    if AComponent.DependencyScope <> '' then
      AddCacheString(Result, 'dependency_scope', AComponent.DependencyScope);
    if AComponent.SHA256 <> '' then
      AddCacheString(Result, 'sha256', AComponent.SHA256);
    Values := TJSONArray.Create;
    StringsToJSONArray(AComponent.EvidencePaths, Values);
    Result.Add('evidence_paths', Values);
    if AComponent.DeclaredLicenses.Count > 0 then
    begin
      Values := TJSONArray.Create;
      StringsToJSONArray(AComponent.DeclaredLicenses, Values);
      Result.Add('declared_licenses', Values);
    end;
    if AComponent.DeclaredPublishers.Count > 0 then
    begin
      Values := TJSONArray.Create;
      StringsToJSONArray(AComponent.DeclaredPublishers, Values);
      Result.Add('declared_publishers', Values);
    end;
  except
    Result.Free;
    raise;
  end;
end;

{**
  Validates one live component against cache bounds and file binding.

  Parameters
  ----------
  AComponent
    Borrowed component to validate.
  ARelativePath
    Exact entry path required for source and evidence paths.
  AContentSHA256
    Entry digest permitted in component hash evidence.

  Returns
  -------
  Boolean
    True when all fields, lists, paths, and hashes are cache-safe.

  Raises
  ------
  None
*}
function ValidateComponentModel(AComponent: TComponent;
  const ARelativePath, AContentSHA256: string): Boolean;
var
  I: Integer;

  {**
    Applies the standard cache string bound to one component field.

    Parameters
    ----------
    AValue
      Candidate field value.
    AAllowEmpty
      Permits an empty field when True.

    Returns
    -------
    Boolean
      True when the field is a bounded valid UTF-8 token.

    Raises
    ------
    None
  *}
  function ValidField(const AValue: string; AAllowEmpty: Boolean = True):
    Boolean;
  begin
    Result := IsBoundedToken(AValue, MaximumScanCacheStringBytes, AAllowEmpty);
  end;

begin
  Result := (AComponent <> nil) and
    ValidField(AComponent.ComponentType) and
    ValidField(AComponent.Name, False) and
    ValidField(AComponent.Version) and ValidField(AComponent.Ecosystem) and
    ValidField(AComponent.PackageURL) and ValidField(AComponent.CPE) and
    ValidField(AComponent.CPEEvidence) and
    ValidField(AComponent.CompanyName) and
    ValidField(AComponent.ProductName) and
    ValidField(AComponent.NativeSONAME) and
    ValidField(AComponent.NativeBuildID) and
    (AComponent.SourceArtifact = ARelativePath) and
    IsSafeRelativePath(AComponent.SourceArtifact) and
    ValidField(AComponent.SourceParser) and
    ValidField(AComponent.DependencyScope) and
    ((AComponent.SHA256 = '') or
      (AComponent.SHA256 = AContentSHA256)) and
    (AComponent.EvidencePaths.Count <= MaximumScanCacheListValues) and
    (AComponent.DeclaredLicenses.Count <= MaximumScanCacheListValues) and
    (AComponent.DeclaredPublishers.Count <= MaximumScanCacheListValues);
  if not Result then
    Exit;
  for I := 0 to AComponent.EvidencePaths.Count - 1 do
    if (AComponent.EvidencePaths[I] <> ARelativePath) or
      not IsSafeRelativePath(AComponent.EvidencePaths[I]) then
      Exit(False);
  for I := 0 to AComponent.DeclaredLicenses.Count - 1 do
    if not ValidField(AComponent.DeclaredLicenses[I]) then
      Exit(False);
  for I := 0 to AComponent.DeclaredPublishers.Count - 1 do
    if not ValidField(AComponent.DeclaredPublishers[I]) then
      Exit(False);
end;

{**
  Validates one live artifact against its entry path, size, hash, and count.

  Parameters
  ----------
  AArtifact
    Borrowed artifact to validate.
  ARelativePath
    Exact entry path required by the artifact.
  AContentSHA256
    Entry digest permitted in artifact hash evidence.
  AExpectedSize
    Size decoded from the verified native identity.
  AComponentCount
    Number of components associated with the artifact.

  Returns
  -------
  Boolean
    True when the artifact is internally consistent and cache-safe.

  Raises
  ------
  None
*}
function ValidateArtifactModel(AArtifact: TArtifact;
  const ARelativePath, AContentSHA256: string; AExpectedSize: Int64;
  AComponentCount: Integer): Boolean;
begin
  Result := (AArtifact <> nil) and
    (AArtifact.RelativePath = ARelativePath) and
    IsSafeRelativePath(AArtifact.RelativePath) and
    IsBoundedToken(AArtifact.ArtifactType, MaximumScanCacheStringBytes, True) and
    IsBoundedToken(AArtifact.Ecosystem, MaximumScanCacheStringBytes, True) and
    IsBoundedToken(AArtifact.ParserName, MaximumScanCacheStringBytes, True) and
    IsBoundedToken(AArtifact.MessageText, MaximumScanCacheStringBytes, True) and
    (AArtifact.FileSize = AExpectedSize) and
    (AArtifact.ComponentCount = AComponentCount) and
    ((AArtifact.SHA256 = '') or (AArtifact.SHA256 = AContentSHA256));
end;

{**
  Parses and validates one cached component object.

  Parameters
  ----------
  AObject
    Borrowed JSON object to decode.
  ARelativePath
    Entry path required for all component provenance.
  AContentSHA256
    Entry digest permitted in component hash evidence.
  AComponent
    Receives a caller-owned component on success, otherwise nil.

  Returns
  -------
  Boolean
    True only when schema, types, bounds, and model invariants are valid.

  Raises
  ------
  EOutOfMemory
    Propagated if the component or its lists cannot be allocated.
*}
function ValidateComponentJSON(AObject: TJSONObject;
  const ARelativePath, AContentSHA256: string;
  out AComponent: TComponent): Boolean;
const
  Allowed: array[0..17] of string = (
    'component_type', 'name', 'version', 'ecosystem', 'package_url', 'cpe',
    'cpe_evidence', 'company_name', 'product_name', 'native_soname',
    'native_build_id', 'source_artifact', 'source_parser', 'dependency_scope',
    'sha256', 'evidence_paths', 'declared_licenses', 'declared_publishers');
  StringFields: array[0..14] of string = (
    'component_type', 'name', 'version', 'ecosystem', 'package_url', 'cpe',
    'cpe_evidence', 'company_name', 'product_name', 'native_soname',
    'native_build_id', 'source_artifact', 'source_parser', 'dependency_scope',
    'sha256');
var
  I: Integer;
  Value: string;
  Values: TJSONArray;
begin
  Result := False;
  AComponent := nil;
  if not ObjectHasOnlyMembers(AObject, Allowed) then
    Exit;
  for I := Low(StringFields) to High(StringFields) do
    if not ReadJSONString(AObject, StringFields[I], False, Value) then
      Exit;
  if not ReadJSONString(AObject, 'component_type', True, Value) or
    not ReadJSONString(AObject, 'name', True, Value) or
    not ReadJSONString(AObject, 'ecosystem', True, Value) or
    not ReadJSONString(AObject, 'source_artifact', True, Value) or
    not ReadJSONString(AObject, 'source_parser', True, Value) then
    Exit;
  if not ReadJSONArray(AObject, 'evidence_paths', Values) or
    not ValidateStringListJSON(Values) then
    Exit;
  if AObject.Find('declared_licenses') <> nil then
    if not ReadJSONArray(AObject, 'declared_licenses', Values) or
      not ValidateStringListJSON(Values) then
      Exit;
  if AObject.Find('declared_publishers') <> nil then
    if not ReadJSONArray(AObject, 'declared_publishers', Values) or
      not ValidateStringListJSON(Values) then
      Exit;
  try
    AComponent := TComponent.Create;
    ReadJSONString(AObject, 'component_type', False,
      AComponent.ComponentType);
    ReadJSONString(AObject, 'name', False, AComponent.Name);
    ReadJSONString(AObject, 'version', False, AComponent.Version);
    ReadJSONString(AObject, 'ecosystem', False, AComponent.Ecosystem);
    ReadJSONString(AObject, 'package_url', False, AComponent.PackageURL);
    ReadJSONString(AObject, 'cpe', False, AComponent.CPE);
    ReadJSONString(AObject, 'cpe_evidence', False, AComponent.CPEEvidence);
    ReadJSONString(AObject, 'company_name', False, AComponent.CompanyName);
    ReadJSONString(AObject, 'product_name', False, AComponent.ProductName);
    ReadJSONString(AObject, 'native_soname', False, AComponent.NativeSONAME);
    ReadJSONString(AObject, 'native_build_id', False,
      AComponent.NativeBuildID);
    ReadJSONString(AObject, 'source_artifact', False,
      AComponent.SourceArtifact);
    ReadJSONString(AObject, 'source_parser', False,
      AComponent.SourceParser);
    ReadJSONString(AObject, 'dependency_scope', False,
      AComponent.DependencyScope);
    ReadJSONString(AObject, 'sha256', False, AComponent.SHA256);
    ReadJSONArray(AObject, 'evidence_paths', Values);
    JSONStringsToList(Values, AComponent.EvidencePaths);
    if ReadJSONArray(AObject, 'declared_licenses', Values) then
      JSONStringsToList(Values, AComponent.DeclaredLicenses);
    if ReadJSONArray(AObject, 'declared_publishers', Values) then
      JSONStringsToList(Values, AComponent.DeclaredPublishers);
    Result := ValidateComponentModel(AComponent, ARelativePath,
      AContentSHA256);
    if not Result then
      FreeAndNil(AComponent);
  except
    FreeAndNil(AComponent);
    Result := False;
  end;
end;

{**
  Parses and validates one cached artifact object.

  Parameters
  ----------
  AObject
    Borrowed JSON object to decode.
  ARelativePath
    Entry path required by the artifact.
  AContentSHA256
    Entry digest permitted in artifact hash evidence.
  AExpectedSize
    Size decoded from the verified identity.
  AComponentCount
    Parsed component count required by artifact metadata.
  AArtifact
    Receives a caller-owned artifact on success, otherwise nil.

  Returns
  -------
  Boolean
    True only when schema, types, bounds, and model invariants are valid.

  Raises
  ------
  EOutOfMemory
    Propagated if the artifact cannot be allocated.
*}
function ValidateArtifactJSON(AObject: TJSONObject;
  const ARelativePath, AContentSHA256: string; AExpectedSize: Int64;
  AComponentCount: Integer; out AArtifact: TArtifact): Boolean;
const
  Allowed: array[0..8] of string = (
    'relative_path', 'artifact_type', 'ecosystem', 'status', 'parser',
    'file_size', 'sha256', 'message', 'component_count');
  StringFields: array[0..6] of string = (
    'relative_path', 'artifact_type', 'ecosystem', 'status', 'parser',
    'sha256', 'message');
var
  I: Integer;
  Value, StatusValue: string;
  IntegerValue, FileSizeValue, ComponentCountValue: Int64;
begin
  Result := False;
  AArtifact := nil;
  if (AObject = nil) or (AObject.Find('absolute_path') <> nil) or
    not ObjectHasOnlyMembers(AObject, Allowed) then
    Exit;
  for I := Low(StringFields) to High(StringFields) do
    if not ReadJSONString(AObject, StringFields[I],
      I <= 4, Value) then
      Exit;
  if not ReadJSONString(AObject, 'status', True, StatusValue) or
    ((StatusValue <> 'parsed') and (StatusValue <> 'partially parsed') and
     (StatusValue <> 'detected but unsupported') and
     (StatusValue <> 'failed')) then
    Exit;
  if not ReadJSONInteger(AObject, 'file_size', IntegerValue) or
    (IntegerValue < 0) then
    Exit;
  FileSizeValue := IntegerValue;
  if not ReadJSONInteger(AObject, 'component_count', IntegerValue) or
    (IntegerValue < 0) or (IntegerValue > MaximumScanCacheComponentsPerEntry) then
    Exit;
  ComponentCountValue := IntegerValue;
  try
    AArtifact := TArtifact.Create;
    ReadJSONString(AObject, 'relative_path', False, AArtifact.RelativePath);
    ReadJSONString(AObject, 'artifact_type', False, AArtifact.ArtifactType);
    ReadJSONString(AObject, 'ecosystem', False, AArtifact.Ecosystem);
    AArtifact.Status := StringToArtifactStatus(StatusValue);
    ReadJSONString(AObject, 'parser', False, AArtifact.ParserName);
    AArtifact.FileSize := FileSizeValue;
    ReadJSONString(AObject, 'sha256', False, AArtifact.SHA256);
    ReadJSONString(AObject, 'message', False, AArtifact.MessageText);
    AArtifact.ComponentCount := ComponentCountValue;
    Result := ValidateArtifactModel(AArtifact, ARelativePath, AContentSHA256,
      AExpectedSize, AComponentCount);
    if not Result then
      FreeAndNil(AArtifact);
  except
    FreeAndNil(AArtifact);
    Result := False;
  end;
end;

{**
  Parses and validates the complete persisted cache context.

  Parameters
  ----------
  AObject
    Borrowed JSON context object.
  AContext
    Receives decoded context fields on success.

  Returns
  -------
  Boolean
    True only for the exact schema and valid bounded field values.

  Raises
  ------
  EOutOfMemory
    Propagated if decoded fields cannot be allocated.
*}
function ValidateContextJSON(AObject: TJSONObject;
  out AContext: TScanCacheContext): Boolean;
const
  Allowed: array[0..5] of string = (
    'analysis_contract', 'platform', 'profile_path_sha256', 'root_path_sha256',
    'root_identity_token', 'settings_sha256');
begin
  AContext.AnalysisContract := '';
  AContext.Platform := '';
  AContext.ProfilePathSHA256 := '';
  AContext.RootPathSHA256 := '';
  AContext.RootIdentityToken := '';
  AContext.SettingsSHA256 := '';
  Result := ObjectHasOnlyMembers(AObject, Allowed) and
    ReadJSONString(AObject, 'analysis_contract', True,
      AContext.AnalysisContract) and
    ReadJSONString(AObject, 'platform', True, AContext.Platform) and
    ReadJSONString(AObject, 'profile_path_sha256', True,
      AContext.ProfilePathSHA256) and
    ReadJSONString(AObject, 'root_path_sha256', True,
      AContext.RootPathSHA256) and
    ReadJSONString(AObject, 'root_identity_token', True,
      AContext.RootIdentityToken) and
    ReadJSONString(AObject, 'settings_sha256', True,
      AContext.SettingsSHA256);
  if Result then
    try
      RequireValidContext(AContext);
    except
      Result := False;
    end;
end;

{**
  Parses one complete positive or negative cache entry transactionally.

  Parameters
  ----------
  AObject
    Borrowed JSON entry object.
  AEntry
    Receives a caller-owned entry on success, otherwise nil.
  AComponentCount
    Receives the number of validated components, otherwise zero.

  Returns
  -------
  Boolean
    True only when schema, identity, evidence, and all limits are valid.

  Raises
  ------
  EOutOfMemory
    Propagated if model or entry allocation fails.
*}
function ParseEntry(AObject: TJSONObject; out AEntry: TScanCacheEntry;
  out AComponentCount: Integer): Boolean;
const
  Allowed: array[0..6] of string = (
    'relative_path', 'identity', 'sha256', 'artifact', 'components',
    'inspection_tools', 'warnings');
var
  RelativePath, IdentityHex, ContentSHA256: string;
  ArtifactObject, ComponentObject: TJSONObject;
  ArtifactData: TJSONData;
  ComponentsArray, InspectionToolsArray, WarningsArray: TJSONArray;
  Artifact: TArtifact;
  Component: TComponent;
  Components: TObjectList;
  InspectionTools, Warnings: TStringList;
  Evidence: TScanCacheEvidence;
  Size: Int64;
  I: Integer;
begin
  Result := False;
  AEntry := nil;
  AComponentCount := 0;
  if not ObjectHasOnlyMembers(AObject, Allowed) or
    not ReadJSONString(AObject, 'relative_path', True, RelativePath) or
    not ReadJSONString(AObject, 'identity', True, IdentityHex) or
    not ReadJSONString(AObject, 'sha256', True, ContentSHA256) or
    not ReadJSONArray(AObject, 'components', ComponentsArray) or
    not ReadJSONArray(AObject, 'inspection_tools', InspectionToolsArray) or
    not ValidateStringListJSON(InspectionToolsArray) or
    not ReadJSONArray(AObject, 'warnings', WarningsArray) or
    not ValidateStringListJSON(WarningsArray) or
    not IsSafeRelativePath(RelativePath) or
    not IdentitySize(IdentityHex, Size) or not IsSHA256(ContentSHA256) or
    (ComponentsArray.Count > MaximumScanCacheComponentsPerEntry) then
    Exit;

  Artifact := nil;
  Components := TObjectList.Create(True);
  InspectionTools := TStringList.Create;
  Warnings := TStringList.Create;
  Evidence := nil;
  try
    for I := 0 to ComponentsArray.Count - 1 do
    begin
      if ComponentsArray.Items[I].JSONType <> jtObject then
        Exit;
      ComponentObject := TJSONObject(ComponentsArray.Items[I]);
      Component := nil;
      if not ValidateComponentJSON(ComponentObject, RelativePath,
        ContentSHA256, Component) then
        Exit;
      Components.Add(Component);
    end;
    ArtifactData := AObject.Find('artifact');
    if ArtifactData = nil then
      Exit;
    if ArtifactData.JSONType = jtObject then
    begin
      ArtifactObject := TJSONObject(ArtifactData);
      if not ValidateArtifactJSON(ArtifactObject, RelativePath, ContentSHA256,
        Size, Components.Count, Artifact) then
        Exit;
    end
    else if (ArtifactData.JSONType <> jtNull) or (Components.Count <> 0) then
      Exit;
    JSONStringsToList(InspectionToolsArray, InspectionTools);
    JSONStringsToList(WarningsArray, Warnings);
    Evidence := TScanCacheEvidence.Create(Artifact, Components,
      InspectionTools, Warnings);
    AEntry := TScanCacheEntry.Create(RelativePath, IdentityHex,
      ContentSHA256, Evidence);
    Evidence := nil;
    AComponentCount := Components.Count;
    Result := True;
  finally
    Evidence.Free;
    Warnings.Free;
    InspectionTools.Free;
    Components.Free;
    Artifact.Free;
    if not Result then
      FreeAndNil(AEntry);
  end;
end;

constructor TScanCache.Create(AMode: TScanCacheMode;
  const AProfileDirectory: string; const AContext: TScanCacheContext;
  const ACacheFileName: string);
begin
  inherited Create;
  RequireValidContext(AContext);
  if (AMode <> scmDisabled) and (Trim(AProfileDirectory) = '') then
    raise EArgumentException.Create('Scan-cache profile directory is empty');
  if not IsSingleLeafName(ACacheFileName) then
    raise EArgumentException.Create('Scan-cache filename must be one safe leaf');
  FMode := AMode;
  if Trim(AProfileDirectory) <> '' then
    FProfileDirectory := ExpandFileName(AProfileDirectory);
  if (FProfileDirectory <> '') and
    (ScanCacheProfilePathSHA256(FProfileDirectory) <>
      AContext.ProfilePathSHA256) then
    raise EArgumentException.Create('Scan-cache context does not match the ' +
      'selected profile path');
  FCacheFileName := ACacheFileName;
  FContext := AContext;
  FLoadedEntries := TObjectList.Create(True);
  FStagedEntries := TObjectList.Create(True);
  InitCriticalSection(FLoadedLock);
  FLoadedLockInitialized := True;
  FStagingValid := True;
end;

destructor TScanCache.Destroy;
begin
  FStagedEntries.Free;
  if FLoadedLockInitialized then
    DoneCriticalSection(FLoadedLock);
  FLoadedEntries.Free;
  FProfilePin.Free;
  inherited Destroy;
end;

function TScanCache.EnsureProfilePin(ACreateDirectory: Boolean;
  out ADiagnostic: string): Boolean;
var
  Pin: TPinnedDirectory;
begin
  Result := False;
  ADiagnostic := '';
  if FProfilePin <> nil then
  begin
    try
      FProfilePin.VerifyCurrentPath;
      Exit(True);
    except
      on E: Exception do
      begin
        ADiagnostic := 'Rescan cache profile is no longer stable: ' + E.Message;
        Exit(False);
      end;
    end;
  end;
  if not DirectoryExists(FProfileDirectory) then
  begin
    if not ACreateDirectory then
      Exit(False);
    if not ForceDirectories(FProfileDirectory) then
    begin
      ADiagnostic := 'Unable to create the rescan-cache profile directory.';
      Exit(False);
    end;
  end;
  try
    Pin := PinExistingDirectory(FProfileDirectory);
    if ScanCacheProfilePathSHA256(Pin.DirectoryName) <>
      FContext.ProfilePathSHA256 then
    begin
      Pin.Free;
      ADiagnostic := 'Rescan-cache profile binding changed before pinning.';
      Exit(False);
    end;
    FProfilePin := Pin;
    FProfileDirectory := Pin.DirectoryName;
    Result := True;
  except
    on E: Exception do
      ADiagnostic := 'Unable to pin the rescan-cache profile: ' + E.Message;
  end;
end;

function TScanCache.FindEntry(AEntries: TObjectList;
  const ARelativePath: string): TObject;
var
  I: Integer;
begin
  Result := nil;
  if AEntries = nil then
    Exit;
  for I := 0 to AEntries.Count - 1 do
    if TScanCacheEntry(AEntries[I]).FRelativePath = ARelativePath then
      Exit(TScanCacheEntry(AEntries[I]));
end;

function TScanCache.Load(out ADiagnostic: string): Boolean;
const
  RootAllowed: array[0..3] of string = (
    'format', 'format_version', 'context', 'entries');
var
  CachePath, Reason, FormatName: string;
  RawContent: RawByteString;
  Identity: TVerifiedFileIdentity;
  Input: TVerifiedInput;
  Data: TJSONData;
  Root, ContextObject: TJSONObject;
  EntriesArray: TJSONArray;
  LoadedContext: TScanCacheContext;
  Entry: TScanCacheEntry;
  ParsedEntries: TObjectList;
  VersionValue: Int64;
  NodeCount, ComponentCount, TotalComponents, I: Integer;
begin
  Result := False;
  ADiagnostic := '';
  EnterCriticalSection(FLoadedLock);
  try
    FLoadedEntries.Clear;
  finally
    LeaveCriticalSection(FLoadedLock);
  end;
  if FMode <> scmUse then
    Exit;
  if not EnsureProfilePin(False, ADiagnostic) then
    Exit;
  CachePath := IncludeTrailingPathDelimiter(FProfileDirectory) +
    FCacheFileName;
  if not FileExists(CachePath) then
  begin
    if DirectoryExists(CachePath) or IsSymbolicLink(CachePath) then
      ADiagnostic := 'Rescan cache ignored: cache path is not a regular file.';
    Exit;
  end;
  if not TryCaptureVerifiedFileIdentity(CachePath, FProfileDirectory, False,
    Identity, Reason) then
  begin
    ADiagnostic := 'Rescan cache ignored: cache file could not be verified: ' +
      Reason;
    Exit;
  end;
  if Identity.Size > MaximumScanCacheBytes then
  begin
    ADiagnostic := Format('Rescan cache ignored: cache file exceeds the %d ' +
      'byte limit.', [MaximumScanCacheBytes]);
    Exit;
  end;
  if not TryOpenVerifiedInput(CachePath, FProfileDirectory, False, Identity,
    Input, Reason) then
  begin
    ADiagnostic := 'Rescan cache ignored: cache file changed before loading: ' +
      Reason;
    Exit;
  end;

  Data := nil;
  ParsedEntries := TObjectList.Create(True);
  try
    try
      if not ReadVerifiedJSONBytes(Input, RawContent) then
        raise EReadError.Create('cache bytes could not be read exactly');
      if not IsValidUTF8Bytes(RawContent) then
        raise EJSONParser.Create('raw JSON is not valid UTF-8');
      if not PreflightRawJSON(RawContent) then
        raise EJSONParser.Create('raw JSON depth, token count, or string ' +
          'structure is invalid');
      Data := ParseStrictUTF8JSON(RawContent);
      if not Input.ValidateStable(Reason) then
        raise EInOutError.Create(Reason);
      FProfilePin.VerifyCurrentPath;

      NodeCount := 0;
      if (Data.JSONType <> jtObject) or
        not ValidateJSONBounds(Data, 0, NodeCount) then
        raise EJSONParser.Create('root or value bounds are invalid');
      Root := TJSONObject(Data);
      if not ObjectHasOnlyMembers(Root, RootAllowed) or
        not ReadJSONString(Root, 'format', True, FormatName) or
        (FormatName <> ScanCacheFormatName) or
        not ReadJSONInteger(Root, 'format_version', VersionValue) or
        (VersionValue <> ScanCacheFormatVersion) or
        not ReadJSONObject(Root, 'context', ContextObject) or
        not ValidateContextJSON(ContextObject, LoadedContext) or
        not ReadJSONArray(Root, 'entries', EntriesArray) or
        (EntriesArray.Count > MaximumScanCacheEntries) then
        raise EJSONParser.Create('document schema is invalid');

      { A valid snapshot for another root/profile/settings/analysis contract
        is an ordinary miss, not a malformed-cache warning. }
      if not ContextsEqual(LoadedContext, FContext) then
        Exit(False);

      TotalComponents := 0;
      for I := 0 to EntriesArray.Count - 1 do
      begin
        if EntriesArray.Items[I].JSONType <> jtObject then
          raise EJSONParser.Create('entry is not an object');
        Entry := nil;
        if not ParseEntry(TJSONObject(EntriesArray.Items[I]), Entry,
          ComponentCount) then
          raise EJSONParser.Create('entry evidence is invalid');
        try
          if FindEntry(ParsedEntries, Entry.FRelativePath) <> nil then
            raise EJSONParser.Create('duplicate relative path');
          if TotalComponents > MaximumScanCacheComponents - ComponentCount then
            raise EJSONParser.Create('component limit exceeded');
          Inc(TotalComponents, ComponentCount);
          ParsedEntries.Add(Entry);
          Entry := nil;
        finally
          Entry.Free;
        end;
      end;

      EnterCriticalSection(FLoadedLock);
      try
        while ParsedEntries.Count > 0 do
          FLoadedEntries.Add(ParsedEntries.Extract(ParsedEntries[0]));
      finally
        LeaveCriticalSection(FLoadedLock);
      end;
      Result := True;
    except
      on E: Exception do
      begin
        EnterCriticalSection(FLoadedLock);
        try
          FLoadedEntries.Clear;
        finally
          LeaveCriticalSection(FLoadedLock);
        end;
        ADiagnostic := 'Rescan cache ignored: malformed or unstable cache ' +
          'data (' + E.Message + ').';
        Result := False;
      end;
    end;
  finally
    ParsedEntries.Free;
    Data.Free;
    Input.Free;
  end;
end;

function TScanCache.TryLookup(const ARelativePath: string;
  const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
  out AEvidence: TScanCacheEvidence): Boolean;
var
  Entry: TScanCacheEntry;
  IdentityHex: string;
begin
  AEvidence := nil;
  if FMode <> scmUse then
    Exit(False);
  if not IsSafeRelativePath(ARelativePath) or
    not IsSHA256(AContentSHA256) then
    Exit(False);
  IdentityHex := EncodeVerifiedFileIdentity(AIdentity);
  if IdentityHex = '' then
    Exit(False);
  EnterCriticalSection(FLoadedLock);
  try
    Entry := TScanCacheEntry(FindEntry(FLoadedEntries, ARelativePath));
    Result := (Entry <> nil) and (Entry.FIdentityHex = IdentityHex) and
      (Entry.FContentSHA256 = AContentSHA256);
    if Result then
      AEvidence := Entry.FEvidence.Clone;
  finally
    LeaveCriticalSection(FLoadedLock);
  end;
end;

function TScanCache.Stage(const ARelativePath: string;
  const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
  AArtifact: TArtifact; AComponents: TObjectList;
  out ADiagnostic: string): Boolean;
begin
  Result := Stage(ARelativePath, AIdentity, AContentSHA256, AArtifact,
    AComponents, nil, nil, ADiagnostic);
end;

function TScanCache.Stage(const ARelativePath: string;
  const AIdentity: TVerifiedFileIdentity; const AContentSHA256: string;
  AArtifact: TArtifact; AComponents: TObjectList;
  AInspectionTools, AWarnings: TStrings;
  out ADiagnostic: string): Boolean;
var
  IdentityHex: string;
  Evidence: TScanCacheEvidence;
  Entry: TScanCacheEntry;
  I: Integer;
begin
  Result := False;
  ADiagnostic := '';
  if FMode = scmDisabled then
    Exit(True);
  if not FStagingValid then
  begin
    ADiagnostic := 'Rescan-cache staging was already invalidated.';
    Exit;
  end;
  IdentityHex := EncodeVerifiedFileIdentity(AIdentity);
  if not IsSafeRelativePath(ARelativePath) or (IdentityHex = '') or
    not IsSHA256(AContentSHA256) or (AComponents = nil) or
    (AComponents.Count > MaximumScanCacheComponentsPerEntry) or
    (FStagedEntries.Count >= MaximumScanCacheEntries) or
    (FStagedComponentCount > MaximumScanCacheComponents - AComponents.Count) or
    (FindEntry(FStagedEntries, ARelativePath) <> nil) then
  begin
    FStagingValid := False;
    ADiagnostic := 'Rescan-cache staging rejected an invalid or over-limit ' +
      'entry.';
    Exit;
  end;
  if ((AArtifact = nil) and (AComponents.Count <> 0)) or
    ((AArtifact <> nil) and not ValidateArtifactModel(AArtifact,
      ARelativePath, AContentSHA256, AIdentity.Size, AComponents.Count)) or
    not ValidateCachedStrings(AInspectionTools, MaximumScanCacheListValues) or
    not ValidateCachedStrings(AWarnings, MaximumScanCacheListValues) then
  begin
    FStagingValid := False;
    ADiagnostic := 'Rescan-cache staging rejected inconsistent artifact ' +
      'evidence.';
    Exit;
  end;
  for I := 0 to AComponents.Count - 1 do
    if not (AComponents[I] is TComponent) or
      not ValidateComponentModel(TComponent(AComponents[I]),
        ARelativePath, AContentSHA256) then
    begin
      FStagingValid := False;
      ADiagnostic := 'Rescan-cache staging rejected invalid component evidence.';
      Exit;
    end;

  Evidence := nil;
  Entry := nil;
  try
    Evidence := TScanCacheEvidence.Create(AArtifact, AComponents,
      AInspectionTools, AWarnings);
    Entry := TScanCacheEntry.Create(ARelativePath, IdentityHex,
      AContentSHA256, Evidence);
    Evidence := nil;
    FStagedEntries.Add(Entry);
    Entry := nil;
    Inc(FStagedComponentCount, AComponents.Count);
    Result := True;
  except
    on E: Exception do
    begin
      FStagingValid := False;
      ADiagnostic := 'Rescan-cache staging failed: ' + E.Message;
    end;
  end;
  Entry.Free;
  Evidence.Free;
end;

procedure TScanCache.ResetStaging;
begin
  FStagedEntries.Clear;
  FStagedComponentCount := 0;
  FStagingValid := True;
end;

function TScanCache.BuildDocument(out AContent: UTF8String;
  out ADiagnostic: string): Boolean;
var
  Root, ContextObject, EntryObject: TJSONObject;
  Entries, Components, InspectionTools, Warnings: TJSONArray;
  Entry: TScanCacheEntry;
  I, J, NodeCount: Integer;
begin
  Result := False;
  AContent := '';
  ADiagnostic := '';
  Root := TJSONObject.Create;
  try
    try
      AddCacheString(Root, 'format', ScanCacheFormatName);
      Root.Add('format_version', ScanCacheFormatVersion);
      ContextObject := TJSONObject.Create;
      AddCacheString(ContextObject, 'analysis_contract',
        FContext.AnalysisContract);
      AddCacheString(ContextObject, 'platform', FContext.Platform);
      AddCacheString(ContextObject, 'profile_path_sha256',
        FContext.ProfilePathSHA256);
      AddCacheString(ContextObject, 'root_path_sha256',
        FContext.RootPathSHA256);
      AddCacheString(ContextObject, 'root_identity_token',
        FContext.RootIdentityToken);
      AddCacheString(ContextObject, 'settings_sha256',
        FContext.SettingsSHA256);
      Root.Add('context', ContextObject);
      Entries := TJSONArray.Create;
      Root.Add('entries', Entries);
      for I := 0 to FStagedEntries.Count - 1 do
      begin
        Entry := TScanCacheEntry(FStagedEntries[I]);
        EntryObject := TJSONObject.Create;
        AddCacheString(EntryObject, 'relative_path', Entry.FRelativePath);
        AddCacheString(EntryObject, 'identity', Entry.FIdentityHex);
        AddCacheString(EntryObject, 'sha256', Entry.FContentSHA256);
        if Entry.FEvidence.Artifact <> nil then
          EntryObject.Add('artifact',
            ArtifactToCacheJSON(Entry.FEvidence.Artifact))
        else
          EntryObject.Add('artifact', TJSONNull.Create);
        Components := TJSONArray.Create;
        for J := 0 to Entry.FEvidence.Components.Count - 1 do
          Components.Add(ComponentToCacheJSON(
            TComponent(Entry.FEvidence.Components[J])));
        EntryObject.Add('components', Components);
        InspectionTools := TJSONArray.Create;
        StringsToJSONArray(Entry.FEvidence.InspectionTools, InspectionTools);
        EntryObject.Add('inspection_tools', InspectionTools);
        Warnings := TJSONArray.Create;
        StringsToJSONArray(Entry.FEvidence.Warnings, Warnings);
        EntryObject.Add('warnings', Warnings);
        Entries.Add(EntryObject);
      end;
      NodeCount := 0;
      if not ValidateJSONBounds(Root, 0, NodeCount) then
      begin
        ADiagnostic := 'Rescan-cache snapshot exceeds the JSON node, depth, ' +
          'or string bounds.';
        Exit;
      end;
      AContent := UTF8String(Root.AsJSON);
      if Length(AContent) > MaximumScanCacheBytes then
      begin
        ADiagnostic := Format(
          'Rescan-cache snapshot exceeds the %d byte limit.',
          [MaximumScanCacheBytes]);
        Exit;
      end;
      if not IsValidUTF8Bytes(RawByteString(AContent)) then
      begin
        ADiagnostic := 'Rescan-cache snapshot contains invalid UTF-8.';
        Exit;
      end;
      if not PreflightRawJSON(RawByteString(AContent)) then
      begin
        ADiagnostic := 'Rescan-cache snapshot exceeds the raw JSON depth or ' +
          'token bound.';
        Exit;
      end;
      Result := True;
    except
      on E: Exception do
        ADiagnostic := 'Unable to serialize the rescan cache: ' + E.Message;
    end;
  finally
    Root.Free;
  end;
end;

function TScanCache.Commit(out ADiagnostic: string): Boolean;
var
  Content: UTF8String;
  I: Integer;
begin
  ADiagnostic := '';
  if FMode = scmDisabled then
    Exit(True);
  if not FStagingValid then
  begin
    ADiagnostic := 'Rescan-cache snapshot is incomplete and was not committed.';
    Exit(False);
  end;
  if not BuildDocument(Content, ADiagnostic) then
    Exit(False);
  if not EnsureProfilePin(True, ADiagnostic) then
    Exit(False);
  try
    WriteAtomicCache(FProfilePin, FCacheFileName, Content);
  except
    on E: Exception do
    begin
      ADiagnostic := 'Unable to atomically commit the rescan cache: ' +
        E.Message;
      Exit(False);
    end;
  end;

  EnterCriticalSection(FLoadedLock);
  try
    FLoadedEntries.Clear;
    try
      for I := 0 to FStagedEntries.Count - 1 do
        FLoadedEntries.Add(TScanCacheEntry(FStagedEntries[I]).Clone);
    except
      { The disk snapshot is already durable. An in-memory clone failure merely
        disables later hits in this session and never invalidates the commit. }
      FLoadedEntries.Clear;
    end;
  finally
    LeaveCriticalSection(FLoadedLock);
  end;
  Result := True;
end;

end.
