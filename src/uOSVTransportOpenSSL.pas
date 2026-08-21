(**
  PurpleRay SBOM Analyzer Linux OSV transport.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Linux boundary
  --------------
  This LCL-free unit dynamically loads the OS-provided GIO 2 resolver runtime
  and OpenSSL 3.  GIO supplies bounded, cancellable DNS resolution.  TCP,
  TLS, and HTTP are implemented here over a nonblocking socket.  The transport
  fails closed unless all required symbols, the system trust paths, SNI,
  TLS >= 1.2, peer-chain verification, and X509_check_host are available.
  It never invokes an external command and never follows a redirect.
*)
unit uOSVTransportOpenSSL;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uOSVCore
  {$IFDEF Linux}, Dynlibs{$ENDIF};

const
  OSVOpenSSLDNSTimeoutMS = 5000;
  OSVOpenSSLConnectTimeoutMS = 3000;
  OSVOpenSSLIOTimeoutMS = 5000;
  OSVOpenSSLTotalTimeoutMS = 30000;

type
  EOSVOpenSSLTransportUnavailable = class(Exception);

  {$IFDEF Linux}
  TOSVGAsyncReadyCallback = procedure(ASourceObject, AResult,
    AUserData: Pointer); cdecl;

  TOSVGIOAPI = record
    GioLibrary: TLibHandle;
    GObjectLibrary: TLibHandle;
    GLibLibrary: TLibHandle;
    CancellableNew: function: Pointer; cdecl;
    CancellableCancel: procedure(ACancellable: Pointer); cdecl;
    ResolverGetDefault: function: Pointer; cdecl;
    ResolverLookupByNameAsync: procedure(AResolver: Pointer; AHost: PChar;
      ACancellable: Pointer; ACallback: TOSVGAsyncReadyCallback;
      AUserData: Pointer); cdecl;
    ResolverLookupByNameFinish: function(AResolver, AResult: Pointer;
      AError: PPointer): Pointer; cdecl;
    ResolverFreeAddresses: procedure(AAddresses: Pointer); cdecl;
    InetAddressGetFamily: function(AAddress: Pointer): LongInt; cdecl;
    InetAddressToBytes: function(AAddress: Pointer): PByte; cdecl;
    ObjectRef: function(AObject: Pointer): Pointer; cdecl;
    ObjectUnref: procedure(AObject: Pointer); cdecl;
    ErrorFree: procedure(AError: Pointer); cdecl;
    MainContextNew: function: Pointer; cdecl;
    MainContextPushThreadDefault: procedure(AContext: Pointer); cdecl;
    MainContextPopThreadDefault: procedure(AContext: Pointer); cdecl;
    MainContextIteration: function(AContext: Pointer;
      AMayBlock: LongInt): LongInt; cdecl;
    MainContextUnref: procedure(AContext: Pointer); cdecl;
  end;

  TOSVOpenSSLAPI = record
    SSLLibrary: TLibHandle;
    CryptoLibrary: TLibHandle;
    InitSSL: function(AOptions: QWord; ASettings: Pointer): LongInt; cdecl;
    TLSClientMethod: function: Pointer; cdecl;
    ContextNew: function(AMethod: Pointer): Pointer; cdecl;
    ContextFree: procedure(AContext: Pointer); cdecl;
    ContextControl: function(AContext: Pointer; ACommand: LongInt;
      ALongArgument: PtrInt; APointerArgument: Pointer): PtrInt; cdecl;
    ContextSetVerify: procedure(AContext: Pointer; AMode: LongInt;
      ACallback: Pointer); cdecl;
    ContextSetDefaultVerifyPaths: function(AContext: Pointer): LongInt; cdecl;
    SSLNew: function(AContext: Pointer): Pointer; cdecl;
    SSLFree: procedure(ASSL: Pointer); cdecl;
    SSLSetFD: function(ASSL: Pointer; AFileDescriptor: LongInt): LongInt;
      cdecl;
    SSLControl: function(ASSL: Pointer; ACommand: LongInt;
      ALongArgument: PtrInt; APointerArgument: Pointer): PtrInt; cdecl;
    SSLGet0Param: function(ASSL: Pointer): Pointer; cdecl;
    SSLConnect: function(ASSL: Pointer): LongInt; cdecl;
    SSLGetError: function(ASSL: Pointer; AReturnCode: LongInt): LongInt;
      cdecl;
    SSLGetVerifyResult: function(ASSL: Pointer): PtrUInt; cdecl;
    SSLGet1PeerCertificate: function(ASSL: Pointer): Pointer; cdecl;
    SSLRead: function(ASSL, ABuffer: Pointer; ALength: LongInt): LongInt;
      cdecl;
    SSLWrite: function(ASSL: Pointer; const ABuffer: Pointer;
      ALength: LongInt): LongInt; cdecl;
    VerifyParamSetHostFlags: procedure(AParameter: Pointer;
      AFlags: Cardinal); cdecl;
    VerifyParamSet1Host: function(AParameter: Pointer; AName: PChar;
      ANameLength: SizeUInt): LongInt; cdecl;
    X509CheckHost: function(ACertificate: Pointer; AName: PChar;
      ANameLength: SizeUInt; AFlags: Cardinal; APeerName: PPChar): LongInt;
      cdecl;
    X509Free: procedure(ACertificate: Pointer); cdecl;
  end;

  TOSVResolvedAddress = record
    Family: LongInt;
    Bytes: array[0..15] of Byte;
  end;
  TOSVResolvedAddressArray = array of TOSVResolvedAddress;
  {$ENDIF}

  { Verified Linux production transport.  One PostQueryBatch may be active at
    a time.  Cancel is safe from another thread: cancellable references and
    descriptor shutdown are serialized under FLock, while only the posting
    thread retires and closes its descriptor after freeing SSL. }
  TOSVOpenSSLTransport = class(TInterfacedObject, IOSVTransport)
  private
    FAvailable: Boolean;
    {$IFDEF Linux}
      FCallActive: Boolean;
      FCancelled: Boolean;
      FCancellable: Pointer;
      FGIO: TOSVGIOAPI;
      FLock: TRTLCriticalSection;
      FLockInitialized: Boolean;
      FOpenSSL: TOSVOpenSSLAPI;
      FResolver: Pointer;
      FSocket: LongInt;
      FTimedOut: Boolean;
    function BeginCall: Boolean;
    procedure EndCall(out AWasCancelled, AWasTimedOut: Boolean);
    procedure AbortActive(ACancelled, ATimedOut: Boolean);
    function Cancelled: Boolean;
    function TimedOut: Boolean;
    function SetActiveCancellable(ACancellable: Pointer): Boolean;
    procedure ClearActiveCancellable(ACancellable: Pointer);
    function SetActiveSocket(ASocket: LongInt): Boolean;
    procedure CloseActiveSocket(ASocket: LongInt);
    procedure LoadLibraries;
    procedure UnloadLibraries;
    function WaitForSocket(ASocket: LongInt; AWantRead: Boolean;
      ADeadline: QWord; ACancelCheck: TOSVCancelCheck): Boolean;
    function ResolveHost(ADeadline: QWord; ACancelCheck: TOSVCancelCheck;
      out AAddresses: TOSVResolvedAddressArray): Boolean;
    function ConnectAddress(const AAddress: TOSVResolvedAddress;
      ADeadline: QWord; ACancelCheck: TOSVCancelCheck): LongInt;
    function ConnectAny(const AAddresses: TOSVResolvedAddressArray;
      ADeadline: QWord; ACancelCheck: TOSVCancelCheck): LongInt;
    function SSLWait(ASSL: Pointer; AReturnCode, ASocket: LongInt;
      ADeadline: QWord; ACancelCheck: TOSVCancelCheck): Boolean;
    function CreateVerifiedSSL(ASocket: LongInt; ADeadline: QWord;
      ACancelCheck: TOSVCancelCheck; out AContext, ASSL: Pointer): Boolean;
    function SSLWriteAll(ASSL: Pointer; ASocket: LongInt;
      const AData: RawByteString; ADeadline: QWord;
      ACancelCheck: TOSVCancelCheck): Boolean;
    function SSLReadBounded(ASSL: Pointer; ASocket: LongInt;
      AMaximumBytes: Int64; ATotalDeadline: QWord;
      ACancelCheck: TOSVCancelCheck; out AData: RawByteString;
      out ATooLarge: Boolean): Boolean;
    {$ENDIF}
  public
    { Loads exact GIO 2 and OpenSSL 3 SONAMEs and every verification symbol.
      Raises EOSVOpenSSLTransportUnavailable instead of degrading policy. }
    constructor Create;
    destructor Destroy; override;
    { Posts only to https://api.osv.dev/v1/querybatch.  DNS, connect, TLS,
      send, receive, certificate, hostname, and HTTP-framing failures all
      fail closed as otoFailed; a body bound violation is
      otoResponseTooLarge.  No response bytes survive a failed decode. }
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    { May be called concurrently with PostQueryBatch.  It cancels the active
      GIO lookup and shuts down the registered TCP socket to wake the posting
      thread.  That thread frees SSL before it closes its owned descriptor. }
    procedure Cancel;
    property Available: Boolean read FAvailable;
    {$IFDEF Linux}
    {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
    { Ignored-probe hook: simulates the posting thread's socket ownership
      without resolving or contacting the production endpoint. }
    function TestBeginSocketOwnership(ASocket: LongInt): Boolean;
    procedure TestEndSocketOwnership(ASocket: LongInt;
      out AWasCancelled, AWasTimedOut: Boolean);
    function TestPollSocket(ASocket: LongInt; AWantRead: Boolean;
      ATimeoutMilliseconds: QWord): Boolean;
    function TestSIGPIPEResetSuppressed: Boolean;
    function TestUncleanTLSCloseRejected(
      const ACloseFramedResponse: RawByteString): Boolean;
    { Exercises an injected exception immediately after every acquisition in
      Create.  These hooks are absent from production builds. }
    class function TestConstructorAcquisitionCount: Integer; static;
    class function TestConstructorFailureAt(AIndex: Integer): Boolean;
      static;
    class function TestResolverStateAcquisitionCount: Integer; static;
    class function TestResolverStateFailureAt(AIndex: Integer): Boolean;
      static;
    class function TestResolverPumpAcquisitionCount: Integer; static;
    class function TestResolverPumpFailureAt(AIndex: Integer): Boolean;
      static;
    class function TestResolverPumpStartFailure: Boolean; static;
    {$ENDIF}
    {$ENDIF}
  end;

implementation

{$IFDEF Linux}

uses
  BaseUnix, Unix, Sockets;

const
  OSVHost = 'api.osv.dev';
  OSVPath = '/v1/querybatch';
  OSVPort = 443;
  MaximumResolvedAddresses = 64;
  MaximumHTTPHeaderBytes = 65536;
  MaximumHTTPFramingOverhead = 1024 * 1024;
  SSLVerifyPeer = 1;
  SSLControlSetMinProtocolVersion = 123;
  SSLControlSetTLSExtHostName = 55;
  TLS12Version = $0303;
  TLSExtNameTypeHostName = 0;
  SSLErrorWantRead = 2;
  SSLErrorWantWrite = 3;
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  SSLErrorSyscall = 5;
  {$ENDIF}
  SSLErrorZeroReturn = 6;
  X509VerifyOK = 0;
  X509CheckFlagNoPartialWildcards = 4;

type
  TOSVSSLReadAction = (osraFail, osraWantRead, osraWantWrite,
    osraCleanEOF);

  PGList = ^TGList;
  TGList = record
    Data: Pointer;
    Next: PGList;
    Previous: PGList;
  end;

  TOSVAsyncResolverState = class;

  TOSVResolverPumpThread = class(TThread)
  private
    FPump: LongInt;
    FState: TOSVAsyncResolverState;
  protected
    procedure Execute; override;
  public
    constructor Create(AState: TOSVAsyncResolverState);
    destructor Destroy; override;
    procedure StartPumping;
  end;

  TOSVAsyncResolverState = class
  private
    FAPI: TOSVGIOAPI;
    FCancellable: Pointer;
    FContext: Pointer;
    FDone: LongInt;
    FDoneEvent: PRTLEvent;
    FFatalOutOfMemory: Boolean;
    FOwner: TOSVOpenSSLTransport;
    FRefCount: LongInt;
    FResolver: Pointer;
    FSuccess: Boolean;
    procedure Complete;
    procedure HandleReady(ASourceObject, AResult: Pointer);
  public
    Addresses: TOSVResolvedAddressArray;
    constructor Create(AOwner: TOSVOpenSSLTransport);
    destructor Destroy; override;
    procedure AddRef;
    function Done: Boolean;
    procedure Iterate;
    procedure Release;
    procedure StartLookup;
    procedure WaitSlice(AMilliseconds: LongInt);
    property Cancellable: Pointer read FCancellable;
    property FatalOutOfMemory: Boolean read FFatalOutOfMemory;
    property Success: Boolean read FSuccess;
  end;

procedure GIOResolverReady(ASourceObject, AResult,
  AUserData: Pointer); cdecl; forward;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
var
  OpenSSLConstructorFailAt: Integer;
  OpenSSLConstructorAcquisitions: Integer;
  OpenSSLResolverPumpFailBeforeStart: Boolean;
{$ENDIF}

procedure ConstructorAcquired;
begin
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  Inc(OpenSSLConstructorAcquisitions);
  if OpenSSLConstructorAcquisitions = OpenSSLConstructorFailAt then
    raise EOSVOpenSSLTransportUnavailable.CreateFmt(
      'Injected OpenSSL transport constructor failure at acquisition %d',
      [OpenSSLConstructorAcquisitions]);
  {$ENDIF}
end;

function NativeSigPending(ASet: PSigSet): LongInt; cdecl;
  external name 'sigpending';

function RequiredSymbol(ALibrary: TLibHandle; const AName: PChar): Pointer;
begin
  Result := GetProcedureAddress(ALibrary, AName);
  if Result = nil then
    raise EOSVOpenSSLTransportUnavailable.CreateFmt(
      'Required OS transport symbol is unavailable: %s', [AName]);
  ConstructorAcquired;
end;

procedure TOSVOpenSSLTransport.LoadLibraries;
begin
  FillChar(FGIO, SizeOf(FGIO), 0);
  FillChar(FOpenSSL, SizeOf(FOpenSSL), 0);
  FGIO.GioLibrary := LoadLibrary('libgio-2.0.so.0');
  if FGIO.GioLibrary <> NilHandle then
    ConstructorAcquired;
  FGIO.GObjectLibrary := LoadLibrary('libgobject-2.0.so.0');
  if FGIO.GObjectLibrary <> NilHandle then
    ConstructorAcquired;
  FGIO.GLibLibrary := LoadLibrary('libglib-2.0.so.0');
  if FGIO.GLibLibrary <> NilHandle then
    ConstructorAcquired;
  FOpenSSL.SSLLibrary := LoadLibrary('libssl.so.3');
  if FOpenSSL.SSLLibrary <> NilHandle then
    ConstructorAcquired;
  FOpenSSL.CryptoLibrary := LoadLibrary('libcrypto.so.3');
  if FOpenSSL.CryptoLibrary <> NilHandle then
    ConstructorAcquired;
  if (FGIO.GioLibrary = NilHandle) or
    (FGIO.GObjectLibrary = NilHandle) or
    (FGIO.GLibLibrary = NilHandle) or
    (FOpenSSL.SSLLibrary = NilHandle) or
    (FOpenSSL.CryptoLibrary = NilHandle) then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'Required GIO 2 or OpenSSL 3 runtime is unavailable');

  Pointer(FGIO.CancellableNew) := RequiredSymbol(FGIO.GioLibrary,
    'g_cancellable_new');
  Pointer(FGIO.CancellableCancel) := RequiredSymbol(FGIO.GioLibrary,
    'g_cancellable_cancel');
  Pointer(FGIO.ResolverGetDefault) := RequiredSymbol(FGIO.GioLibrary,
    'g_resolver_get_default');
  Pointer(FGIO.ResolverLookupByNameAsync) := RequiredSymbol(
    FGIO.GioLibrary, 'g_resolver_lookup_by_name_async');
  Pointer(FGIO.ResolverLookupByNameFinish) := RequiredSymbol(
    FGIO.GioLibrary, 'g_resolver_lookup_by_name_finish');
  Pointer(FGIO.ResolverFreeAddresses) := RequiredSymbol(FGIO.GioLibrary,
    'g_resolver_free_addresses');
  Pointer(FGIO.InetAddressGetFamily) := RequiredSymbol(FGIO.GioLibrary,
    'g_inet_address_get_family');
  Pointer(FGIO.InetAddressToBytes) := RequiredSymbol(FGIO.GioLibrary,
    'g_inet_address_to_bytes');
  Pointer(FGIO.ObjectRef) := RequiredSymbol(FGIO.GObjectLibrary,
    'g_object_ref');
  Pointer(FGIO.ObjectUnref) := RequiredSymbol(FGIO.GObjectLibrary,
    'g_object_unref');
  Pointer(FGIO.ErrorFree) := RequiredSymbol(FGIO.GLibLibrary,
    'g_error_free');
  Pointer(FGIO.MainContextNew) := RequiredSymbol(FGIO.GLibLibrary,
    'g_main_context_new');
  Pointer(FGIO.MainContextPushThreadDefault) := RequiredSymbol(
    FGIO.GLibLibrary, 'g_main_context_push_thread_default');
  Pointer(FGIO.MainContextPopThreadDefault) := RequiredSymbol(
    FGIO.GLibLibrary, 'g_main_context_pop_thread_default');
  Pointer(FGIO.MainContextIteration) := RequiredSymbol(FGIO.GLibLibrary,
    'g_main_context_iteration');
  Pointer(FGIO.MainContextUnref) := RequiredSymbol(FGIO.GLibLibrary,
    'g_main_context_unref');

  Pointer(FOpenSSL.InitSSL) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'OPENSSL_init_ssl');
  Pointer(FOpenSSL.TLSClientMethod) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'TLS_client_method');
  Pointer(FOpenSSL.ContextNew) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_CTX_new');
  Pointer(FOpenSSL.ContextFree) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_CTX_free');
  Pointer(FOpenSSL.ContextControl) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_CTX_ctrl');
  Pointer(FOpenSSL.ContextSetVerify) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_CTX_set_verify');
  Pointer(FOpenSSL.ContextSetDefaultVerifyPaths) := RequiredSymbol(
    FOpenSSL.SSLLibrary, 'SSL_CTX_set_default_verify_paths');
  Pointer(FOpenSSL.SSLNew) := RequiredSymbol(FOpenSSL.SSLLibrary, 'SSL_new');
  Pointer(FOpenSSL.SSLFree) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_free');
  Pointer(FOpenSSL.SSLSetFD) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_set_fd');
  Pointer(FOpenSSL.SSLControl) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_ctrl');
  Pointer(FOpenSSL.SSLGet0Param) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_get0_param');
  Pointer(FOpenSSL.SSLConnect) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_connect');
  Pointer(FOpenSSL.SSLGetError) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_get_error');
  Pointer(FOpenSSL.SSLGetVerifyResult) := RequiredSymbol(
    FOpenSSL.SSLLibrary, 'SSL_get_verify_result');
  Pointer(FOpenSSL.SSLGet1PeerCertificate) := RequiredSymbol(
    FOpenSSL.SSLLibrary, 'SSL_get1_peer_certificate');
  Pointer(FOpenSSL.SSLRead) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_read');
  Pointer(FOpenSSL.SSLWrite) := RequiredSymbol(FOpenSSL.SSLLibrary,
    'SSL_write');
  Pointer(FOpenSSL.VerifyParamSetHostFlags) := RequiredSymbol(
    FOpenSSL.CryptoLibrary, 'X509_VERIFY_PARAM_set_hostflags');
  Pointer(FOpenSSL.VerifyParamSet1Host) := RequiredSymbol(
    FOpenSSL.CryptoLibrary, 'X509_VERIFY_PARAM_set1_host');
  Pointer(FOpenSSL.X509CheckHost) := RequiredSymbol(FOpenSSL.CryptoLibrary,
    'X509_check_host');
  Pointer(FOpenSSL.X509Free) := RequiredSymbol(FOpenSSL.CryptoLibrary,
    'X509_free');
  if FOpenSSL.InitSSL(0, nil) <> 1 then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'OpenSSL 3 initialization failed');
  ConstructorAcquired;
end;

procedure TOSVOpenSSLTransport.UnloadLibraries;
begin
  if FResolver <> nil then
  begin
    FGIO.ObjectUnref(FResolver);
    FResolver := nil;
  end;
  if FOpenSSL.CryptoLibrary <> NilHandle then
    UnloadLibrary(FOpenSSL.CryptoLibrary);
  if FOpenSSL.SSLLibrary <> NilHandle then
    UnloadLibrary(FOpenSSL.SSLLibrary);
  if FGIO.GLibLibrary <> NilHandle then
    UnloadLibrary(FGIO.GLibLibrary);
  if FGIO.GObjectLibrary <> NilHandle then
    UnloadLibrary(FGIO.GObjectLibrary);
  if FGIO.GioLibrary <> NilHandle then
    UnloadLibrary(FGIO.GioLibrary);
  FillChar(FOpenSSL, SizeOf(FOpenSSL), 0);
  FillChar(FGIO, SizeOf(FGIO), 0);
end;

constructor TOSVAsyncResolverState.Create(AOwner: TOSVOpenSSLTransport);
begin
  inherited Create;
  FRefCount := 1;
  if AOwner = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO resolver owner is unavailable');
  FOwner := AOwner;
  FOwner._AddRef;
  FAPI := FOwner.FGIO;
  ConstructorAcquired;
  FDoneEvent := RTLEventCreate;
  if FDoneEvent = nil then
    raise EOutOfMemory.Create('Unable to create resolver completion event');
  ConstructorAcquired;
  FContext := FAPI.MainContextNew();
  if FContext = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO resolver context creation failed');
  ConstructorAcquired;
  FCancellable := FAPI.CancellableNew();
  if FCancellable = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO cancellable creation failed');
  ConstructorAcquired;
  FResolver := FAPI.ObjectRef(FOwner.FResolver);
  if FResolver = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO resolver acquisition failed');
  ConstructorAcquired;
end;

destructor TOSVAsyncResolverState.Destroy;
var
  OwnerValue: TOSVOpenSSLTransport;
begin
  if FResolver <> nil then
    FAPI.ObjectUnref(FResolver);
  if FCancellable <> nil then
    FAPI.ObjectUnref(FCancellable);
  if FContext <> nil then
    FAPI.MainContextUnref(FContext);
  if FDoneEvent <> nil then
    RTLEventDestroy(FDoneEvent);
  OwnerValue := FOwner;
  FOwner := nil;
  if OwnerValue <> nil then
    OwnerValue._Release;
  inherited Destroy;
end;

procedure TOSVAsyncResolverState.AddRef;
begin
  InterlockedIncrement(FRefCount);
end;

procedure TOSVAsyncResolverState.Release;
begin
  if InterlockedDecrement(FRefCount) = 0 then
    Free;
end;

function TOSVAsyncResolverState.Done: Boolean;
begin
  Result := InterlockedCompareExchange(FDone, 0, 0) <> 0;
end;

procedure TOSVAsyncResolverState.Complete;
begin
  InterlockedExchange(FDone, 1);
  RTLEventSetEvent(FDoneEvent);
end;

procedure TOSVAsyncResolverState.WaitSlice(AMilliseconds: LongInt);
begin
  RTLEventWaitFor(FDoneEvent, AMilliseconds);
end;

procedure TOSVAsyncResolverState.Iterate;
begin
  FAPI.MainContextIteration(FContext, 1);
end;

procedure TOSVAsyncResolverState.StartLookup;
begin
  AddRef; { exactly-once GAsyncReadyCallback ownership }
  FAPI.MainContextPushThreadDefault(FContext);
  try
    try
      FAPI.ResolverLookupByNameAsync(FResolver, OSVHost, FCancellable,
        @GIOResolverReady, Self);
    except
      Release;
      raise;
    end;
  finally
    FAPI.MainContextPopThreadDefault(FContext);
  end;
end;

procedure TOSVAsyncResolverState.HandleReady(ASourceObject,
  AResult: Pointer);
var
  AddressBytes: PByte;
  AddressList, Current: PGList;
  AddressValue: TOSVResolvedAddress;
  ErrorValue: Pointer;
  FamilyValue, I, ExistingIndex: Integer;
  Duplicate: Boolean;
begin
  ErrorValue := nil;
  AddressList := nil;
  try
    if (ASourceObject = nil) or (AResult = nil) then
      Exit;
    AddressList := FAPI.ResolverLookupByNameFinish(ASourceObject, AResult,
      @ErrorValue);
    if (AddressList = nil) or (ErrorValue <> nil) then
      Exit;
    Current := AddressList;
    while (Current <> nil) and
      (Length(Addresses) < MaximumResolvedAddresses) do
    begin
      FillChar(AddressValue, SizeOf(AddressValue), 0);
      FamilyValue := FAPI.InetAddressGetFamily(Current^.Data);
      if (FamilyValue = AF_INET) or (FamilyValue = AF_INET6) then
      begin
        AddressBytes := FAPI.InetAddressToBytes(Current^.Data);
        if AddressBytes <> nil then
        begin
          AddressValue.Family := FamilyValue;
          if FamilyValue = AF_INET then
            Move(AddressBytes^, AddressValue.Bytes[0], 4)
          else
            Move(AddressBytes^, AddressValue.Bytes[0], 16);
          Duplicate := False;
          for ExistingIndex := 0 to High(Addresses) do
          begin
            Duplicate := Addresses[ExistingIndex].Family = FamilyValue;
            if Duplicate then
            begin
              if FamilyValue = AF_INET then
                I := 4
              else
                I := 16;
              Duplicate := CompareByte(Addresses[ExistingIndex].Bytes[0],
                AddressValue.Bytes[0], I) = 0;
            end;
            if Duplicate then
              Break;
          end;
          if not Duplicate then
          begin
            SetLength(Addresses, Length(Addresses) + 1);
            Addresses[High(Addresses)] := AddressValue;
          end;
        end;
      end;
      Current := Current^.Next;
    end;
    FSuccess := Length(Addresses) > 0;
  finally
    if AddressList <> nil then
      FAPI.ResolverFreeAddresses(AddressList);
    if ErrorValue <> nil then
      FAPI.ErrorFree(ErrorValue);
  end;
end;

procedure GIOResolverReady(ASourceObject, AResult,
  AUserData: Pointer); cdecl;
var
  State: TOSVAsyncResolverState;
begin
  State := TOSVAsyncResolverState(AUserData);
  if State = nil then
    Exit;
  try
    try
      State.HandleReady(ASourceObject, AResult);
    except
      on E: EOutOfMemory do
      begin
        State.FFatalOutOfMemory := True;
        State.FSuccess := False;
      end;
      on E: Exception do
        State.FSuccess := False;
    end;
  finally
    State.Complete;
    State.Release;
  end;
end;

constructor TOSVResolverPumpThread.Create(AState: TOSVAsyncResolverState);
begin
  { Initial suspension is required for partial-construction safety: FPC's
    TThread destructor terminates and resumes a Create(True) worker without
    entering Execute when a derived constructor raises. }
  inherited Create(True);
  ConstructorAcquired;
  { The constructing/calling thread owns the suspended worker until
    StartPumping has passed every raising operation. }
  FreeOnTerminate := False;
  if AState = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO resolver pump state is unavailable');
  FState := AState;
  FState.AddRef;
  ConstructorAcquired;
end;

destructor TOSVResolverPumpThread.Destroy;
var
  State: TOSVAsyncResolverState;
begin
  State := FState;
  FState := nil;
  inherited Destroy;
  if State <> nil then
    State.Release;
end;

procedure TOSVResolverPumpThread.Execute;
var
  State: TOSVAsyncResolverState;
begin
  State := FState;
  try
    if InterlockedCompareExchange(FPump, 0, 0) <> 0 then
      while not State.Done do
        State.Iterate;
  finally
    FState := nil;
    State.Release;
  end;
end;

procedure TOSVResolverPumpThread.StartPumping;
begin
  InterlockedExchange(FPump, 1);
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  if OpenSSLResolverPumpFailBeforeStart then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'Injected resolver pump failure before TThread.Start');
  {$ENDIF}
  { FPC 3.2.2 Start delegates to Resume.  Its supported Unix implementation
    only atomically clears suspension and signals an RTL event; it has no
    exception path.  Ownership transfers only after this call returns. }
  FreeOnTerminate := True;
  Start;
end;

constructor TOSVOpenSSLTransport.Create;
begin
  inherited Create;
  FSocket := -1;
  FLockInitialized := False;
  InitCriticalSection(FLock);
  FLockInitialized := True;
  ConstructorAcquired;
  LoadLibraries;
  FResolver := FGIO.ResolverGetDefault();
  if FResolver = nil then
    raise EOSVOpenSSLTransportUnavailable.Create(
      'GIO resolver acquisition failed');
  ConstructorAcquired;
  FAvailable := True;
end;

destructor TOSVOpenSSLTransport.Destroy;
begin
  if FLockInitialized then
    AbortActive(True, False);
  UnloadLibraries;
  if FLockInitialized then
  begin
    FLockInitialized := False;
    DoneCriticalSection(FLock);
  end;
  inherited Destroy;
end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
class function TOSVOpenSSLTransport.TestConstructorAcquisitionCount:
  Integer;
var
  Instance: TOSVOpenSSLTransport;
begin
  Instance := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  try
    Instance := TOSVOpenSSLTransport.Create;
    Result := OpenSSLConstructorAcquisitions;
  finally
    Instance.Free;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestConstructorFailureAt(
  AIndex: Integer): Boolean;
var
  Instance: TOSVOpenSSLTransport;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  Instance := nil;
  OpenSSLConstructorAcquisitions := 0;
  OpenSSLConstructorFailAt := AIndex;
  try
    try
      Instance := TOSVOpenSSLTransport.Create;
    except
      on E: EOSVOpenSSLTransportUnavailable do
        Result := (OpenSSLConstructorAcquisitions = AIndex) and
          (Pos('Injected OpenSSL transport constructor failure',
            E.Message) = 1);
    end;
  finally
    Instance.Free;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestResolverStateAcquisitionCount:
  Integer;
var
  Owner: IOSVTransport;
  OwnerObject: TOSVOpenSSLTransport;
  State: TOSVAsyncResolverState;
begin
  Owner := nil;
  State := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  try
    OwnerObject := TOSVOpenSSLTransport.Create;
    Owner := OwnerObject;
    if Owner = nil then
      raise Exception.Create('OpenSSL constructor probe lost its owner');
    OpenSSLConstructorAcquisitions := 0;
    State := TOSVAsyncResolverState.Create(OwnerObject);
    Result := OpenSSLConstructorAcquisitions;
  finally
    if State <> nil then
      State.Release;
    Owner := nil;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestResolverStateFailureAt(
  AIndex: Integer): Boolean;
var
  Owner: IOSVTransport;
  OwnerObject: TOSVOpenSSLTransport;
  State: TOSVAsyncResolverState;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  Owner := nil;
  State := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  try
    OwnerObject := TOSVOpenSSLTransport.Create;
    Owner := OwnerObject;
    if Owner = nil then
      raise Exception.Create('OpenSSL constructor probe lost its owner');
    OpenSSLConstructorAcquisitions := 0;
    OpenSSLConstructorFailAt := AIndex;
    try
      State := TOSVAsyncResolverState.Create(OwnerObject);
    except
      on E: EOSVOpenSSLTransportUnavailable do
        Result := (OpenSSLConstructorAcquisitions = AIndex) and
          (Pos('Injected OpenSSL transport constructor failure',
            E.Message) = 1);
    end;
  finally
    if State <> nil then
      State.Release;
    Owner := nil;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestResolverPumpAcquisitionCount:
  Integer;
var
  Owner: IOSVTransport;
  OwnerObject: TOSVOpenSSLTransport;
  Pump: TOSVResolverPumpThread;
  State: TOSVAsyncResolverState;
begin
  Owner := nil;
  Pump := nil;
  State := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  try
    OwnerObject := TOSVOpenSSLTransport.Create;
    Owner := OwnerObject;
    if Owner = nil then
      raise Exception.Create('OpenSSL pump probe lost its owner');
    OpenSSLConstructorAcquisitions := 0;
    State := TOSVAsyncResolverState.Create(OwnerObject);
    OpenSSLConstructorAcquisitions := 0;
    Pump := TOSVResolverPumpThread.Create(State);
    { The worker remains initially suspended until StartPumping. }
    Pump.FreeOnTerminate := False;
    Result := OpenSSLConstructorAcquisitions;
  finally
    Pump.Free;
    if State <> nil then
      State.Release;
    Owner := nil;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestResolverPumpFailureAt(
  AIndex: Integer): Boolean;
var
  Owner: IOSVTransport;
  OwnerObject: TOSVOpenSSLTransport;
  Pump: TOSVResolverPumpThread;
  State: TOSVAsyncResolverState;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  Owner := nil;
  Pump := nil;
  State := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  try
    OwnerObject := TOSVOpenSSLTransport.Create;
    Owner := OwnerObject;
    if Owner = nil then
      raise Exception.Create('OpenSSL pump probe lost its owner');
    OpenSSLConstructorAcquisitions := 0;
    State := TOSVAsyncResolverState.Create(OwnerObject);
    OpenSSLConstructorAcquisitions := 0;
    OpenSSLConstructorFailAt := AIndex;
    try
      Pump := TOSVResolverPumpThread.Create(State);
    except
      on E: EOSVOpenSSLTransportUnavailable do
        Result := (OpenSSLConstructorAcquisitions = AIndex) and
          (Pos('Injected OpenSSL transport constructor failure',
            E.Message) = 1);
    end;
  finally
    if Pump <> nil then
    begin
      Pump.FreeOnTerminate := False;
      Pump.Free;
    end;
    if State <> nil then
      State.Release;
    Owner := nil;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;

class function TOSVOpenSSLTransport.TestResolverPumpStartFailure: Boolean;
var
  Owner: IOSVTransport;
  OwnerObject: TOSVOpenSSLTransport;
  Pump: TOSVResolverPumpThread;
  State: TOSVAsyncResolverState;
begin
  Result := False;
  Owner := nil;
  Pump := nil;
  State := nil;
  OpenSSLConstructorFailAt := 0;
  OpenSSLConstructorAcquisitions := 0;
  OpenSSLResolverPumpFailBeforeStart := False;
  try
    OwnerObject := TOSVOpenSSLTransport.Create;
    Owner := OwnerObject;
    if Owner = nil then
      raise Exception.Create('OpenSSL start probe lost its owner');
    OpenSSLConstructorAcquisitions := 0;
    State := TOSVAsyncResolverState.Create(OwnerObject);
    OpenSSLConstructorAcquisitions := 0;
    Pump := TOSVResolverPumpThread.Create(State);
    OpenSSLResolverPumpFailBeforeStart := True;
    try
      Pump.StartPumping;
    except
      on E: EOSVOpenSSLTransportUnavailable do
        Result := E.Message =
          'Injected resolver pump failure before TThread.Start';
    end;
  finally
    OpenSSLResolverPumpFailBeforeStart := False;
    if Pump <> nil then
    begin
      Pump.FreeOnTerminate := False;
      Pump.Free;
    end;
    if State <> nil then
      State.Release;
    Owner := nil;
    OpenSSLConstructorFailAt := 0;
    OpenSSLConstructorAcquisitions := 0;
  end;
end;
{$ENDIF}

function TOSVOpenSSLTransport.BeginCall: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := not FCallActive;
    if Result then
    begin
      FCallActive := True;
      FCancelled := False;
      FTimedOut := False;
      FCancellable := nil;
      FSocket := -1;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVOpenSSLTransport.EndCall(out AWasCancelled,
  AWasTimedOut: Boolean);
begin
  EnterCriticalSection(FLock);
  try
    AWasCancelled := FCancelled;
    AWasTimedOut := FTimedOut;
    FCallActive := False;
    FCancellable := nil;
    FSocket := -1;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVOpenSSLTransport.AbortActive(ACancelled, ATimedOut: Boolean);
var
  CancellableValue: Pointer;
begin
  CancellableValue := nil;
  EnterCriticalSection(FLock);
  try
    if FCallActive then
    begin
      if ACancelled then
        FCancelled := True;
      if ATimedOut then
        FTimedOut := True;
    end;
    if FCancellable <> nil then
      CancellableValue := FGIO.ObjectRef(FCancellable);
    { The posting thread owns the descriptor until it has freed SSL.  Closing
      it here would let the descriptor number be reused while SSL still
      retains that number.  Shutdown is sufficient to wake poll/OpenSSL and
      is performed while holding FLock so CloseActiveSocket cannot retire the
      descriptor until this syscall has returned. }
    if FSocket >= 0 then
      fpShutdown(FSocket, 2);
  finally
    LeaveCriticalSection(FLock);
  end;
  if CancellableValue <> nil then
  begin
    FGIO.CancellableCancel(CancellableValue);
    FGIO.ObjectUnref(CancellableValue);
  end;
end;

function TOSVOpenSSLTransport.Cancelled: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FCancelled;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVOpenSSLTransport.TimedOut: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FTimedOut;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVOpenSSLTransport.SetActiveCancellable(
  ACancellable: Pointer): Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := not FCancelled and not FTimedOut and (FCancellable = nil);
    if Result then
      FCancellable := ACancellable;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVOpenSSLTransport.ClearActiveCancellable(
  ACancellable: Pointer);
begin
  EnterCriticalSection(FLock);
  try
    if FCancellable = ACancellable then
      FCancellable := nil;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVOpenSSLTransport.SetActiveSocket(ASocket: LongInt): Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := not FCancelled and not FTimedOut and (FSocket < 0);
    if Result then
      FSocket := ASocket;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVOpenSSLTransport.CloseActiveSocket(ASocket: LongInt);
var
  MustClose: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    MustClose := FSocket = ASocket;
    if MustClose then
      FSocket := -1;
  finally
    LeaveCriticalSection(FLock);
  end;
  if MustClose then
  begin
    fpShutdown(ASocket, 2);
    fpClose(ASocket);
  end;
end;

procedure TOSVOpenSSLTransport.Cancel;
begin
  AbortActive(True, False);
end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
function TOSVOpenSSLTransport.TestBeginSocketOwnership(
  ASocket: LongInt): Boolean;
var
  WasCancelled, WasTimedOut: Boolean;
begin
  Result := BeginCall;
  if Result and not SetActiveSocket(ASocket) then
  begin
    EndCall(WasCancelled, WasTimedOut);
    Result := False;
  end;
end;

procedure TOSVOpenSSLTransport.TestEndSocketOwnership(ASocket: LongInt;
  out AWasCancelled, AWasTimedOut: Boolean);
begin
  CloseActiveSocket(ASocket);
  EndCall(AWasCancelled, AWasTimedOut);
end;

function TOSVOpenSSLTransport.TestPollSocket(ASocket: LongInt;
  AWantRead: Boolean; ATimeoutMilliseconds: QWord): Boolean;
var
  WasCancelled, WasTimedOut: Boolean;
begin
  Result := BeginCall;
  if not Result then
    Exit;
  try
    Result := WaitForSocket(ASocket, AWantRead,
      GetTickCount64 + ATimeoutMilliseconds, nil);
  finally
    EndCall(WasCancelled, WasTimedOut);
  end;
end;
{$ENDIF}

function CallbackCancelled(ACancelCheck: TOSVCancelCheck): Boolean; inline;
begin
  Result := Assigned(ACancelCheck) and ACancelCheck();
end;

function DeadlineAfter(AMilliseconds: QWord): QWord; inline;
begin
  Result := GetTickCount64 + AMilliseconds;
end;

function EarlierDeadline(AFirst, ASecond: QWord): QWord; inline;
begin
  if AFirst < ASecond then
    Result := AFirst
  else
    Result := ASecond;
end;

function RemainingMilliseconds(ADeadline: QWord): LongInt;
var
  NowValue, Remaining: QWord;
begin
  NowValue := GetTickCount64;
  if NowValue >= ADeadline then
    Exit(0);
  Remaining := ADeadline - NowValue;
  if Remaining > High(LongInt) then
    Result := High(LongInt)
  else
    Result := LongInt(Remaining);
end;

function BeginSIGPIPESuppression(out AOldMask: TSigSet;
  out AWasPending: Boolean): Boolean;
var
  BlockSet, PendingSet: TSigSet;
begin
  Result := False;
  AWasPending := False;
  BlockSet := Default(TSigSet);
  PendingSet := Default(TSigSet);
  fpSigEmptySet(BlockSet);
  fpSigAddSet(BlockSet, SIGPIPE);
  if fpSigProcMask(SIG_BLOCK, @BlockSet, @AOldMask) <> 0 then
    Exit;
  if NativeSigPending(@PendingSet) <> 0 then
  begin
    fpSigProcMask(SIG_SETMASK, @AOldMask, nil);
    Exit;
  end;
  AWasPending := fpSigIsMember(PendingSet, SIGPIPE) <> 0;
  Result := True;
end;

procedure EndSIGPIPESuppression(const AOldMask: TSigSet;
  AWasPending: Boolean);
var
  PendingSet, WaitSet: TSigSet;
  SavedError: LongInt;
  ZeroTimeout: TTimeSpec;
begin
  SavedError := fpGetErrNo;
  PendingSet := Default(TSigSet);
  WaitSet := Default(TSigSet);
  if not AWasPending and (NativeSigPending(@PendingSet) = 0) and
    (fpSigIsMember(PendingSet, SIGPIPE) <> 0) then
  begin
    fpSigEmptySet(WaitSet);
    fpSigAddSet(WaitSet, SIGPIPE);
    ZeroTimeout.tv_sec := 0;
    ZeroTimeout.tv_nsec := 0;
    while fpSigTimedWait(WaitSet, nil, @ZeroTimeout) = SIGPIPE do
      ;
  end;
  fpSigProcMask(SIG_SETMASK, @AOldMask, nil);
  fpSetErrNo(SavedError);
end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
function TOSVOpenSSLTransport.TestSIGPIPEResetSuppressed: Boolean;
var
  DescriptorPair: TSockPairArray;
  OldMask: TSigSet;
  OneByte: Byte;
  WriteError: LongInt;
  WriteResult: Int64;
  SuppressionActive, WasPending: Boolean;
begin
  Result := False;
  DescriptorPair[0] := -1;
  DescriptorPair[1] := -1;
  SuppressionActive := False;
  if fpSocketPair(AF_UNIX, SOCK_STREAM, 0, @DescriptorPair[0]) <> 0 then
    Exit;
  try
    if not BeginSIGPIPESuppression(OldMask, WasPending) then
      Exit;
    SuppressionActive := True;
    fpClose(DescriptorPair[1]);
    DescriptorPair[1] := -1;
    OneByte := 1;
    WriteResult := fpWrite(DescriptorPair[0], OneByte, 1);
    WriteError := fpGetErrNo;
    Result := (WriteResult < 0) and (WriteError = ESysEPIPE);
    if not Result then
      raise Exception.CreateFmt('SIGPIPE probe write=%d errno=%d',
        [WriteResult, WriteError]);
  finally
    if DescriptorPair[0] >= 0 then
      fpClose(DescriptorPair[0]);
    if DescriptorPair[1] >= 0 then
      fpClose(DescriptorPair[1]);
    if SuppressionActive then
      EndSIGPIPESuppression(OldMask, WasPending);
  end;
end;
{$ENDIF}

function TOSVOpenSSLTransport.WaitForSocket(ASocket: LongInt;
  AWantRead: Boolean; ADeadline: QWord;
  ACancelCheck: TOSVCancelCheck): Boolean;
var
  CallbackRequested: Boolean;
  ExpectedEvents: CShort;
  PollItem: TPollFD;
  PollResult, SliceMilliseconds: LongInt;
begin
  PollItem := Default(TPollFD);
  PollItem.fd := ASocket;
  if AWantRead then
    ExpectedEvents := POLLIN
  else
    ExpectedEvents := POLLOUT;
  PollItem.events := ExpectedEvents;
  repeat
    CallbackRequested := CallbackCancelled(ACancelCheck);
    if Cancelled or CallbackRequested then
    begin
      if CallbackRequested then
        Cancel;
      Exit(False);
    end;
    SliceMilliseconds := RemainingMilliseconds(ADeadline);
    if SliceMilliseconds <= 0 then
    begin
      AbortActive(False, True);
      Exit(False);
    end;
    if SliceMilliseconds > 50 then
      SliceMilliseconds := 50;
    PollItem.revents := 0;
    PollResult := fpPoll(@PollItem, 1, SliceMilliseconds);
    if PollResult > 0 then
    begin
      if (PollItem.revents and POLLNVAL) <> 0 then
        Exit(False);
      { ERR/HUP can accompany requested readiness.  Let the immediate socket
        or SSL operation drain buffered input or obtain SO_ERROR; without the
        requested event they are terminal. }
      if (PollItem.revents and ExpectedEvents) <> 0 then
        Exit(True);
      if (PollItem.revents and (POLLERR or POLLHUP)) <> 0 then
        Exit(False);
      { A one-fd poll should not report success without a requested or
        terminal event.  Treat such a result as a closed failure boundary. }
      Exit(False);
    end;
    if (PollResult < 0) and (fpGetErrNo <> ESysEINTR) then
      Exit(False);
  until False;
end;

function TOSVOpenSSLTransport.ResolveHost(ADeadline: QWord;
  ACancelCheck: TOSVCancelCheck; out AAddresses: TOSVResolvedAddressArray):
  Boolean;
var
  CallbackRequested: Boolean;
  ResolverState: TOSVAsyncResolverState;
  ResolverThread: TOSVResolverPumpThread;
begin
  Result := False;
  SetLength(AAddresses, 0);
  ResolverState := TOSVAsyncResolverState.Create(Self);
  ResolverThread := nil;
  try
    if not SetActiveCancellable(ResolverState.Cancellable) then
      Exit;
    ResolverThread := TOSVResolverPumpThread.Create(ResolverState);
    ResolverState.StartLookup;
    ResolverThread.StartPumping;
    ResolverThread := nil; { self-releasing; never joined on request path }
    while not ResolverState.Done do
    begin
      CallbackRequested := CallbackCancelled(ACancelCheck);
      if Cancelled or CallbackRequested then
      begin
        if CallbackRequested then
          Cancel;
        Break;
      end;
      if RemainingMilliseconds(ADeadline) <= 0 then
      begin
        AbortActive(False, True);
        Break;
      end;
      ResolverState.WaitSlice(25);
    end;
    if ResolverState.Done and ResolverState.FatalOutOfMemory then
      raise EOutOfMemory.Create('GIO resolver result allocation failed');
    if ResolverState.Done and ResolverState.Success and
      not Cancelled and not TimedOut then
    begin
      AAddresses := Copy(ResolverState.Addresses, 0,
        Length(ResolverState.Addresses));
      Result := Length(AAddresses) > 0;
    end;
  finally
    if ResolverThread <> nil then
    begin
      { The local still owns a definitely suspended worker.  FPC's thread
        destructor terminates/resumes it without entering Execute, while the
        derived destructor releases its resolver-state reference. }
      ResolverThread.FreeOnTerminate := False;
      ResolverThread.Free;
    end;
    ClearActiveCancellable(ResolverState.Cancellable);
    ResolverState.Release;
  end;
end;

function TOSVOpenSSLTransport.ConnectAddress(
  const AAddress: TOSVResolvedAddress; ADeadline: QWord;
  ACancelCheck: TOSVCancelCheck): LongInt;
var
  Address4: TInetSockAddr;
  Address6: TInetSockAddr6;
  ConnectResult, ErrorLength, ErrorValue, Flags: LongInt;
begin
  Result := -1;
  Address4 := Default(TInetSockAddr);
  Address6 := Default(TInetSockAddr6);
  if (AAddress.Family <> AF_INET) and (AAddress.Family <> AF_INET6) then
    Exit;
  Result := fpSocket(AAddress.Family, SOCK_STREAM, 0);
  if Result < 0 then
    Exit;
  if not SetActiveSocket(Result) then
  begin
    fpClose(Result);
    Result := -1;
    Exit;
  end;
  Flags := fpFcntl(Result, F_GETFL, 0);
  if (Flags < 0) or (fpFcntl(Result, F_SETFL, Flags or O_NONBLOCK) < 0) then
  begin
    CloseActiveSocket(Result);
    Result := -1;
    Exit;
  end;
  if AAddress.Family = AF_INET then
  begin
    Address4.sin_family := AF_INET;
    Address4.sin_port := htons(OSVPort);
    Move(AAddress.Bytes[0], Address4.sin_addr.s_bytes[1], 4);
    ConnectResult := fpConnect(Result, @Address4, SizeOf(Address4));
  end
  else
  begin
    Address6.sin6_family := AF_INET6;
    Address6.sin6_port := htons(OSVPort);
    Move(AAddress.Bytes[0], Address6.sin6_addr.u6_addr8[0], 16);
    ConnectResult := fpConnect(Result, @Address6, SizeOf(Address6));
  end;
  if ConnectResult = 0 then
    Exit;
  if fpGetErrNo <> ESysEINPROGRESS then
  begin
    CloseActiveSocket(Result);
    Result := -1;
    Exit;
  end;
  if not WaitForSocket(Result, False, ADeadline, ACancelCheck) then
  begin
    CloseActiveSocket(Result);
    Result := -1;
    Exit;
  end;
  ErrorValue := 0;
  ErrorLength := SizeOf(ErrorValue);
  if (fpGetSockOpt(Result, SOL_SOCKET, SO_ERROR, @ErrorValue,
    @ErrorLength) <> 0) or (ErrorValue <> 0) then
  begin
    CloseActiveSocket(Result);
    Result := -1;
  end;
end;

function TOSVOpenSSLTransport.ConnectAny(
  const AAddresses: TOSVResolvedAddressArray; ADeadline: QWord;
  ACancelCheck: TOSVCancelCheck): LongInt;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to High(AAddresses) do
  begin
    if Cancelled or TimedOut or (RemainingMilliseconds(ADeadline) <= 0) then
      Exit;
    Result := ConnectAddress(AAddresses[I], ADeadline, ACancelCheck);
    if Result >= 0 then
      Exit;
  end;
end;

function TOSVOpenSSLTransport.SSLWait(ASSL: Pointer; AReturnCode,
  ASocket: LongInt; ADeadline: QWord; ACancelCheck: TOSVCancelCheck): Boolean;
var
  ErrorValue: LongInt;
begin
  ErrorValue := FOpenSSL.SSLGetError(ASSL, AReturnCode);
  case ErrorValue of
    SSLErrorWantRead:
      Result := WaitForSocket(ASocket, True, ADeadline, ACancelCheck);
    SSLErrorWantWrite:
      Result := WaitForSocket(ASocket, False, ADeadline, ACancelCheck);
  else
    Result := False;
  end;
end;

function TOSVOpenSSLTransport.CreateVerifiedSSL(ASocket: LongInt;
  ADeadline: QWord; ACancelCheck: TOSVCancelCheck;
  out AContext, ASSL: Pointer): Boolean;
var
  CertificateValue, ParameterValue: Pointer;
  ConnectResult: LongInt;
begin
  Result := False;
  AContext := nil;
  ASSL := nil;
  AContext := FOpenSSL.ContextNew(FOpenSSL.TLSClientMethod());
  if AContext = nil then
    Exit;
  if FOpenSSL.ContextControl(AContext, SSLControlSetMinProtocolVersion,
    TLS12Version, nil) <> 1 then
    Exit;
  FOpenSSL.ContextSetVerify(AContext, SSLVerifyPeer, nil);
  if FOpenSSL.ContextSetDefaultVerifyPaths(AContext) <> 1 then
    Exit;
  ASSL := FOpenSSL.SSLNew(AContext);
  if ASSL = nil then
    Exit;
  ParameterValue := FOpenSSL.SSLGet0Param(ASSL);
  if ParameterValue = nil then
    Exit;
  FOpenSSL.VerifyParamSetHostFlags(ParameterValue,
    X509CheckFlagNoPartialWildcards);
  if FOpenSSL.VerifyParamSet1Host(ParameterValue, OSVHost,
    Length(OSVHost)) <> 1 then
    Exit;
  if FOpenSSL.SSLControl(ASSL, SSLControlSetTLSExtHostName,
    TLSExtNameTypeHostName, Pointer(PChar(OSVHost))) = 0 then
    Exit;
  if FOpenSSL.SSLSetFD(ASSL, ASocket) <> 1 then
    Exit;
  repeat
    ConnectResult := FOpenSSL.SSLConnect(ASSL);
    if ConnectResult = 1 then
      Break;
    if not SSLWait(ASSL, ConnectResult, ASocket, ADeadline,
      ACancelCheck) then
      Exit;
  until False;
  if FOpenSSL.SSLGetVerifyResult(ASSL) <> X509VerifyOK then
    Exit;
  CertificateValue := FOpenSSL.SSLGet1PeerCertificate(ASSL);
  if CertificateValue = nil then
    Exit;
  try
    if FOpenSSL.X509CheckHost(CertificateValue, OSVHost,
      Length(OSVHost), X509CheckFlagNoPartialWildcards, nil) <> 1 then
      Exit;
  finally
    FOpenSSL.X509Free(CertificateValue);
  end;
  Result := True;
end;

function TOSVOpenSSLTransport.SSLWriteAll(ASSL: Pointer; ASocket: LongInt;
  const AData: RawByteString; ADeadline: QWord;
  ACancelCheck: TOSVCancelCheck): Boolean;
var
  Offset, WriteResult: SizeInt;
begin
  Result := False;
  Offset := 1;
  while Offset <= Length(AData) do
  begin
    if RemainingMilliseconds(ADeadline) <= 0 then
    begin
      AbortActive(False, True);
      Exit;
    end;
    WriteResult := FOpenSSL.SSLWrite(ASSL, @AData[Offset],
      Length(AData) - Offset + 1);
    if WriteResult > 0 then
      Inc(Offset, WriteResult)
    else if not SSLWait(ASSL, WriteResult, ASocket, ADeadline,
      ACancelCheck) then
      Exit;
  end;
  Result := True;
end;

function ClassifySSLReadResult(AReadResult, AError: LongInt):
  TOSVSSLReadAction; inline;
begin
  if AReadResult > 0 then
    Exit(osraFail);
  case AError of
    SSLErrorWantRead: Result := osraWantRead;
    SSLErrorWantWrite: Result := osraWantWrite;
    SSLErrorZeroReturn: Result := osraCleanEOF;
  else
    Result := osraFail;
  end;
end;

function TOSVOpenSSLTransport.SSLReadBounded(ASSL: Pointer;
  ASocket: LongInt; AMaximumBytes: Int64; ATotalDeadline: QWord;
  ACancelCheck: TOSVCancelCheck; out AData: RawByteString;
  out ATooLarge: Boolean): Boolean;
const
  BufferSize = 16384;
var
  Buffer: array[0..BufferSize - 1] of Byte;
  Capacity, ReadResult, Used: SizeInt;
  ErrorValue: LongInt;
  IODeadline: QWord;
  CallbackRequested: Boolean;
begin
  Result := False;
  ATooLarge := False;
  AData := '';
  Capacity := 0;
  Used := 0;
  repeat
    CallbackRequested := CallbackCancelled(ACancelCheck);
    if Cancelled or CallbackRequested then
    begin
      if CallbackRequested then
        Cancel;
      Exit;
    end;
    if RemainingMilliseconds(ATotalDeadline) <= 0 then
    begin
      AbortActive(False, True);
      Exit;
    end;
    IODeadline := EarlierDeadline(DeadlineAfter(OSVOpenSSLIOTimeoutMS),
      ATotalDeadline);
    ReadResult := FOpenSSL.SSLRead(ASSL, @Buffer[0], BufferSize);
    if ReadResult > 0 then
    begin
      if Int64(Used) + ReadResult > AMaximumBytes then
      begin
        ATooLarge := True;
        Exit;
      end;
      if Used + ReadResult > Capacity then
      begin
        if Capacity = 0 then
          Capacity := BufferSize;
        while Capacity < Used + ReadResult do
          Capacity := Capacity * 2;
        if Capacity > AMaximumBytes then
          Capacity := SizeInt(AMaximumBytes);
        SetLength(AData, Capacity);
      end;
      Move(Buffer[0], AData[Used + 1], ReadResult);
      Inc(Used, ReadResult);
      Continue;
    end;
    { OpenSSL requires SSL_get_error for every non-positive return.  A zero
      return is not EOF by itself: only a received TLS close_notify produces
      SSL_ERROR_ZERO_RETURN.  SYSCALL/SSL failures are unclean truncation. }
    ErrorValue := FOpenSSL.SSLGetError(ASSL, ReadResult);
    case ClassifySSLReadResult(ReadResult, ErrorValue) of
      osraCleanEOF:
        Break;
      osraWantRead:
        begin
          if not WaitForSocket(ASocket, True, IODeadline,
            ACancelCheck) then
            Exit;
          Continue;
        end;
      osraWantWrite:
        begin
          if not WaitForSocket(ASocket, False, IODeadline,
            ACancelCheck) then
            Exit;
          Continue;
        end;
    else
      Exit;
    end;
  until False;
  SetLength(AData, Used);
  Result := True;
end;

function FindCRLF(const AValue: RawByteString; AStart: SizeInt): SizeInt;
var
  I: SizeInt;
begin
  for I := AStart to Length(AValue) - 1 do
    if (AValue[I] = #13) and (AValue[I + 1] = #10) then
      Exit(I);
  Result := 0;
end;

function IsHTTPToken(const AValue: RawByteString): Boolean;
var
  I: SizeInt;
begin
  Result := AValue <> '';
  for I := 1 to Length(AValue) do
    if not (AValue[I] in ['A'..'Z', 'a'..'z', '0'..'9', '-', '_']) then
      Exit(False);
end;

function IsSafeHeaderValue(const AValue: RawByteString): Boolean;
var
  I: SizeInt;
begin
  for I := 1 to Length(AValue) do
    if (Byte(AValue[I]) < 32) or (Byte(AValue[I]) = 127) then
      Exit(False);
  Result := True;
end;

function TryParseDecimal(const AValue: RawByteString;
  out AResult: Int64): Boolean;
var
  Digit: Integer;
  I: SizeInt;
begin
  AResult := 0;
  if AValue = '' then
    Exit(False);
  for I := 1 to Length(AValue) do
  begin
    if not (AValue[I] in ['0'..'9']) then
      Exit(False);
    Digit := Ord(AValue[I]) - Ord('0');
    if AResult > (High(Int64) - Digit) div 10 then
      Exit(False);
    AResult := AResult * 10 + Digit;
  end;
  Result := True;
end;

function TryParseHex(const AValue: RawByteString; out AResult: QWord): Boolean;
var
  Digit: Integer;
  I: SizeInt;
begin
  AResult := 0;
  if (AValue = '') or (Length(AValue) > 16) then
    Exit(False);
  for I := 1 to Length(AValue) do
  begin
    case AValue[I] of
      '0'..'9': Digit := Ord(AValue[I]) - Ord('0');
      'A'..'F': Digit := Ord(AValue[I]) - Ord('A') + 10;
      'a'..'f': Digit := Ord(AValue[I]) - Ord('a') + 10;
    else
      Exit(False);
    end;
    if AResult > (High(QWord) - QWord(Digit)) shr 4 then
      Exit(False);
    AResult := (AResult shl 4) or QWord(Digit);
  end;
  Result := True;
end;

function DecodeChunkedBody(const ARaw: RawByteString; ABodyStart: SizeInt;
  AMaximumBodyBytes: Int64; out ABody: RawByteString;
  out ATooLarge: Boolean): Boolean;
var
  Capacity, Used: SizeInt;
  ChunkSize: QWord;
  LineEnd, PositionValue, SemicolonAt: SizeInt;
  SizeText: RawByteString;
begin
  Result := False;
  ATooLarge := False;
  ABody := '';
  Capacity := 0;
  Used := 0;
  PositionValue := ABodyStart;
  repeat
    LineEnd := FindCRLF(ARaw, PositionValue);
    if (LineEnd = 0) or (LineEnd - PositionValue > 4096) then
      Exit;
    SizeText := Copy(ARaw, PositionValue, LineEnd - PositionValue);
    SemicolonAt := Pos(';', SizeText);
    if SemicolonAt > 0 then
      SizeText := Copy(SizeText, 1, SemicolonAt - 1);
    if not TryParseHex(SizeText, ChunkSize) then
      Exit;
    PositionValue := LineEnd + 2;
    if ChunkSize = 0 then
    begin
      { Consume syntactically bounded trailer fields through the empty line. }
      repeat
        LineEnd := FindCRLF(ARaw, PositionValue);
        if (LineEnd = 0) or (LineEnd - PositionValue > 4096) then
          Exit;
        if LineEnd = PositionValue then
        begin
          Inc(PositionValue, 2);
          Result := PositionValue = Length(ARaw) + 1;
          if Result then
            SetLength(ABody, Used);
          Exit;
        end;
        PositionValue := LineEnd + 2;
      until False;
    end;
    if ChunkSize > QWord(AMaximumBodyBytes - Used) then
    begin
      ATooLarge := True;
      Exit;
    end;
    if (ChunkSize > QWord(High(SizeInt))) or
      (PositionValue + SizeInt(ChunkSize) + 1 > Length(ARaw)) then
      Exit;
    if Used + SizeInt(ChunkSize) > Capacity then
    begin
      if Capacity = 0 then
        Capacity := 16384;
      while Capacity < Used + SizeInt(ChunkSize) do
        Capacity := Capacity * 2;
      if Capacity > AMaximumBodyBytes then
        Capacity := SizeInt(AMaximumBodyBytes);
      SetLength(ABody, Capacity);
    end;
    if ChunkSize > 0 then
      Move(ARaw[PositionValue], ABody[Used + 1], SizeInt(ChunkSize));
    Inc(Used, SizeInt(ChunkSize));
    Inc(PositionValue, SizeInt(ChunkSize));
    if (PositionValue + 1 > Length(ARaw)) or
      (ARaw[PositionValue] <> #13) or
      (ARaw[PositionValue + 1] <> #10) then
      Exit;
    Inc(PositionValue, 2);
  until False;
end;

function DecodeHTTPResponse(const ARaw: RawByteString;
  AMaximumBodyBytes: Int64; out AStatus: Integer;
  out ABody: RawByteString; out ATooLarge: Boolean): Boolean;
var
  BodyStart, ColonAt, HeaderEnd, LineEnd, PositionValue: SizeInt;
  ContentLength: Int64;
  ContentLengthSeen, ContentEncodingSeen, TransferEncodingSeen: Boolean;
  HeaderName, HeaderValue, StatusLine: RawByteString;
begin
  Result := False;
  ATooLarge := False;
  AStatus := 0;
  ABody := '';
  HeaderEnd := Pos(#13#10#13#10, ARaw);
  if (HeaderEnd = 0) or (HeaderEnd > MaximumHTTPHeaderBytes) then
    Exit;
  LineEnd := FindCRLF(ARaw, 1);
  if LineEnd = 0 then
    Exit;
  StatusLine := Copy(ARaw, 1, LineEnd - 1);
  if ((Copy(StatusLine, 1, 9) <> 'HTTP/1.1 ') and
    (Copy(StatusLine, 1, 9) <> 'HTTP/1.0 ')) or
    (Length(StatusLine) < 12) or
    not (StatusLine[10] in ['0'..'9']) or
    not (StatusLine[11] in ['0'..'9']) or
    not (StatusLine[12] in ['0'..'9']) then
    Exit;
  AStatus := (Ord(StatusLine[10]) - Ord('0')) * 100 +
    (Ord(StatusLine[11]) - Ord('0')) * 10 +
    Ord(StatusLine[12]) - Ord('0');
  ContentLength := -1;
  ContentLengthSeen := False;
  ContentEncodingSeen := False;
  TransferEncodingSeen := False;
  PositionValue := LineEnd + 2;
  while PositionValue < HeaderEnd do
  begin
    LineEnd := FindCRLF(ARaw, PositionValue);
    if (LineEnd = 0) or (LineEnd > HeaderEnd) then
      Exit;
    HeaderValue := Copy(ARaw, PositionValue, LineEnd - PositionValue);
    if (HeaderValue = '') or (HeaderValue[1] in [' ', #9]) then
      Exit;
    ColonAt := Pos(':', HeaderValue);
    if ColonAt <= 1 then
      Exit;
    HeaderName := LowerCase(Copy(HeaderValue, 1, ColonAt - 1));
    if not IsHTTPToken(HeaderName) then
      Exit;
    HeaderValue := Trim(Copy(HeaderValue, ColonAt + 1, MaxInt));
    if not IsSafeHeaderValue(HeaderValue) then
      Exit;
    if HeaderName = 'content-length' then
    begin
      if ContentLengthSeen or not TryParseDecimal(HeaderValue,
        ContentLength) then
        Exit;
      ContentLengthSeen := True;
    end
    else if HeaderName = 'transfer-encoding' then
    begin
      if TransferEncodingSeen or (LowerCase(HeaderValue) <> 'chunked') then
        Exit;
      TransferEncodingSeen := True;
    end
    else if HeaderName = 'content-encoding' then
    begin
      if ContentEncodingSeen or
        ((HeaderValue <> '') and (LowerCase(HeaderValue) <> 'identity')) then
        Exit;
      ContentEncodingSeen := True;
    end;
    PositionValue := LineEnd + 2;
  end;
  if ContentLengthSeen and TransferEncodingSeen then
    Exit;
  BodyStart := HeaderEnd + 4;
  if TransferEncodingSeen then
    Exit(DecodeChunkedBody(ARaw, BodyStart, AMaximumBodyBytes, ABody,
      ATooLarge));
  if ContentLengthSeen then
  begin
    if ContentLength > AMaximumBodyBytes then
    begin
      ATooLarge := True;
      Exit;
    end;
    if ContentLength <> Length(ARaw) - BodyStart + 1 then
      Exit;
    ABody := Copy(ARaw, BodyStart, SizeInt(ContentLength));
  end
  else
  begin
    if Length(ARaw) - BodyStart + 1 > AMaximumBodyBytes then
    begin
      ATooLarge := True;
      Exit;
    end;
    ABody := Copy(ARaw, BodyStart, MaxInt);
  end;
  Result := True;
end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
function TOSVOpenSSLTransport.TestUncleanTLSCloseRejected(
  const ACloseFramedResponse: RawByteString): Boolean;
var
  Body: RawByteString;
  Status: Integer;
  TooLarge: Boolean;
begin
  { The prefix is deliberately valid close-framed HTTP/JSON.  It may only be
    accepted when TLS ended with close_notify, never when SSL_read returned
    zero with SSL_ERROR_SYSCALL after a reset/truncation. }
  Result := DecodeHTTPResponse(ACloseFramedResponse,
    OSVMaximumResponseBytes, Status, Body, TooLarge) and
    (ClassifySSLReadResult(0, SSLErrorZeroReturn) = osraCleanEOF) and
    (ClassifySSLReadResult(0, SSLErrorSyscall) = osraFail);
end;
{$ENDIF}

function TOSVOpenSSLTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
var
  Addresses: TOSVResolvedAddressArray;
  ContextValue, SSLValue: Pointer;
  RawResponse, RequestValue: RawByteString;
  SocketValue: LongInt;
  TooLarge: Boolean;
  SIGPIPEBlocked, SIGPIPEWasPending, WasCancelled, WasTimedOut: Boolean;
  OldSignalMask: TSigSet;
  ConnectDeadline, DNSDeadline, IODeadline, TotalDeadline: QWord;
begin
  Result := otoFailed;
  AHTTPStatus := 0;
  AResponseBody := '';
  if not FAvailable or (AMaximumResponseBytes <= 0) or
    (AMaximumResponseBytes > OSVMaximumResponseBytes) or
    (Length(ARequestBody) > 2 * 1024 * 1024) then
    Exit;
  if not BeginCall then
    Exit;
  ContextValue := nil;
  SSLValue := nil;
  SocketValue := -1;
  SIGPIPEBlocked := False;
  try
    TotalDeadline := DeadlineAfter(OSVOpenSSLTotalTimeoutMS);
    DNSDeadline := EarlierDeadline(DeadlineAfter(OSVOpenSSLDNSTimeoutMS),
      TotalDeadline);
    if not ResolveHost(DNSDeadline, ACancelCheck, Addresses) then
      Exit;
    ConnectDeadline := EarlierDeadline(
      DeadlineAfter(OSVOpenSSLConnectTimeoutMS), TotalDeadline);
    SocketValue := ConnectAny(Addresses, ConnectDeadline, ACancelCheck);
    if SocketValue < 0 then
      Exit;
    { OpenSSL's socket BIO does not use MSG_NOSIGNAL.  Suppress SIGPIPE only
      in this posting thread, preserve the caller's mask/pending state, and
      consume only a signal generated during this scoped TLS lifetime. }
    if not BeginSIGPIPESuppression(OldSignalMask,
      SIGPIPEWasPending) then
      Exit;
    SIGPIPEBlocked := True;
    IODeadline := EarlierDeadline(DeadlineAfter(OSVOpenSSLIOTimeoutMS),
      TotalDeadline);
    if not CreateVerifiedSSL(SocketValue, IODeadline, ACancelCheck,
      ContextValue, SSLValue) then
      Exit;
    RequestValue := 'POST ' + OSVPath + ' HTTP/1.1'#13#10 +
      'Host: ' + OSVHost + #13#10 +
      'Content-Type: application/json'#13#10 +
      'Accept: application/json'#13#10 +
      'Accept-Encoding: identity'#13#10 +
      'Connection: close'#13#10 +
      'Content-Length: ' + IntToStr(Length(ARequestBody)) + #13#10#13#10 +
      ARequestBody;
    IODeadline := EarlierDeadline(DeadlineAfter(OSVOpenSSLIOTimeoutMS),
      TotalDeadline);
    if not SSLWriteAll(SSLValue, SocketValue, RequestValue, IODeadline,
      ACancelCheck) then
      Exit;
    if not SSLReadBounded(SSLValue, SocketValue,
      AMaximumResponseBytes + MaximumHTTPHeaderBytes +
      MaximumHTTPFramingOverhead, TotalDeadline, ACancelCheck, RawResponse,
      TooLarge) then
    begin
      if TooLarge then
        Result := otoResponseTooLarge;
      Exit;
    end;
    if not DecodeHTTPResponse(RawResponse, AMaximumResponseBytes,
      AHTTPStatus, AResponseBody, TooLarge) then
    begin
      if TooLarge then
        Result := otoResponseTooLarge;
      Exit;
    end;
    { Framing validation is CPU-bounded, but it is still part of the public
      call's total deadline rather than an unmetered tail after network I/O. }
    if RemainingMilliseconds(TotalDeadline) <= 0 then
    begin
      AbortActive(False, True);
      Exit;
    end;
    Result := otoSucceeded;
  finally
    if SSLValue <> nil then
      FOpenSSL.SSLFree(SSLValue);
    if ContextValue <> nil then
      FOpenSSL.ContextFree(ContextValue);
    if SocketValue >= 0 then
      CloseActiveSocket(SocketValue);
    if SIGPIPEBlocked then
      EndSIGPIPESuppression(OldSignalMask, SIGPIPEWasPending);
    { Capture cancellation and mark the call inactive in one locked action.
      A concurrent Cancel therefore belongs either to this call or to the
      subsequent idle state; it cannot land between the outcome check and
      EndCall. }
    EndCall(WasCancelled, WasTimedOut);
    if WasCancelled then
      Result := otoCancelled
    else if WasTimedOut then
      Result := otoFailed;
    if Result <> otoSucceeded then
    begin
      AHTTPStatus := 0;
      AResponseBody := '';
    end;
  end;
end;

{$ELSE}

constructor TOSVOpenSSLTransport.Create;
begin
  inherited Create;
  FAvailable := False;
  raise EOSVOpenSSLTransportUnavailable.Create(
    'The OpenSSL transport is available only on Linux');
end;

destructor TOSVOpenSSLTransport.Destroy;
begin
  inherited Destroy;
end;

procedure TOSVOpenSSLTransport.Cancel;
begin
end;

function TOSVOpenSSLTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
begin
  AHTTPStatus := 0;
  AResponseBody := '';
  Result := otoFailed;
end;

{$ENDIF}

end.
