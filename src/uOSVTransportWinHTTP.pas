(**
  PurpleRay SBOM Analyzer Windows OSV transport.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  The Windows implementation uses WinHTTP's native certificate-chain and
  hostname verification against the Windows trust store.  It fixes the host,
  port, path, HTTPS flag, TLS 1.2 minimum policy, and disables redirects,
  authentication, and cookies.  Requests use WinHTTP's asynchronous mode so
  cancellation never closes a handle concurrently with a synchronous API
  call.  Request callback state remains alive through HANDLE_CLOSING.
*)
unit uOSVTransportWinHTTP;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uOSVCore;

const
  OSVWinHTTPResolveTimeoutMS = 5000;
  OSVWinHTTPConnectTimeoutMS = 3000;
  OSVWinHTTPSendTimeoutMS = 5000;
  OSVWinHTTPReceiveTimeoutMS = 5000;
  OSVWinHTTPTotalTimeoutMS = 30000;

type
  EOSVWinHTTPTransportUnavailable = class(Exception);

  { Verified Windows production transport.  One PostQueryBatch may be active
    at a time.  Cancel is safe from another thread: it marks the operation and
    signals the posting thread, which exclusively retires the async request
    after any WinHTTP API call on that thread has unwound. }
  TOSVWinHTTPTransport = class(TInterfacedObject, IOSVTransport)
  private
    FAvailable: Boolean;
    {$IFDEF Windows}
    FCallActive: Boolean;
    FCancelled: Boolean;
    FLock: TRTLCriticalSection;
    FLockInitialized: Boolean;
    FRequest: Pointer;
    FRequestAbortPending: Boolean;
    FRequestAPICalls: Integer;
    FTimedOut: Boolean;
    FWakeEvent: Pointer;
    function BeginCall: Boolean;
    procedure EndCall(out AWasCancelled, AWasTimedOut: Boolean);
    procedure AbortActive(ACancelled, ATimedOut: Boolean);
    function Cancelled: Boolean;
    function TimedOut: Boolean;
    function RegisterRequest(AHandle: Pointer): Boolean;
    function EnterRequestAPI(AHandle: Pointer): Boolean;
    procedure LeaveRequestAPI(AHandle: Pointer);
    procedure CloseRegisteredRequest(AHandle: Pointer);
    function ExecuteQueryBatch(const AHost, APath: UnicodeString;
      APort: Word; ASecure: Boolean; const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    {$ENDIF}
  public
    { Creates an idle native transport; no endpoint is contacted. }
    constructor Create;
    destructor Destroy; override;
    { Posts only to https://api.osv.dev/v1/querybatch.  Native timeout,
      certificate, hostname, revocation, security-option, and request
      failures are otoFailed; a body bound violation is otoResponseTooLarge.
      The async request buffer and callback state live through send completion
      and HANDLE_CLOSING respectively. }
    function PostQueryBatch(const ARequestBody: RawByteString;
      AMaximumResponseBytes: Int64; ACancelCheck: TOSVCancelCheck;
      out AHTTPStatus: Integer; out AResponseBody: RawByteString):
      TOSVTransportOutcome;
    { May be called concurrently with PostQueryBatch; it never closes a
      request from another thread while a WinHTTP API call uses that handle. }
    procedure Cancel;
    {$IF Defined(Windows) and Defined(OSV_TRANSPORT_TEST_HOOKS)}
    { Test-only loopback entry point.  Production callers cannot select an
      endpoint; this symbol is absent from release builds. }
    function TestPostQueryBatchLoopback(APort: Word;
      ACancelCheck: TOSVCancelCheck): TOSVTransportOutcome;
    class function TestOutstandingAsyncStates: Integer; static;
    class function TestConstructorAcquisitionCount: Integer; static;
    class function TestConstructorFailureAt(AIndex: Integer): Boolean;
      static;
    class function TestAsyncStateAcquisitionCount: Integer; static;
    class function TestAsyncStateFailureAt(AIndex: Integer): Boolean;
      static;
    class function TestReaperAcquisitionCount: Integer; static;
    class function TestReaperFailureAt(AIndex: Integer): Boolean; static;
    class function TestReaperStartFailure: Boolean; static;
    {$ENDIF}
    property Available: Boolean read FAvailable;
  end;

implementation

{$IFDEF Windows}

uses
  Windows, WinHTTP;

const
  OSVHost: UnicodeString = 'api.osv.dev';
  OSVPath: UnicodeString = '/v1/querybatch';
  OSVVerb: UnicodeString = 'POST';
  OSVUserAgent: UnicodeString = 'PurpleRay-SBOM-Analyzer/OSV';
  OSVReadBufferSize = 16384;
  OSVWinHTTPPollIntervalMS = 25;

function NativeWinHttpSetTimeouts(hInternet: HINTERNET;
  nResolveTimeout, nConnectTimeout, nSendTimeout,
  nReceiveTimeout: Integer): BOOL; stdcall; external 'winhttp.dll'
  name 'WinHttpSetTimeouts';

function NativeWinHttpSetStatusCallback(hInternet: HINTERNET;
  lpfnInternetCallback: WINHTTP_STATUS_CALLBACK; dwNotificationFlags: DWORD;
  dwReserved: DWORD_PTR): Pointer; stdcall; external 'winhttp.dll'
  name 'WinHttpSetStatusCallback';

type
  { WinHTTP callbacks touch only scalar fields and events.  The request
    buffers are managed here but are destroyed only by an FPC-created posting
    or reaper thread after HANDLE_CLOSING. }
  TWinHTTPAsyncState = class
  private
    FCloseEvent: THandle;
    FCallbacksActive: LongInt;
    FInformationLength: LongInt;
    FNativeError: LongInt;
    FOperationEvent: THandle;
    FOperationStatus: LongInt;
    FRefCount: LongInt;
  public
    Headers: UnicodeString;
    ReadBuffer: array[0..OSVReadBufferSize - 1] of Byte;
    RequestBody: RawByteString;
    constructor Create;
    destructor Destroy; override;
    procedure AddRef; inline;
    procedure CallbackEnter; inline;
    procedure CallbackLeave; inline;
    function CallbacksActive: Boolean; inline;
    procedure Release; inline;
    procedure PrepareOperation;
    procedure Notify(AStatus: DWORD; AInformation: Pointer;
      AInformationLength: DWORD);
    property CloseEvent: THandle read FCloseEvent;
    property InformationLength: LongInt read FInformationLength;
    property NativeError: LongInt read FNativeError;
    property OperationEvent: THandle read FOperationEvent;
    property OperationStatus: LongInt read FOperationStatus;
  end;

  TWinHTTPCloseReaper = class(TThread)
  private
    FState: TWinHTTPAsyncState;
    FWaitForClosing: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(AState: TWinHTTPAsyncState);
    destructor Destroy; override;
    procedure Arm(AWaitForClosing: Boolean);
  end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
var
  WinHTTPTestOutstandingStates: LongInt;
  WinHTTPConstructorFailAt: Integer;
  WinHTTPConstructorAcquisitions: Integer;
  WinHTTPReaperFailBeforeStart: Boolean;

procedure ConstructorAcquired;
begin
  Inc(WinHTTPConstructorAcquisitions);
  if WinHTTPConstructorAcquisitions = WinHTTPConstructorFailAt then
    raise EOSVWinHTTPTransportUnavailable.CreateFmt(
      'Injected WinHTTP constructor failure at acquisition %d',
      [WinHTTPConstructorAcquisitions]);
end;
{$ENDIF}

constructor TWinHTTPAsyncState.Create;
begin
  inherited Create;
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  InterlockedIncrement(WinHTTPTestOutstandingStates);
  {$ENDIF}
  FRefCount := 1;
  FOperationEvent := CreateEvent(nil, True, False, nil);
  if FOperationEvent = 0 then
    raise EOSVWinHTTPTransportUnavailable.Create(
      'Unable to allocate the WinHTTP operation event');
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
  FCloseEvent := CreateEvent(nil, True, False, nil);
  if FCloseEvent = 0 then
    raise EOSVWinHTTPTransportUnavailable.Create(
      'Unable to allocate the WinHTTP close event');
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
end;

destructor TWinHTTPAsyncState.Destroy;
begin
  if FCloseEvent <> 0 then
    CloseHandle(FCloseEvent);
  if FOperationEvent <> 0 then
    CloseHandle(FOperationEvent);
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  InterlockedDecrement(WinHTTPTestOutstandingStates);
  {$ENDIF}
  inherited Destroy;
end;

procedure TWinHTTPAsyncState.AddRef;
begin
  InterlockedIncrement(FRefCount);
end;

procedure TWinHTTPAsyncState.CallbackEnter;
begin
  InterlockedIncrement(FCallbacksActive);
end;

procedure TWinHTTPAsyncState.CallbackLeave;
begin
  { This is the callback's final access to State.  The reaper observes zero
    only after every callback, including HANDLE_CLOSING, has stopped touching
    the object and its event handles. }
  InterlockedDecrement(FCallbacksActive);
end;

function TWinHTTPAsyncState.CallbacksActive: Boolean;
begin
  Result := InterlockedCompareExchange(FCallbacksActive, 0, 0) <> 0;
end;

procedure TWinHTTPAsyncState.Release;
begin
  if InterlockedDecrement(FRefCount) = 0 then
    Free;
end;

procedure TWinHTTPAsyncState.PrepareOperation;
begin
  InterlockedExchange(FInformationLength, 0);
  InterlockedExchange(FNativeError, 0);
  InterlockedExchange(FOperationStatus, 0);
  ResetEvent(FOperationEvent);
end;

procedure TWinHTTPAsyncState.Notify(AStatus: DWORD; AInformation: Pointer;
  AInformationLength: DWORD);
var
  AsyncResult: LPWINHTTP_ASYNC_RESULT;
begin
  case AStatus of
    WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE,
    WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE,
    WINHTTP_CALLBACK_STATUS_READ_COMPLETE,
    WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
    WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
      begin
        if AStatus = WINHTTP_CALLBACK_STATUS_READ_COMPLETE then
          InterlockedExchange(FInformationLength,
            LongInt(AInformationLength))
        else if (AStatus = WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) and
          (AInformation <> nil) and
          (AInformationLength >= SizeOf(WINHTTP_ASYNC_RESULT)) then
        begin
          AsyncResult := LPWINHTTP_ASYNC_RESULT(AInformation);
          InterlockedExchange(FNativeError, LongInt(AsyncResult^.dwError));
        end;
        if InterlockedCompareExchange(FOperationStatus,
          LongInt(AStatus), 0) = 0 then
          SetEvent(FOperationEvent);
      end;
    WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
      begin
        { HANDLE_CLOSING is the last callback for this request. }
        SetEvent(FCloseEvent);
        if InterlockedCompareExchange(FOperationStatus,
          LongInt(AStatus), 0) = 0 then
          SetEvent(FOperationEvent);
      end;
  end;
end;

procedure OSVWinHTTPStatusCallback(hInternet: HINTERNET;
  dwContext: DWORD_PTR; dwInternetStatus: DWORD;
  lpvStatusInformation: LPVOID; dwStatusInformationLength: DWORD); stdcall;
var
  State: TWinHTTPAsyncState;
begin
  if dwContext = 0 then
    Exit;
  State := TWinHTTPAsyncState(Pointer(dwContext));
  State.CallbackEnter;
  try
    State.Notify(dwInternetStatus, lpvStatusInformation,
      dwStatusInformationLength);
  finally
    State.CallbackLeave;
  end;
end;

constructor TWinHTTPCloseReaper.Create(AState: TWinHTTPAsyncState);
begin
  { Initial suspension makes FPC's automatic destructor safe if any derived
    constructor step raises: SysDestroy terminates/resumes the worker without
    entering Execute. }
  inherited Create(True);
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
  { The constructing/calling thread owns the suspended worker until Arm has
    passed every raising operation. }
  FreeOnTerminate := False;
  if AState = nil then
    raise EOSVWinHTTPTransportUnavailable.Create(
      'WinHTTP close-reaper state is unavailable');
  FState := AState;
  FState.AddRef;
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
end;

procedure TWinHTTPCloseReaper.Arm(AWaitForClosing: Boolean);
begin
  FWaitForClosing := AWaitForClosing;
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  if WinHTTPReaperFailBeforeStart then
    raise EOSVWinHTTPTransportUnavailable.Create(
      'Injected WinHTTP reaper failure before TThread.Start');
  {$ENDIF}
  { In FPC 3.2.2 Start delegates to the Win32 Resume implementation, which
    calls ResumeThread and has no exception path.  The caller transfers
    ownership only after this call returns. }
  FreeOnTerminate := True;
  Start;
end;

destructor TWinHTTPCloseReaper.Destroy;
var
  State: TWinHTTPAsyncState;
begin
  State := FState;
  FState := nil;
  inherited Destroy;
  if State <> nil then
    State.Release;
end;

procedure TWinHTTPCloseReaper.Execute;
var
  State: TWinHTTPAsyncState;
begin
  State := FState;
  FState := nil;
  try
    if FWaitForClosing then
    begin
      WaitForSingleObject(State.CloseEvent, INFINITE);
      while State.CallbacksActive do
        Sleep(1);
    end;
  finally
    State.Release;
  end;
end;

constructor TOSVWinHTTPTransport.Create;
begin
  inherited Create;
  FLockInitialized := False;
  InitCriticalSection(FLock);
  FLockInitialized := True;
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
  FWakeEvent := Pointer(CreateEvent(nil, True, False, nil));
  if FWakeEvent = nil then
    raise EOSVWinHTTPTransportUnavailable.Create(
      'Unable to allocate the WinHTTP cancellation event');
  {$IFDEF OSV_TRANSPORT_TEST_HOOKS}
  ConstructorAcquired;
  {$ENDIF}
  FAvailable := True;
end;

destructor TOSVWinHTTPTransport.Destroy;
begin
  if FLockInitialized then
    Cancel;
  if FWakeEvent <> nil then
  begin
    CloseHandle(THandle(FWakeEvent));
    FWakeEvent := nil;
  end;
  if FLockInitialized then
  begin
    FLockInitialized := False;
    DoneCriticalSection(FLock);
  end;
  inherited Destroy;
end;

function TOSVWinHTTPTransport.BeginCall: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := not FCallActive;
    if Result then
    begin
      FCallActive := True;
      FCancelled := False;
      FTimedOut := False;
      FRequest := nil;
      FRequestAbortPending := False;
      FRequestAPICalls := 0;
      ResetEvent(THandle(FWakeEvent));
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVWinHTTPTransport.EndCall(out AWasCancelled,
  AWasTimedOut: Boolean);
begin
  EnterCriticalSection(FLock);
  try
    AWasCancelled := FCancelled;
    AWasTimedOut := FTimedOut;
    FCallActive := False;
    FRequest := nil;
    FRequestAbortPending := False;
    FRequestAPICalls := 0;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVWinHTTPTransport.AbortActive(ACancelled, ATimedOut: Boolean);
var
  RequestValue: Pointer;
begin
  RequestValue := nil;
  EnterCriticalSection(FLock);
  try
    if FCallActive then
    begin
      if ACancelled then
        FCancelled := True;
      if ATimedOut then
        FTimedOut := True;
      if FRequest <> nil then
      begin
        if FRequestAPICalls = 0 then
        begin
          RequestValue := FRequest;
          FRequest := nil;
          FRequestAbortPending := False;
        end
        else
          FRequestAbortPending := True;
      end;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
  if RequestValue <> nil then
    WinHttpCloseHandle(HINTERNET(RequestValue));
end;

function TOSVWinHTTPTransport.Cancelled: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FCancelled;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVWinHTTPTransport.TimedOut: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FTimedOut;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVWinHTTPTransport.RegisterRequest(AHandle: Pointer): Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FCallActive and not FCancelled and not FTimedOut;
    if Result then
    begin
      FRequest := AHandle;
      FRequestAbortPending := False;
      FRequestAPICalls := 0;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

function TOSVWinHTTPTransport.EnterRequestAPI(AHandle: Pointer): Boolean;
begin
  EnterCriticalSection(FLock);
  try
    Result := FCallActive and not FCancelled and not FTimedOut and
      (FRequest = AHandle) and not FRequestAbortPending;
    if Result then
      Inc(FRequestAPICalls);
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TOSVWinHTTPTransport.LeaveRequestAPI(AHandle: Pointer);
var
  RequestValue: Pointer;
begin
  RequestValue := nil;
  EnterCriticalSection(FLock);
  try
    if FRequestAPICalls > 0 then
      Dec(FRequestAPICalls);
    if (FRequestAPICalls = 0) and FRequestAbortPending and
      (FRequest = AHandle) then
    begin
      RequestValue := FRequest;
      FRequest := nil;
      FRequestAbortPending := False;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
  if RequestValue <> nil then
    WinHttpCloseHandle(HINTERNET(RequestValue));
end;

procedure TOSVWinHTTPTransport.CloseRegisteredRequest(AHandle: Pointer);
var
  RequestValue: Pointer;
begin
  RequestValue := nil;
  EnterCriticalSection(FLock);
  try
    if FRequest = AHandle then
    begin
      if FRequestAPICalls = 0 then
      begin
        RequestValue := FRequest;
        FRequest := nil;
        FRequestAbortPending := False;
      end
      else
        FRequestAbortPending := True;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
  if RequestValue <> nil then
    WinHttpCloseHandle(HINTERNET(RequestValue));
end;

procedure TOSVWinHTTPTransport.Cancel;
var
  MustWake: Boolean;
begin
  EnterCriticalSection(FLock);
  try
    MustWake := FCallActive;
    if MustWake then
      FCancelled := True;
  finally
    LeaveCriticalSection(FLock);
  end;
  { WinHTTP request handles are owned by the posting thread.  Waking that
    thread avoids every cross-thread CloseHandle/API-call race. }
  if MustWake then
    SetEvent(THandle(FWakeEvent));
end;

function CallbackCancelled(ACancelCheck: TOSVCancelCheck): Boolean;
begin
  Result := Assigned(ACancelCheck) and ACancelCheck();
end;

function TOSVWinHTTPTransport.ExecuteQueryBatch(
  const AHost, APath: UnicodeString; APort: Word; ASecure: Boolean;
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
const
  IgnoreCertificateFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA or
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID or
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID or
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
var
  BufferLength, BytesRead, DisableFeatures, NativeError, OptionLength,
    RedirectPolicy, RevocationFeature, SecurityFlags, SecureProtocols,
    StatusCode: DWORD;
  Capacity, Used: SizeInt;
  CallbackAttached, NativeResult, RequestRegistered: Boolean;
  ConnectionHandle, RequestHandle, SessionHandle: HINTERNET;
  ContextValue: DWORD_PTR;
  Reaper: TWinHTTPCloseReaper;
  RequestPointer: Pointer;
  RequestFlags: DWORD;
  State: TWinHTTPAsyncState;
  TotalDeadline: QWord;
  WasCancelled, WasTimedOut: Boolean;

  function AbortRequested: Boolean;
  begin
    if Cancelled then
    begin
      AbortActive(False, False);
      Exit(True);
    end;
    if CallbackCancelled(ACancelCheck) then
      AbortActive(True, False)
    else if GetTickCount64 >= TotalDeadline then
      AbortActive(False, True);
    Result := Cancelled or TimedOut;
  end;

  function AsyncCallAccepted(ACallResult: Boolean;
    ALastError: DWORD): Boolean;
  begin
    Result := ACallResult or (ALastError = ERROR_IO_PENDING);
  end;

  function WaitForOperation(AExpectedStatus: DWORD): Boolean;
  var
    WaitHandles: array[0..1] of THandle;
    Status: LongInt;
    WaitResult: DWORD;
  begin
    Result := False;
    WaitHandles[0] := State.OperationEvent;
    WaitHandles[1] := THandle(FWakeEvent);
    repeat
      if AbortRequested then
        Exit;
      WaitResult := WaitForMultipleObjects(2, @WaitHandles[0], False,
        OSVWinHTTPPollIntervalMS);
      if WaitResult = WAIT_OBJECT_0 then
      begin
        Status := State.OperationStatus;
        Exit(DWORD(Status) = AExpectedStatus);
      end;
      if WaitResult = WAIT_OBJECT_0 + 1 then
      begin
        AbortRequested;
        Exit;
      end;
      if WaitResult <> WAIT_TIMEOUT then
        Exit;
    until False;
  end;

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
  SessionHandle := nil;
  ConnectionHandle := nil;
  RequestHandle := nil;
  CallbackAttached := False;
  RequestRegistered := False;
  Reaper := nil;
  State := nil;
  try
    TotalDeadline := GetTickCount64 + OSVWinHTTPTotalTimeoutMS;
    if CallbackCancelled(ACancelCheck) then
    begin
      Cancel;
      Exit;
    end;
    SessionHandle := WinHttpOpen(PWideChar(OSVUserAgent),
      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    if SessionHandle = nil then
      Exit;
    if AbortRequested then
      Exit;
    if not NativeWinHttpSetTimeouts(SessionHandle,
      OSVWinHTTPResolveTimeoutMS, OSVWinHTTPConnectTimeoutMS,
      OSVWinHTTPSendTimeoutMS, OSVWinHTTPReceiveTimeoutMS) then
      Exit;
    SecureProtocols := WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if not WinHttpSetOption(SessionHandle, WINHTTP_OPTION_SECURE_PROTOCOLS,
      @SecureProtocols, SizeOf(SecureProtocols)) then
      Exit;
    ConnectionHandle := WinHttpConnect(SessionHandle, PWideChar(AHost),
      APort, 0);
    if ConnectionHandle = nil then
      Exit;
    if AbortRequested then
      Exit;
    if ASecure then
      RequestFlags := WINHTTP_FLAG_SECURE
    else
      RequestFlags := 0;
    RequestHandle := WinHttpOpenRequest(ConnectionHandle,
      PWideChar(OSVVerb), PWideChar(APath), nil, WINHTTP_NO_REFERER,
      nil, RequestFlags);
    if RequestHandle = nil then
      Exit;

    RedirectPolicy := WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if not WinHttpSetOption(RequestHandle, WINHTTP_OPTION_REDIRECT_POLICY,
      @RedirectPolicy, SizeOf(RedirectPolicy)) then
      Exit;
    DisableFeatures := WINHTTP_DISABLE_REDIRECTS or
      WINHTTP_DISABLE_AUTHENTICATION or WINHTTP_DISABLE_COOKIES;
    if not WinHttpSetOption(RequestHandle, WINHTTP_OPTION_DISABLE_FEATURE,
      @DisableFeatures, SizeOf(DisableFeatures)) then
      Exit;
    if ASecure then
    begin
      RevocationFeature := WINHTTP_ENABLE_SSL_REVOCATION;
      if not WinHttpSetOption(RequestHandle, WINHTTP_OPTION_ENABLE_FEATURE,
        @RevocationFeature, SizeOf(RevocationFeature)) then
        Exit;
    end;

    State := TWinHTTPAsyncState.Create;
    Reaper := TWinHTTPCloseReaper.Create(State);
    Reaper.Arm(True);
    Reaper := nil; { self-releasing ownership transferred after nonraising Start }
    ContextValue := DWORD_PTR(State);
    if not WinHttpSetOption(RequestHandle, WINHTTP_OPTION_CONTEXT_VALUE,
      @ContextValue, SizeOf(ContextValue)) then
      Exit;
    if NativeWinHttpSetStatusCallback(RequestHandle,
      @OSVWinHTTPStatusCallback,
      WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE or
      WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE or
      WINHTTP_CALLBACK_STATUS_READ_COMPLETE or
      WINHTTP_CALLBACK_STATUS_REQUEST_ERROR or
      WINHTTP_CALLBACK_STATUS_SECURE_FAILURE or
      WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING, 0) = Pointer(-1) then
      Exit;
    CallbackAttached := True;
    if not RegisterRequest(Pointer(RequestHandle)) then
      Exit;
    RequestRegistered := True;

    State.Headers := 'Content-Type: application/json'#13#10 +
      'Accept: application/json'#13#10 +
      'Accept-Encoding: identity'#13#10;
    UniqueString(State.Headers);
    State.RequestBody := ARequestBody;
    UniqueString(State.RequestBody);
    if Length(State.RequestBody) = 0 then
      RequestPointer := nil
    else
      RequestPointer := @State.RequestBody[1];
    State.PrepareOperation;
    if not EnterRequestAPI(Pointer(RequestHandle)) then
      Exit;
    try
      NativeResult := WinHttpSendRequest(RequestHandle,
        PWideChar(State.Headers), Length(State.Headers), RequestPointer,
        Length(State.RequestBody), Length(State.RequestBody), ContextValue);
      if NativeResult then
        NativeError := ERROR_SUCCESS
      else
        NativeError := GetLastError;
    finally
      LeaveRequestAPI(Pointer(RequestHandle));
    end;
    if not AsyncCallAccepted(NativeResult, NativeError) or
      not WaitForOperation(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE) then
      Exit;

    State.PrepareOperation;
    if not EnterRequestAPI(Pointer(RequestHandle)) then
      Exit;
    try
      NativeResult := WinHttpReceiveResponse(RequestHandle, nil);
      if NativeResult then
        NativeError := ERROR_SUCCESS
      else
        NativeError := GetLastError;
    finally
      LeaveRequestAPI(Pointer(RequestHandle));
    end;
    if not AsyncCallAccepted(NativeResult, NativeError) or
      not WaitForOperation(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE) then
      Exit;

    if ASecure then
    begin
      SecurityFlags := 0;
      OptionLength := SizeOf(SecurityFlags);
      if not EnterRequestAPI(Pointer(RequestHandle)) then
        Exit;
      try
        NativeResult := WinHttpQueryOption(RequestHandle,
          WINHTTP_OPTION_SECURITY_FLAGS, @SecurityFlags, @OptionLength);
      finally
        LeaveRequestAPI(Pointer(RequestHandle));
      end;
      if not NativeResult or
        ((SecurityFlags and IgnoreCertificateFlags) <> 0) then
        Exit;
    end;
    StatusCode := 0;
    BufferLength := SizeOf(StatusCode);
    if not EnterRequestAPI(Pointer(RequestHandle)) then
      Exit;
    try
      NativeResult := WinHttpQueryHeaders(RequestHandle,
        WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, @StatusCode, @BufferLength,
        WINHTTP_NO_HEADER_INDEX);
    finally
      LeaveRequestAPI(Pointer(RequestHandle));
    end;
    if not NativeResult then
      Exit;
    AHTTPStatus := StatusCode;

    Capacity := 0;
    Used := 0;
    repeat
      State.PrepareOperation;
      if not EnterRequestAPI(Pointer(RequestHandle)) then
        Exit;
      try
        NativeResult := WinHttpReadData(RequestHandle,
          @State.ReadBuffer[0], OSVReadBufferSize, nil);
        if NativeResult then
          NativeError := ERROR_SUCCESS
        else
          NativeError := GetLastError;
      finally
        LeaveRequestAPI(Pointer(RequestHandle));
      end;
      if not AsyncCallAccepted(NativeResult, NativeError) or
        not WaitForOperation(WINHTTP_CALLBACK_STATUS_READ_COMPLETE) then
        Exit;
      BytesRead := DWORD(State.InformationLength);
      if BytesRead = 0 then
        Break;
      if Int64(Used) + BytesRead > AMaximumResponseBytes then
      begin
        Result := otoResponseTooLarge;
        Exit;
      end;
      if Used + BytesRead > Capacity then
      begin
        if Capacity = 0 then
          Capacity := OSVReadBufferSize;
        while Capacity < Used + BytesRead do
          Capacity := Capacity * 2;
        if Capacity > AMaximumResponseBytes then
          Capacity := SizeInt(AMaximumResponseBytes);
        SetLength(AResponseBody, Capacity);
      end;
      Move(State.ReadBuffer[0], AResponseBody[Used + 1], BytesRead);
      Inc(Used, BytesRead);
    until False;
    SetLength(AResponseBody, Used);
    if AbortRequested then
      Exit;
    Result := otoSucceeded;
  finally
    if Reaper <> nil then
    begin
      { Arm can fail only at the ignored pre-Start injection seam.  The local
        therefore owns a definitely suspended worker and may destroy it. }
      Reaper.FreeOnTerminate := False;
      Reaper.Free;
      Reaper := nil;
    end;
    if RequestHandle <> nil then
    begin
      if RequestRegistered then
        CloseRegisteredRequest(Pointer(RequestHandle))
      else
        WinHttpCloseHandle(RequestHandle);
    end;
    if (State <> nil) and not CallbackAttached then
      State.Notify(WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING, nil, 0);
    if ConnectionHandle <> nil then
      WinHttpCloseHandle(ConnectionHandle);
    if SessionHandle <> nil then
      WinHttpCloseHandle(SessionHandle);
    if State <> nil then
      State.Release;
    { Atomically capture the terminal flags while marking this call inactive,
      closing the race between an external Cancel and outcome selection. }
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

function TOSVWinHTTPTransport.PostQueryBatch(
  const ARequestBody: RawByteString; AMaximumResponseBytes: Int64;
  ACancelCheck: TOSVCancelCheck; out AHTTPStatus: Integer;
  out AResponseBody: RawByteString): TOSVTransportOutcome;
begin
  Result := ExecuteQueryBatch(OSVHost, OSVPath,
    INTERNET_DEFAULT_HTTPS_PORT, True, ARequestBody,
    AMaximumResponseBytes, ACancelCheck, AHTTPStatus, AResponseBody);
end;

{$IFDEF OSV_TRANSPORT_TEST_HOOKS}
function TOSVWinHTTPTransport.TestPostQueryBatchLoopback(APort: Word;
  ACancelCheck: TOSVCancelCheck): TOSVTransportOutcome;
var
  HTTPStatus: Integer;
  ResponseBody: RawByteString;
begin
  Result := ExecuteQueryBatch('127.0.0.1', '/', APort, False,
    '{"queries":[{"package":{"purl":"pkg:npm/test@1"}}]}',
    1024, ACancelCheck, HTTPStatus, ResponseBody);
end;

class function TOSVWinHTTPTransport.TestOutstandingAsyncStates: Integer;
begin
  Result := InterlockedCompareExchange(WinHTTPTestOutstandingStates, 0, 0);
end;

class function TOSVWinHTTPTransport.TestConstructorAcquisitionCount:
  Integer;
var
  Instance: TOSVWinHTTPTransport;
begin
  Instance := nil;
  WinHTTPConstructorFailAt := 0;
  WinHTTPConstructorAcquisitions := 0;
  try
    Instance := TOSVWinHTTPTransport.Create;
    Result := WinHTTPConstructorAcquisitions;
  finally
    Instance.Free;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestConstructorFailureAt(
  AIndex: Integer): Boolean;
var
  Instance: TOSVWinHTTPTransport;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  Instance := nil;
  WinHTTPConstructorAcquisitions := 0;
  WinHTTPConstructorFailAt := AIndex;
  try
    try
      Instance := TOSVWinHTTPTransport.Create;
    except
      on E: EOSVWinHTTPTransportUnavailable do
        Result := (WinHTTPConstructorAcquisitions = AIndex) and
          (Pos('Injected WinHTTP constructor failure', E.Message) = 1);
    end;
  finally
    Instance.Free;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestAsyncStateAcquisitionCount:
  Integer;
var
  State: TWinHTTPAsyncState;
begin
  State := nil;
  WinHTTPConstructorFailAt := 0;
  WinHTTPConstructorAcquisitions := 0;
  try
    State := TWinHTTPAsyncState.Create;
    Result := WinHTTPConstructorAcquisitions;
  finally
    if State <> nil then
      State.Release;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestAsyncStateFailureAt(
  AIndex: Integer): Boolean;
var
  State: TWinHTTPAsyncState;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  State := nil;
  WinHTTPConstructorAcquisitions := 0;
  WinHTTPConstructorFailAt := AIndex;
  try
    try
      State := TWinHTTPAsyncState.Create;
    except
      on E: EOSVWinHTTPTransportUnavailable do
        Result := (WinHTTPConstructorAcquisitions = AIndex) and
          (Pos('Injected WinHTTP constructor failure', E.Message) = 1);
    end;
  finally
    if State <> nil then
      State.Release;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestReaperAcquisitionCount: Integer;
var
  Reaper: TWinHTTPCloseReaper;
  State: TWinHTTPAsyncState;
begin
  Reaper := nil;
  State := nil;
  WinHTTPConstructorFailAt := 0;
  WinHTTPConstructorAcquisitions := 0;
  try
    State := TWinHTTPAsyncState.Create;
    WinHTTPConstructorAcquisitions := 0;
    Reaper := TWinHTTPCloseReaper.Create(State);
    Reaper.FreeOnTerminate := False;
    Result := WinHTTPConstructorAcquisitions;
  finally
    Reaper.Free;
    if State <> nil then
      State.Release;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestReaperFailureAt(
  AIndex: Integer): Boolean;
var
  Reaper: TWinHTTPCloseReaper;
  State: TWinHTTPAsyncState;
begin
  Result := False;
  if AIndex <= 0 then
    Exit;
  Reaper := nil;
  State := nil;
  WinHTTPConstructorFailAt := 0;
  WinHTTPConstructorAcquisitions := 0;
  try
    State := TWinHTTPAsyncState.Create;
    WinHTTPConstructorAcquisitions := 0;
    WinHTTPConstructorFailAt := AIndex;
    try
      Reaper := TWinHTTPCloseReaper.Create(State);
    except
      on E: EOSVWinHTTPTransportUnavailable do
        Result := (WinHTTPConstructorAcquisitions = AIndex) and
          (Pos('Injected WinHTTP constructor failure', E.Message) = 1);
    end;
  finally
    if Reaper <> nil then
    begin
      Reaper.FreeOnTerminate := False;
      Reaper.Free;
    end;
    if State <> nil then
      State.Release;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;

class function TOSVWinHTTPTransport.TestReaperStartFailure: Boolean;
var
  Reaper: TWinHTTPCloseReaper;
  State: TWinHTTPAsyncState;
begin
  Result := False;
  Reaper := nil;
  State := nil;
  WinHTTPConstructorFailAt := 0;
  WinHTTPConstructorAcquisitions := 0;
  WinHTTPReaperFailBeforeStart := False;
  try
    State := TWinHTTPAsyncState.Create;
    WinHTTPConstructorAcquisitions := 0;
    Reaper := TWinHTTPCloseReaper.Create(State);
    WinHTTPReaperFailBeforeStart := True;
    try
      Reaper.Arm(True);
    except
      on E: EOSVWinHTTPTransportUnavailable do
        Result := E.Message =
          'Injected WinHTTP reaper failure before TThread.Start';
    end;
  finally
    WinHTTPReaperFailBeforeStart := False;
    if Reaper <> nil then
    begin
      Reaper.FreeOnTerminate := False;
      Reaper.Free;
    end;
    if State <> nil then
      State.Release;
    WinHTTPConstructorFailAt := 0;
    WinHTTPConstructorAcquisitions := 0;
  end;
end;
{$ENDIF}

{$ELSE}

constructor TOSVWinHTTPTransport.Create;
begin
  inherited Create;
  FAvailable := False;
  raise EOSVWinHTTPTransportUnavailable.Create(
    'The WinHTTP transport is available only on Windows');
end;

destructor TOSVWinHTTPTransport.Destroy;
begin
  inherited Destroy;
end;

procedure TOSVWinHTTPTransport.Cancel;
begin
end;

function TOSVWinHTTPTransport.PostQueryBatch(
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
