(**
  PurpleRay SBOM Analyzer production OSV transport factory.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.
*)
unit uOSVTransportFactory;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uOSVCore;

type
  EOSVProductionTransportUnavailable = class(Exception);

{ Creates the fail-closed native transport for the current platform.  Windows
  uses WinHTTP.  Linux uses the OS GIO resolver plus OpenSSL 3.  Unsupported
  targets, missing runtime libraries, or missing verification symbols raise
  EOSVProductionTransportUnavailable.  EOutOfMemory is propagated unchanged.
  This function never falls back to an unverified transport. }
function CreateProductionOSVTransport: IOSVTransport;

implementation

{$IFDEF Windows}
uses
  uOSVTransportWinHTTP;
{$ENDIF}
{$IFDEF Linux}
uses
  uOSVTransportOpenSSL;
{$ENDIF}

function CreateProductionOSVTransport: IOSVTransport;
begin
  Result := nil;
  try
    {$IFDEF Windows}
    Result := TOSVWinHTTPTransport.Create;
    {$ELSE}
      {$IFDEF Linux}
      Result := TOSVOpenSSLTransport.Create;
      {$ELSE}
      raise EOSVProductionTransportUnavailable.Create(
        'No verified OSV transport is available for this platform');
      {$ENDIF}
    {$ENDIF}
  except
    on E: EOutOfMemory do
      raise;
    on E: EOSVProductionTransportUnavailable do
      raise;
    on E: Exception do
      raise EOSVProductionTransportUnavailable.Create(
        'Verified OSV transport is unavailable: ' + E.Message);
  end;
end;

end.
