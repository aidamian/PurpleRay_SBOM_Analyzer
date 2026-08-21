(**
  PurpleRay SBOM Analyzer settings-persistence unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Loads and atomically saves the user's last scan settings with safe defaults
  and non-fatal recovery from malformed JSON.

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
unit uSettingsStore;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, uModels;

type
  TSettingsStore = class
  private
    FDataDirectory: string;
    function GetFileName: string;
  public
    {**
      Creates a settings store rooted at an explicit or default data directory.

      Parameters
      ----------
      ADataDirectory
        Override directory; an empty value selects ApplicationDataDirectory.

      Returns
      -------
      TSettingsStore
        Newly configured store.

      Raises
      ------
      None
    }
    constructor Create(const ADataDirectory: string = '');

    {**
      Atomically persists scan settings as versioned JSON.

      Parameters
      ----------
      ASettings
        Settings instance to serialize. The one-scan refresh override is forced
        off in the persisted clone.

      Returns
      -------
      None

      Raises
      ------
      EArgumentNilException
        Raised when ASettings is nil.
      EJSON, EOutOfMemory
        Propagated if deterministic UTF-8 serialization cannot complete.
      EFCreateError, EWriteError, EInOutError
        Propagated by atomic persistence.
    }
    procedure Save(ASettings: TScanSettings);

    {**
      Loads persisted settings or returns safe defaults with a warning.

      Parameters
      ----------
      AWarning
        Receives a non-fatal parse or file-access diagnostic.

      Returns
      -------
      TScanSettings
        Newly allocated loaded or default settings owned by the caller.

      Raises
      ------
      EOutOfMemory
        Propagated if a settings object cannot be allocated.
    }
    function Load(out AWarning: string): TScanSettings;
    property FileName: string read GetFileName;
  end;

implementation

uses
  fpjson, uPlatform, uAtomicFiles, uJSONUtils;

constructor TSettingsStore.Create(const ADataDirectory: string);
begin
  inherited Create;
  if ADataDirectory <> '' then
    FDataDirectory := ExcludeTrailingPathDelimiter(ExpandFileName(ADataDirectory))
  else
    FDataDirectory := ApplicationDataDirectory;
end;

function TSettingsStore.GetFileName: string;
begin
  Result := IncludeTrailingPathDelimiter(FDataDirectory) + 'settings.json';
end;

procedure TSettingsStore.Save(ASettings: TScanSettings);
var
  Root: TJSONObject;
  Content: UTF8String;
  PersistedSettings: TScanSettings;
begin
  if ASettings = nil then
    raise EArgumentNilException.Create('Settings must not be nil');
  PersistedSettings := ASettings.Clone;
  Root := nil;
  try
    Root := TJSONObject.Create;
    { A cache refresh is task provenance, never a future default. Enforce that
      invariant at the persistence boundary as well as in the current UI. }
    PersistedSettings.RefreshRescanCache := False;
    Root.Add('format_version', 1);
    Root.Add('scan_settings', PersistedSettings.ToJSON);
    Content := SerializeJSONUTF8(Root, [], 2, True);
    WriteAtomicUTF8(FileName, Content, True);
  finally
    Root.Free;
    PersistedSettings.Free;
  end;
end;

function TSettingsStore.Load(out AWarning: string): TScanSettings;
var
  Data: TJSONData;
  LoadedSettings: TScanSettings;
  Root: TJSONObject;
begin
  AWarning := '';
  Result := TScanSettings.Create;
  LoadedSettings := nil;
  if not FileExists(FileName) then
    Exit;
  try
    Data := ReadJSONFile(FileName);
    try
      if Data.JSONType <> jtObject then
        raise Exception.Create('settings root is not a JSON object');
      Root := TJSONObject(Data);
      if JSONInt64(Root, 'format_version', 0) <> 1 then
        raise Exception.Create('settings format version is unsupported');
      if JSONObject(Root, 'scan_settings') = nil then
        raise Exception.Create('scan settings are missing');
      LoadedSettings := TScanSettings.FromJSON(
        JSONObject(Root, 'scan_settings'));
      LoadedSettings.RefreshRescanCache := False;
      FreeAndNil(Result);
      Result := LoadedSettings;
      LoadedSettings := nil;
    finally
      Data.Free;
    end;
  except
    on E: Exception do
    begin
      AWarning := 'Saved scan settings could not be loaded: ' + E.Message +
        '. Defaults will be used.';
      FreeAndNil(Result);
      Result := TScanSettings.Create;
    end;
  end;
  LoadedSettings.Free;
end;

end.
