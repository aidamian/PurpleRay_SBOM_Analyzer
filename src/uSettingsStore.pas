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
    constructor Create(const ADataDirectory: string = '');
    procedure Save(ASettings: TScanSettings);
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
begin
  Root := TJSONObject.Create;
  try
    Root.Add('format_version', 1);
    Root.Add('scan_settings', ASettings.ToJSON);
    Content := UTF8Encode(NormalizeJSONLineEndings(Root.FormatJSON([], 2)) + #10);
    WriteAtomicUTF8(FileName, Content, True);
  finally
    Root.Free;
  end;
end;

function TSettingsStore.Load(out AWarning: string): TScanSettings;
var
  Data: TJSONData;
  Root: TJSONObject;
begin
  AWarning := '';
  Result := TScanSettings.Create;
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
      Result.Free;
      Result := TScanSettings.FromJSON(JSONObject(Root, 'scan_settings'));
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
end;

end.
