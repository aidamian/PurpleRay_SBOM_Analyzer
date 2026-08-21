(**
  PurpleRay SBOM Analyzer artifact-identification unit.

  Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
  the Apache License, Version 2.0; see LICENSE.

  Description
  -----------
  Classifies filenames as supported manifests, locks, binaries, or license
  evidence and selects the parser responsible for each artifact.

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
unit uArtifactIdentifier;

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  TParserKind = (
    pkNone,
    pkPackageJSON,
    pkPackageLockJSON,
    pkRequirements,
    pkGoMod,
    pkMavenPOM,
    pkMSBuildProject,
    pkNuGetLock,
    pkDirectoryPackages,
    pkComposerJSON,
    pkComposerLock,
    pkLazarusXML,
    pkPipfileLock,
    pkGoSum,
    pkCargoLock,
    pkCargoTOML,
    pkPoetryLock,
    pkYarnLock,
    pkGradleLock,
    pkGemLock,
    pkEnvironmentYAML,
    pkPackageResolved,
    pkPodfileLock,
    pkVcpkgJSON,
    pkConanText,
    pkPNPMLock,
    pkPyProjectTOML,
    pkInstalledPackageJSON,
    pkPythonDistInfoMetadata);

  TArtifactDefinition = record
    Detected: Boolean;
    ArtifactType: string;
    Ecosystem: string;
    ParserName: string;
    ParserKind: TParserKind;
    PartialParser: Boolean;
  end;

{**
  Identifies the parser and evidence type applicable to a filesystem entry.

  Parameters
  ----------
  AFileName
    Absolute or local filename used for content and extension checks.
  ARelativePath
    Root-relative path used for path-sensitive manifest recognition.
  ADefinition
    Receives the detected artifact type, ecosystem, parser, and parser mode.

  Returns
  -------
  Boolean
    True when the file is recognized as a supported or reportable artifact.

  Raises
  ------
  None
    Recognition failures are represented by False.
}
function IdentifyArtifact(const AFileName, ARelativePath: string;
  out ADefinition: TArtifactDefinition): Boolean;

{**
  Tests whether a filename is a conventional license-evidence filename.

  Parameters
  ----------
  AFileName
    Filename or path whose final component is inspected case-insensitively.

  Returns
  -------
  Boolean
    True for LICENSE, COPYING, NOTICE, and their supported variants.

  Raises
  ------
  None
}
function IsLicenseEvidenceFile(const AFileName: string): Boolean;

implementation

{**
  Tests one normalized path for an exact directory-segment match.

  Parameters
  ----------
  ARelativePath
    Root-relative path in either native or slash-separated notation.
  ASegment
    One directory name without path separators.

  Returns
  -------
  Boolean
    True only when ASegment occupies one complete path component.

  Raises
  ------
  None
*}
function ContainsPathSegment(const ARelativePath, ASegment: string): Boolean;
var
  PathValue, SegmentValue: string;
begin
  PathValue := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
  SegmentValue := ASegment;
  {$IFDEF Windows}
  PathValue := LowerCase(PathValue);
  SegmentValue := LowerCase(SegmentValue);
  {$ENDIF}
  Result := (SegmentValue <> '') and
    (Pos('/' + SegmentValue + '/', '/' + PathValue + '/') > 0);
end;

{**
  Recognizes Python installed-distribution metadata by its immediate parent.

  Parameters
  ----------
  ARelativePath
    Root-relative candidate path.

  Returns
  -------
  Boolean
    True only for ``METADATA`` directly beneath a nonempty ``*.dist-info``
    directory.

  Raises
  ------
  None
*}
function IsPythonDistInfoMetadataPath(const ARelativePath: string): Boolean;
const
  DistInfoSuffix = '.dist-info';
var
  PathValue, ParentPath, ParentName, MetadataName: string;
  LastSlash: SizeInt;
begin
  PathValue := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
  {$IFDEF Windows}
  PathValue := LowerCase(PathValue);
  MetadataName := 'metadata';
  {$ELSE}
  MetadataName := 'METADATA';
  {$ENDIF}
  LastSlash := LastDelimiter('/', PathValue);
  if (LastSlash <= 1) or
    (Copy(PathValue, LastSlash + 1, MaxInt) <> MetadataName) then
    Exit(False);
  ParentPath := Copy(PathValue, 1, LastSlash - 1);
  LastSlash := LastDelimiter('/', ParentPath);
  if LastSlash > 0 then
    ParentName := Copy(ParentPath, LastSlash + 1, MaxInt)
  else
    ParentName := ParentPath;
  Result := (Length(ParentName) > Length(DistInfoSuffix)) and
    (Copy(ParentName, Length(ParentName) - Length(DistInfoSuffix) + 1,
      Length(DistInfoSuffix)) = DistInfoSuffix);
end;

procedure Define(out ADefinition: TArtifactDefinition; const AType,
  AEcosystem, AParser: string; AKind: TParserKind; APartial: Boolean = False);
begin
  ADefinition.Detected := True;
  ADefinition.ArtifactType := AType;
  ADefinition.Ecosystem := AEcosystem;
  ADefinition.ParserName := AParser;
  ADefinition.ParserKind := AKind;
  ADefinition.PartialParser := APartial;
end;

function IsLicenseEvidenceFile(const AFileName: string): Boolean;
var
  NameValue: string;
begin
  NameValue := LowerCase(AFileName);
  Result := (NameValue = 'license') or (Pos('license.', NameValue) = 1) or
    (NameValue = 'copying') or (Pos('copying.', NameValue) = 1) or
    (NameValue = 'notice') or (Pos('notice.', NameValue) = 1);
end;

function IdentifyArtifact(const AFileName, ARelativePath: string;
  out ADefinition: TArtifactDefinition): Boolean;
var
  FileNameValue, NameValue, ExtensionValue, RelativeValue,
    RelativeCompareValue: string;
begin
  ADefinition.Detected := False;
  ADefinition.ArtifactType := '';
  ADefinition.Ecosystem := '';
  ADefinition.ParserName := '';
  ADefinition.ParserKind := pkNone;
  ADefinition.PartialParser := False;
  FileNameValue := ExtractFileName(AFileName);
  NameValue := LowerCase(FileNameValue);
  ExtensionValue := LowerCase(ExtractFileExt(NameValue));
  RelativeValue := StringReplace(ARelativePath, '\', '/', [rfReplaceAll]);
  RelativeCompareValue := LowerCase(RelativeValue);

  if IsPythonDistInfoMetadataPath(RelativeValue) then
    Define(ADefinition, 'Python installed distribution metadata', 'PyPI',
      'python-dist-info-metadata', pkPythonDistInfoMetadata)
  else if
    {$IFDEF Windows}(NameValue = 'package.json'){$ELSE}
    (FileNameValue = 'package.json'){$ENDIF} and
    ContainsPathSegment(RelativeValue, 'node_modules') then
    Define(ADefinition, 'installed package.json', 'npm',
      'installed-package-json', pkInstalledPackageJSON)
  else if NameValue = 'package.json' then
    Define(ADefinition, 'package.json', 'npm', 'package-json', pkPackageJSON)
  else if NameValue = 'package-lock.json' then
    Define(ADefinition, 'package-lock.json', 'npm', 'package-lock-json',
      pkPackageLockJSON)
  else if (Pos('requirements', NameValue) = 1) and
    (ExtensionValue = '.txt') then
    Define(ADefinition, 'requirements.txt', 'PyPI', 'requirements-text',
      pkRequirements)
  else if NameValue = 'pyproject.toml' then
    Define(ADefinition, 'pyproject.toml', 'PyPI',
      'conservative-pyproject-toml', pkPyProjectTOML, True)
  else if NameValue = 'poetry.lock' then
    Define(ADefinition, 'poetry.lock', 'PyPI', 'conservative-poetry-lock',
      pkPoetryLock, True)
  else if NameValue = 'pipfile' then
    Define(ADefinition, 'Pipfile', 'PyPI', 'unsupported-toml', pkNone)
  else if NameValue = 'pipfile.lock' then
    Define(ADefinition, 'Pipfile.lock', 'PyPI', 'pipfile-lock-json',
      pkPipfileLock, True)
  else if (NameValue = 'environment.yml') or (NameValue = 'environment.yaml') then
    Define(ADefinition, 'environment.yml', 'Conda', 'conservative-conda-yaml',
      pkEnvironmentYAML, True)
  else if NameValue = 'go.mod' then
    Define(ADefinition, 'go.mod', 'Go', 'go-mod-text', pkGoMod)
  else if NameValue = 'go.sum' then
    Define(ADefinition, 'go.sum', 'Go', 'conservative-go-sum', pkGoSum, True)
  else if NameValue = 'cargo.toml' then
    Define(ADefinition, 'Cargo.toml', 'Cargo', 'conservative-cargo-toml',
      pkCargoTOML, True)
  else if NameValue = 'cargo.lock' then
    Define(ADefinition, 'Cargo.lock', 'Cargo', 'conservative-cargo-lock',
      pkCargoLock, True)
  else if NameValue = 'pom.xml' then
    Define(ADefinition, 'pom.xml', 'Maven', 'maven-pom-xml', pkMavenPOM)
  else if (NameValue = 'build.gradle') or (NameValue = 'build.gradle.kts') then
    Define(ADefinition, 'Gradle build file', 'Gradle', 'unsupported-gradle', pkNone)
  else if (NameValue = 'gradle.lockfile') or
    ((ExtensionValue = '.lockfile') and
    (Pos('/gradle/dependency-locks/', '/' + RelativeCompareValue) > 0)) then
    Define(ADefinition, 'Gradle lock file', 'Gradle',
      'conservative-gradle-lock', pkGradleLock, True)
  else if ExtensionValue = '.csproj' then
    Define(ADefinition, 'MSBuild project', 'NuGet', 'msbuild-package-reference',
      pkMSBuildProject)
  else if NameValue = 'packages.lock.json' then
    Define(ADefinition, 'packages.lock.json', 'NuGet', 'nuget-lock-json',
      pkNuGetLock)
  else if NameValue = 'directory.packages.props' then
    Define(ADefinition, 'Directory.Packages.props', 'NuGet',
      'msbuild-central-package-xml', pkDirectoryPackages)
  else if NameValue = 'composer.json' then
    Define(ADefinition, 'composer.json', 'Composer', 'composer-json',
      pkComposerJSON)
  else if NameValue = 'composer.lock' then
    Define(ADefinition, 'composer.lock', 'Composer', 'composer-lock-json',
      pkComposerLock)
  else if NameValue = 'gemfile' then
    Define(ADefinition, 'Gemfile', 'RubyGems', 'unsupported-ruby', pkNone)
  else if NameValue = 'gemfile.lock' then
    Define(ADefinition, 'Gemfile.lock', 'RubyGems',
      'conservative-gemfile-lock', pkGemLock, True)
  else if NameValue = 'vcpkg.json' then
    Define(ADefinition, 'vcpkg.json', 'vcpkg', 'conservative-vcpkg-json',
      pkVcpkgJSON, True)
  else if NameValue = 'conanfile.txt' then
    Define(ADefinition, 'conanfile.txt', 'Conan', 'conservative-conan-text',
      pkConanText, True)
  else if NameValue = 'package.resolved' then
    Define(ADefinition, 'Package.resolved', 'Swift',
      'conservative-swift-resolved-json', pkPackageResolved, True)
  else if NameValue = 'podfile.lock' then
    Define(ADefinition, 'Podfile.lock', 'CocoaPods',
      'conservative-podfile-lock', pkPodfileLock, True)
  else if NameValue = 'yarn.lock' then
    Define(ADefinition, 'yarn.lock', 'npm', 'conservative-yarn-lock',
      pkYarnLock, True)
  else if (NameValue = 'pnpm-lock.yaml') or (NameValue = 'pnpm-lock.yml') then
    Define(ADefinition, 'pnpm-lock.yaml', 'npm', 'conservative-pnpm-lock',
      pkPNPMLock, True)
  else if (ExtensionValue = '.lpi') or (ExtensionValue = '.lpk') then
    Define(ADefinition, 'Lazarus project/package', 'FreePascal',
      'lazarus-project-xml', pkLazarusXML)
  else if IsLicenseEvidenceFile(AFileName) then
    Define(ADefinition, 'license evidence', '', 'license-evidence', pkNone)
  else
    Exit(False);
  Result := True;
end;

end.
