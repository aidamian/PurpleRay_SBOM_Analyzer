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
    pkPNPMLock);

  TArtifactDefinition = record
    Detected: Boolean;
    ArtifactType: string;
    Ecosystem: string;
    ParserName: string;
    ParserKind: TParserKind;
    PartialParser: Boolean;
  end;

function IdentifyArtifact(const AFileName, ARelativePath: string;
  out ADefinition: TArtifactDefinition): Boolean;
function IsLicenseEvidenceFile(const AFileName: string): Boolean;

implementation

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
  NameValue, ExtensionValue, RelativeValue: string;
begin
  ADefinition.Detected := False;
  ADefinition.ArtifactType := '';
  ADefinition.Ecosystem := '';
  ADefinition.ParserName := '';
  ADefinition.ParserKind := pkNone;
  ADefinition.PartialParser := False;
  NameValue := LowerCase(AFileName);
  ExtensionValue := LowerCase(ExtractFileExt(NameValue));
  RelativeValue := LowerCase(StringReplace(ARelativePath, '\', '/',
    [rfReplaceAll]));

  if NameValue = 'package.json' then
    Define(ADefinition, 'package.json', 'npm', 'package-json', pkPackageJSON)
  else if NameValue = 'package-lock.json' then
    Define(ADefinition, 'package-lock.json', 'npm', 'package-lock-json',
      pkPackageLockJSON)
  else if (Pos('requirements', NameValue) = 1) and
    (ExtensionValue = '.txt') then
    Define(ADefinition, 'requirements.txt', 'PyPI', 'requirements-text',
      pkRequirements)
  else if NameValue = 'pyproject.toml' then
    Define(ADefinition, 'pyproject.toml', 'PyPI', 'unsupported-toml', pkNone)
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
    (Pos('/gradle/dependency-locks/', '/' + RelativeValue) > 0)) then
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
