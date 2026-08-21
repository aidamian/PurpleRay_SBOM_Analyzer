# Copyright (c) 2026 Andrei Ionut Damian.
# Licensed under Apache-2.0. Retain LICENSE and NOTICE, and cite the project as
# described in NOTICE when redistributing or creating derivative works.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string]$Version,

    [string]$Executable,

    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Executable)) {
    $Executable = Join-Path $RepositoryRoot 'build/release/purpleray-sbom-analyzer.exe'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $RepositoryRoot 'dist'
}
$Executable = [System.IO.Path]::GetFullPath($Executable)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "Windows release executable not found: $Executable"
}
foreach ($RequiredFile in @('LICENSE', 'NOTICE')) {
    $RequiredPath = Join-Path $RepositoryRoot $RequiredFile
    if (-not (Test-Path -LiteralPath $RequiredPath -PathType Leaf)) {
        throw "Required packaging file not found: $RequiredPath"
    }
}

$ExpectedFileVersion = "$Version.0"
$ExpectedParts = @($Version.Split('.') | ForEach-Object { [int]$_ })
$VersionInfo = (Get-Item -LiteralPath $Executable).VersionInfo
$ExpectedMetadata = [ordered]@{
    ProductName      = 'PurpleRay SBOM Analyzer'
    ProductVersion   = $Version
    FileVersion      = $ExpectedFileVersion
    FileDescription  = 'PurpleRay SBOM Analyzer'
    CompanyName      = 'Andrei Ionut Damian'
    InternalName     = 'purpleray-sbom-analyzer'
    LegalCopyright   = 'Copyright (c) 2026 Andrei Ionut Damian'
    OriginalFilename = 'purpleray-sbom-analyzer.exe'
}
$ExpectedNumericMetadata = [ordered]@{
    FileMajorPart    = $ExpectedParts[0]
    FileMinorPart    = $ExpectedParts[1]
    FileBuildPart    = $ExpectedParts[2]
    FilePrivatePart  = 0
    ProductMajorPart = $ExpectedParts[0]
    ProductMinorPart = $ExpectedParts[1]
    ProductBuildPart = $ExpectedParts[2]
    ProductPrivatePart = 0
}
$MetadataErrors = [System.Collections.Generic.List[string]]::new()
foreach ($Field in $ExpectedMetadata.Keys) {
    if ($VersionInfo.$Field -ne $ExpectedMetadata[$Field]) {
        $MetadataErrors.Add(
            "$Field expected '$($ExpectedMetadata[$Field])', got '$($VersionInfo.$Field)'"
        )
    }
}
foreach ($Field in $ExpectedNumericMetadata.Keys) {
    if ($VersionInfo.$Field -ne $ExpectedNumericMetadata[$Field]) {
        $MetadataErrors.Add(
            "$Field expected '$($ExpectedNumericMetadata[$Field])', got '$($VersionInfo.$Field)'"
        )
    }
}
if ($MetadataErrors.Count -gt 0) {
    throw "Invalid Windows version metadata:`n - $($MetadataErrors -join "`n - ")"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Package = Join-Path $OutputDirectory "purpleray-sbom-analyzer-v$Version-windows-x64.zip"
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("purpleray-package-windows-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Stage | Out-Null
try {
    Copy-Item -LiteralPath $Executable -Destination (Join-Path $Stage 'purpleray-sbom-analyzer.exe')
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'LICENSE') -Destination (Join-Path $Stage 'LICENSE')
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'NOTICE') -Destination (Join-Path $Stage 'NOTICE')
    Compress-Archive -LiteralPath @(
        (Join-Path $Stage 'purpleray-sbom-analyzer.exe'),
        (Join-Path $Stage 'LICENSE'),
        (Join-Path $Stage 'NOTICE')
    ) -DestinationPath $Package -CompressionLevel Optimal -Force
} finally {
    if (Test-Path -LiteralPath $Stage) {
        Remove-Item -LiteralPath $Stage -Recurse -Force
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$Archive = [System.IO.Compression.ZipFile]::OpenRead($Package)
try {
    $Files = @($Archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') })
    $ActualNames = @($Files.FullName | Sort-Object)
    $ExpectedNames = @('LICENSE', 'NOTICE', 'purpleray-sbom-analyzer.exe')
    if (Compare-Object -ReferenceObject $ExpectedNames -DifferenceObject $ActualNames) {
        throw "Windows archive must contain exactly: $($ExpectedNames -join ', ')"
    }
    foreach ($NoticeName in @('LICENSE', 'NOTICE')) {
        $Entry = $Archive.GetEntry($NoticeName)
        $Reader = [System.IO.StreamReader]::new($Entry.Open())
        try {
            $ArchivedText = $Reader.ReadToEnd()
        } finally {
            $Reader.Dispose()
        }
        $SourceText = [System.IO.File]::ReadAllText((Join-Path $RepositoryRoot $NoticeName))
        if ($ArchivedText -ne $SourceText) {
            throw "$NoticeName in the Windows archive differs from the tracked source"
        }
    }
} finally {
    $Archive.Dispose()
}

Write-Host "Created and verified $Package"
