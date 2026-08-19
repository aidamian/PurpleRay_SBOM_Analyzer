<#
Copyright (c) 2026 Andrei Ionut Damian.

SBOM Analyzer is open source, but this notice and the project's BibTeX
citation must be retained and the original work cited in derivative works.
#>

$ErrorActionPreference = 'Stop'
$ProjectRepository = 'aidamian/SBOM_Analyzer'

function Stop-WithError {
    param([Parameter(Mandatory = $true)][string]$Message)

    [Console]::Error.WriteLine("start-windows.ps1: $Message")
    exit 1
}

if ($env:OS -ne 'Windows_NT') {
    Stop-WithError 'this script must be run from Windows PowerShell or PowerShell on Windows'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    Stop-WithError 'the published release requires 64-bit Windows'
}
if (-not [Environment]::UserInteractive) {
    Stop-WithError 'an interactive Windows desktop session is required'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Release = Invoke-RestMethod `
    -Uri "https://api.github.com/repos/$ProjectRepository/releases/latest" `
    -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'SBOM-Analyzer-start-windows' }
$TagName = [string]$Release.tag_name
if ($TagName -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
    Stop-WithError "GitHub returned an invalid release tag: $TagName"
}

$AssetName = "sbom-analyzer-$TagName-windows-x64.zip"
$Asset = $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
$ChecksumAsset = $Release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
if (-not $Asset -or -not $ChecksumAsset) {
    Stop-WithError 'the latest release does not contain the Windows package and checksums'
}

$InstallDirectory = Join-Path (Get-Location).ProviderPath "SBOM_Analyzer_$TagName"
$DataDirectory = Join-Path $HOME '.sbom-analyzer'
$ArchivePath = Join-Path $InstallDirectory ".$AssetName.download.zip"
$ChecksumPath = Join-Path $InstallDirectory '.SHA256SUMS.txt.download'
$BinaryPath = Join-Path $InstallDirectory 'sbom-analyzer.exe'

New-Item -ItemType Directory -Force -Path $InstallDirectory, $DataDirectory | Out-Null

try {
    Write-Host "Downloading SBOM Analyzer $TagName into $InstallDirectory"
    Invoke-WebRequest -UseBasicParsing -Uri $Asset.browser_download_url -OutFile $ArchivePath
    Invoke-WebRequest -UseBasicParsing -Uri $ChecksumAsset.browser_download_url -OutFile $ChecksumPath

    $EscapedAssetName = [Regex]::Escape($AssetName)
    $ChecksumLine = Get-Content -LiteralPath $ChecksumPath |
        Where-Object { $_ -match "^[0-9A-Fa-f]{64}\s+\*?$EscapedAssetName$" } |
        Select-Object -First 1
    if (-not $ChecksumLine) {
        Stop-WithError "no valid checksum was published for $AssetName"
    }

    $ExpectedChecksum = ($ChecksumLine -split '\s+')[0].ToLowerInvariant()
    $ActualChecksum = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualChecksum -ne $ExpectedChecksum) {
        Stop-WithError 'release checksum verification failed'
    }

    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $InstallDirectory -Force
}
finally {
    Remove-Item -LiteralPath $ArchivePath, $ChecksumPath -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    Stop-WithError 'the Windows archive did not contain sbom-analyzer.exe'
}

$Signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    Write-Warning (
        'This Windows release is not Authenticode-signed. Windows Smart App Control ' +
        'can block unsigned applications even after their checksum is verified.'
    )
}

Write-Host "Shared application data: $DataDirectory"
Write-Host "Launching $BinaryPath"
try {
    Start-Process -FilePath $BinaryPath -WorkingDirectory $InstallDirectory
}
catch {
    if ($_.Exception.Message -match 'Application Control policy|Smart App Control') {
        Stop-WithError (
            'Windows Smart App Control blocked this unsigned release. Windows has no ' +
            'per-app exception. For an immediate local test, open Windows Security > ' +
            'App & browser control > Smart App Control settings, turn Smart App Control ' +
            'Off, and run this script again. The permanent project fix is a release ' +
            'signed with a publicly trusted Authenticode certificate.'
        )
    }
    throw
}
