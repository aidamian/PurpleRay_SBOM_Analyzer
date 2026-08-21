<#
Copyright (c) 2026 Andrei Ionut Damian.

Licensed under the Apache License, Version 2.0; see LICENSE.
Please retain the applicable attribution notices and cite the project using
the BibTeX entry in NOTICE.
#>

[CmdletBinding()]
param(
    [string]$ReleaseVersion,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ApplicationArguments
)

$ReleaseVersionWasPassed = $PSBoundParameters.ContainsKey('ReleaseVersion')

& {
    param(
        [string]$RequestedReleaseVersion,
        [bool]$VersionArgumentWasPassed,
        [string[]]$ForwardedArguments
    )

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $ProjectRepository = 'aidamian/PurpleRay_SBOM_Analyzer'
    $ProjectUrl = "https://github.com/$ProjectRepository"

    function Stop-WithError {
        param([Parameter(Mandatory = $true)][string]$Message)

        throw [InvalidOperationException]::new("start-windows.ps1: $Message")
    }

    function Test-CanonicalVersion {
        param([AllowEmptyString()][string]$Version)

        return $Version -cmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
    }

    function Get-FinalResponseUri {
        param([Parameter(Mandatory = $true)]$Response)

        if ($Response.BaseResponse.RequestMessage -and
            $Response.BaseResponse.RequestMessage.RequestUri) {
            return [Uri]$Response.BaseResponse.RequestMessage.RequestUri
        }
        if ($Response.BaseResponse.ResponseUri) {
            return [Uri]$Response.BaseResponse.ResponseUri
        }
        Stop-WithError 'could not determine the final URL for the latest release'
    }

    function Get-PublishedChecksum {
        param(
            [Parameter(Mandatory = $true)][string]$ChecksumFile,
            [Parameter(Mandatory = $true)][string]$AssetName
        )

        $Pattern = '^([0-9A-Fa-f]{64})\s+\*?' + [Regex]::Escape($AssetName) + '$'
        foreach ($Line in Get-Content -LiteralPath $ChecksumFile) {
            $Match = [Regex]::Match([string]$Line, $Pattern)
            if ($Match.Success) {
                return $Match.Groups[1].Value.ToLowerInvariant()
            }
        }
        Stop-WithError "no valid checksum was published for $AssetName"
    }

    function Test-PackageChecksum {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$ExpectedChecksum
        )

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return $false
        }
        $ActualChecksum = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        return $ActualChecksum -ceq $ExpectedChecksum
    }

    function Test-ZipLayout {
        param([Parameter(Mandatory = $true)][string]$ArchivePath)

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $Archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
        try {
            $Names = @($Archive.Entries | ForEach-Object { $_.FullName })
        }
        finally {
            $Archive.Dispose()
        }

        $IsLegacyLayout = $Names.Count -eq 1 -and
            $Names[0] -ceq 'purpleray-sbom-analyzer.exe'
        $IsCurrentLayout = $Names.Count -eq 3 -and
            $Names -ccontains 'LICENSE' -and
            $Names -ccontains 'NOTICE' -and
            $Names -ccontains 'purpleray-sbom-analyzer.exe'
        if (-not $IsLegacyLayout -and -not $IsCurrentLayout) {
            Stop-WithError (
                'the Windows archive has an unexpected layout; expected the executable ' +
                'alone (legacy) or the executable, LICENSE, and NOTICE at its root'
            )
        }
        return $IsCurrentLayout
    }

    function ConvertTo-NativeArgument {
        param([AllowEmptyString()][string]$Argument)

        if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
            return $Argument
        }

        $Builder = [Text.StringBuilder]::new()
        [void]$Builder.Append('"')
        $BackslashCount = 0
        foreach ($Character in $Argument.ToCharArray()) {
            if ($Character -eq '\') {
                $BackslashCount++
                continue
            }
            if ($Character -eq '"') {
                [void]$Builder.Append(('\' * (($BackslashCount * 2) + 1)))
                [void]$Builder.Append('"')
                $BackslashCount = 0
                continue
            }
            if ($BackslashCount -gt 0) {
                [void]$Builder.Append(('\' * $BackslashCount))
                $BackslashCount = 0
            }
            [void]$Builder.Append($Character)
        }
        if ($BackslashCount -gt 0) {
            [void]$Builder.Append(('\' * ($BackslashCount * 2)))
        }
        [void]$Builder.Append('"')
        return $Builder.ToString()
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

    if ($VersionArgumentWasPassed) {
        $SelectedVersion = $RequestedReleaseVersion
    }
    else {
        $SelectedVersion = [Environment]::GetEnvironmentVariable('PURPLERAY_VERSION')
    }
    if ($null -ne $SelectedVersion -and $SelectedVersion.Length -gt 0 -and
        -not (Test-CanonicalVersion $SelectedVersion)) {
        Stop-WithError (
            "release version must be canonical MAJOR.MINOR.PATCH without a v prefix: $SelectedVersion"
        )
    }
    if ($VersionArgumentWasPassed -and
        ($null -eq $SelectedVersion -or $SelectedVersion.Length -eq 0)) {
        Stop-WithError '-ReleaseVersion requires canonical MAJOR.MINOR.PATCH'
    }

    $PreviousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            $PreviousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        if ($SelectedVersion) {
            $TagName = "v$SelectedVersion"
        }
        else {
            $LatestResponse = Invoke-WebRequest -UseBasicParsing -Uri "$ProjectUrl/releases/latest"
            $LatestUri = Get-FinalResponseUri $LatestResponse
            $TagName = $LatestUri.AbsolutePath.TrimEnd('/').Split('/')[-1]
            if (-not $TagName.StartsWith('v', [StringComparison]::Ordinal)) {
                Stop-WithError "GitHub returned an invalid release tag: $TagName"
            }
            $SelectedVersion = $TagName.Substring(1)
            if (-not (Test-CanonicalVersion $SelectedVersion)) {
                Stop-WithError "GitHub returned a non-canonical release tag: $TagName"
            }
        }

        $AssetName = "purpleray-sbom-analyzer-$TagName-windows-x64.zip"
        $ReleaseBaseUrl = "$ProjectUrl/releases/download/$TagName"
        $InstallDirectory = Join-Path (Get-Location).ProviderPath "PurpleRay_SBOM_Analyzer_$TagName"
        $UserProfileDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if (-not $UserProfileDirectory) {
            Stop-WithError 'could not determine the current Windows user profile directory'
        }
        $DataDirectory = Join-Path (Join-Path $UserProfileDirectory '.purpleray') 'sbom-analyzer'
        $ArchivePath = Join-Path $InstallDirectory $AssetName
        $ChecksumPath = Join-Path $InstallDirectory ".SHA256SUMS.$PID.download"
        $DownloadPath = Join-Path $InstallDirectory ".$AssetName.$PID.download"
        $ExtractDirectory = Join-Path $InstallDirectory ".extract.$([Guid]::NewGuid().ToString('N'))"
        $BinaryPath = Join-Path $InstallDirectory 'purpleray-sbom-analyzer.exe'
        $StagedBinaryPath = Join-Path $InstallDirectory '.purpleray-sbom-analyzer.exe.staged'

        New-Item -ItemType Directory -Force -Path $InstallDirectory, $DataDirectory | Out-Null
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBaseUrl/SHA256SUMS.txt" `
                -OutFile $ChecksumPath
            $ExpectedChecksum = Get-PublishedChecksum $ChecksumPath $AssetName

            if (Test-PackageChecksum $ArchivePath $ExpectedChecksum) {
                Write-Host "Using checksum-verified cached package: $ArchivePath"
            }
            else {
                if (Test-Path -LiteralPath $ArchivePath -PathType Leaf) {
                    Write-Warning 'Cached package failed checksum verification; downloading a fresh copy.'
                }
                Write-Host "Downloading $AssetName"
                Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseBaseUrl/$AssetName" `
                    -OutFile $DownloadPath
                if (-not (Test-PackageChecksum $DownloadPath $ExpectedChecksum)) {
                    Stop-WithError 'release checksum verification failed'
                }
                Move-Item -LiteralPath $DownloadPath -Destination $ArchivePath -Force
            }

            $GitHubCLI = Get-Command gh -ErrorAction SilentlyContinue
            $GitHubCLISupportsAttestations = $false
            if ($null -ne $GitHubCLI) {
                & gh attestation verify --help *> $null
                $GitHubCLISupportsAttestations = ($LASTEXITCODE -eq 0)
            }

            if ($GitHubCLISupportsAttestations) {
                Write-Host "Verifying GitHub build-provenance attestation for $AssetName"
                & gh attestation verify $ArchivePath --repo $ProjectRepository
                if ($LASTEXITCODE -ne 0) {
                    Stop-WithError 'GitHub build-provenance attestation verification failed'
                }
            }
            elseif ($null -ne $GitHubCLI) {
                Write-Host (
                    'The installed GitHub CLI does not support artifact attestation ' +
                    'verification. Checksum verification succeeded, but provenance was not checked.'
                )
                Write-Host (
                    "Optional: upgrade gh, then run: gh attestation verify `"$ArchivePath`" " +
                    "--repo $ProjectRepository"
                )
            }
            else {
                Write-Host (
                    'GitHub CLI was not found; checksum verification succeeded, but provenance ' +
                    'was not checked.'
                )
                Write-Host (
                    "Optional: install gh, then run: gh attestation verify `"$ArchivePath`" " +
                    "--repo $ProjectRepository"
                )
            }

            $HasNotices = Test-ZipLayout $ArchivePath
            New-Item -ItemType Directory -Path $ExtractDirectory | Out-Null
            Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractDirectory
            $ExtractedBinaryPath = Join-Path $ExtractDirectory 'purpleray-sbom-analyzer.exe'
            Copy-Item -LiteralPath $ExtractedBinaryPath -Destination $StagedBinaryPath -Force
            Move-Item -LiteralPath $StagedBinaryPath -Destination $BinaryPath -Force
            if ($HasNotices) {
                Copy-Item -LiteralPath (Join-Path $ExtractDirectory 'LICENSE') `
                    -Destination (Join-Path $InstallDirectory 'LICENSE') -Force
                Copy-Item -LiteralPath (Join-Path $ExtractDirectory 'NOTICE') `
                    -Destination (Join-Path $InstallDirectory 'NOTICE') -Force
            }
        }
        finally {
            Remove-Item -LiteralPath $ChecksumPath, $DownloadPath, $StagedBinaryPath `
                -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $ExtractDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }

        if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
            Stop-WithError 'the Windows archive did not contain purpleray-sbom-analyzer.exe'
        }

        $Signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
        if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            Write-Warning (
                'This Windows release is not Authenticode-signed, so Smart App Control may block it. ' +
                'Disabling Smart App Control reduces protection and, depending on the Windows build ' +
                'and system state, may be irreversible without resetting or reinstalling Windows. ' +
                'Check the current Microsoft FAQ and prefer a disposable VM for unsigned-build testing: ' +
                'https://support.microsoft.com/en-us/windows/security/threat-malware-protection/' +
                'smart-app-control-frequently-asked-questions'
            )
        }

        Write-Host "Shared application data: $DataDirectory"
        Write-Host "Launching $BinaryPath"
        $StartProcessParameters = @{
            FilePath = $BinaryPath
            WorkingDirectory = $InstallDirectory
        }
        if ($ForwardedArguments.Count -gt 0) {
            $StartProcessParameters.ArgumentList =
                (($ForwardedArguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
        }
        try {
            Start-Process @StartProcessParameters
        }
        catch {
            if ($_.Exception.Message -match 'Application Control policy|Smart App Control') {
                Stop-WithError (
                    'Windows Smart App Control blocked this unsigned release. Windows has no ' +
                    'per-app exception. Disabling Smart App Control reduces protection and, ' +
                    'depending on the Windows build and system state, may be irreversible without ' +
                    'resetting or reinstalling Windows. Check the current Microsoft FAQ and prefer ' +
                    'a disposable VM for unsigned-build testing: https://support.microsoft.com/' +
                    'en-us/windows/security/threat-malware-protection/' +
                    'smart-app-control-frequently-asked-questions'
                )
            }
            throw
        }
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $PreviousSecurityProtocol
    }
} $ReleaseVersion $ReleaseVersionWasPassed $ApplicationArguments
