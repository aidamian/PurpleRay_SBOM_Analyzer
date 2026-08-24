@echo off
rem Copyright (c) 2026 Andrei Ionut Damian.
rem
rem Licensed under the Apache License, Version 2.0; see LICENSE.
rem Please retain the applicable attribution notices and cite the project using
rem the BibTeX entry in NOTICE.
rem
rem PurpleRay SBOM Analyzer - self-contained Windows launcher.
rem
rem Downloads the latest checksum-verified Windows release into a versioned
rem directory beside this file and starts the desktop application. It uses
rem only tools that ship with Windows 10 1803+ and Windows 11 (curl.exe,
rem certutil.exe, tar.exe, findstr.exe, find.exe) and never needs PowerShell
rem or the GitHub CLI.
rem
rem Usage:  start-win.bat            (double-click works too)
rem         set PURPLERAY_VERSION=X.Y.Z  before running to pin a release.
rem Command-line arguments are ignored. To pass options to the application,
rem run purpleray-sbom-analyzer.exe from the installed directory directly.
rem
rem All releases share the per-user data directory
rem   (user profile)\.purpleray\sbom-analyzer
rem so switching versions never loses scan history or settings.

rem Capture system-provided paths while delayed expansion is still off, so
rem an exclamation mark in a path survives; everything after this block
rem renders data through !VAR! only.
setlocal EnableExtensions DisableDelayedExpansion
set "SCRIPT_DIRECTORY=%~dp0"
set "SYSTEM_ROOT=%SystemRoot%"
set "PROFILE_DIRECTORY=%USERPROFILE%"
set "HOST_OS=%OS%"
set "HOST_ARCH=%PROCESSOR_ARCHITECTURE%"
set "HOST_ARCH_WOW=%PROCESSOR_ARCHITEW6432%"
set "PINNED_VERSION=%PURPLERAY_VERSION%"
setlocal EnableDelayedExpansion

set "SCRIPT_NAME=start-win.bat"
set "PROJECT_REPOSITORY=aidamian/PurpleRay_SBOM_Analyzer"
set "PROJECT_URL=https://github.com/aidamian/PurpleRay_SBOM_Analyzer"
set "EXIT_CODE=0"
set "WORK_DIRECTORY="

rem Inbox tools are pinned to System32 so nothing on PATH or in the current
rem directory can shadow them.
set "CURL=!SYSTEM_ROOT!\System32\curl.exe"
set "CERTUTIL=!SYSTEM_ROOT!\System32\certutil.exe"
set "TAR=!SYSTEM_ROOT!\System32\tar.exe"
set "FINDSTR=!SYSTEM_ROOT!\System32\findstr.exe"
set "FIND=!SYSTEM_ROOT!\System32\find.exe"

rem ---------------------------------------------------------------- checks
if /I not "!HOST_OS!"=="Windows_NT" (
    call :fail "this launcher requires Windows"
    goto :done
)
if /I not "!HOST_ARCH!"=="AMD64" if /I not "!HOST_ARCH_WOW!"=="AMD64" (
    call :fail "the published release requires 64-bit Windows"
    goto :done
)
for %%T in (CURL CERTUTIL TAR FINDSTR FIND) do (
    if not exist "!%%T!" (
        call :fail "a required Windows component is missing: !%%T!"
        goto :done
    )
)
if not defined PROFILE_DIRECTORY (
    call :fail "could not determine the Windows user profile directory"
    goto :done
)

rem ----------------------------------------------- scratch files (private)
rem Validation writes values to files and runs pinned findstr on the files,
rem so untrusted text never travels through a pipe or a second parser.
set "WORK_DIRECTORY=!SCRIPT_DIRECTORY!.purpleray-launch.%RANDOM%%RANDOM%"
mkdir "!WORK_DIRECTORY!" || (
    call :fail "could not create a scratch directory beside the launcher"
    goto :done
)
set "PROBE_PATH=!WORK_DIRECTORY!\probe.txt"
set "FILTER_PATH=!WORK_DIRECTORY!\filter.txt"
set "RAW_PATH=!WORK_DIRECTORY!\raw.txt"

rem ---------------------------------------------------------- version pin
set "SELECTED_VERSION="
if defined PINNED_VERSION (
    call :check_version PINNED_VERSION || goto :cleanup
    set "SELECTED_VERSION=!PINNED_VERSION!"
)

rem ------------------------------------------------- resolve release tag
set "TAG_NAME="
if defined SELECTED_VERSION set "TAG_NAME=v!SELECTED_VERSION!"
if defined TAG_NAME goto :tag_resolved
echo Resolving the latest release of !PROJECT_REPOSITORY!
"!CURL!" -q -fsSL -o NUL -w "%%{url_effective}" "!PROJECT_URL!/releases/latest" > "!RAW_PATH!" || (
    call :fail "could not resolve the latest release; check network access"
    goto :cleanup
)
rem find re-emits every line with CRLF so findstr's $ anchor matches.
"!FIND!" /V "" < "!RAW_PATH!" > "!PROBE_PATH!"
"!FINDSTR!" /R /C:"^https://github\.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" "!PROBE_PATH!" > "!FILTER_PATH!" || (
    call :fail "GitHub returned an unexpected release URL"
    goto :cleanup
)
set "FINAL_URL="
for /f "usebackq delims=" %%U in ("!FILTER_PATH!") do if not defined FINAL_URL set "FINAL_URL=%%U"
if not defined FINAL_URL (
    call :fail "GitHub returned an unexpected release URL"
    goto :cleanup
)
set "TAG_NAME=!FINAL_URL:*/releases/tag/=!"
:tag_resolved
set "SELECTED_VERSION=!TAG_NAME:~1!"
call :check_version SELECTED_VERSION || goto :cleanup
set "TAG_NAME=v!SELECTED_VERSION!"

rem ---------------------------------------------------------- locations
set "ASSET_NAME=purpleray-sbom-analyzer-!TAG_NAME!-windows-x64.zip"
set "RELEASE_BASE_URL=!PROJECT_URL!/releases/download/!TAG_NAME!"
set "INSTALL_DIRECTORY=!SCRIPT_DIRECTORY!PurpleRay_SBOM_Analyzer_!TAG_NAME!"
set "DATA_DIRECTORY=!PROFILE_DIRECTORY!\.purpleray\sbom-analyzer"
set "ARCHIVE_PATH=!INSTALL_DIRECTORY!\!ASSET_NAME!"
set "CHECKSUM_PATH=!WORK_DIRECTORY!\SHA256SUMS.txt"
set "DOWNLOAD_PATH=!WORK_DIRECTORY!\!ASSET_NAME!.download"
set "EXTRACT_DIRECTORY=!WORK_DIRECTORY!\extract"
set "LIST_PATH=!WORK_DIRECTORY!\entries.txt"
set "TYPES_PATH=!WORK_DIRECTORY!\entry-types.txt"
set "BINARY_PATH=!INSTALL_DIRECTORY!\purpleray-sbom-analyzer.exe"
set "STAGED_PATH=!WORK_DIRECTORY!\purpleray-sbom-analyzer.exe.staged"
set "STAGED_LICENSE=!WORK_DIRECTORY!\LICENSE.staged"
set "STAGED_NOTICE=!WORK_DIRECTORY!\NOTICE.staged"

if not exist "!INSTALL_DIRECTORY!\" (
    mkdir "!INSTALL_DIRECTORY!" || (
        call :fail "could not create the install directory"
        goto :cleanup
    )
)
if not exist "!DATA_DIRECTORY!\" (
    mkdir "!DATA_DIRECTORY!" || (
        call :fail "could not create the application data directory"
        goto :cleanup
    )
)

rem --------------------------------------------------- published checksum
"!CURL!" -q -fsSL --retry 3 -o "!RAW_PATH!" "!RELEASE_BASE_URL!/SHA256SUMS.txt" || (
    call :fail "could not download SHA256SUMS.txt for !TAG_NAME!"
    goto :cleanup
)
"!FIND!" /V "" < "!RAW_PATH!" > "!CHECKSUM_PATH!"
rem Only GNU-style lines "<hex>  <asset>" (text) or "<hex> *<asset>" (binary)
rem survive the filter; it runs on the file, so untrusted text is never expanded.
set "ASSET_REGEX=!ASSET_NAME:.=\.!"
"!FINDSTR!" /R /C:"^[0-9a-fA-F][0-9a-fA-F]*  !ASSET_REGEX!$" /C:"^[0-9a-fA-F][0-9a-fA-F]* \*!ASSET_REGEX!$" "!CHECKSUM_PATH!" > "!FILTER_PATH!"
set "MATCH_COUNT=0"
set "EXPECTED_CHECKSUM="
for /f "usebackq tokens=1,2,* delims= " %%A in ("!FILTER_PATH!") do (
    set /a MATCH_COUNT+=1
    set "EXPECTED_CHECKSUM=%%A"
)
if not "!MATCH_COUNT!"=="1" (
    call :fail "SHA256SUMS.txt must contain exactly one entry for !ASSET_NAME! (found !MATCH_COUNT!)"
    goto :cleanup
)
call :check_hex64 EXPECTED_CHECKSUM || (
    call :fail "the published checksum for !ASSET_NAME! is not a 64-digit SHA-256"
    goto :cleanup
)

rem ------------------------------------------- cached package fast path
if not exist "!ARCHIVE_PATH!" goto :download_package
call :file_sha256 ARCHIVE_PATH
if /I "!FILE_SHA256!"=="!EXPECTED_CHECKSUM!" (
    echo Using checksum-verified cached package: !ARCHIVE_PATH!
    goto :package_ready
)
echo WARNING: cached package failed checksum verification; downloading a fresh copy.
:download_package
echo Downloading !ASSET_NAME!
"!CURL!" -q -fL --retry 3 --progress-bar -o "!DOWNLOAD_PATH!" "!RELEASE_BASE_URL!/!ASSET_NAME!" || (
    call :fail "release download failed for !ASSET_NAME!"
    goto :cleanup
)
call :file_sha256 DOWNLOAD_PATH
if /I not "!FILE_SHA256!"=="!EXPECTED_CHECKSUM!" (
    call :fail "release checksum verification failed"
    goto :cleanup
)
move /Y "!DOWNLOAD_PATH!" "!ARCHIVE_PATH!" >nul || (
    call :fail "could not place the verified package"
    goto :cleanup
)
:package_ready
echo Checksum verification succeeded for !ASSET_NAME!.
echo Optional provenance check: gh attestation verify "!ARCHIVE_PATH!" --repo !PROJECT_REPOSITORY!

rem ------------------------------------------------- archive layout check
rem Names must be exactly the executable alone, or the executable with
rem LICENSE and NOTICE; every member must be a regular file.
"!TAR!" -tf "!ARCHIVE_PATH!" > "!RAW_PATH!" 2>nul || (
    call :fail "the Windows archive could not be listed"
    goto :cleanup
)
"!FIND!" /V "" < "!RAW_PATH!" > "!LIST_PATH!"
"!TAR!" -tvf "!ARCHIVE_PATH!" > "!RAW_PATH!" 2>nul || (
    call :fail "the Windows archive could not be listed"
    goto :cleanup
)
"!FIND!" /V "" < "!RAW_PATH!" > "!TYPES_PATH!"
call :count_lines LIST_PATH ENTRY_COUNT
call :count_lines TYPES_PATH VERBOSE_COUNT
call :count_exact LIST_PATH "purpleray-sbom-analyzer.exe" EXE_COUNT
call :count_exact LIST_PATH "LICENSE" LICENSE_COUNT
call :count_exact LIST_PATH "NOTICE" NOTICE_COUNT
"!FINDSTR!" /R /V /C:"^-" "!TYPES_PATH!" > "!FILTER_PATH!"
call :count_lines FILTER_PATH IRREGULAR_COUNT
rem A PAX hardlink is listed with a regular mode followed by " link to ".
"!FINDSTR!" /C:" link to " "!TYPES_PATH!" > "!FILTER_PATH!"
if errorlevel 2 (
    call :fail "the Windows archive listing could not be validated"
    goto :cleanup
)
if not errorlevel 1 (
    call :fail "the Windows archive contains a link member"
    goto :cleanup
)
if not "!EXE_COUNT!"=="1" (
    call :fail "the Windows archive must contain purpleray-sbom-analyzer.exe exactly once"
    goto :cleanup
)
if not "!ENTRY_COUNT!"=="!VERBOSE_COUNT!" (
    call :fail "the Windows archive listings disagree"
    goto :cleanup
)
if not "!IRREGULAR_COUNT!"=="0" (
    call :fail "the Windows archive contains a member that is not a regular file"
    goto :cleanup
)
set "LAYOUT_OK=0"
if "!ENTRY_COUNT!"=="1" if "!LICENSE_COUNT!"=="0" if "!NOTICE_COUNT!"=="0" set "LAYOUT_OK=1"
if "!ENTRY_COUNT!"=="3" if "!LICENSE_COUNT!"=="1" if "!NOTICE_COUNT!"=="1" set "LAYOUT_OK=1"
if not "!LAYOUT_OK!"=="1" (
    call :fail "the Windows archive has an unexpected layout"
    goto :cleanup
)

rem ------------------------------------------------------------ extract
mkdir "!EXTRACT_DIRECTORY!" || (
    call :fail "could not create a temporary extraction directory"
    goto :cleanup
)
"!TAR!" -xf "!ARCHIVE_PATH!" -C "!EXTRACT_DIRECTORY!" || (
    call :fail "the Windows archive could not be extracted"
    goto :cleanup
)
if not exist "!EXTRACT_DIRECTORY!\purpleray-sbom-analyzer.exe" (
    call :fail "the extracted archive is missing purpleray-sbom-analyzer.exe"
    goto :cleanup
)
copy /Y "!EXTRACT_DIRECTORY!\purpleray-sbom-analyzer.exe" "!STAGED_PATH!" >nul || (
    call :fail "could not stage the executable"
    goto :cleanup
)
if "!ENTRY_COUNT!"=="3" (
    copy /Y "!EXTRACT_DIRECTORY!\LICENSE" "!STAGED_LICENSE!" >nul || (
        call :fail "could not stage LICENSE"
        goto :cleanup
    )
    copy /Y "!EXTRACT_DIRECTORY!\NOTICE" "!STAGED_NOTICE!" >nul || (
        call :fail "could not stage NOTICE"
        goto :cleanup
    )
    move /Y "!STAGED_LICENSE!" "!INSTALL_DIRECTORY!\LICENSE" >nul || (
        call :fail "could not install LICENSE"
        goto :cleanup
    )
    move /Y "!STAGED_NOTICE!" "!INSTALL_DIRECTORY!\NOTICE" >nul || (
        call :fail "could not install NOTICE"
        goto :cleanup
    )
)
move /Y "!STAGED_PATH!" "!BINARY_PATH!" >nul || (
    call :fail "could not install the executable"
    goto :cleanup
)

rem ------------------------------------------------------------- launch
echo.
echo NOTE: current Windows releases are not Authenticode-signed, so Smart App
echo Control may block them. Windows has no per-app exception. Turning Smart App
echo Control off reduces protection; on some Windows builds and system states it
echo cannot be turned back on without resetting Windows. Prefer a disposable VM
echo for unsigned-build testing. Microsoft FAQ:
echo https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions
echo.
echo Shared application data: !DATA_DIRECTORY!
echo Launching !BINARY_PATH!
start "" /D "!INSTALL_DIRECTORY!" "!BINARY_PATH!"
if errorlevel 1 call :fail "Windows refused to start the executable (Smart App Control or a missing file)"
goto :cleanup

rem ------------------------------------------------------------ helpers
rem Helpers receive VARIABLE NAMES, never values, and validate by writing
rem the value to the probe file and running pinned findstr on that file.

:check_version
rem Canonical MAJOR.MINOR.PATCH, no v prefix, no leading zeros.
(echo(!%~1!) > "!PROBE_PATH!"
"!FINDSTR!" /R /C:"^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" "!PROBE_PATH!" >nul || (
    call :fail "release version must be canonical MAJOR.MINOR.PATCH without a v prefix"
    exit /b 1
)
"!FINDSTR!" /R /C:"^0[0-9]" /C:"\.0[0-9]" "!PROBE_PATH!" >nul && (
    call :fail "release version must not contain leading zeros"
    exit /b 1
)
exit /b 0

:check_hex64
rem The named variable must hold exactly 64 hexadecimal digits.
(echo(!%~1!) > "!PROBE_PATH!"
"!FINDSTR!" /R /I /C:"^[0-9a-f][0-9a-f]*$" "!PROBE_PATH!" >nul || exit /b 1
set "CHECK_VALUE=!%~1!"
if not "!CHECK_VALUE:~64!"=="" exit /b 1
if "!CHECK_VALUE:~63,1!"=="" exit /b 1
exit /b 0

:file_sha256
rem %1 names a variable holding a path. Sets FILE_SHA256 (empty on failure).
rem The hash line is selected by shape (hex digits and spaces only), so the
rem localized certutil header text never matters.
set "FILE_SHA256="
set "HASH_CANDIDATE="
"!CERTUTIL!" -hashfile "!%~1!" SHA256 > "!PROBE_PATH!" 2>nul || exit /b 1
"!FINDSTR!" /R /I /C:"^[0-9a-f][0-9a-f ]*$" "!PROBE_PATH!" > "!FILTER_PATH!" || exit /b 1
for /f "usebackq delims=" %%H in ("!FILTER_PATH!") do if not defined HASH_CANDIDATE set "HASH_CANDIDATE=%%H"
if not defined HASH_CANDIDATE exit /b 1
set "HASH_CANDIDATE=!HASH_CANDIDATE: =!"
call :check_hex64 HASH_CANDIDATE || exit /b 1
set "FILE_SHA256=!HASH_CANDIDATE!"
exit /b 0

:count_lines
rem %1 names a file-path variable, %2 the result variable.
"!FIND!" /C /V "" < "!%~1!" > "!PROBE_PATH!"
set "COUNT_VALUE="
set /p COUNT_VALUE=<"!PROBE_PATH!"
set "COUNT_VALUE=!COUNT_VALUE: =!"
if not defined COUNT_VALUE set "COUNT_VALUE=0"
set "%~2=!COUNT_VALUE!"
exit /b 0

:count_exact
rem %1 names a file-path variable, %2 is a literal (quoted) member name,
rem %3 the result variable. /C without /R is a literal whole-line match.
"!FINDSTR!" /X /C:"%~2" "!%~1!" > "!FILTER_PATH!"
call :count_lines FILTER_PATH %~3
exit /b 0

:fail
echo !SCRIPT_NAME!: %~1 1>&2
set "EXIT_CODE=1"
exit /b 1

:cleanup
if defined WORK_DIRECTORY if exist "!WORK_DIRECTORY!\" rmdir /S /Q "!WORK_DIRECTORY!" >nul 2>&1

:done
rem Keep the window open on failure so a double-click user can read the
rem message. Set PURPLERAY_NO_PAUSE to suppress this.
if not "!EXIT_CODE!"=="0" if not defined PURPLERAY_NO_PAUSE pause
endlocal & endlocal & exit /b %EXIT_CODE%
