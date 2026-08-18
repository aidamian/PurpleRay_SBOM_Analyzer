# SBOM Analyzer

SBOM Analyzer is a small, native desktop application that inventories local
software artifacts and produces deterministic CycloneDX 1.6 JSON. It scans
without network access, never executes files from the selected folder, and does
not call external scanners or helper processes at runtime.

The application uses one Object Pascal/Lazarus LCL codebase for Windows x64
(Win32), Linux x64 (GTK3), and macOS x64 (Cocoa).

## What it does

- Runs each recursive scan on a worker thread with cooperative cancellation.
- Detects package manifests, lock files, license-evidence files, and PE, ELF,
  Mach-O, and universal Mach-O binaries by content.
- Parses JSON and XML formats reliably and uses deliberately conservative text
  parsing for formats such as TOML, YAML, Gradle, and Ruby lock files.
- Keeps unsupported and partially parsed artifacts visible instead of silently
  dropping them.
- Normalizes and deduplicates components, merges evidence paths, and emits
  stable CycloneDX 1.6 JSON.
- Persists scan history and settings as recoverable atomic JSON files.
- Excludes absolute filesystem paths from the SBOM unless the user explicitly
  enables them for that scan.

This is static, best-effort inventory. It is not a vulnerability scanner, a
license-compliance assessment, or a guarantee that every dependency can be
discovered.

## Using the application

Choose **New Scan** and select a folder, or drop a local folder onto the main
window. Review the settings, then start the scan. The history pane keeps old
tasks, while the detail tabs expose the summary, components, artifacts,
generated JSON, warnings, and parser messages.

The default settings calculate SHA-256 hashes, do not follow symbolic links,
and do not include absolute paths in exported data. Ignore patterns are
editable. When link following is enabled, canonical paths prevent loops and
links cannot leave the selected root unless the corresponding advanced option
is also enabled.

Keyboard shortcuts:

- `Ctrl+N` (`Cmd+N` on macOS): new scan
- `Ctrl+E` (`Cmd+E` on macOS): export the selected SBOM
- `Ctrl+C` (`Cmd+C` on macOS): copy the selected component or artifact row
- `F5`: reload persisted history
- `Escape`: cancel the active scan

## Ubuntu/WSL2 development

The reproducible CI toolchain is Free Pascal 3.2.2 and Lazarus 4.2. On a clean
Ubuntu x64 WSL2 installation, install the same official Lazarus release and the
GTK3 development headers with:

```bash
sudo apt-get update
sudo apt-get install --yes ca-certificates curl libgtk-3-dev

toolchain_directory=$(mktemp -d)
cd "$toolchain_directory"
curl --fail --location --retry 3 --output fpc-laz.deb \
  'https://sourceforge.net/projects/lazarus/files/Lazarus%20Linux%20amd64%20DEB/Lazarus%204.2/fpc-laz_3.2.2-210709_amd64.deb/download'
curl --fail --location --retry 3 --output fpc-src.deb \
  'https://sourceforge.net/projects/lazarus/files/Lazarus%20Linux%20amd64%20DEB/Lazarus%204.2/fpc-src_3.2.2-210709_amd64.deb/download'
curl --fail --location --retry 3 --output lazarus-project.deb \
  'https://sourceforge.net/projects/lazarus/files/Lazarus%20Linux%20amd64%20DEB/Lazarus%204.2/lazarus-project_4.2.0-0_amd64.deb/download'
sudo apt-get install --yes ./fpc-laz.deb ./fpc-src.deb ./lazarus-project.deb

fpc -iV
lazbuild --version
```

The final commands should report FPC `3.2.2` and Lazarus `4.2`. Return to the
repository and build the Linux application:

```bash
scripts/run-tests.sh
scripts/build-linux.sh
```

The explicit equivalent build command is:

```bash
lazbuild -B \
  --build-mode=Release \
  --widgetset=gtk3 \
  src/sbom_analyzer.lpi
```

The executable is written to `build/release/sbom-analyzer`. Launch it under
WSLg with:

```bash
build/release/sbom-analyzer
```

WSLg normally sets `WAYLAND_DISPLAY` and `DISPLAY` automatically. If neither is
present, update WSL from Windows with `wsl --update`, restart it with
`wsl --shutdown`, and open the WSL workspace again.

To use the Lazarus IDE, open the repository through VS Code's **WSL: Open Folder
in WSL** command, then run:

```bash
lazarus src/sbom_analyzer.lpi
```

Select the GTK3 widgetset for a Linux build. All forms are constructed from
standard LCL controls at runtime, so no designer files are required.

## Tests

`scripts/run-tests.sh` compiles and runs the non-UI suite. The fixtures cover
requirements, npm manifests and locks, Maven and MSBuild XML, atomic history
recovery, SHA-256, native binary headers, component deduplication,
deterministic/path-safe CycloneDX generation, ignore matching, symbolic-link
loops, and cancellation. Tests require no network or external scanner.

For an explicit local invocation:

```bash
mkdir -p build/test-units tests/bin
fpc -Fu./src -FU./build/test-units -FE./tests/bin \
  -Mobjfpc -Sh -O2 -g -gl -B tests/test_runner.lpr
tests/bin/test_runner
```

## Data and recovery

The program asks FPC for the per-user application configuration directory. The
usual locations are:

- Linux and WSL: `$XDG_CONFIG_HOME/sbom-analyzer/`, or
  `~/.config/sbom-analyzer/` when `XDG_CONFIG_HOME` is unset
- Windows: `%LOCALAPPDATA%\sbom-analyzer\`
- macOS: the per-user config location returned by FPC for `sbom-analyzer`

Files in that directory are user data:

- `settings.json`: last-used scan settings
- `history.json`: task history, artifact records, and normalized components
- `history.json.bak`: previous valid history
- `history.corrupt-<timestamp>.json`: a malformed history preserved for
  diagnosis
- `sboms/<task-id>.cdx.json`: generated CycloneDX documents

History and settings are written through a flushed temporary file, with one
backup retained. A malformed active history is preserved and the backup is
loaded when valid.

## Supported evidence

Reliable parsers cover `package.json`, `package-lock.json`,
`requirements*.txt`, `go.mod`, `pom.xml`, `*.csproj`, `packages.lock.json`,
`Directory.Packages.props`, `composer.json`, `composer.lock`, and Lazarus
`*.lpi`/`*.lpk` files.

The scanner also detects Yarn, pnpm, Cargo, Poetry, Pipfile, Conda, Gradle,
RubyGems, vcpkg, Conan, Swift Package Manager, and CocoaPods evidence. Those
formats use conservative partial parsing where a dependency can be identified
without guessing; otherwise the artifact is marked unsupported. `LICENSE`,
`COPYING`, and `NOTICE` variants are recorded only as possible license
evidence—no license is inferred from a filename.

## Project layout

```text
assets/                    application icon sources
packaging/macos/           minimal application-bundle metadata template
scripts/                   local build, test, version, and packaging helpers
src/                       Lazarus project, UI, scanner, parsers, and persistence
tests/                     deterministic non-UI test runner and fixtures
.github/workflows/         native three-platform CI and release automation
```

`src/uVersionInfo.pas` is a development fallback. CI generates that unit in its
ephemeral workspace from the selected semantic version and full commit SHA; it
never commits generated version changes back to `main`.

The checked-in `src/app_icon.res` embeds the Windows/LCL icon. After changing
`assets/app-icon.ico`, regenerate it with:

```bash
scripts/regenerate-icon-resource.sh
```

## CI and releases

`.github/workflows/build-release.yml` tests and builds all three native targets
on `windows-latest`, `ubuntu-latest`, and `macos-15-intel`. It uses FPC 3.2.2 and
Lazarus 4.2 from the official SourceForge release files. The maintained
[`ollydev/setup-lazarus`](https://github.com/ollydev/setup-lazarus) setup action
is pinned to an immutable commit and is used only during builds; it introduces
no runtime dependency. Official GitHub artifact and checkout actions are pinned
as well. The macOS job is pinned to GitHub's Intel runner and explicitly
compiles and verifies an x86_64 application.

Pull requests get a `MAJOR.MINOR.PATCH-dev.<commit>` version, run all tests, and
upload temporary packages without tags or releases. Pushes to `main` serialize
release work, inspect conventional commit subjects since the latest reachable
`vMAJOR.MINOR.PATCH` tag, then apply the highest required increment:

- `fix:` → patch
- `feat:` → minor
- `fix!:` / `feat!:` / `BREAKING CHANGE:` → major
- no recognized prefix → patch

Only after every native test and build succeeds does the workflow create the
tag and publish the Windows ZIP, standalone Linux executable, macOS ZIP, and
`SHA256SUMS.txt`. If the current commit is already version-tagged, that version
is reused. Manual runs rebuild without publishing by default; publishing must be
selected explicitly. Existing tags and releases are verified and updated
idempotently instead of duplicated.

## Citation and copyright

If you use SBOM Analyzer in research, publications, reports, or derivative
software, please cite the original project:

```bibtex
@misc{damian2026sbomanalyzer,
  author = {Andrei Ionut Damian},
  title  = {{SBOM Analyzer}},
  year   = {2026},
  url    = {https://github.com/aidamian/SBOM_Analyzer}
}
```

Copyright (c) 2026 Andrei Ionut Damian. SBOM Analyzer is an open-source
project, but copyright and authorship rights remain with the author. Derivative
works should retain this copyright notice and cite the original project
appropriately using the citation above.

## Platform limitations

- Windows and macOS outputs are not code-signed. A production distribution
  should add Windows signing plus Apple Developer ID signing and notarization.
- The macOS release targets x86_64 and may require Rosetta on Apple Silicon.
- Lazarus's GTK3 backend can emit non-fatal layout diagnostics with some GTK
  themes or WSLg versions; these do not indicate that scanning has failed.
- Runtime scanning intentionally does not resolve shared-library dependencies,
  contact registries, execute package managers, or evaluate build scripts.
