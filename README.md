# PurpleRay SBOM Analyzer

PurpleRay SBOM Analyzer is a small, native desktop application that inventories
local software artifacts and produces deterministic CycloneDX 1.7 JSON. The
serializer retains tested CycloneDX 1.6 compatibility. It scans without network
access and never executes files from the selected folder. Its native parsers
are supplemented, when applicable, by bounded static-inspection facilities
already present on the operating system; it never downloads or requires a
separate scanner.

The application uses one Object Pascal/Lazarus LCL codebase for Windows x64
(Win32), Linux x64 (GTK3), and macOS x64 (Cocoa).

Its main window is a lightweight native feature shell with a compact selector
and tabless workspace. Each completed feature is compiled into the executable
as an LFM-backed `TFrame`; this is not a plugin system. The selector exposes
`SBOM Analyzer` and `Compare Scans`, and both features remain alive when the
user switches between them.

## What it does

- Runs each recursive scan on a worker thread with cooperative cancellation.
- Detects package manifests, lock files, license-evidence files, and PE, ELF,
  Mach-O, and universal Mach-O binaries by content.
- Parses JSON and XML formats reliably and uses deliberately conservative text
  parsing for formats such as TOML, YAML, Gradle, and Ruby lock files.
- Keeps unsupported and partially parsed artifacts visible instead of silently
  dropping them.
- Skips pipes, sockets, devices, and other non-regular filesystem entries with
  an explicit warning, and reports initial or mid-stream directory-enumeration
  failures.
- Applies deterministic 8 MiB, 32 MiB, or 64 MiB parser-specific input limits
  before hashing or loading manifests into memory.
- Uses applicable built-in OS evidence to enrich native binaries with declared
  linked libraries, build identifiers, signing metadata, or version resources.
- Reads ELF dynamic entries, PE normal and delay-load imports, and Mach-O load
  commands directly, including dependency declarations in universal Mach-O
  slices.
- Normalizes and deduplicates components, canonicalizes supported Package URLs,
  merges evidence paths, and emits stable CycloneDX 1.7 JSON with a primary
  component and directly evidenced dependency graph.
- Preserves licenses and publishers explicitly declared by supported manifests,
  and can add an operator-supplied organization/email as SBOM author metadata.
- Marks each generated document as a post-build, incomplete best-effort
  inventory using standard CycloneDX lifecycle and composition fields.
- Persists scan history and settings as recoverable atomic JSON files.
- Compares any two completed retained scans without reading the targets again.
- Excludes absolute filesystem paths from the SBOM unless the user explicitly
  enables them for that scan.

This is static, best-effort inventory. It is not a vulnerability scanner, a
license-compliance assessment, or a guarantee that every dependency can be
discovered.

## Using the application

Select **SBOM Analyzer**, choose **New Scan**, and select a folder, or drop a
local folder onto the main window. The settings dialog identifies that exact
target in both its title and a copyable read-only field. Review the settings,
then start the scan.
The history pane keeps old tasks and has its own search box. Drag the vertical
splitter to resize it. The detail tabs expose the summary, components,
artifacts, generated JSON, warnings, and parser messages.

Select **Compare Scans** to compare the retained component inventories from
two completed tasks. The comparison is directional: the first task is the
baseline and the second is the comparison. By default, the newest completed
scan is compared with the newest older scan of the same target when one is
available. **Swap** reverses that direction. The report shows added, removed,
and unambiguous version-changed components and can be searched, filtered,
sorted, or copied without rescanning either folder.

Package URLs provide the strongest comparison identity after removing only
their version. Records without a usable Package URL use a conservative
ecosystem/name/type fallback. Known namespace ambiguity is never guessed, and
field-only matches are reported as cautions because no coordinate evidence is
available. Exact duplicates are collapsed; multi-version matches cancel
identical versions first and retain the remaining entries as additions/removals
instead of inventing version changes. Scope, license, publisher, parser, hash,
and evidence-path differences alone are not reported as component changes in
this release. Target, diagnostic, and scanner-version differences are shown as
cautions.

**Export SBOM** suggests a filename beginning with the scan timestamp and
folder name, for example
`20260818_143205_example_00112233-4455-6677-8899-aabbccddeeff.cdx.json`.
**Back up data...** creates one ZIP archive containing the complete persisted
task history, settings, backups, diagnostic history files, and generated SBOMs.
Both export commands ask before replacing an existing file and retain
open-folder and copy-path actions in the footer after success.

The default settings calculate SHA-256 hashes, do not follow symbolic links,
and do not include absolute paths in exported data. Ignore patterns are
editable and can be restored to their built-in defaults. Optional SBOM author
organization and email values persist locally. Absolute-path and outside-root
choices reset before each scan unless **Remember absolute-path and outside-root
choices for future scans** is explicitly selected; accepted one-off values
still apply to that scan. When link following is enabled, canonical paths
prevent loops and links cannot leave the selected root unless the corresponding
advanced option is also enabled.

Cancel always targets the running scan even when an older history row is
selected, and asks for confirmation. `Escape` does not cancel while focus is in
an edit, memo, or combo box. Closing during a scan offers to cancel and then
finishes shutdown asynchronously so the UI thread remains responsive.

A completed, failed, or cancelled task can be removed from history with the
task-list context menu or the `Delete` key. Deletion asks for confirmation and
removes only the application-managed `sboms/<task-id>.cdx.json` file. SBOMs
exported elsewhere are never deleted. Pending and running tasks cannot be
removed.

Keyboard shortcuts:

- `Ctrl+N` (`Cmd+N` on macOS): new scan
- `Ctrl+1` (`Cmd+1` on macOS): switch to SBOM Analyzer
- `Ctrl+2` (`Cmd+2` on macOS): switch to Compare Scans
- `Ctrl+E` (`Cmd+E` on macOS): export the selected SBOM
- `Ctrl+C` (`Cmd+C` on macOS): copy the selected summary, component, or
  artifact row, or selected comparison rows (including full values hidden by
  compact table cells)
- `Ctrl+F` (`Cmd+F` on macOS): focus the search box in Compare Scans
- `F5`: refresh the active feature from shared history
- `Escape`: cancel the active scan only while SBOM Analyzer is active; Compare
  Scans never cancels a hidden scan

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
  src/purpleray_sbom_analyzer.lpi
```

The executable is written to `build/release/purpleray-sbom-analyzer`. Launch it under
WSLg with:

```bash
build/release/purpleray-sbom-analyzer
```

WSLg normally sets `WAYLAND_DISPLAY` and `DISPLAY` automatically. If neither is
present, update WSL from Windows with `wsl --update`, restart it with
`wsl --shutdown`, and open the WSL workspace again.

### One-command release launchers

To check WSL2/WSLg support, download the latest checksum-verified Linux release,
and launch it in one command, run:

```bash
./start-wsl2.sh
```

To download that launcher directly from GitHub and run it in the current WSL2
directory:

```bash
curl --fail --show-error --silent --location \
  https://raw.githubusercontent.com/aidamian/PurpleRay_SBOM_Analyzer/main/start-wsl2.sh \
  | bash
```

The script creates a versioned directory such as
`./PurpleRay_SBOM_Analyzer_v0.3.0/` in
the current working directory. Every version uses the shared
`~/.purpleray/sbom-analyzer/` data directory, so releases can be switched
without losing task history or settings. The script never requires root
access.

Native Linux users can use the equivalent launcher:

```bash
./start-linux.sh
```

Or download and run it directly in the current directory:

```bash
curl --fail --show-error --silent --location \
  https://raw.githubusercontent.com/aidamian/PurpleRay_SBOM_Analyzer/main/start-linux.sh \
  | bash
```

The launcher stops before downloading anything unless `DISPLAY` or
`WAYLAND_DISPLAY` identifies a graphical session. If it reports that no Linux
UI is available, run it from a UI-enabled Linux desktop session with Wayland or
X11.

From Windows PowerShell, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-windows.ps1
```

Or download and run it directly in the current PowerShell directory:

```powershell
irm 'https://raw.githubusercontent.com/aidamian/PurpleRay_SBOM_Analyzer/main/start-windows.ps1' | iex
```

All three launchers use the same versioned-directory layout and shared per-user
`.purpleray/sbom-analyzer` data directory.

The macOS release build is currently paused and there is no macOS root launcher
yet. Do not pipe `start-linux.sh` into Bash on macOS: it deliberately accepts
Linux only. A macOS one-line command will be added when that release target is
re-enabled.

The current Windows release is not Authenticode-signed. Windows 11 Smart App
Control can therefore block it, and Windows does not provide a per-application
exception. For an immediate local test, open **Windows Security > App & browser
control > Smart App Control settings**, turn Smart App Control off, and run the
launcher again. The permanent distribution fix is to sign each Windows release
with a publicly trusted Authenticode certificate; checksum verification alone
does not establish a trusted Windows publisher.

To use the Lazarus IDE, open the repository through VS Code's **WSL: Open Folder
in WSL** command, then run:

```bash
lazarus src/purpleray_sbom_analyzer.lpi
```

Select the GTK3 widgetset for a Linux build. The lightweight application shell,
SBOM Analyzer workspace, Compare Scans workspace, and scan-settings dialog are
stored as the human-readable `src/uMainForm.lfm`,
`src/uSBOMAnalyzerFrame.lfm`, `src/uCompareScansFrame.lfm`, and
`src/uScanSettingsDialog.lfm` resources. All four can be edited in the Lazarus
form designer.

## Tests

`scripts/run-tests.sh` compiles and runs the non-UI suite. The fixtures cover
requirements, npm manifests and locks, Maven and MSBuild XML, atomic history
recovery and location migration, database archive export, export naming,
SHA-256, native binary headers and dependency tables, OS-evidence parsing,
component deduplication, declared-license/publisher persistence and parsing,
bounded SPDX-expression validation, CycloneDX author/lifecycle/composition
metadata,
worker exception containment, bounded manifest parsing, case-preserving and
glob-safe enumeration, special-file and permission handling,
application-shell/frame ownership and Lazarus resource registration,
shared-history ownership and safe task deletion, deterministic component
identity reconciliation and directional scan comparison,
deterministic/path-safe CycloneDX 1.6/1.7 generation, root-component promotion,
observed dependency edges, honest version/scope fields, Package URL
normalization, ignore matching, symbolic-link loops, and cancellation.
Platform-inapplicable cases are reported explicitly as `SKIP`: Linux exercises
literal wildcard and case-variant filenames, FIFOs, and `chmod`-based denial,
while Windows exercises device/offline attribute and directory-enumeration
error classification. The suite does not claim a Windows ACL-denial integration
test. The core tests require no network or downloaded scanner. The Linux CI job
additionally validates generated 1.6 and 1.7 fixtures against checksum-pinned
[official CycloneDX schemas](https://github.com/CycloneDX/specification).

For an explicit local invocation:

```bash
mkdir -p build/test-units tests/bin
fpc -Fu./src -FU./build/test-units -FE./tests/bin \
  -Mobjfpc -Sh -O2 -g -gl -B tests/test_runner.lpr
tests/bin/test_runner
```

## Data and recovery

The application stores all persistent data under the user's home directory:

- Linux, WSL, and macOS: `~/.purpleray/sbom-analyzer/`
- Windows: `%USERPROFILE%\.purpleray\sbom-analyzer\`

On first run after upgrading, the application moves files from
`~/.sbom-analyzer/` (or `%USERPROFILE%\.sbom-analyzer\` on Windows) into the
new location and removes the old directory only after every entry was moved
successfully. It also imports the older platform-specific FPC configuration
directory for direct upgrades from early builds. If a saved SBOM path still
points at an old directory, it is repaired when history is loaded. A migration
problem is reported without silently discarding the old data.

Files in that directory are user data:

- `settings.json`: last-used scan settings
- `history.json`: task history, artifact records, and normalized components
- `history.json.bak`: previous valid history
- `history.corrupt-<timestamp>.json`: a malformed history preserved for
  diagnosis
- `sboms/<task-id>.cdx.json`: generated CycloneDX documents

History and settings are written through a flushed temporary file, with one
backup retained. A malformed active history is preserved and the backup is
loaded when valid. Both compiled features use one shared in-memory history
service, so completed scans and deletions become visible without maintaining
divergent copies of the task database.

## Supported evidence

Reliable parsers cover `package.json`, `package-lock.json`,
`requirements*.txt`, `go.mod`, `pom.xml`, `*.csproj`, `packages.lock.json`,
`Directory.Packages.props`, `composer.json`, `composer.lock`, and Lazarus
`*.lpi`/`*.lpk` files.

The scanner also detects Yarn, pnpm, Cargo, `pyproject.toml`, Poetry, Pipfile,
Conda, Gradle, RubyGems, vcpkg, Conan, Swift Package Manager, and CocoaPods
evidence. Those
formats use conservative partial parsing where a dependency can be identified
without guessing; otherwise the artifact is marked unsupported. `LICENSE`,
`COPYING`, and `NOTICE` variants are recorded only as possible license
evidence—no license is inferred from a filename or file contents. License and
publisher values are emitted only when supported manifest fields declare them.
A sole registry-valid SPDX declaration is serialized as an expression;
multiple or non-SPDX declarations remain separate names without inventing an
`AND`/`OR` relationship.

Component versions are written to CycloneDX only when the scanned evidence
identifies one exact version, such as a resolved lock-file version, an exact
manifest version, a dotted native library-name version, or a Windows PE version
resource. Unresolved manifest constraints remain visible in the
`purpleray-sbom-analyzer:requested-range` property but are not misrepresented as
installed versions. A bare ELF SONAME suffix such as the `6` in `libc.so.6` is
preserved as `purpleray-sbom-analyzer:soname-abi-version`, not emitted as a
product version. An unversioned import such as `kernel32.dll` has no defensible
component version, so its `version` member is intentionally omitted.

For native binaries, bounded internal parsing is the portable baseline. It
reads ELF `DT_NEEDED` entries, PE import and delay-import tables, and Mach-O
load-dylib commands without loading or executing the target. The scanner then
uses these safe, locally available OS facilities where they apply:

- Linux: `readelf --dynamic --notes` to corroborate ELF declarations and obtain
  GNU build IDs, when `readelf` is already installed.
- macOS: `/usr/bin/codesign --display` for Mach-O signing identifiers and hash
  metadata.
- Windows: the native version-resource API for PE file-version evidence.

These facilities are detected at runtime; none is downloaded or installed by
the application. Each invoked tool is launched directly with an argument
list—never through a shell—and has a three-second execution limit, a 512 KiB
output limit, and cooperative cancellation. The scanned binary is provided
only as input and is never run. `ldd` is deliberately excluded because some
implementations may execute the program being inspected. SDK utilities that
would prompt for or require a separate installation are likewise not assumed
to exist.

## Project layout

```text
assets/                    application icon sources
packaging/macos/           minimal application-bundle metadata template
scripts/                   local build, test, version, and packaging helpers
src/                       Lazarus project, UI, scanner, parsers, and persistence
tests/                     deterministic non-UI test runner and fixtures
.github/workflows/         native three-platform CI and release automation
```

The tracked root `VERSION` file is the sole operator-managed version authority.
It contains exactly one canonical `MAJOR.MINOR.PATCH` value: no prefix, suffix,
or leading zero is accepted, and each numeric component must fit the Windows
version-resource range (`0` through `65535`). No version-setting helper script
is mandatory. CI reads that file, generates `src/uVersionInfo.pas`, and updates
the Lazarus PE version-resource fields in its ephemeral workspace using the
same version and full commit SHA. Generated changes are never committed back to
`main`.

The checked-in Pascal and Lazarus version fields are synchronized fallbacks for
direct IDE builds. After editing `VERSION`, an operator can validate or
synchronize those fallbacks with the optional helpers:

```bash
scripts/check-version.sh
scripts/write-version.sh
```

The writer always reads the root `VERSION`; a supplied version is accepted only
when it matches that file. Its commit defaults to `unknown` for checked-in local
fallbacks. The non-mutating checker is a local consistency aid; CI does not
require the operator to run either helper. CI validates `VERSION` directly,
then generates build-only metadata with the full commit SHA before testing and
compiling.

The checked-in `src/app_icon.res` embeds the Windows/LCL icon. After changing
`assets/app-icon.ico`, regenerate it with:

```bash
scripts/regenerate-icon-resource.sh
```

## CI and releases

`.github/workflows/build-release.yml` currently tests and builds the Windows and
Linux targets on `windows-latest` and pinned `ubuntu-24.04`. The macOS matrix entry is
retained as a commented block in the workflow and is temporarily paused to
conserve GitHub Actions minutes. Builds use FPC 3.2.2 and Lazarus 4.2 from the
official SourceForge release files. The maintained
[`ollydev/setup-lazarus`](https://github.com/ollydev/setup-lazarus) setup action
is pinned to an immutable commit and currently provisions Windows only; it
introduces no runtime dependency. Linux restores checksum-verified official
installers from the GitHub Actions cache and uses one bounded APT setup with a
signed fallback mirror. Official GitHub cache, artifact, and checkout actions
are pinned as well. When re-enabled, the macOS job uses GitHub's Intel runner and
explicitly compiles and verifies an x86_64 application. Newer runs cancel
obsolete runs, and preparation, dependency installation, builds, and publishing
have bounded timeouts so a stalled hosted runner cannot consume minutes
indefinitely. Markdown-only changes do not start the native build matrix.

Pull requests and branch builds use the exact version recorded in `VERSION`, run
all tests, and upload temporary packages without changing it. GitHub Actions no
longer calculates or increments semantic versions from commit messages.

A push to `main` publishes only when the operator-selected `vMAJOR.MINOR.PATCH`
tag does not exist. Once that version has been released, later commits using the
same `VERSION` still build and test but do not create another release. To publish
the next release, edit `VERSION` to a new value and commit it. Manual workflow
runs rebuild without publishing by default; when publishing is explicitly
selected, the workflow rejects a version whose tag belongs to another commit.

After every active native build succeeds, the release workflow creates the tag
and publishes the complete platform set together with `SHA256SUMS.txt`. Any
failed platform keeps the workflow marked as failed and prevents a partial
release. An existing tag on the same commit can be rebuilt idempotently.

### Verifying release provenance

Every newly published release artifact receives a free GitHub build-provenance
attestation. After downloading an artifact, verify that GitHub associates its
exact SHA-256 digest with a build from this repository:

```bash
gh attestation verify purpleray-sbom-analyzer-vX.Y.Z-linux-x64 \
  --repo aidamian/PurpleRay_SBOM_Analyzer
```

For Windows, pass the downloaded ZIP instead:

```powershell
gh attestation verify .\purpleray-sbom-analyzer-vX.Y.Z-windows-x64.zip `
  --repo aidamian/PurpleRay_SBOM_Analyzer
```

The command requires the GitHub CLI and network access only for explicit
verification; the application itself remains offline. Attestations establish
which repository, commit, and workflow produced a file. They complement the
published checksums but are not Authenticode signatures and do not cause
Windows to trust an otherwise unsigned executable.

## Code signing policy

Planned release signing: Free code signing provided by
[SignPath.io](https://signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/). Signing will be activated after
the Foundation approves the project and supplies its project identifiers.

- Committers and reviewers: [Andrei Ionut Damian](https://github.com/aidamian)
- Approvers: [Andrei Ionut Damian](https://github.com/aidamian)
- Source repository: <https://github.com/aidamian/PurpleRay_SBOM_Analyzer>
- Release artifacts are built exclusively from this repository by GitHub
  Actions on GitHub-hosted runners.
- Every release signing request requires manual approval by the signing
  approver. Build automation may submit a request but cannot approve it.

### Privacy

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it. The application performs scans locally without network access.
The optional launcher scripts contact GitHub only when the user runs them to
request and download a release.

## License

PurpleRay SBOM Analyzer is licensed under the
[Apache License, Version 2.0](LICENSE). Copyright and authorship remain with
Andrei Ionut Damian. Distributions and derivative works must comply with the
license and retain the applicable attribution notices from [NOTICE](NOTICE).
The citation below is requested for academic and professional attribution; it
does not add restrictions to the Apache-2.0 license.

## Citation and copyright

If you use PurpleRay SBOM Analyzer in research, publications, reports, or derivative
software, please cite the original project:

```bibtex
@misc{damian2026purpleraysbomanalyzer,
  author = {Andrei Ionut Damian},
  title  = {{PurpleRay SBOM Analyzer}},
  year   = {2026},
  url    = {https://github.com/aidamian/PurpleRay_SBOM_Analyzer}
}
```

Copyright (c) 2026 Andrei Ionut Damian. Copyright and authorship rights remain
with the author under the Apache License, Version 2.0. Please retain the
applicable copyright and attribution notices and cite the original project
appropriately using the citation above.

## Platform limitations

- Windows and macOS outputs are not code-signed. Unsigned Windows releases can
  be blocked by Smart App Control. A production distribution must add Windows
  Authenticode signing plus Apple Developer ID signing and notarization.
- The macOS release targets x86_64 and may require Rosetta on Apple Silicon.
- Lazarus's GTK3 backend can emit non-fatal layout diagnostics with some GTK
  themes or WSLg versions; these do not indicate that scanning has failed.
- Shared-library analysis is static. Direct declarations are read from ELF,
  PE, and Mach-O binaries, but the scanner does not invoke a loader, execute
  targets, resolve libraries to host-specific absolute paths, or infer every
  transitive/runtime-loaded dependency. It also does not contact registries,
  execute package managers, or evaluate build scripts.
