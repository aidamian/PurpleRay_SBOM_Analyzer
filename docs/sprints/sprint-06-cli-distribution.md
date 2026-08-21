# Sprint 6 — CLI and distribution

| Field | Recorded fact |
|---|---|
| Status | Accepted on 2026-08-21 |
| Baseline | `v0.6.0` / `7223f1c` |
| Delivery | [`7a3a682`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/7a3a682cc694ac30d0ecf1c599720b1db22b147b), including the operator-approved `VERSION=0.7.0` change |
| Release | `v0.7.0` was not published; the scope first shipped in [`v0.7.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.7.1) |

## Planned

- Parse `--help`, `--version`, and usage errors before LCL initialization.
- Add an offline `--scan … --output … [--settings …]` path sharing the GUI's
  scanner and serializer, without history/profile mutation.
- Publish verified notice-complete Windows and Linux packages, Debian desktop
  integration, and reproducible Scoop/WinGet metadata.
- Harden release concurrency, asset/content gates, checksums, attestations,
  launcher version/cache verification, and onboarding documentation.
- State the active Linux/Windows boundary honestly; keep macOS paused.

## Delivered

- Command dispatcher: [uCommandLine.pas](../../src/uCommandLine.pas)
- Shared LCL-free scan service: [uScanService.pas](../../src/uScanService.pas)
- Atomic and platform-specific output boundary:
  [uAtomicFiles.pas](../../src/uAtomicFiles.pas) and
  [uPlatform.pas](../../src/uPlatform.pas)
- Distribution scripts:
  [package-linux.sh](../../scripts/package-linux.sh),
  [package-windows.ps1](../../scripts/package-windows.ps1), and
  [manifest generator](../../scripts/generate-package-manifests.py)
- Release workflow: [build-release.yml](../../.github/workflows/build-release.yml)
- Permanent regression coverage: [test_runner.lpr](../../tests/test_runner.lpr)

The focused security review found and corrected an output-parent replacement
race. The accepted path pins and revalidates the parent identity and fails
closed if it changes before atomic publication.

## Validation recorded at the time

| Target | Registered | Passed | Failed | Platform skips |
|---|---:|---:|---:|---:|
| Linux normal | 54 | 53 | 0 | 1 |
| Linux checked runtime | 54 | 53 | 0 | 1 |
| Native Win64 normal | 54 | 49 | 0 | 5 |
| Native Win64 checked runtime | 54 | 49 | 0 | 5 |

- Native Linux and Win64 CLI probes passed help/version/usage, Unicode,
  displayless/no-window scan, output, and profile-isolation checks.
- Linux GTK3 and Win64 Release builds completed warning-free and exact binaries
  launched responsively. Full explicit-data UI probes passed on GTK scale 1/2
  and native Win64.
- CycloneDX 1.6/1.7 fixtures passed pinned official schemas and locale byte
  comparison.
- Linux tar/DEB, Windows ZIP, Scoop, and WinGet outputs were produced twice
  and corresponding artifacts were byte-identical. Package contents, notices,
  AppStream, and official package-manager schemas passed.
- Workflow/static, frozen-source, and final profile-isolation gates passed.

## Release incident and deferred external gates

- Workflow run
  [`32465926815`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/actions/runs/32465926815)
  failed in `prepare` while checking tracked version fallbacks. Commit
  [`2a11c7e`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/2a11c7e1194d868299f9400c7c297fd14904f536)
  repaired that contract, but `v0.7.0` was intentionally left unpublished.
- macOS delivery, SignPath signing, and WinGet community submission remained
  external or paused. Generated WinGet manifests were validated, not submitted.
- The final environment lacked `desktop-file-validate`; an earlier exact
  desktop-file audit passed and AppStream validation passed in the final gate.
