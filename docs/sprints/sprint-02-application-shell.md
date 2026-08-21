# Sprint 2 — application shell

| Field | Recorded fact |
|---|---|
| Status | Accepted on 2026-08-20 |
| Baseline | `985cc96`, working version `0.3.6` |
| Delivery | [`c2baabd`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/c2baabd653f37fb55975ea60c75a4545a0c5a335) |
| Intended release | `v0.4.0`; release-preparation commit [`ddc5921`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/ddc5921c36b1c53f889e0f5013161942d37eba7a) did not produce a tag |
| First published in | [`v0.4.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.4.1) |

## Planned

- Turn `TMainForm` into a lightweight product shell.
- Move the complete analyzer workflow into a persistent, LFM-backed feature
  frame hosted in a tabless notebook.
- Define shell-to-feature routing for activation, keyboard shortcuts, dropped
  folders, scan activity, and asynchronous close.
- Expose no unfinished placeholder feature.

## Delivered

- [main shell](../../src/uMainForm.pas) and [shell resource](../../src/uMainForm.lfm)
- [analyzer frame](../../src/uSBOMAnalyzerFrame.pas) and
  [frame resource](../../src/uSBOMAnalyzerFrame.lfm)
- [settings dialog](../../src/uScanSettingsDialog.pas) and its
  [resource](../../src/uScanSettingsDialog.lfm)
- Structural and lifecycle coverage in the
  [central regression runner](../../tests/test_runner.lpr)

The acceptance gate also corrected a Lazarus 3/GTK3 scaled-layout loop in the
settings dialog and an asynchronous GTK list-selection problem that could
temporarily leave Summary empty.

## Validation recorded at the time

| Target | Registered | Passed | Failed | Platform skips |
|---|---:|---:|---:|---:|
| Linux normal | 34 | 33 | 0 | 1 |
| Linux checked runtime | 34 | 33 | 0 | 1 |
| Native Win64 normal | 34 | 29 | 0 | 5 |
| Native Win64 checked runtime | 34 | 29 | 0 | 5 |

- FPC 3.2.2 was used for the four suites.
- Linux GTK3 and Win64/Win32 Release builds passed; the native Windows binary
  launched responsively, closed normally, and carried exact `0.3.6` metadata.
- A real-LCL GTK3 scale-2 probe exercised scanning, search, sorting, copying,
  cancellation, active-scan close, and persisted terminal history. Three
  generated SBOMs passed the CycloneDX 1.6 schema.
- Version consistency and whitespace checks passed. CI was pinned to Lazarus
  4.2; local GTK validation used Lazarus 3.0.

## Evidence gaps and deferred work

- The exact probe source, screenshots, and raw logs remained ignored; this
  tracked summary preserves the result but not independently replayable raw UI
  evidence.
- The `v0.4.0` workflow failed before publication because CI checked generated
  version fallbacks too early. There is no `v0.4.0` tag.
- Only the Analyzer feature shipped here; comparison was deliberately deferred
  to Sprint 5.
