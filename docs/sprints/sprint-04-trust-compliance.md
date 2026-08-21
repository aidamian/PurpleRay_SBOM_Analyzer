# Sprint 4 — trust and compliance UI

| Field | Recorded fact |
|---|---|
| Status | Accepted locally and released on 2026-08-20 |
| Baseline | `v0.4.1` / `398e081` |
| Implementation | [`326299f`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/326299fdbd0506b78cc40d958dcd15a919fde9d9) |
| Release commit and tag | [`37412c1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/37412c16691486ee4503c9760883833df5b5f00b) / [`v0.5.0`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.5.0) |

## Planned

- Preserve declared licence and publisher evidence without guessing from
  nearby files.
- Validate SPDX expressions and emit author, lifecycle, and incomplete-
  composition metadata.
- Show target/privacy choices clearly and make them safe per scan.
- Surface warnings, errors, counts, status, and zero-file cautions.
- Correct cancellation, close-during-scan, tables, messages, progress, export,
  history-time, and empty-state behavior.

## Delivered

- Declared metadata and bounded parsing:
  [uManifestParsers.pas](../../src/uManifestParsers.pas)
- SPDX grammar: [uSPDXExpressions.pas](../../src/uSPDXExpressions.pas)
- Presentation contract: [uPresentation.pas](../../src/uPresentation.pas)
- CycloneDX trust metadata: [uCycloneDX.pas](../../src/uCycloneDX.pas)
- Analyzer and settings workflows:
  [uSBOMAnalyzerFrame.pas](../../src/uSBOMAnalyzerFrame.pas) and
  [uScanSettingsDialog.pas](../../src/uScanSettingsDialog.pas)
- Permanent regression coverage: [test_runner.lpr](../../tests/test_runner.lpr)

The gate also found and fixed an XML external-entity risk: manifest XML is now
parsed from one bounded stream with document types and entity expansion
disabled, including UTF-16 coverage.

## Validation recorded at the time

| Target | Registered | Passed | Failed | Platform skips |
|---|---:|---:|---:|---:|
| Linux normal | 48 | 47 | 0 | 1 |
| Linux checked runtime | 48 | 47 | 0 | 1 |
| Native Win64 normal | 48 | 43 | 0 | 5 |
| Native Win64 checked runtime | 48 | 43 | 0 | 5 |

- Linux GTK3 and Win64 Release builds completed with zero warnings/errors.
- Four structure/compliance documents for each locale passed the pinned
  CycloneDX 1.6/1.7 schemas and were byte-identical across locales.
- The real GTK3 workflow probe passed at scale 1 and 2, including privacy,
  warnings, cancellation, copy, and asynchronous close.
- The production Win64 executable launched responsively and closed cleanly
  with exact `0.4.1` metadata.

## Evidence gaps, incidents, and deferred work

- Windows Application Control blocked the bespoke Win64 full-workflow probe,
  so the complete dialog flow had GTK runtime evidence only in this gate.
- One production Win64 validation launch rewrote the operator's real history
  in the new compatible format. Comparison with its backup found only the new
  `remember_privacy_choices:false` setting and no task/SBOM loss; the backup
  was retained. No restoration was attempted.
- Universal parser depth/node limits, additional declaration formats, and the
  verified single-input scanner boundary were deferred.
