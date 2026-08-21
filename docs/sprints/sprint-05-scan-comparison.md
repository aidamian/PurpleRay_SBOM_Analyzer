# Sprint 5 — scan comparison

| Field | Recorded fact |
|---|---|
| Status | Accepted on 2026-08-20; released on 2026-08-21 |
| Baseline | `v0.5.0` / `37412c1` |
| Implementation | [`a85d243`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/a85d2438301745ea31264e54f70030c890e88f0d) |
| Release commit and tag | [`7223f1c`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/7223f1c9ff5e3d47ebc888bce850f2a29dde6b0c) / [`v0.6.0`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.6.0) |

## Planned

- Add a second compiled `Compare Scans` feature without interrupting Analyzer
  work.
- Centralize application-lifetime task ownership and notifications.
- Compare two completed inventories directionally using conservative stable
  identities, without borrowing history-owned pointers.
- Add safe terminal-task deletion and selection preservation.
- Exercise both feature frames, routing, live completion, deletion, and close
  on GTK scale 1/2 and native Win64.

## Delivered

- Deterministic comparison core:
  [uComponentComparison.pas](../../src/uComponentComparison.pas)
- Native comparison feature:
  [uCompareScansFrame.pas](../../src/uCompareScansFrame.pas) and
  [uCompareScansFrame.lfm](../../src/uCompareScansFrame.lfm)
- Shared history ownership and safe deletion:
  [uTaskHistory.pas](../../src/uTaskHistory.pas)
- Shell routing: [uMainForm.pas](../../src/uMainForm.pas)
- Permanent regression coverage: [test_runner.lpr](../../tests/test_runner.lpr)

Comparison reports Added, Removed, Changed, and Unchanged components. It uses a
strict Package URL identity when possible and conservative weak matching
otherwise; ambiguous residuals remain additions/removals rather than invented
version pairs.

## Validation recorded at the time

| Target | Registered | Passed | Failed | Platform skips |
|---|---:|---:|---:|---:|
| Linux normal | 51 | 50 | 0 | 1 |
| Linux checked runtime | 51 | 50 | 0 | 1 |
| Native Win64 normal | 51 | 46 | 0 | 5 |
| Native Win64 checked runtime | 51 | 46 | 0 | 5 |

- The explicit-data real-LCL probe passed on GTK3 scale 1, GTK3 scale 2, and
  native Win64. It covered both features, filters/sorts/swap/copy, live history,
  safe deletion, a background 1 GiB scan, shortcut isolation, and async close.
- Both Release builds had zero warnings/errors and launched responsively.
- Eight generated CycloneDX documents passed official schemas and were
  locale-byte-identical.
- Version, workflow, shell, PowerShell, Python, whitespace, frozen-source, and
  final operator-profile isolation checks passed.

## Evidence gaps, incidents, and deferred work

- An earlier aborted, non-isolated native Windows launch touched the real
  `history.json` and backup. Pre-launch hashes were not captured, so prior
  byte equality cannot be proved. The final isolated gate caused no further
  profile changes.
- Comparison intentionally ignores licence, publisher, scope, parser,
  evidence, and hash-only changes.
- External-scanner handoff, BSI readiness, occurrences, declared hashes, and
  layout persistence remained deferred.
