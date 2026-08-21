# Sprint 1 — scanner safety

| Field | Recorded fact |
|---|---|
| Status | Historically accepted on 2026-08-20; consolidated evidence incomplete |
| Baseline | `v0.3.5` / `61acb7a` |
| Delivery | [`3f0d43c`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/3f0d43c95af99b5b3d12c9a67b5133f97dce93c8), followed by version-only commit [`985cc96`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/985cc9698fa8aff73e53807d78906a7cebed5d50) |
| Intended version | `0.3.6` |
| Release | No `v0.3.6` tag or dedicated release; the work first appears in the published `v0.4.1` ancestry |

## Planned

- Fix the sorted-token merge crash and prevent error cleanup from repeating
  component finalization.
- Catch otherwise escaped worker exceptions and still deliver terminal state.
- Skip special files, preserve case-distinct names, use deterministic ordinal
  enumeration, and report unreadable directories.
- Bound manifest parsing and repair current Lazarus `.lpi`/`.lpk` parsing.
- Add a regression for every corrected scanner behavior.

## Delivered

The scanner and test implementation is in `3f0d43c`. Despite its subject,
`985cc96 fix(scanner): harden traversal and worker failures` changes only the
root version from `0.3.5` to `0.3.6`; it must not be cited as the source-code
implementation by itself.

Tracked implementation and regression surfaces:

- [scan engine](../../src/uScanEngine.pas), [worker](../../src/uScanWorker.pas),
  and [platform boundary](../../src/uPlatform.pas)
- [component normalization](../../src/uComponentNormalizer.pas) and
  [manifest parsing](../../src/uManifestParsers.pas)
- [central regression runner](../../tests/test_runner.lpr) and the
  [current Lazarus fixture](../../tests/fixtures/lazarus-current.lpi)

## Validation recorded at the time

The ignored 2026-08-20 roadmap recorded the sprint as accepted and stated that:

- Linux and native Win64 normal and checked-runtime suites passed;
- both Release GUI targets built, launched, and remained responsive;
- fixture and `src/` production scans completed;
- generated fixture output passed the official CycloneDX 1.6 JSON schema; and
- output was byte-identical under `LC_ALL=C` and `LC_ALL=C.UTF-8`.

## Evidence gaps and deferred work

- No tracked or consolidated Sprint 1 validation report preserves exact test
  totals, commands, artifact hashes, profile-isolation hashes, or a CI run.
- There is no `v0.3.6` tag, so this sprint was not independently published.
- The later single-verified-input, archive/native-analysis, parallelism, and
  rescan-cache work was explicitly deferred to Sprint 7.
