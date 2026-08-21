# Sprint 7 — scanner depth

| Field | Recorded fact |
|---|---|
| Status | Accepted and released on 2026-08-21; consolidated validation summary incomplete |
| Baseline | Accepted but unpublished Sprint 6 tree at `7a3a682` |
| Main implementation | [`834849d`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/834849d9f3a9f3a7a9358c0f99f0f18f4ab3c02b) and [`5b30fee`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/5b30feeb573caa3b227e47550507c9f42db9a8c5) |
| Release fix and tag | [`a86a0af`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/a86a0af651ddaeb7885590b3c2e918a90fa502d2) / [`v0.7.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.7.1) |

## Planned

- Establish one verified, bounded, no-follow input per enumerated file and use
  it for hashing, parsing, archive/native inspection, and allowed OS evidence.
- Recognize installed Python/npm trees, bounded JAR/WAR/EAR metadata, and
  static libraries without executing scanned content or invoking analyzers.
- Harden ELF/PE parsing and add evidence-backed generic Package URLs/CPEs.
- Replace `readelf` dependence with internal bounded ELF evidence.
- Add deterministic bounded parallel scanning and an opt-in, profile-isolated
  rescan cache after the serial behavior was frozen.

## Delivered

- Verified input and bounded reader:
  [uVerifiedInput.pas](../../src/uVerifiedInput.pas) and
  [uBoundedBinaryReader.pas](../../src/uBoundedBinaryReader.pas)
- Installed-tree/archive analysis:
  [uManifestParsers.pas](../../src/uManifestParsers.pas) and
  [uArchiveInspector.pas](../../src/uArchiveInspector.pas)
- Native identity evidence:
  [uBinaryIdentifiers.pas](../../src/uBinaryIdentifiers.pas),
  [uPEVersionInfo.pas](../../src/uPEVersionInfo.pas), and
  [uNativeDependencyInspector.pas](../../src/uNativeDependencyInspector.pas)
- Deterministic pool and cache:
  [uScanPool.pas](../../src/uScanPool.pas) and
  [uScanCache.pas](../../src/uScanCache.pas)
- Dedicated permanent coverage:
  [sprint7_regressions.inc](../../tests/sprint7_regressions.inc)

The unusually broad implementation is primarily in `834849d`, despite that
commit's narrow `fix(ci)` subject. `5b30fee` contains the final scanner-depth
and release corrections. `a86a0af` pins LF notice bytes for reproducible
Windows packaging.

## Validation recorded at the time

- The historical release record states that Linux and native Win64 normal and
  checked-runtime suites passed, as did release builds, native CLI probes,
  CycloneDX schema/content checks, deterministic output, scaled GTK3/native
  Win64 UI probes, and package checks.
- The retained UI summary says the explicit-data cache workflow passed at GTK3
  scale 1, GTK3 scale 2, and native Win64, including hit/miss/refresh,
  cancellation rollback, async-close rollback, and operator-profile isolation.
- GitHub Actions run
  [`32492451963`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/actions/runs/32492451963)
  published `v0.7.1`. The release record says five required artifacts plus the
  checksum file were present and all six provenance subjects verified.

## Evidence gaps and deferred work

- No consolidated final Sprint 7 validation document preserves exact native
  test totals, final artifact hashes, schema counts, or the complete frozen-
  source matrix in one durable place. Release success and permanent tests are
  durable; those local details are not.
- WSLg emitted known non-fatal Lazarus 3/GTK3 hidden-notebook/allocation
  diagnostics during the retained UI probe.
- The entry plan expected a separate `v0.7.0` recovery and proposed `0.8.0`.
  Actual history intentionally skipped `v0.7.0` and published the combined
  Sprint 6/7 scope as `v0.7.1`; the tracked record follows actual history.
- Opt-in online OSV analysis and the remaining evidence/export work were
  deferred to Sprint 8. macOS, signing, and WinGet submission remained outside
  the accepted boundary.
