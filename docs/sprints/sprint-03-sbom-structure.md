# Sprint 3 — SBOM structure

| Field | Recorded fact |
|---|---|
| Status | Accepted and released on 2026-08-20 |
| Baseline | Unpublished `0.4.0` tree at `ddc5921` |
| Delivery and release commit | [`398e081`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/398e0810a17d8d49607b60010f0634fda78555f8) |
| Release | [`v0.4.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.4.1) |

## Planned

- Make CycloneDX 1.7 the default while retaining a tested 1.6 path.
- Add `metadata.component` and a directly evidenced `dependencies[]` graph.
- Normalize supported PyPI, npm, Maven/Gradle, and Conda Package URLs.
- Separate exact versions from ranges, tags, local/VCS references, and SONAME
  ABI evidence.
- Map supported dependency scopes to CycloneDX semantics.
- Fix current Lazarus project parsing and validate both schema versions in CI.

## Delivered

- Serializer and graph contract: [uCycloneDX.pas](../../src/uCycloneDX.pas)
- Package, version, scope, and Lazarus parsing:
  [uManifestParsers.pas](../../src/uManifestParsers.pas)
- Checksum-pinned official validator:
  [validate-cyclonedx.py](../../scripts/validate-cyclonedx.py)
- Permanent semantics and determinism coverage:
  [test_runner.lpr](../../tests/test_runner.lpr)

The graph is intentionally evidence-limited: root-to-manifest and observed
binary-owner-to-runtime edges are emitted, but no transitive dependency or
loader-resolution claim is invented.

## Validation recorded at the time

| Target | Registered | Passed | Failed | Platform skips |
|---|---:|---:|---:|---:|
| Linux normal | 40 | 39 | 0 | 1 |
| Linux checked runtime | 40 | 39 | 0 | 1 |
| Native Win64 normal | 40 | 35 | 0 | 5 |
| Native Win64 checked runtime | 40 | 35 | 0 | 5 |

- Both CycloneDX 1.6 and 1.7 generated fixtures passed checksum-pinned official
  schemas and were byte-identical across `C` and `C.UTF-8` locales.
- Linux GTK3 and Win64 Release builds completed without warnings and were
  responsively launched; Windows metadata was complete and exact.
- GitHub Actions run
  [`32372837484`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/actions/runs/32372837484)
  published the native assets, checksums, tag, and provenance attestations.

## Evidence gaps, caveats, and deferred work

- The tagged source retained `0.4.0` Pascal/Lazarus fallback metadata even
  though CI generated correct `0.4.1` release binaries. This local-build
  inconsistency was corrected in the following sprint.
- npm case behavior for rare grandfathered names remained an explicit future
  compatibility decision.
- Declared ranges and lock-file resolutions were not fully reconciled into a
  richer dependency graph; the graph remained direct-evidence only.
