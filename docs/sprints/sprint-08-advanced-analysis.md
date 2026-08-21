# Sprint 8 — opt-in online and advanced analysis

| Field | Recorded fact |
|---|---|
| Status | Implementation delivered to `main`; final cross-platform acceptance remains incomplete |
| Baseline | `v0.7.1` / `a86a0af` |
| Delivery | [`51915ce`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/commit/51915ce057770fa62f07e307492022dab444f626) |
| Version state | Commit `51915ce` changed root `VERSION` to `0.8.0`; the 2026-08-21 toolchain/evidence follow-up synchronizes the checked-in fallback metadata |
| Release state at 2026-08-21 audit | No local or remote `v0.8.0` tag; no release evidence recorded |

## Planned

- Preserve strict declared npm/Cargo/Poetry hashes as explicitly unverified
  evidence and emit privacy-filtered CycloneDX occurrences.
- Add a transient, unchecked-by-default desktop OSV.dev lookup only after the
  offline SBOM has been activated, hashed, and cached. Keep the CLI offline.
- Use a fixed endpoint, exact-version eligible Package URLs, native verified
  TLS, cancellation/deadline/resource bounds, and minimized persistence.
- Export a separate deterministic BSI TR-03183-2 v2.1.0 readiness assessment
  without claiming compliance or mutating the inventory.
- Complete Linux/Win64 tests, schemas, builds, CLI, scaled/native UI, static,
  packaging, source-freeze, and profile-isolation gates on one frozen tree.

## Delivered

- Declared hashes and occurrences:
  [uManifestParsers.pas](../../src/uManifestParsers.pas) and
  [uCycloneDX.pas](../../src/uCycloneDX.pas)
- Known-issue model/service:
  [uKnownIssues.pas](../../src/uKnownIssues.pas) and
  [uKnownIssueService.pas](../../src/uKnownIssueService.pas)
- Bounded OSV coordinator and transport selection:
  [uOSVCore.pas](../../src/uOSVCore.pas) and
  [uOSVTransportFactory.pas](../../src/uOSVTransportFactory.pas)
- Native TLS transports:
  [uOSVTransportOpenSSL.pas](../../src/uOSVTransportOpenSSL.pas) and
  [uOSVTransportWinHTTP.pas](../../src/uOSVTransportWinHTTP.pas)
- BSI producer and closed schema:
  [uBSIReadiness.pas](../../src/uBSIReadiness.pas) and
  [purpleray-bsi-readiness-v1.schema.json](../../schemas/purpleray-bsi-readiness-v1.schema.json)
- GTK3 save-dialog compatibility:
  [uSaveDialogCompat.pas](../../src/uSaveDialogCompat.pas)
- Dedicated permanent coverage:
  [sprint8_regressions.inc](../../tests/sprint8_regressions.inc)

## Validation completed before delivery

The historical validation record preserves this permanent matrix, but it ran
before the final save-dialog compatibility refreeze and therefore does not by
itself close final acceptance:

| Target | Registered | Passed | Failed | Platform skips | Heap result |
|---|---:|---:|---:|---:|---|
| Linux normal | 86 | 85 | 0 | 1 | Not enabled |
| Linux checked/heap | 86 | 85 | 0 | 1 | 0 leaks |
| Native Win64 normal | 86 | 81 | 0 | 5 | Not enabled |
| Native Win64 checked/heap | 86 | 81 | 0 | 5 | 0 leaks |

Also recorded as complete:

- Focused OSV core/OpenSSL/WinHTTP security review and loopback/fake-transport
  deadline, cancellation, descriptor/handle-lifetime, TLS, JSON, and resource-
  limit probes.
- Representative CycloneDX 1.6/1.7 schema checks and BSI schema/producer probes
  on Linux and native Win64.
- A network-disabled replay with pinned Grype 0.117.0/database v6.1.9 and
  OSV-Scanner 2.5.1; both found the expected lodash advisory.
- A pre-compatibility workflow/static/package-metadata gate.

The 2026-08-21 toolchain/evidence follow-up added a fresh local Linux gate on
the official Lazarus 4.8 and stable FPC 3.2.2 packages:

- the version-consistency check passed with `VERSION`, Pascal metadata, and the
  Lazarus project metadata all at `0.8.0`;
- the permanent suite registered 86 tests: 85 passed, none failed, and the one
  Windows-only check was skipped;
- the GTK3 Release build compiled 46,318 lines with 81 hints, 5 notes, and no
  warnings or errors; and
- the rebuilt displayless executable reported
  `PurpleRay SBOM Analyzer 0.8.0`.

The CI definition now pins Lazarus 4.8 with FPC 3.2.2 on both active platforms
and verifies the official Linux package and Windows installer SHA-256 digests.
This is local and static evidence; it does not substitute for a completed
native Windows GitHub Actions run on an immutable commit.

## Acceptance gaps

The following final-tree evidence was still missing or had not been recorded
against one immutable candidate when this tracked record was created:

- commit and push the current `0.8.0` fallback synchronization, then validate
  that immutable candidate in the native CI matrix;
- exact Linux and Win64 Release artifact hashes plus responsive native launch;
- the complete isolated GTK scale 1, GTK scale 2, and native Win64 UI matrix
  after the save-dialog compatibility change;
- final Linux/Win64 displayless CLI proof;
- final CycloneDX schema document counts, locale hashes, and BSI instance
  counts;
- affected workflow/static checks after the compatibility refreeze;
- final source/status aggregate and Linux/Win64 operator-profile hashes; and
- a successful `v0.8.0` release workflow, tag, assets, checksums, and
  attestations.

Until those rows are closed with exact evidence, Sprint 8 must not be labelled
fully accepted or released. Point-in-time OSV matches remain non-exploitability
advisory evidence, BSI output remains readiness-only, and macOS/signing/WinGet
submission remain outside this acceptance claim.
