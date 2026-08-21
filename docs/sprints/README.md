# Sprint delivery evidence

This directory is the tracked, durable record of the first eight implementation
sprints. It answers two separate questions for each sprint:

1. What was planned?
2. What was delivered and actually validated?

The records were reconstructed on 2026-08-21 from Git history, tags, tracked
tests and source, and the detailed operator work records that were then stored
under the intentionally ignored `purpleray-sbom-analyzer-internal/` directory.
The commit and release links below are immutable evidence; test totals and UI
results transcribed from ignored records are labelled as such. Missing evidence
is not treated as a pass.

## Status at the evidence audit

| Sprint | Planned outcome | Delivery status | Release status | Durable record |
|---:|---|---|---|---|
| 1 | Scanner safety | Accepted historically; validation summary incomplete | No dedicated `v0.3.6` release | [Sprint 1](sprint-01-scanner-safety.md) |
| 2 | Multi-feature application shell | Accepted | `v0.4.0` was not published; first included in `v0.4.1` | [Sprint 2](sprint-02-application-shell.md) |
| 3 | Consumable CycloneDX structure | Accepted and released | [`v0.4.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.4.1) | [Sprint 3](sprint-03-sbom-structure.md) |
| 4 | Trust and compliance UI | Accepted and released | [`v0.5.0`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.5.0) | [Sprint 4](sprint-04-trust-compliance.md) |
| 5 | Scan comparison | Accepted and released | [`v0.6.0`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.6.0) | [Sprint 5](sprint-05-scan-comparison.md) |
| 6 | CLI and distribution | Accepted; its proposed release failed before publication | First published together with Sprint 7 in `v0.7.1` | [Sprint 6](sprint-06-cli-distribution.md) |
| 7 | Scanner depth | Accepted and released | [`v0.7.1`](https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/tag/v0.7.1) | [Sprint 7](sprint-07-scanner-depth.md) |
| 8 | Opt-in OSV analysis and evidence completion | Delivered to `main`; a WSL2 UI correction is locally validated but not yet committed | Unreleased `0.8.x`; current `VERSION=0.8.1` has no matching tag or release | [Sprint 8](sprint-08-advanced-analysis.md) |

## Evidence rules

- **Planned** means the item appeared in the sprint plan. It is not proof of
  implementation.
- **Delivered** requires a tracked commit and links to the resulting source or
  permanent regression tests.
- **Accepted** requires a recorded validation gate. Where only an ignored
  historical summary survives, the record says so and identifies any missing
  counts, hashes, logs, or profile evidence.
- **Released** requires an immutable Git tag/release. A changed `VERSION` file
  or a successful local build is not a release.
- Raw binaries, temporary profiles, downloaded scanner databases, screenshots,
  and multi-gigabyte probe trees should remain untracked. The sprint record
  should instead retain the command/result summary, relevant hashes when they
  matter, and links to the permanent test and source contract.

## Known record-level gaps

- Sprint 1 has no consolidated validation document. Its acceptance statement
  survives only as a short historical summary, without exact test totals,
  artifact hashes, or an immutable CI run.
- Sprint 7 has a detailed plan and permanent regression file, but no
  consolidated final validation document. Release evidence exists; some local
  matrix details do not.
- Sprint 8's ignored handoff was stale after the implementation was pushed: it
  still described `VERSION=0.7.1` and pending delivery. The tracked record now
  reflects commit `51915ce` and `VERSION=0.8.0`, while retaining the unresolved
  final acceptance rows. A later WSL2 UI correction is recorded separately in
  the Sprint 8 file and remains a candidate until it has an immutable commit
  and CI result.

Future work should update the applicable sprint file in the same change that
closes an evidence gap or publishes a release. Do not replace a gap with an
inference from current behavior; record the new exact run instead.
