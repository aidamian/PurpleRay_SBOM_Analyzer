# PurpleRay SBOM Analyzer glossary

This glossary defines terms used in PurpleRay's interface, CycloneDX output,
BSI readiness report, documentation, and vulnerability-scanner handoff. It
describes PurpleRay's current behavior and is not legal, licensing,
certification, or vulnerability-remediation advice.

**ABI (Application Binary Interface)** — The low-level calling and binary-
compatibility contract between compiled components. An ABI suffix is not
necessarily a product version.

**Absolute and relative path** — An absolute path includes its filesystem root
and can expose private machine details. PurpleRay uses relative paths in
shareable output unless the user enables absolute paths for that scan.

**Added component** — A component identity and version present on the
comparison side after equal versions have been matched. In a multi-version
identity, an unmatched version remains an addition rather than becoming a
speculative version change.

**Advisory and advisory ID** — A published security record and its identifier,
which may be an OSV, CVE, GHSA, or ecosystem-specific ID. “Advisory” is broader
than “CVE.”

**API (Application Programming Interface)** — A defined way for software
systems to exchange requests and results. PurpleRay's optional online check
uses the OSV.dev HTTPS API.

**Artifact** — A local file or archive recognized during a scan, such as a
manifest, lock file, executable, library, or Java archive. An artifact is
evidence and is not necessarily a software component.

**Artifact status** — PurpleRay classifies a recognized artifact as parsed,
partially parsed, detected but unsupported, or failed. A partial or failed
status records a limitation; it does not mean the artifact contains no useful
information.

**Atomic write** — Writing a complete temporary file before replacing the
destination in one controlled step, preventing consumers from seeing a
partially written managed file.

**Attestation** — A statement about an artifact or build, often signed.
PurpleRay's release provenance attestations describe release assets and are
separate from a scanned component's code signature or hash.

**Author, creator, manufacturer, and publisher** — Distinct provenance or
contact roles. PurpleRay preserves declared publisher data and optional
operator-entered SBOM author data without treating either as authoritative BSI
creator or manufacturer evidence.

**Baseline scan** — The first selected scan in a directional comparison. Its
component values form the “before” side.

**Blocked and blocker** — `blocked` means PurpleRay cannot establish a required
claim from the managed SBOM. A blocker is a stable, machine-readable gap, not
necessarily a scan failure.

**BOM and SBOM** — A BOM is a Bill of Materials; an SBOM is a machine-readable
Software Bill of Materials describing software components and relationships.
An SBOM alone is not a vulnerability report, exploitability decision, or
licence-compliance determination.

**`bom-ref`** — A unique node reference within one CycloneDX document. It
supports internal relationships but is not automatically a global package
identifier.

**BSI and TR** — BSI is Germany's Federal Office for Information Security
(*Bundesamt für Sicherheit in der Informationstechnik*). TR means Technical
Guideline (*Technische Richtlinie*).

**BSI TR-03183-2 v2.1.0** — The exact [BSI guideline](https://www.bsi.bund.de/dok/TR-03183-en)
and version used by PurpleRay's readiness mapper. The report does not claim
that this is the currently applicable version or that the output is conformant
or certified.

**Build equivalence** — Evidence that source and build information corresponds
to the deployed artifact. A post-build filesystem scan cannot prove this by
itself.

**Build ID** — An identifier embedded by a compiler or linker that helps
distinguish builds. It is not automatically a package name or version.

**Byte-identical** — Containing exactly the same bytes and therefore the same
SHA-256 digest. This is stronger than two JSON documents having equivalent
values.

**Changed component** — A component identity with exactly one unique version
on each side and different versions between the baseline and comparison scans.
PurpleRay does not infer a version change for multi-version identities.

**CISA KEV** — The US Cybersecurity and Infrastructure Security Agency's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Inclusion confirms exploitation in the wild, not exploitation of a particular
installation. PurpleRay does not retrieve or export KEV data; it is deferred
from the manual OSV refresh.

**CLI and GUI** — The Command-Line Interface accepts text arguments without
opening the desktop application; the Graphical User Interface is the
interactive desktop application. PurpleRay's CLI is offline, while only the
GUI can request the optional OSV.dev lookup.

**Code signature** — A platform-specific signature associated with an
executable or package. It can identify a signer and reveal modification but
does not show that the software is vulnerability-free.

**Comparison scan** — The second selected scan in a directional comparison.
Its component values form the “after” side.

**Compliance, conformity, and certification** — Compliance means satisfying
applicable requirements; conformity is an evidenced assertion of alignment;
certification is a formal determination by an authorized or qualified party.
PurpleRay's readiness report claims none of them.

**Component** — A normalized software item inferred from one or more artifacts.
One artifact can identify several components, and evidence for the same
component can be merged deterministically.

**Component identity** — The version-independent key used to match components
across scans. PurpleRay prefers a Package URL with only its version removed and
otherwise falls back conservatively to ecosystem, case-sensitive name, and
component type.

**Component status** — The parse status of the artifact that produced a
component. It describes the evidence source, not the component's security or
operational health.

**Composition and aggregate** — CycloneDX composition data describes inventory
completeness. PurpleRay uses an `incomplete` aggregate because bounded
post-build inspection cannot prove that every dependency was found.

**Concluded licence** — A licence expression recorded as an analysis conclusion
rather than a package declaration. PurpleRay uses such an expression as
evidence for the BSI distribution-licence mapping but does not infer one from a
manifest or nearby licence file.

**CPE (Common Platform Enumeration)** — A standardized naming scheme for
classes of software, operating systems, and hardware. PurpleRay may derive a
conservative candidate from native-binary evidence but does not resolve it
against the [NVD CPE Dictionary](https://nvd.nist.gov/products/cpe).

**CVE (Common Vulnerabilities and Exposures)** — A
[program and identifier system](https://www.cve.org/) for publicly disclosed
vulnerabilities. A CVE ID identifies a record; it is not a scanner, severity
score, or proof of exploitability.

**CVSS (Common Vulnerability Scoring System)** — A
[standard](https://www.first.org/cvss/) that expresses technical severity as a
vector and numeric score. Severity is not exploitation likelihood or business
risk. PurpleRay does not currently retrieve or export CVSS data.

**CWE (Common Weakness Enumeration)** — A taxonomy of software and hardware
weakness classes. A CWE describes a kind of weakness, while a CVE usually
identifies a disclosed vulnerability. PurpleRay does not currently retrieve or
export CWE data.

**CycloneDX or CDX** — An open BOM standard maintained by the OWASP Foundation;
see the [CycloneDX specification](https://cyclonedx.org/specification/overview/).
PurpleRay generates deterministic CycloneDX 1.7 JSON, retains tested 1.6
compatibility, and uses the common `.cdx.json` suffix.

**Declared licence** — A licence explicitly stated in package or project
metadata. PurpleRay preserves the declaration without treating it as a legal
conclusion.

**`declared-not-locally-verified`** — A package or lock file declared a digest,
but PurpleRay did not download and hash the referenced release artifact. The
value remains provenance, not local verification.

**Dependency graph** — The relationships between components. PurpleRay emits
directly evidenced relationships and does not invent missing transitive or
runtime-loaded dependencies.

**Deployable or source URI and SHA-512** — BSI-specific locations and verified
SHA-512 evidence for distributed or source artifacts. A local component
SHA-256 or unverified lock-file declaration does not satisfy this mapping.

**deps.dev** — An external [dependency-data service](https://deps.dev/) for
package metadata and dependency graphs. PurpleRay does not query it; it is
deferred from the manual OSV refresh.

**Derivable** — A BSI readiness status meaning potentially useful evidence
exists elsewhere in the source document, but the preferred mapped field is
empty. Human review may still be required.

**Deterministic** — Having stable ordering and serialization for the same
retained input state. Separate scans can still differ because task IDs and
timestamps intentionally change.

**Direct and transitive dependency** — A direct dependency is explicitly
associated with a component by observed evidence; a transitive dependency is
introduced through another dependency. Post-build inspection may not recover
the complete transitive graph.

**Distribution licence** — The licence terms determined to apply when
distributing a component. PurpleRay's BSI mapper expects a concluded SPDX
expression as evidence, but the two concepts are not interchangeable.

**Ecosystem** — A package namespace with its own naming and versioning rules,
such as npm, Maven, PyPI, Cargo, NuGet, Go, or RubyGems.

**Effective licence** — The optional `bsi:component:effectiveLicence` value
recognized by the BSI mapper. It is distinct from original, declared, and
distribution-licence evidence, and PurpleRay does not infer it.

**ELF (Executable and Linkable Format)** — A native file format commonly used
for Linux executables, shared objects, and object files.

**Eligible Package URL** — A Package URL PurpleRay may send to OSV.dev. It must
be canonical, exact-versioned, from a supported non-generic ecosystem, and
contain neither qualifiers nor a subpath.

**EPSS (Exploit Prediction Scoring System)** — A
[daily probability estimate](https://www.first.org/epss/) that exploitation
activity for a CVE will be observed in the next 30 days. It is a prioritization
input, not severity or proof about one installation. PurpleRay does not
retrieve or export EPSS data; it is deferred from the manual OSV refresh.

**Evidence and evidence occurrence** — Evidence is observed data supporting an
inventory field. A CycloneDX evidence occurrence records where component
evidence was seen, subject to the scan's path-privacy settings.

**Exact version and version constraint** — An exact version identifies one
resolved release. A constraint such as `>=1.2,<2` describes acceptable releases
and must not be presented as an installed version.

**Field mapping** — The CycloneDX field or fields checked for a BSI requirement.
A mapping identifies where evidence was found or expected; it does not make
missing evidence true.

**GHSA (GitHub Security Advisory)** — An advisory identifier used by GitHub.
OSV.dev aggregates GHSA records and may return their IDs.

**GNU build ID** — A build identifier commonly embedded in ELF files by
GNU-compatible linkers. PurpleRay preserves it as binary evidence, not as a
package version.

**Grype** — An external vulnerability scanner that can consume exported
CycloneDX SBOMs. PurpleRay's release workflow tests a pinned, offline-configured
handoff fixture, but the application neither bundles nor invokes Grype.

**Hash, digest, and checksum** — Fixed-length values calculated from bytes.
The terms overlap in common usage, but a cryptographic digest is not a digital
signature and does not identify the producer.

**HTTP status** — The numeric result of an HTTP request. A network or HTTP
failure makes the optional online check incomplete and must not be interpreted
as “no known issues.”

**Immutable inventory** — PurpleRay does not rewrite a managed SBOM after it is
stored and hashed successfully. “Immutable” is an application transaction
rule, not an operating-system file attribute.

**Inventory-only** — The managed SBOM contains observed components and evidence
but no optional OSV.dev findings. Selecting the online lookup leaves the
managed SBOM byte-identical.

**JSON, XML, TOML, and YAML** — Structured text formats used by manifests,
settings, and reports. PurpleRay uses strict JSON and XML parsers and bounded,
conservative parsing for the TOML and YAML evidence it supports.

**Known issue** — PurpleRay's neutral UI term for an advisory association
returned by OSV.dev. A match means a package coordinate matched a record, not
that the scanned application is exploitable in its environment.

**Known-issue snapshot** — The bounded, timestamped OSV.dev check retained
with a task in atomic history. A manual refresh replaces it only after a valid
result and keeps the last valid snapshot after cancellation or failure.

**Lock file** — Resolved dependency evidence that often records exact versions
and may declare archive hashes. A declared hash is not locally verified unless
PurpleRay also reads and hashes the corresponding artifact.

**Mach-O and universal Mach-O** — The native binary format used by macOS. A
universal Mach-O file contains multiple architecture-specific slices.

**Managed SBOM** — The exact CycloneDX file PurpleRay writes and retains for a
completed task. Optional online checks and readiness exports do not rewrite it.

**Manifest** — Project or package metadata that can declare names, versions,
dependency constraints, publishers, or licences, such as `package.json` or a
Maven POM file.

**Mapped** — A BSI readiness status meaning the expected mapped condition was
established. Depending on the requirement, this can mean suitable evidence is
present or an expected vulnerability section is absent.

**Match** — One association between an exact Package URL and an advisory ID.
The match count can exceed the advisory count because one advisory can match
several package coordinates.

**`MUST`, `MUST_IF_EXISTS`, and `MAY`** — Readiness-report requirement levels
meaning mandatory, mandatory when the subject exists, and optional.

**No finding** — No advisory match was retained for the eligible coordinates
queried at that time. This does not prove that the software is vulnerability-
free, unaffected, or safe to deploy.

**Not applicable** — A schema-defined readiness status meaning the requirement
does not apply to the assessed subject. PurpleRay's current generator does not
emit it.

**Not observed** — A readiness status meaning optional evidence was not found.
It records the absence honestly but is not a mandatory-requirement blocker.

**NVD (National Vulnerability Database)** — A US database that enriches CVE
records with severity, weakness, and CPE applicability data. PurpleRay does not
perform a separate NVD lookup or authoritative CPE resolution.

**Original licence** — The BSI term PurpleRay maps from a declared CycloneDX
SPDX expression as upstream licence evidence. It remains distinct from an
effective or distribution licence.

**OSV (Open Source Vulnerabilities)** — A
[vulnerability-data schema and ecosystem](https://google.github.io/osv.dev/)
that expresses affected packages and versions using native package-versioning
rules.

**OSV.dev** — The online service PurpleRay may query after writing the inventory
SBOM. PurpleRay sends eligible exact-version Package URLs and retains bounded
advisory matches; it does not upload the SBOM, scanned files, paths, hashes,
licences, or author data. Manual refresh uses the same batch-match contract;
retrieval of full OSV records is deferred.

**OSV-Scanner** — The separate first-party scanner for OSV data. PurpleRay
documents it as an external handoff option but neither bundles nor invokes it.

**Package coordinate** — A structured package identity. PurpleRay's strongest
coordinate for OSV.dev lookup is a canonical Package URL with an exact version.

**Package URL or PURL** — A standardized `pkg:` package identifier defined by
[ECMA-427](https://ecma-international.org/publications-and-standards/standards/ecma-427/).
For example, `pkg:npm/lodash@4.17.20` identifies an exact npm package release.

**PE (Portable Executable)** — The native executable and library format used by
Windows.

**PE `VERSIONINFO`** — A Windows resource containing fields such as product
name, company, and file version. PurpleRay extracts these declared values
without executing the binary; their presence does not prove authenticity.

**Point-in-time lookup** — A result based on the advisory database at the
recorded check time. PurpleRay does not continuously monitor completed scans,
so saved results can become stale. Refresh runs only when an operator
explicitly requests it.

**Post-build inspection** — Inspection of files after they have been created,
unlike an authoritative build-time SBOM that receives exact data from the
build and package-resolution process.

**Primary or root component** — The selected scan target represented as the
top-level component in CycloneDX metadata. The dependency graph and evidence
relate other components to this root.

**Provenance** — Information about where evidence or an output came from and
how it was produced. Provenance is stronger when bound to verifiable identities
and digests.

**Readiness assessment** — A deterministic field-availability and gap report
derived from the exact managed SBOM. It is not an SBOM, compliance statement,
conformity assessment, or certificate.

**Referenced BOM** — Another BOM linked from a component. PurpleRay records
whether suitable reference evidence exists but does not fetch that document
during readiness export.

**Rejected Package URL** — A coordinate too imprecise or unsupported for the
bounded OSV.dev query. PurpleRay keeps rejection counts in task history, shows
reasons only during the live check, and never retains rejected coordinate
values.

**Removed component** — A component identity and version present on the
baseline side after equal versions have been matched. In a multi-version
identity, an unmatched version remains a removal rather than becoming a
speculative version change.

**`review-required`** — A reserved schema status for a result with no
deterministic blocker that still needs human validation. PurpleRay's current
mapper does not emit it, and it never means compliant.

**Scope** — Evidence about dependency use, such as runtime, development,
optional, or test use. Scope does not state whether a vulnerability is
exploitable.

**`security.txt` and RFC 9116** — A standard way for an organization to publish
security-contact information. The readiness mapper recognizes a suitable URL
when present but does not invent or contact one.

**SHA-1, SHA-256, SHA-384, and SHA-512** — Members of the Secure Hash Algorithm
family. PurpleRay calculates SHA-256 locally when enabled and can preserve
supported declared hashes; specific BSI mappings may require locally verified
SHA-512.

**Shared and static library** — A shared library is loaded and shared at
runtime, such as a DLL or ELF shared object. A static library is object code
intended to be copied into another binary during linking.

**SONAME** — The shared-object name recorded by an ELF library. A numeric SONAME
suffix may denote ABI compatibility and is not treated as a defensible product
version.

**SPDX** — An [open standard](https://spdx.dev/learn/overview/) for communicating
SBOM, licence, copyright, security, and related information. PurpleRay uses
SPDX licence identifiers and expressions but exports CycloneDX rather than an
SPDX SBOM.

**SPDX licence identifier and expression** — A standardized licence name such
as `Apache-2.0`, or an expression such as `MIT OR Apache-2.0`. Valid syntax does
not determine whether the licence applies to a particular distribution.

**SRI (Subresource Integrity)** — A notation used by formats such as npm lock
files to declare one or more base64-encoded cryptographic digests.

**Static inspection** — Reading data without executing or loading the target.
PurpleRay does not run discovered programs, scripts, installers, or package-
manager commands.

**SWID (Software Identification tag)** — A standardized software identity tag.
PurpleRay's BSI mapper recognizes an existing SWID tag identifier but does not
generate SWID tags.

**Symbolic link or symlink** — A filesystem entry that redirects to another
path. Following links is disabled by default because they can create loops or
leave the selected scan root.

**TLS and CA certificate** — Transport Layer Security protects an HTTPS
connection, while a trusted Certificate Authority helps verify the service's
identity. TLS protects data in transit but does not make advisory data complete
or correct.

**Unchanged component** — A component identity with an equal version on both
sides of a comparison. PurpleRay includes unchanged components in the count
but not in the change table.

**UUID and URI** — A Universally Unique Identifier provides structured identity
for items such as tasks or documents. A Uniform Resource Identifier names a
resource but does not prove that it exists or was verified.

**Verified hash** — A digest PurpleRay calculated while reading the
corresponding bounded local input through its verified-input contract.

**Verified rescan cache** — An optional performance cache reused only after a
fresh file SHA-256 and contextual identity checks. It does not trust pathname
metadata alone.

**VEX (Vulnerability Exploitability eXchange)** — A way for an authoritative
party to state whether a product is affected, not affected, fixed, or under
investigation for a vulnerability; see [CISA's SBOM and VEX resources](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary).
An automated package match cannot justify `not affected`. PurpleRay does not
retrieve or export VEX data; VEX remains outside the manual OSV refresh.
