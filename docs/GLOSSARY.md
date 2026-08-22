# PurpleRay SBOM Analyzer glossary

This glossary explains terms that appear in PurpleRay's interface,
CycloneDX output, BSI readiness report, documentation, and vulnerability-
scanner handoff. It describes PurpleRay's current behavior; it is not legal,
licensing, certification, or vulnerability-remediation advice.

Use your viewer's search function for a specific term, or browse by subject:

- [Inventory and scan concepts](#inventory-and-scan-concepts)
- [CycloneDX and identifiers](#cyclonedx-and-identifiers)
- [Licence terminology](#licence-terminology)
- [Known issues and online checking](#known-issues-and-online-checking)
- [Vulnerability-enrichment terms](#vulnerability-enrichment-terms-not-currently-produced)
- [BSI readiness terminology](#bsi-readiness-terminology)
- [Native artifacts and integrity](#native-artifacts-and-integrity)
- [Transport and operational terms](#transport-and-operational-terms)
- [Official references](#official-references)

## Inventory and scan concepts

### Artifact

A local file or archive recognized during a scan, such as a manifest, lock
file, executable, library, or Java archive. An artifact is evidence and is not
necessarily the same thing as a software component.

### Artifact status

PurpleRay classifies recognized artifacts as parsed, partially parsed,
detected but unsupported, or failed. A visible partial or failed status is an
honest limit, not a claim that the artifact contains no useful information.

### BOM and SBOM

A **BOM** is a Bill of Materials. An **SBOM**, or Software Bill of Materials,
is a machine-readable inventory of software components and their relationships.
PurpleRay's SBOM is not, by itself, a vulnerability report, exploitability
decision, or licence-compliance determination.

### Component

A normalized software item inferred from one or more artifacts. One artifact
can identify several components, and evidence for the same component can be
merged deterministically.

### Composition and aggregate

CycloneDX composition data describes how complete an inventory is. PurpleRay
uses an `incomplete` aggregate because bounded post-build inspection cannot
prove that every dependency has been discovered.

### Dependency graph

The set of relationships between components. PurpleRay emits directly
evidenced relationships; it does not invent missing transitive or runtime-
loaded dependencies.

### Direct and transitive dependency

A direct dependency is explicitly associated with a component by observed
evidence. A transitive dependency is brought in by another dependency.
Post-build static inspection may not recover the complete transitive graph.

### Evidence and evidence occurrence

Evidence is observed data supporting an inventory field. A CycloneDX evidence
occurrence identifies where component evidence was observed, subject to the
scan's path-privacy settings.

### Manifest

Project or package metadata that can declare names, versions, dependency
constraints, publishers, or licences. Examples include `package.json` and
Maven POM files.

### Lock file

Resolved dependency evidence that often records exact package versions and
may contain declared archive hashes. A lock-file hash is not locally verified
unless PurpleRay also reads and hashes the corresponding artifact.

### Managed SBOM

The exact CycloneDX file written and retained by PurpleRay for a completed
task. Optional online checks and readiness exports do not rewrite it.

### Primary or root component

The selected scan target represented as the top-level component in CycloneDX
metadata. Other components are related to this root through the dependency
graph and evidence.

### Post-build inspection

Inspection of files after they have already been created. It differs from an
authoritative build-time SBOM, which can receive exact information directly
from the build and package-resolution process.

### Static inspection

Reading data without executing or loading the scanned target. PurpleRay does
not run discovered programs, scripts, installers, or package-manager commands.

## CycloneDX and identifiers

### `bom-ref`

A unique reference used to identify a node inside one CycloneDX document. A
`bom-ref` supports internal relationships but is not automatically a global
package identifier.

### CycloneDX or CDX

An open BOM standard maintained by the OWASP Foundation. PurpleRay generates
deterministic CycloneDX 1.7 JSON and retains tested CycloneDX 1.6 compatibility.
The suffix `.cdx.json` identifies CycloneDX JSON to many downstream tools.

### CPE

**Common Platform Enumeration**, a standardized naming scheme for classes of
software, operating systems, and hardware. PurpleRay may derive a conservative
CPE candidate from suitable native-binary evidence; it does not claim that the
candidate was resolved against the NVD CPE Dictionary.

### Ecosystem

A package namespace and its naming and versioning conventions, such as npm,
Maven, PyPI, Cargo, NuGet, Go, or RubyGems.

### Exact version and version constraint

An exact version identifies one resolved release. A constraint such as
`>=1.2,<2` describes acceptable releases and must not be presented as an
installed version.

### Package coordinate

A structured package identity. For PurpleRay's online OSV.dev lookup, the
strongest coordinate is a canonical Package URL containing an exact version.

### Package URL or PURL

A standardized `pkg:` identifier for a package. For example,
`pkg:npm/lodash@4.17.20` identifies an exact npm package version.

### Eligible Package URL

A Package URL that PurpleRay permits in an OSV.dev request: canonical,
exact-version, from a supported ecosystem, non-generic, and without qualifiers
or a subpath.

### Rejected Package URL

A detected coordinate that is not sufficiently precise or supported for the
bounded OSV.dev query. PurpleRay records rejection counts and reasons but does
not persist rejected coordinate values.

### Scope

Evidence about how a dependency is used, such as runtime, development,
optional, or test use. Scope is not a statement about whether a vulnerability
is exploitable.

### SWID

A **Software Identification tag**. PurpleRay's BSI mapper can recognize an
existing SWID tag identifier, but PurpleRay does not currently generate SWID
tags.

## Licence terminology

### SPDX

**System Package Data Exchange**, an open standard for communicating software
bill-of-materials, licence, copyright, security, and related information.
PurpleRay uses SPDX licence identifiers and expression syntax but currently
exports CycloneDX rather than an SPDX SBOM.

### SPDX licence identifier and expression

A standardized licence name such as `Apache-2.0`, or an expression such as
`MIT OR Apache-2.0`. A syntactically valid expression does not decide whether
that licence actually applies to a particular distribution.

### Declared licence

A licence explicitly stated by package or project metadata. PurpleRay
preserves that declaration but does not silently turn it into a legal
conclusion.

### Concluded or distribution licence

The licence determination that applies to distributing a component after an
appropriate analysis. PurpleRay cannot infer this conclusion merely from a
manifest declaration or nearby licence file.

### Original and effective licence

Terms used by the BSI readiness mapping for upstream licence evidence and an
optional effective-licence property. They are not automatically
interchangeable with a package's declared licence.

### Author, creator, manufacturer, and publisher

Distinct provenance or contact roles. PurpleRay preserves declared publisher
data and optional operator-entered SBOM author data, but it does not relabel
those values as an authoritative BSI creator or manufacturer without evidence.

## Known issues and online checking

### Advisory and advisory ID

A published security record and its identifier. An advisory may use an OSV,
CVE, GHSA, or ecosystem-specific identifier. “Advisory” is broader than “CVE.”

### CVE

**Common Vulnerabilities and Exposures**, a program and identifier system for
publicly disclosed vulnerabilities. A CVE ID identifies a record; CVE is not a
scanner, severity score, or proof that a discovered package is exploitable.

### GHSA

A **GitHub Security Advisory** identifier. GHSA records are one of the data
sources aggregated by OSV.dev and can be returned as advisory IDs.

### Known issue

PurpleRay's neutral UI term for an advisory association returned by OSV.dev.
A match means the package coordinate matched an advisory record; it does not
prove that the scanned application is exploitable in its actual environment.

### Match

One association between an exact Package URL and an advisory ID. Match count
can exceed advisory count because one advisory can match more than one package
coordinate.

### OSV

**Open Source Vulnerabilities**: a vulnerability-data schema and ecosystem
designed to express affected packages and versions using their native package
versioning conventions.

### OSV.dev

The fixed online service PurpleRay can query after writing the inventory SBOM.
PurpleRay sends eligible exact-version Package URLs and retains bounded
advisory matches. It does not upload the SBOM, scanned files, paths, hashes,
licences, or author data.

### OSV-Scanner

The separate first-party scanner for OSV data. PurpleRay documents it as an
external handoff option; it is not bundled or invoked by the application.

### Point-in-time lookup

A result based on the advisory database at the recorded check time. PurpleRay
does not currently monitor completed scans continuously, so saved results can
become stale.

### No finding

No advisory match was retained for the eligible coordinates queried at that
time. This is not proof that the software is vulnerability-free, unaffected,
or safe to deploy.

### NVD

The US National Vulnerability Database, which enriches CVE records with data
such as severity, weakness, and CPE applicability. PurpleRay does not currently
perform a separate NVD lookup or authoritative CPE resolution.

### Grype

An external vulnerability scanner that can consume an exported CycloneDX
SBOM. PurpleRay's release workflow uses a pinned, offline-configured handoff
fixture, but Grype is not bundled or invoked by the application.

## Vulnerability-enrichment terms not currently produced

The following terms are relevant to possible future online enrichment. Their
presence in this glossary does not mean PurpleRay currently retrieves or
exports them.

### CISA KEV

The US Cybersecurity and Infrastructure Security Agency's **Known Exploited
Vulnerabilities** catalog. Inclusion means there is authoritative evidence of
exploitation in the wild and is useful for prioritization; it does not by
itself prove exploitation of a particular installation.

### CVSS

The **Common Vulnerability Scoring System**, which describes technical
severity using a vector and numeric score. Severity is not the same as
likelihood of exploitation or business risk.

### CWE

**Common Weakness Enumeration**, a taxonomy for classes of software and
hardware weakness. A CWE describes the kind of weakness, while a CVE usually
identifies a specific disclosed vulnerability.

### EPSS

The **Exploit Prediction Scoring System**, a daily probability estimate for
the likelihood that exploitation activity for a CVE will be observed during a
future time window. It is a prioritization input, not a severity score or a
claim about one installation.

### VEX

**Vulnerability Exploitability eXchange**, a way for a supplier or other
authoritative party to state whether a product is affected, not affected,
fixed, or under investigation for a vulnerability. An automated package match
alone is not enough to assert `not affected`.

## BSI readiness terminology

### BSI and TR

**BSI** is the *Bundesamt für Sicherheit in der Informationstechnik*, Germany's
Federal Office for Information Security. **TR** means *Technische Richtlinie*,
or Technical Guideline.

### BSI TR-03183-2 v2.1.0

The exact guideline and version to which PurpleRay's current readiness mapper
is pinned. The report does not claim that this remains the currently applicable
version, nor does it claim conformity or certification.

### Readiness assessment

A deterministic field-availability and gap report derived from the exact
managed SBOM. It is not an SBOM, compliance statement, conformity assessment,
or certificate.

### Field mapping

The CycloneDX field or fields examined for one BSI requirement. A mapping says
where evidence was found or expected; it does not make missing evidence true.

### Mapped

Acceptable evidence exists at the expected field mapping.

### Derivable

Potentially usable evidence exists elsewhere in the source document, but the
preferred mapped field is not directly populated. Human review may still be
necessary.

### Not observed

Optional evidence was not found. This is recorded honestly but is not itself a
mandatory-requirement blocker.

### Not applicable

The requirement is determined not to apply to the assessed subject. The report
schema supports this status even when current PurpleRay output seldom uses it.

### Blocked and blocker

`blocked` means PurpleRay cannot establish a required claim from the managed
SBOM. A blocker is a stable, machine-readable gap; it is not necessarily a
scan failure.

### `review-required`

No deterministic blocker was found, but human validation remains necessary.
This status never means compliant.

### `MUST`, `MUST_IF_EXISTS`, and `MAY`

Requirement levels represented in the readiness report: mandatory, mandatory
when the subject exists, and optional.

### Compliance, conformity, and certification

Compliance means satisfying applicable requirements. Conformity is an
evidenced assertion of alignment, and certification is a formal determination
by an authorized or qualified party. PurpleRay's readiness report claims none
of these.

### Build equivalence

Evidence that source and build information corresponds to the deployed
artifact. A post-build filesystem scan cannot prove this by itself.

### Deployable or source URI and SHA-512

BSI-specific locations and verified SHA-512 evidence for distributed or source
artifacts. A local component SHA-256 or an unverified lock-file declaration is
not a substitute for the required mapping.

### `security.txt` and RFC 9116

A standardized way for an organization to publish security-contact
information. The readiness mapper recognizes a suitable URL when present; it
does not invent or contact one.

### Referenced BOM

Another BOM linked from a component. PurpleRay records whether suitable
reference evidence exists but does not fetch the referenced document during
the readiness export.

## Native artifacts and integrity

### ABI

**Application Binary Interface**, the low-level calling and binary-compatibility
contract between compiled components. An ABI suffix is not necessarily a
software product version.

### ELF

**Executable and Linkable Format**, commonly used for Linux executables,
shared objects, and object files.

### Mach-O and universal Mach-O

The native binary format used by macOS. A universal Mach-O file contains
multiple architecture-specific slices.

### PE

**Portable Executable**, the native executable and library format used by
Windows.

### SONAME

The shared-object name recorded by an ELF library. A numeric SONAME suffix can
represent ABI compatibility and is not treated as a defensible product
version.

### Build ID

An identifier embedded by a compiler or linker. It helps distinguish binary
builds but is not automatically a package name or version.

### GNU build ID

A build identifier commonly embedded in ELF files by GNU-compatible linkers.
PurpleRay preserves it as binary evidence, not as a package version.

### PE `VERSIONINFO`

A Windows resource containing fields such as product name, company, and file
version. PurpleRay can extract these declared values without executing the
binary; their presence does not independently prove authenticity.

### Shared and static library

A shared library is loaded and shared at runtime, such as a Windows DLL or an
ELF shared object. A static library is an archive of object code intended to be
copied into another binary during linking.

### Hash, digest, and checksum

A fixed-length value calculated from bytes. These words overlap in ordinary
usage, but a cryptographic digest is not a digital signature and does not
identify who produced the data.

### SHA-1, SHA-256, SHA-384, and SHA-512

Members of the Secure Hash Algorithm family. PurpleRay locally calculates
SHA-256 when enabled and can preserve supported declared package hashes.
Specific BSI mappings may require locally verified SHA-512 instead.

### Verified hash

PurpleRay calculated the digest while reading the corresponding bounded local
input through its verified-input contract.

### `declared-not-locally-verified`

A package or lock file declared a digest, but PurpleRay did not download and
rehash the referenced release artifact. The declaration remains useful
provenance but is not represented as local verification.

### SRI

**Subresource Integrity**, a notation used by formats such as npm lock files
to declare one or more base64-encoded cryptographic digests.

### Provenance

Information about where evidence or an output came from and how it was
produced. Provenance is stronger when it is bound to verifiable identities and
digests.

### Attestation

A signed statement about an artifact or build. PurpleRay release provenance
attestations describe release assets; they are separate from a scanned
component's code signature or hash.

### Code signature

A platform-specific signature associated with an executable or package. It can
help identify a signer and detect modification, but it does not prove that the
software is vulnerability-free.

### Verified rescan cache

An optional performance cache reused only after a fresh file SHA-256 and
contextual identity checks. It does not trust pathname metadata alone.

## Transport and operational terms

### API

An **Application Programming Interface**, a defined way for software systems
to exchange requests and results. PurpleRay's optional online check uses the
OSV.dev HTTPS API.

### CLI and GUI

The **Command-Line Interface** accepts text arguments and runs without opening
the desktop interface. The **Graphical User Interface** is the interactive
desktop application. PurpleRay's CLI is structurally offline; only the GUI can
request the optional OSV.dev lookup.

### Atomic write

Writing a complete temporary file and then replacing the destination in one
controlled activation step. It prevents consumers from observing a partially
written managed file.

### Byte-identical

Exactly the same sequence of bytes and therefore the same SHA-256 digest. This
is stronger than two JSON documents merely having equivalent values.

### Deterministic

Stable ordering and serialization for the same retained input state. Two
separately started scans can still differ because task IDs and timestamps are
intentionally different.

### Immutable inventory

PurpleRay does not rewrite the managed SBOM after it has been successfully
stored and hashed. “Immutable” here is an application transaction rule, not an
operating-system immutable-file attribute.

### Inventory-only

The managed SBOM contains observed component and evidence data but no optional
OSV.dev findings. Selecting the online lookup leaves the managed SBOM
byte-identical.

### Absolute and relative path

An absolute path includes its filesystem root and can expose private machine
details. PurpleRay uses relative paths in shareable output unless the user
explicitly enables absolute paths for that scan.

### TLS and CA certificate

**Transport Layer Security** protects an HTTPS connection. A trusted
**Certificate Authority** helps verify the service identity. TLS protects data
in transit but does not make advisory data complete or correct.

### HTTP status

The numeric result of an HTTP request. A network or HTTP failure means the
optional online check is incomplete; it must never be interpreted as “no
known issues.”

### JSON, XML, TOML, and YAML

Structured text formats used by manifests, settings, or reports. PurpleRay
uses strict parsers for JSON and XML and conservative bounded parsing for the
TOML and YAML evidence it supports.

### Symbolic link or symlink

A filesystem entry that redirects to another path. Following symbolic links
is disabled by default because links can create loops or leave the selected
scan root.

### UUID and URI

A **Universally Unique Identifier** is a structured identifier used for items
such as task or document identities. A **Uniform Resource Identifier** names a
resource; a URI does not guarantee that the resource exists or was verified.

## Official references

- [CycloneDX specification overview](https://cyclonedx.org/specification/overview/)
- [SPDX overview](https://spdx.dev/learn/overview/)
- [Package URL standard, ECMA-427](https://ecma-international.org/publications-and-standards/standards/ecma-427/)
- [OSV and OSV.dev](https://google.github.io/osv.dev/)
- [CVE Program](https://www.cve.org/)
- [NVD Common Platform Enumeration](https://nvd.nist.gov/products/cpe)
- [BSI TR-03183](https://www.bsi.bund.de/dok/TR-03183-en)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
- [FIRST CVSS](https://www.first.org/cvss/)
- [CISA SBOM and VEX resources](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom/sbomresourceslibrary)
