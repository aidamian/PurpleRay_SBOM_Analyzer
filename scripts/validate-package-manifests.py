#!/usr/bin/env python3
"""Validate PurpleRay SBOM Analyzer package-manager manifests.

Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
the Apache License, Version 2.0; see ../LICENSE.

Description
-----------
Validates one generated Scoop JSON manifest and the three generated WinGet
YAML manifests against checksum-pinned official schemas downloaded from
immutable upstream commits. Downloaded schemas exist only inside a temporary
directory. Candidate archives are inspected in memory and are never extracted.

Citation request
----------------
Please retain this notice and cite the project as follows:

@misc{damian2026purpleraysbomanalyzer,
  author = {Andrei Ionut Damian},
  title  = {{PurpleRay SBOM Analyzer}},
  year   = {2026},
  url    = {https://github.com/aidamian/PurpleRay_SBOM_Analyzer}
}
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import json
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple


MAX_SCHEMA_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_WINGET_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_WINGET_UNCOMPRESSED_BYTES = 1024 * 1024
EXPECTED_WINGET_TYPES = frozenset(("version", "installer", "defaultLocale"))


@dataclass(frozen=True)
class SchemaSource:
    """Describe one checksum-pinned schema from an official repository.

    Parameters
    ----------
    name
        Stable local key used to select the schema.
    url
        Raw GitHub URL pinned to an immutable commit.
    sha256
        Trusted lowercase SHA-256 digest of the schema bytes.

    Returns
    -------
    SchemaSource
        Immutable schema-source descriptor.

    Raises
    ------
    None
    """

    name: str
    url: str
    sha256: str


SCOOP_COMMIT = "b588a06e41d920d2123ec70aee682bae14935939"
WINGET_COMMIT = "ca787659cd021fa3d44165a695c6beec27f73b29"
SCHEMA_SOURCES: Tuple[SchemaSource, ...] = (
    SchemaSource(
        "scoop",
        (
            "https://raw.githubusercontent.com/ScoopInstaller/Scoop/"
            f"{SCOOP_COMMIT}/schema.json"
        ),
        "6c15a47b09dba92bcdee8b0dadbe2776339c699e3bf4db0eff0ef0a000f2496c",
    ),
    SchemaSource(
        "winget-version",
        (
            "https://raw.githubusercontent.com/microsoft/winget-cli/"
            f"{WINGET_COMMIT}/schemas/JSON/manifests/v1.10.0/"
            "manifest.version.1.10.0.json"
        ),
        "330a3ece4ed602afb0c4f35290d14dec1e188e7b3c2fb330893ac3daac82b547",
    ),
    SchemaSource(
        "winget-installer",
        (
            "https://raw.githubusercontent.com/microsoft/winget-cli/"
            f"{WINGET_COMMIT}/schemas/JSON/manifests/v1.10.0/"
            "manifest.installer.1.10.0.json"
        ),
        "cca7bea1fbdaa18a3d5231de7f9f896b1dd41283c33a03a0565771861d393b31",
    ),
    SchemaSource(
        "winget-defaultLocale",
        (
            "https://raw.githubusercontent.com/microsoft/winget-cli/"
            f"{WINGET_COMMIT}/schemas/JSON/manifests/v1.10.0/"
            "manifest.defaultLocale.1.10.0.json"
        ),
        "77e406d25b35f908f70fb893335155e9e8a83aa59a6f3e9f959692e995e51e3c",
    ),
)


class PackageManifestError(RuntimeError):
    """Represent an input, integrity, dependency, or validation failure."""


def require_dependencies() -> Tuple[Any, Any]:
    """Load the YAML and JSON Schema implementations without installing them.

    Parameters
    ----------
    None

    Returns
    -------
    tuple of module
        Imported ``yaml`` and ``jsonschema`` modules, in that order.

    Raises
    ------
    PackageManifestError
        Raised when PyYAML or jsonschema is unavailable. The utility never
        installs packages or changes the active Python environment.
    """

    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PackageManifestError(
            "Python package 'PyYAML' is required. Install it in a local virtual "
            "environment, then use that environment's Python interpreter."
        ) from exc
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PackageManifestError(
            "Python package 'jsonschema' is required. Install it in a local "
            "virtual environment, then use that environment's Python interpreter."
        ) from exc
    return yaml, jsonschema


def dependency_version(distribution_name: str) -> str:
    """Return an installed dependency version for a success diagnostic.

    Parameters
    ----------
    distribution_name
        Python distribution name understood by ``importlib.metadata``.

    Returns
    -------
    str
        Installed version, or ``unknown`` when metadata is unavailable.

    Raises
    ------
    None
    """

    try:
        return importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def sha256_bytes(content: bytes) -> str:
    """Calculate the lowercase SHA-256 digest of bytes.

    Parameters
    ----------
    content
        Bytes whose integrity is checked.

    Returns
    -------
    str
        A 64-character lowercase hexadecimal digest.

    Raises
    ------
    None
    """

    return hashlib.sha256(content).hexdigest()


def download_verified_schema(source: SchemaSource, timeout: float) -> bytes:
    """Download one immutable official schema and verify its digest.

    Parameters
    ----------
    source
        Commit-pinned URL and trusted digest.
    timeout
        Per-request timeout in seconds.

    Returns
    -------
    bytes
        Verified schema bytes.

    Raises
    ------
    PackageManifestError
        Raised for a network failure, oversized response, or digest mismatch.
    """

    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": "PurpleRay-SBOM-Analyzer-package-schema-validator"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read(MAX_SCHEMA_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise PackageManifestError(
            f"Could not download pinned {source.name} schema {source.url}: {exc}"
        ) from exc
    if len(content) > MAX_SCHEMA_BYTES:
        raise PackageManifestError(
            f"Pinned {source.name} schema exceeds the "
            f"{MAX_SCHEMA_BYTES}-byte safety limit"
        )
    actual_digest = sha256_bytes(content)
    if actual_digest != source.sha256:
        raise PackageManifestError(
            f"SHA-256 mismatch for {source.url}: expected {source.sha256}, "
            f"received {actual_digest}"
        )
    return content


def reject_duplicate_json_pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    """Construct a JSON object while rejecting duplicate member names.

    Parameters
    ----------
    pairs
        Ordered name/value pairs supplied by ``json.loads``.

    Returns
    -------
    dict
        Object containing each unique member.

    Raises
    ------
    PackageManifestError
        Raised when a member name occurs more than once.
    """

    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackageManifestError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def load_json_bytes(content: bytes, source: str) -> Any:
    """Decode strict UTF-8 JSON and reject duplicate object members.

    Parameters
    ----------
    content
        Candidate UTF-8 JSON bytes.
    source
        Human-readable source included in diagnostics.

    Returns
    -------
    object
        Decoded JSON value.

    Raises
    ------
    PackageManifestError
        Raised when the bytes are not valid, duplicate-free UTF-8 JSON.
    """

    try:
        return json.loads(
            content.decode("utf-8"), object_pairs_hook=reject_duplicate_json_pairs
        )
    except PackageManifestError as exc:
        raise PackageManifestError(f"Invalid JSON in {source}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageManifestError(f"Invalid JSON in {source}: {exc}") from exc


def load_yaml_bytes(yaml: Any, content: bytes, source: str) -> Any:
    """Decode one strict UTF-8 YAML document with unique mapping keys.

    Parameters
    ----------
    yaml
        Imported PyYAML module.
    content
        Candidate UTF-8 YAML bytes.
    source
        Human-readable source included in diagnostics.

    Returns
    -------
    object
        Decoded YAML value.

    Raises
    ------
    PackageManifestError
        Raised for invalid UTF-8, malformed YAML, unhashable mapping keys, or
        duplicate mapping keys.
    """

    class UniqueKeyLoader(yaml.SafeLoader):
        """Use SafeLoader semantics while rejecting duplicate mapping keys."""

    def construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> Any:
        """Construct one YAML mapping and fail on repeated keys."""

        loader.flatten_mapping(node)
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise PackageManifestError(
                    f"Invalid YAML in {source}: unhashable mapping key {key!r}"
                ) from exc
            if duplicate:
                raise PackageManifestError(
                    f"Invalid YAML in {source}: duplicate mapping key {key!r}"
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping
    )
    try:
        text = content.decode("utf-8")
        return yaml.load(text, Loader=UniqueKeyLoader)
    except PackageManifestError:
        raise
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PackageManifestError(f"Invalid YAML in {source}: {exc}") from exc


def read_bounded_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    """Read a regular file after applying an explicit size limit.

    Parameters
    ----------
    path
        Candidate input file.
    maximum_bytes
        Largest accepted byte count.
    label
        Input kind included in diagnostics.

    Returns
    -------
    bytes
        Complete file contents.

    Raises
    ------
    PackageManifestError
        Raised when the path is absent, not a regular file, too large, or
        cannot be inspected or read.
    """

    try:
        if not path.is_file():
            raise PackageManifestError(f"{label} is not a regular file: {path}")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise PackageManifestError(
                f"{label} exceeds the {maximum_bytes}-byte safety limit: {path}"
            )
        return path.read_bytes()
    except PackageManifestError:
        raise
    except OSError as exc:
        raise PackageManifestError(f"Could not read {label} {path}: {exc}") from exc


def load_scoop_manifest(path: Path) -> Mapping[str, Any]:
    """Load one bounded Scoop JSON manifest.

    Parameters
    ----------
    path
        Generated Scoop manifest path.

    Returns
    -------
    mapping
        Decoded Scoop manifest object.

    Raises
    ------
    PackageManifestError
        Raised when the file is invalid, oversized, or its root is not an
        object.
    """

    document = load_json_bytes(
        read_bounded_file(path, MAX_MANIFEST_BYTES, "Scoop manifest"), str(path)
    )
    if not isinstance(document, dict):
        raise PackageManifestError(f"{path}: Scoop manifest root must be an object")
    return document


def safe_winget_entry_names(archive: zipfile.ZipFile, source: Path) -> Sequence[str]:
    """Validate a WinGet ZIP layout and return its three manifest names.

    Parameters
    ----------
    archive
        Open candidate WinGet ZIP archive.
    source
        Archive path included in diagnostics.

    Returns
    -------
    sequence of str
        The three top-level YAML entry names in archive order.

    Raises
    ------
    PackageManifestError
        Raised for directories, unsafe names, encryption, duplicates, wrong
        file count, non-YAML files, or excessive uncompressed content.
    """

    infos = archive.infolist()
    if len(infos) != 3:
        raise PackageManifestError(
            f"{source}: WinGet archive must contain exactly three files"
        )
    names = []
    total_size = 0
    for info in infos:
        name = info.filename
        posix_name = PurePosixPath(name)
        if (
            info.is_dir()
            or not name
            or "\\" in name
            or posix_name.name != name
            or name in (".", "..")
            or not name.endswith(".yaml")
        ):
            raise PackageManifestError(
                f"{source}: unsafe or non-YAML WinGet archive entry {name!r}"
            )
        if info.flag_bits & 0x1:
            raise PackageManifestError(
                f"{source}: encrypted WinGet entry is not allowed: {name}"
            )
        if info.file_size > MAX_MANIFEST_BYTES:
            raise PackageManifestError(
                f"{source}: WinGet entry exceeds the "
                f"{MAX_MANIFEST_BYTES}-byte safety limit: {name}"
            )
        total_size += info.file_size
        names.append(name)
    if len(set(names)) != len(names):
        raise PackageManifestError(f"{source}: duplicate WinGet archive entry name")
    if total_size > MAX_WINGET_UNCOMPRESSED_BYTES:
        raise PackageManifestError(
            f"{source}: WinGet archive expands beyond the "
            f"{MAX_WINGET_UNCOMPRESSED_BYTES}-byte safety limit"
        )
    return names


def load_winget_manifests(
    yaml: Any, path: Path
) -> Mapping[str, Tuple[str, Mapping[str, Any]]]:
    """Load and classify a bounded three-file WinGet manifest archive.

    Parameters
    ----------
    yaml
        Imported PyYAML module.
    path
        Generated WinGet manifest ZIP path.

    Returns
    -------
    mapping
        Manifest type mapped to ``(entry name, decoded object)``.

    Raises
    ------
    PackageManifestError
        Raised for unsafe/corrupt ZIP data, malformed YAML, a non-object root,
        duplicate manifest types, or an incomplete multi-file set.
    """

    read_bounded_file(path, MAX_WINGET_ARCHIVE_BYTES, "WinGet manifest archive")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = safe_winget_entry_names(archive, path)
            documents: Dict[str, Tuple[str, Mapping[str, Any]]] = {}
            for name in names:
                document = load_yaml_bytes(yaml, archive.read(name), f"{path}!{name}")
                if not isinstance(document, dict):
                    raise PackageManifestError(
                        f"{path}!{name}: WinGet manifest root must be an object"
                    )
                manifest_type = document.get("ManifestType")
                if not isinstance(manifest_type, str):
                    raise PackageManifestError(
                        f"{path}!{name}: ManifestType must be a string"
                    )
                if manifest_type in documents:
                    raise PackageManifestError(
                        f"{path}: duplicate WinGet ManifestType {manifest_type!r}"
                    )
                documents[manifest_type] = (name, document)
    except PackageManifestError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise PackageManifestError(f"Invalid WinGet ZIP archive {path}: {exc}") from exc
    if set(documents) != EXPECTED_WINGET_TYPES:
        found = ", ".join(sorted(documents)) or "none"
        raise PackageManifestError(
            f"{path}: expected version, installer, and defaultLocale manifests; "
            f"found {found}"
        )
    return documents


def external_references(document: Any) -> Iterable[str]:
    """Yield external ``$ref`` values from a decoded JSON schema.

    Parameters
    ----------
    document
        Decoded JSON schema value traversed recursively.

    Returns
    -------
    iterable of str
        Non-fragment references that could require external resolution.

    Raises
    ------
    None
    """

    if isinstance(document, dict):
        for key, value in document.items():
            if key == "$ref" and isinstance(value, str) and not value.startswith("#"):
                yield value
            else:
                yield from external_references(value)
    elif isinstance(document, list):
        for value in document:
            yield from external_references(value)


def download_schema_bundle(target_directory: Path, timeout: float) -> Mapping[str, Any]:
    """Download, verify, store temporarily, and decode all official schemas.

    Parameters
    ----------
    target_directory
        Temporary directory receiving the verified schema bytes.
    timeout
        Per-schema network timeout in seconds.

    Returns
    -------
    mapping
        Schema key mapped to decoded JSON schema.

    Raises
    ------
    PackageManifestError
        Raised for download/integrity failure, malformed official JSON, or an
        external schema reference outside the checksum-pinned bundle.
    OSError
        May propagate when temporary schema files cannot be written.
    """

    target_directory.mkdir(parents=True, exist_ok=True)
    schemas: Dict[str, Any] = {}
    for source in SCHEMA_SOURCES:
        content = download_verified_schema(source, timeout)
        (target_directory / f"{source.name}.schema.json").write_bytes(content)
        schema = load_json_bytes(content, source.url)
        references = sorted(set(external_references(schema)))
        if references:
            raise PackageManifestError(
                f"Pinned {source.name} schema contains unpinned external "
                f"references: {', '.join(references)}"
            )
        schemas[source.name] = schema
    return schemas


def create_validators(jsonschema: Any, schemas: Mapping[str, Any]) -> Mapping[str, Any]:
    """Create format-aware validators for every verified official schema.

    Parameters
    ----------
    jsonschema
        Imported jsonschema module.
    schemas
        Decoded, checksum-verified official schemas.

    Returns
    -------
    mapping
        Schema key mapped to a configured validator instance.

    Raises
    ------
    PackageManifestError
        Raised when a required schema is absent.
    jsonschema.exceptions.SchemaError
        Raised when an official schema is internally invalid.
    """

    validators = {}
    for source in SCHEMA_SOURCES:
        if source.name not in schemas:
            raise PackageManifestError(f"Verified schema is missing: {source.name}")
        schema = schemas[source.name]
        validator_class = jsonschema.validators.validator_for(schema)
        validator_class.check_schema(schema)
        validators[source.name] = validator_class(
            schema, format_checker=jsonschema.FormatChecker()
        )
    return validators


def validation_messages(validator: Any, document: Any) -> Sequence[str]:
    """Collect deterministic path-qualified JSON Schema diagnostics.

    Parameters
    ----------
    validator
        Configured jsonschema validator.
    document
        Candidate manifest object.

    Returns
    -------
    sequence of str
        Sorted diagnostics, or an empty sequence when the document is valid.

    Raises
    ------
    jsonschema.exceptions.ValidationError
        Individual errors are consumed, but unexpected resolver failures may
        propagate from the validator implementation.
    """

    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            tuple(
                (0, str(part)) if isinstance(part, int) else (1, str(part))
                for part in error.absolute_path
            ),
            error.message,
        ),
    )
    messages = []
    for error in errors:
        path = "$"
        for part in error.absolute_path:
            path += f"[{part}]" if isinstance(part, int) else f".{part}"
        messages.append(f"{path}: {error.message}")
    return messages


def require_schema_valid(
    validator: Any, document: Any, source: str, schema_name: str
) -> None:
    """Raise a combined diagnostic when a document violates its schema.

    Parameters
    ----------
    validator
        Configured official-schema validator.
    document
        Candidate manifest object.
    source
        Human-readable manifest path or archive entry.
    schema_name
        Official schema label included in diagnostics.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised when one or more JSON Schema constraints fail.
    """

    messages = validation_messages(validator, document)
    if messages:
        raise PackageManifestError(
            f"{source} is not valid against official {schema_name} schema: "
            + "; ".join(messages)
        )


def validate_winget_relationships(
    documents: Mapping[str, Tuple[str, Mapping[str, Any]]], source: Path
) -> None:
    """Validate cross-file identity, locale, version, and filename invariants.

    Parameters
    ----------
    documents
        Type-indexed, already schema-valid WinGet manifest set.
    source
        ZIP path included in diagnostics.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised when the three manifests disagree or use nonconforming names.
    """

    version_name, version_document = documents["version"]
    identifier = version_document["PackageIdentifier"]
    package_version = version_document["PackageVersion"]
    default_locale = version_document["DefaultLocale"]
    for manifest_type, (_, document) in documents.items():
        if document["ManifestVersion"] != "1.10.0":
            raise PackageManifestError(
                f"{source}: {manifest_type} ManifestVersion must be exactly 1.10.0"
            )
        if document["PackageIdentifier"] != identifier:
            raise PackageManifestError(
                f"{source}: {manifest_type} PackageIdentifier does not match version manifest"
            )
        if document["PackageVersion"] != package_version:
            raise PackageManifestError(
                f"{source}: {manifest_type} PackageVersion does not match version manifest"
            )
    locale_name, locale_document = documents["defaultLocale"]
    if locale_document["PackageLocale"] != default_locale:
        raise PackageManifestError(
            f"{source}: defaultLocale PackageLocale does not match DefaultLocale"
        )
    expected_names = {
        "version": f"{identifier}.yaml",
        "installer": f"{identifier}.installer.yaml",
        "defaultLocale": f"{identifier}.locale.{default_locale}.yaml",
    }
    actual_names = {
        "version": version_name,
        "installer": documents["installer"][0],
        "defaultLocale": locale_name,
    }
    for manifest_type, expected_name in expected_names.items():
        if actual_names[manifest_type] != expected_name:
            raise PackageManifestError(
                f"{source}: {manifest_type} manifest must be named {expected_name!r}"
            )


def validate_loaded_manifests(
    validators: Mapping[str, Any],
    scoop_document: Mapping[str, Any],
    winget_documents: Mapping[str, Tuple[str, Mapping[str, Any]]],
    scoop_source: Path,
    winget_source: Path,
) -> None:
    """Apply official schemas and WinGet multi-file consistency checks.

    Parameters
    ----------
    validators
        Configured official Scoop and WinGet validators.
    scoop_document
        Decoded Scoop manifest.
    winget_documents
        Type-indexed decoded WinGet manifest set.
    scoop_source
        Scoop path included in diagnostics.
    winget_source
        WinGet ZIP path included in diagnostics.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised for any schema or cross-document validation failure.
    """

    require_schema_valid(
        validators["scoop"], scoop_document, str(scoop_source), "Scoop"
    )
    for manifest_type in ("version", "installer", "defaultLocale"):
        name, document = winget_documents[manifest_type]
        require_schema_valid(
            validators[f"winget-{manifest_type}"],
            document,
            f"{winget_source}!{name}",
            f"WinGet 1.10 {manifest_type}",
        )
    validate_winget_relationships(winget_documents, winget_source)


def validate_manifest_files(
    yaml: Any,
    validators: Mapping[str, Any],
    scoop_path: Path,
    winget_path: Path,
) -> None:
    """Load and validate one complete generated package-manifest pair.

    Parameters
    ----------
    yaml
        Imported PyYAML module.
    validators
        Configured official-schema validators.
    scoop_path
        Generated Scoop JSON manifest.
    winget_path
        Generated WinGet three-manifest ZIP archive.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised for unsafe, malformed, schema-invalid, or inconsistent inputs.
    """

    scoop_document = load_scoop_manifest(scoop_path)
    winget_documents = load_winget_manifests(yaml, winget_path)
    validate_loaded_manifests(
        validators,
        scoop_document,
        winget_documents,
        scoop_path,
        winget_path,
    )


def self_test_documents() -> Tuple[Mapping[str, Any], Mapping[str, Mapping[str, Any]]]:
    """Build a valid current-format Scoop and WinGet fixture set.

    Parameters
    ----------
    None

    Returns
    -------
    tuple
        Scoop object followed by WinGet objects keyed by manifest type.

    Raises
    ------
    None
    """

    identifier = "AndreiIonutDamian.PurpleRaySBOMAnalyzer"
    version = "0.6.0"
    archive_url = (
        "https://github.com/aidamian/PurpleRay_SBOM_Analyzer/releases/download/"
        "v0.6.0/purpleray-sbom-analyzer-v0.6.0-windows-x64.zip"
    )
    digest = "A" * 64
    scoop = {
        "version": version,
        "description": "Generate and inspect CycloneDX software bills of materials.",
        "homepage": "https://github.com/aidamian/PurpleRay_SBOM_Analyzer",
        "license": "Apache-2.0",
        "architecture": {"64bit": {"url": archive_url, "hash": digest.lower()}},
        "bin": "purpleray-sbom-analyzer.exe",
    }
    winget = {
        "version": {
            "PackageIdentifier": identifier,
            "PackageVersion": version,
            "DefaultLocale": "en-US",
            "ManifestType": "version",
            "ManifestVersion": "1.10.0",
        },
        "installer": {
            "PackageIdentifier": identifier,
            "PackageVersion": version,
            "InstallerType": "zip",
            "NestedInstallerType": "portable",
            "Installers": [
                {
                    "Architecture": "x64",
                    "InstallerUrl": archive_url,
                    "InstallerSha256": digest,
                    "NestedInstallerFiles": [
                        {
                            "RelativeFilePath": "purpleray-sbom-analyzer.exe",
                            "PortableCommandAlias": "purpleray-sbom-analyzer",
                        }
                    ],
                }
            ],
            "ManifestType": "installer",
            "ManifestVersion": "1.10.0",
        },
        "defaultLocale": {
            "PackageIdentifier": identifier,
            "PackageVersion": version,
            "PackageLocale": "en-US",
            "Publisher": "Andrei Ionut Damian",
            "PackageName": "PurpleRay SBOM Analyzer",
            "License": "Apache-2.0",
            "ShortDescription": "Generate and inspect CycloneDX SBOMs.",
            "ManifestType": "defaultLocale",
            "ManifestVersion": "1.10.0",
        },
    }
    return scoop, winget


def write_self_test_winget_zip(
    yaml: Any, path: Path, documents: Mapping[str, Mapping[str, Any]]
) -> None:
    """Write a deterministic WinGet ZIP used only by the built-in self-test.

    Parameters
    ----------
    yaml
        Imported PyYAML module.
    path
        Temporary archive path.
    documents
        WinGet documents keyed by manifest type.

    Returns
    -------
    None

    Raises
    ------
    OSError
        May propagate when the temporary archive cannot be written.
    """

    identifier = str(documents["version"]["PackageIdentifier"])
    locale = str(documents["version"]["DefaultLocale"])
    names = {
        "version": f"{identifier}.yaml",
        "installer": f"{identifier}.installer.yaml",
        "defaultLocale": f"{identifier}.locale.{locale}.yaml",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for manifest_type in ("version", "installer", "defaultLocale"):
            archive.writestr(
                names[manifest_type],
                yaml.safe_dump(
                    documents[manifest_type], sort_keys=False, allow_unicode=True
                ).encode("utf-8"),
            )


def require_expected_failure(label: str, operation: Any) -> None:
    """Assert that a negative self-test raises PackageManifestError.

    Parameters
    ----------
    label
        Negative-test label used in a failure diagnostic.
    operation
        Zero-argument callable expected to fail.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised when the operation unexpectedly succeeds.
    """

    try:
        operation()
    except PackageManifestError:
        return
    raise PackageManifestError(f"self-test unexpectedly accepted {label}")


def run_self_test(yaml: Any, validators: Mapping[str, Any]) -> None:
    """Exercise positive, malformed, duplicate-key, and schema-invalid cases.

    Parameters
    ----------
    yaml
        Imported PyYAML module.
    validators
        Configured official-schema validators.

    Returns
    -------
    None

    Raises
    ------
    PackageManifestError
        Raised when a positive fixture fails or any negative fixture succeeds.
    OSError
        May propagate when temporary fixtures cannot be written.
    """

    scoop, winget = self_test_documents()
    with tempfile.TemporaryDirectory(prefix="purpleray-package-manifest-self-test-") as name:
        root = Path(name)
        scoop_path = root / "purpleray-sbom-analyzer.json"
        winget_path = root / "purpleray-sbom-analyzer-winget-manifests.zip"
        scoop_path.write_text(json.dumps(scoop), encoding="utf-8", newline="\n")
        write_self_test_winget_zip(yaml, winget_path, winget)
        validate_manifest_files(yaml, validators, scoop_path, winget_path)

        require_expected_failure(
            "malformed YAML",
            lambda: load_yaml_bytes(yaml, b"Installers: [\n", "malformed.yaml"),
        )
        require_expected_failure(
            "duplicate YAML keys",
            lambda: load_yaml_bytes(
                yaml,
                b"ManifestType: version\nManifestType: installer\n",
                "duplicate.yaml",
            ),
        )
        invalid_scoop = copy.deepcopy(scoop)
        invalid_scoop.pop("homepage")
        require_expected_failure(
            "schema-invalid Scoop manifest",
            lambda: require_schema_valid(
                validators["scoop"], invalid_scoop, "self-test.json", "Scoop"
            ),
        )
        invalid_version = copy.deepcopy(winget["version"])
        invalid_version.pop("PackageIdentifier")
        require_expected_failure(
            "schema-invalid WinGet manifest",
            lambda: require_schema_valid(
                validators["winget-version"],
                invalid_version,
                "self-test.yaml",
                "WinGet 1.10 version",
            ),
        )


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse package-manifest paths, self-test mode, and network timeout.

    Parameters
    ----------
    arguments
        Command-line tokens excluding the executable name.

    Returns
    -------
    argparse.Namespace
        Parsed Scoop path, WinGet path, self-test flag, and timeout.

    Raises
    ------
    SystemExit
        Raised by argparse for invalid command syntax.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Validate generated Scoop JSON and WinGet YAML using "
            "checksum-pinned official schemas."
        )
    )
    parser.add_argument(
        "--scoop-manifest",
        "--scoop-json",
        dest="scoop_manifest",
        type=Path,
        help="generated Scoop .json manifest",
    )
    parser.add_argument(
        "--winget-archive",
        "--winget-zip",
        dest="winget_archive",
        type=Path,
        help="generated three-manifest WinGet .zip archive",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="also run valid, malformed, duplicate-key, and schema-invalid fixtures",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="per-schema download timeout (default: 30)",
    )
    namespace = parser.parse_args(arguments)
    supplied_paths = namespace.scoop_manifest is not None or namespace.winget_archive is not None
    if supplied_paths and (
        namespace.scoop_manifest is None or namespace.winget_archive is None
    ):
        parser.error("--scoop-manifest and --winget-archive must be provided together")
    if not supplied_paths and not namespace.self_test:
        parser.error("provide both manifest paths or use --self-test")
    if namespace.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    return namespace


def main(arguments: Sequence[str] | None = None) -> int:
    """Download trusted schemas and validate requested package manifests.

    Parameters
    ----------
    arguments
        Optional command-line tokens; ``sys.argv[1:]`` is used when omitted.

    Returns
    -------
    int
        Zero when all checks pass; one for dependency, integrity, input, or
        validation failures.

    Raises
    ------
    SystemExit
        May be raised by argparse for invalid command syntax.
    """

    namespace = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        yaml, jsonschema = require_dependencies()
        with tempfile.TemporaryDirectory(prefix="purpleray-package-schemas-") as name:
            schemas = download_schema_bundle(Path(name), namespace.timeout_seconds)
            validators = create_validators(jsonschema, schemas)
            if namespace.self_test:
                run_self_test(yaml, validators)
                print("PASS: official Scoop and WinGet 1.10 schema self-tests")
            if namespace.scoop_manifest is not None:
                validate_manifest_files(
                    yaml,
                    validators,
                    namespace.scoop_manifest,
                    namespace.winget_archive,
                )
                print(
                    f"PASS: {namespace.scoop_manifest} is a valid Scoop manifest"
                )
                print(
                    f"PASS: {namespace.winget_archive} is a valid WinGet 1.10 "
                    "multi-file manifest archive"
                )
        print(
            "Validator dependencies: "
            f"PyYAML {dependency_version('PyYAML')}, "
            f"jsonschema {dependency_version('jsonschema')}"
        )
    except (OSError, PackageManifestError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        exception_module = type(exc).__module__
        if exception_module.startswith(("jsonschema", "referencing")):
            print(f"ERROR: JSON Schema processing failed: {exc}", file=sys.stderr)
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
