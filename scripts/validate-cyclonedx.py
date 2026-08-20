#!/usr/bin/env python3
"""
PurpleRay SBOM Analyzer CycloneDX schema-validation utility.

Copyright (c) 2026 Andrei Ionut Damian. This source is licensed under
the Apache License, Version 2.0; see ../LICENSE.

Description
-----------
Validates generated CycloneDX 1.6 and 1.7 JSON documents against official
schemas downloaded from immutable CycloneDX specification commits. Every
schema, including schemas reached through external references, is verified by
SHA-256 before use. Downloaded files live only in a temporary directory.

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
import hashlib
import json
import sys
import tempfile
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence


SCHEMA_REPOSITORY = "https://raw.githubusercontent.com/CycloneDX/specification"
MAX_SCHEMA_BYTES = 1024 * 1024
SCHEMA_RELEASES: Mapping[str, Mapping[str, Any]] = {
    "1.6": {
        "commit": "8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7",
        "root": "bom-1.6.schema.json",
        "files": {
            "bom-1.6.schema.json": (
                "efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541"
            ),
            "jsf-0.82.schema.json": (
                "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"
            ),
            "spdx.schema.json": (
                "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6"
            ),
        },
    },
    "1.7": {
        "commit": "b29bae660048e0ad2fbc5f2972927b442ce951c4",
        "root": "bom-1.7.schema.json",
        "files": {
            "bom-1.7.schema.json": (
                "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce"
            ),
            "cryptography-defs.schema.json": (
                "027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44"
            ),
            "jsf-0.82.schema.json": (
                "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"
            ),
            "spdx.schema.json": (
                "ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3"
            ),
        },
    },
}


class SchemaValidationError(RuntimeError):
    """Represent an operational or document-validation failure."""


def require_jsonschema() -> Any:
    """Load the external JSON Schema implementation.

    Parameters
    ----------
    None

    Returns
    -------
    module
        The imported ``jsonschema`` module.

    Raises
    ------
    SchemaValidationError
        Raised when ``jsonschema`` is unavailable. The utility never installs
        dependencies or changes the active Python environment.
    """

    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SchemaValidationError(
            "Python package 'jsonschema' is required. Install it in a local "
            "virtual environment, then run this command with that environment's "
            "Python interpreter."
        ) from exc
    return jsonschema


def sha256_bytes(content: bytes) -> str:
    """Calculate a lowercase SHA-256 digest for downloaded content.

    Parameters
    ----------
    content
        Bytes whose integrity is checked.

    Returns
    -------
    str
        The 64-character hexadecimal SHA-256 digest.

    Raises
    ------
    None
    """

    return hashlib.sha256(content).hexdigest()


def download_verified_file(url: str, expected_sha256: str, timeout: float) -> bytes:
    """Download one immutable schema file and verify its digest.

    Parameters
    ----------
    url
        Raw GitHub URL containing a commit-pinned CycloneDX schema.
    expected_sha256
        Trusted lowercase SHA-256 digest embedded in this utility.
    timeout
        Per-request network timeout in seconds.

    Returns
    -------
    bytes
        Verified schema bytes.

    Raises
    ------
    SchemaValidationError
        Raised for HTTP/network failures, an oversized response, or a SHA-256
        mismatch.
    """

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "PurpleRay-SBOM-Analyzer-schema-validator"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read(MAX_SCHEMA_BYTES + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise SchemaValidationError(f"Could not download pinned schema {url}: {exc}") from exc

    if len(content) > MAX_SCHEMA_BYTES:
        raise SchemaValidationError(
            f"Pinned schema exceeds the {MAX_SCHEMA_BYTES}-byte safety limit: {url}"
        )

    actual_sha256 = sha256_bytes(content)
    if actual_sha256 != expected_sha256:
        raise SchemaValidationError(
            f"SHA-256 mismatch for {url}: expected {expected_sha256}, "
            f"received {actual_sha256}"
        )
    return content


def load_json_bytes(content: bytes, source: str) -> Any:
    """Decode a UTF-8 JSON document with source-aware errors.

    Parameters
    ----------
    content
        UTF-8 encoded JSON bytes.
    source
        Human-readable path or URL included in diagnostics.

    Returns
    -------
    object
        Decoded JSON value.

    Raises
    ------
    SchemaValidationError
        Raised when the bytes are not valid UTF-8 JSON.
    """

    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"Invalid JSON in {source}: {exc}") from exc


def download_schema_bundle(
    spec_version: str, target_directory: Path, timeout: float
) -> Dict[str, Any]:
    """Download and verify one complete CycloneDX schema bundle.

    Parameters
    ----------
    spec_version
        Supported CycloneDX specification version (``1.6`` or ``1.7``).
    target_directory
        Temporary directory receiving verified schema files.
    timeout
        Per-file network timeout in seconds.

    Returns
    -------
    dict
        Mapping of schema filenames to decoded JSON schema objects.

    Raises
    ------
    SchemaValidationError
        Raised for an unsupported version, download/integrity failure, or
        malformed official schema JSON.
    OSError
        May propagate when the temporary files cannot be written.
    """

    release = SCHEMA_RELEASES.get(spec_version)
    if release is None:
        raise SchemaValidationError(
            f"Unsupported CycloneDX specVersion {spec_version!r}; expected 1.6 or 1.7"
        )

    commit = str(release["commit"])
    files = release["files"]
    target_directory.mkdir(parents=True, exist_ok=True)
    schemas: Dict[str, Any] = {}
    for filename, expected_sha256 in files.items():
        url = f"{SCHEMA_REPOSITORY}/{commit}/schema/{filename}"
        content = download_verified_file(url, str(expected_sha256), timeout)
        (target_directory / filename).write_bytes(content)
        schemas[str(filename)] = load_json_bytes(content, url)
    return schemas


def reject_unpinned_reference(uri: str) -> Any:
    """Reject resolver attempts outside the verified local schema bundle.

    Parameters
    ----------
    uri
        Unresolved remote schema URI requested by ``jsonschema``.

    Returns
    -------
    object
        This function never returns.

    Raises
    ------
    SchemaValidationError
        Always raised so validation cannot silently fetch unverified content.
    """

    raise SchemaValidationError(f"Schema contains an unpinned external reference: {uri}")


def create_validator(jsonschema: Any, spec_version: str, schemas: Mapping[str, Any]) -> Any:
    """Create an offline validator backed by a verified schema bundle.

    Parameters
    ----------
    jsonschema
        Imported ``jsonschema`` module.
    spec_version
        CycloneDX specification version associated with ``schemas``.
    schemas
        Mapping of filenames to verified decoded schemas.

    Returns
    -------
    jsonschema.protocols.Validator
        Configured validator whose external references resolve locally.

    Raises
    ------
    SchemaValidationError
        Raised when the expected root schema is absent.
    jsonschema.exceptions.SchemaError
        Raised when an official schema is internally invalid.
    """

    release = SCHEMA_RELEASES[spec_version]
    root_filename = str(release["root"])
    if root_filename not in schemas:
        raise SchemaValidationError(f"Verified root schema is missing: {root_filename}")
    root_schema = schemas[root_filename]

    store: Dict[str, Any] = {}
    for filename, schema in schemas.items():
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        store[filename] = schema
        store[f"http://cyclonedx.org/schema/{filename}"] = schema
        store[f"https://cyclonedx.org/schema/{filename}"] = schema
        if isinstance(schema_id, str):
            store[schema_id] = schema

    validator_class = jsonschema.validators.validator_for(root_schema)
    validator_class.check_schema(root_schema)

    try:
        from referencing import Registry, Resource  # type: ignore[import-not-found]
    except ImportError:
        # jsonschema versions before 4.18 use RefResolver and do not require the
        # separate referencing package. Keep this path for supported distro
        # packages such as Ubuntu's jsonschema 4.10.x.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver_class = jsonschema.RefResolver
        resolver = resolver_class.from_schema(
            root_schema,
            store=store,
            handlers={
                "http": reject_unpinned_reference,
                "https": reject_unpinned_reference,
            },
        )
        return validator_class(
            root_schema,
            resolver=resolver,
            format_checker=validator_class.FORMAT_CHECKER,
        )

    registry = Registry(retrieve=reject_unpinned_reference)
    resources: Dict[int, Any] = {}
    for uri, schema in store.items():
        identity = id(schema)
        resource = resources.get(identity)
        if resource is None:
            resource = Resource.from_contents(schema)
            resources[identity] = resource
        registry = registry.with_resource(uri, resource)
    return validator_class(
        root_schema,
        registry=registry,
        format_checker=validator_class.FORMAT_CHECKER,
    )


def validation_messages(validator: Any, document: Any) -> Sequence[str]:
    """Collect deterministic validation messages for one document.

    Parameters
    ----------
    validator
        Configured ``jsonschema`` validator.
    document
        Decoded CycloneDX JSON value.

    Returns
    -------
    sequence of str
        Sorted, path-qualified validation diagnostics; empty when valid.

    Raises
    ------
    jsonschema.exceptions.RefResolutionError
        May propagate if the official schema unexpectedly references a file
        outside the pinned bundle.
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


def document_spec_version(document: Any, source: str) -> str:
    """Read and constrain a document's CycloneDX specification version.

    Parameters
    ----------
    document
        Decoded candidate CycloneDX JSON value.
    source
        Human-readable input path included in diagnostics.

    Returns
    -------
    str
        ``1.6`` or ``1.7``.

    Raises
    ------
    SchemaValidationError
        Raised when the root is not an object or its ``specVersion`` is not a
        supported exact value.
    """

    if not isinstance(document, dict):
        raise SchemaValidationError(f"{source}: CycloneDX document root must be an object")
    spec_version = document.get("specVersion")
    if spec_version not in SCHEMA_RELEASES:
        raise SchemaValidationError(
            f"{source}: unsupported CycloneDX specVersion {spec_version!r}; expected 1.6 or 1.7"
        )
    return str(spec_version)


def load_documents(paths: Iterable[Path]) -> Sequence[tuple[Path, Any, str]]:
    """Load candidate BOM files before performing network access.

    Parameters
    ----------
    paths
        Paths to generated CycloneDX JSON documents.

    Returns
    -------
    sequence of tuple
        Input path, decoded document, and exact specification version for each
        candidate, preserving command-line order.

    Raises
    ------
    SchemaValidationError
        Raised when a file cannot be read, contains invalid JSON, or declares
        an unsupported specification version.
    """

    documents = []
    for path in paths:
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SchemaValidationError(f"Could not read {path}: {exc}") from exc
        document = load_json_bytes(content, str(path))
        documents.append((path, document, document_spec_version(document, str(path))))
    return documents


def run_self_test(validators: Mapping[str, Any]) -> None:
    """Prove that each pinned validator accepts and rejects known documents.

    Parameters
    ----------
    validators
        Mapping containing configured 1.6 and 1.7 validators.

    Returns
    -------
    None

    Raises
    ------
    SchemaValidationError
        Raised if a minimal valid document fails or a document missing the
        required ``bomFormat`` field is unexpectedly accepted.
    """

    for spec_version in ("1.6", "1.7"):
        validator = validators[spec_version]
        valid_document = {"bomFormat": "CycloneDX", "specVersion": spec_version}
        valid_errors = validation_messages(validator, valid_document)
        if valid_errors:
            raise SchemaValidationError(
                f"CycloneDX {spec_version} validator rejected its valid self-test: "
                + "; ".join(valid_errors)
            )

        invalid_document = {"specVersion": spec_version}
        if not validation_messages(validator, invalid_document):
            raise SchemaValidationError(
                f"CycloneDX {spec_version} validator accepted its invalid self-test"
            )


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse command-line inputs for file validation or the built-in self-test.

    Parameters
    ----------
    arguments
        Command-line tokens excluding the executable name.

    Returns
    -------
    argparse.Namespace
        Parsed document paths, self-test flag, and network timeout.

    Raises
    ------
    SystemExit
        Raised by ``argparse`` for invalid command-line input.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Validate generated CycloneDX 1.6/1.7 JSON using checksum-pinned "
            "official schemas."
        )
    )
    parser.add_argument("documents", nargs="*", type=Path, help="generated .cdx.json file")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="also test known valid and invalid minimal documents for both versions",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="per-schema download timeout (default: 30)",
    )
    namespace = parser.parse_args(arguments)
    if not namespace.documents and not namespace.self_test:
        parser.error("provide at least one generated document or use --self-test")
    if namespace.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    return namespace


def main(arguments: Sequence[str] | None = None) -> int:
    """Validate requested documents and print concise, actionable results.

    Parameters
    ----------
    arguments
        Optional command-line tokens; ``sys.argv[1:]`` is used when omitted.

    Returns
    -------
    int
        Zero when every check passes; one for dependency, integrity, schema,
        input, or validation failures.

    Raises
    ------
    SystemExit
        May be raised by argument parsing for invalid command syntax.
    """

    namespace = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        documents = load_documents(namespace.documents)
        required_versions = {item[2] for item in documents}
        if namespace.self_test:
            required_versions.update(SCHEMA_RELEASES)

        jsonschema = require_jsonschema()
        with tempfile.TemporaryDirectory(prefix="purpleray-cyclonedx-schemas-") as temp_name:
            temporary_root = Path(temp_name)
            validators = {}
            for spec_version in sorted(required_versions):
                schemas = download_schema_bundle(
                    spec_version,
                    temporary_root / spec_version,
                    namespace.timeout_seconds,
                )
                validators[spec_version] = create_validator(
                    jsonschema, spec_version, schemas
                )

            if namespace.self_test:
                run_self_test(validators)
                print("PASS: official CycloneDX 1.6 and 1.7 schema self-tests")

            failures = 0
            for path, document, spec_version in documents:
                messages = validation_messages(validators[spec_version], document)
                if messages:
                    failures += 1
                    print(
                        f"FAIL: {path} is not valid CycloneDX {spec_version}:",
                        file=sys.stderr,
                    )
                    for message in messages:
                        print(f"  - {message}", file=sys.stderr)
                else:
                    print(f"PASS: {path} is valid CycloneDX {spec_version}")
            if failures:
                return 1
    except (OSError, SchemaValidationError) as exc:
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
