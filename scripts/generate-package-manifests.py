#!/usr/bin/env python3
"""Generate and verify Scoop and WinGet metadata for a Windows release.

Copyright (c) 2026 Andrei Ionut Damian.
Licensed under the Apache License, Version 2.0. Retain LICENSE and NOTICE,
and cite PurpleRay SBOM Analyzer as described in NOTICE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path


REPOSITORY_URL = "https://github.com/aidamian/PurpleRay_SBOM_Analyzer"
PACKAGE_IDENTIFIER = "AndreiIonutDamian.PurpleRaySBOMAnalyzer"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
TEMPLATE_TOKEN_PATTERN = re.compile(r"@[A-Z0-9_]+@")
WINGET_TEMPLATE_NAMES = (
    f"{PACKAGE_IDENTIFIER}.yaml.in",
    f"{PACKAGE_IDENTIFIER}.installer.yaml.in",
    f"{PACKAGE_IDENTIFIER}.locale.en-US.yaml.in",
)


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of *path*."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def render_template(path: Path, replacements: dict[str, str]) -> str:
    """Render one UTF-8 template and reject missing or unused tokens."""

    rendered = path.read_text(encoding="utf-8")
    for token, value in replacements.items():
        if token in rendered:
            rendered = rendered.replace(token, value)
    unresolved = sorted(set(TEMPLATE_TOKEN_PATTERN.findall(rendered)))
    if unresolved:
        raise ValueError(f"unresolved template tokens in {path}: {', '.join(unresolved)}")
    if not rendered.endswith("\n"):
        raise ValueError(f"template must end in one newline: {path}")
    return rendered


def expected_outputs(repo_root: Path, version: str, archive: Path) -> tuple[str, dict[str, str]]:
    """Return the expected Scoop JSON and WinGet YAML documents."""

    digest = sha256_file(archive)
    archive_name = f"purpleray-sbom-analyzer-v{version}-windows-x64.zip"
    windows_url = f"{REPOSITORY_URL}/releases/download/v{version}/{archive_name}"
    replacements = {
        "@VERSION@": version,
        "@WINDOWS_URL@": windows_url,
        "@WINDOWS_SHA256@": digest,
        "@WINDOWS_SHA256_UPPER@": digest.upper(),
    }
    scoop = render_template(
        repo_root / "packaging/scoop/purpleray-sbom-analyzer.json.in", replacements
    )
    winget = {
        name.removesuffix(".in"): render_template(
            repo_root / "packaging/winget" / name, replacements
        )
        for name in WINGET_TEMPLATE_NAMES
    }
    return scoop, winget


def validate_scoop(document: str, version: str, digest: str) -> None:
    """Validate required Scoop fields and updater behavior."""

    manifest = json.loads(document)
    architecture = manifest.get("architecture", {}).get("64bit", {})
    autoupdate = manifest.get("autoupdate", {})
    if manifest.get("version") != version:
        raise ValueError("Scoop version does not match the requested release")
    if architecture.get("hash") != digest:
        raise ValueError("Scoop hash does not match the Windows archive")
    if manifest.get("checkver") != "github":
        raise ValueError("Scoop checkver must follow GitHub releases")
    if "$version" not in autoupdate.get("architecture", {}).get("64bit", {}).get("url", ""):
        raise ValueError("Scoop autoupdate URL must contain $version")
    if not autoupdate.get("hash", {}).get("url", "").endswith("/SHA256SUMS.txt"):
        raise ValueError("Scoop autoupdate must resolve hashes from SHA256SUMS.txt")
    if manifest.get("bin") != "purpleray-sbom-analyzer.exe":
        raise ValueError("Scoop manifest does not expose the application executable")


def validate_winget(documents: dict[str, str], version: str, digest: str) -> None:
    """Validate the generated WinGet multi-file portable manifest set."""

    if set(documents) != {name.removesuffix(".in") for name in WINGET_TEMPLATE_NAMES}:
        raise ValueError("WinGet package must contain exactly three multi-file manifests")
    combined = "\n".join(documents.values())
    required_fragments = (
        f"PackageIdentifier: {PACKAGE_IDENTIFIER}",
        f"PackageVersion: {version}",
        "InstallerType: zip",
        "NestedInstallerType: portable",
        "RelativeFilePath: purpleray-sbom-analyzer.exe",
        "PortableCommandAlias: purpleray-sbom-analyzer",
        f"InstallerSha256: {digest.upper()}",
        "ManifestType: version",
        "ManifestType: installer",
        "ManifestType: defaultLocale",
        "ManifestVersion: 1.10.0",
    )
    for fragment in required_fragments:
        if fragment not in combined:
            raise ValueError(f"WinGet manifest is missing: {fragment}")
    if combined.count(f"PackageVersion: {version}") != 3:
        raise ValueError("all WinGet files must use the requested version")
    if TEMPLATE_TOKEN_PATTERN.search(combined):
        raise ValueError("WinGet manifests contain unresolved template tokens")


def write_winget_zip(path: Path, documents: dict[str, str]) -> None:
    """Write the WinGet documents to a deterministic ZIP archive."""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(documents):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, documents[name].encode("utf-8"), compresslevel=9)


def verify_outputs(
    output_dir: Path, version: str, expected_scoop: str, expected_winget: dict[str, str]
) -> None:
    """Verify generated files byte-for-byte and inspect the WinGet ZIP."""

    scoop_path = output_dir / "purpleray-sbom-analyzer.json"
    winget_path = output_dir / f"purpleray-sbom-analyzer-v{version}-winget-manifests.zip"
    if scoop_path.read_text(encoding="utf-8") != expected_scoop:
        raise ValueError(f"generated Scoop manifest differs from its template: {scoop_path}")
    with zipfile.ZipFile(winget_path, "r") as archive:
        files = sorted(info.filename for info in archive.infolist() if not info.is_dir())
        if files != sorted(expected_winget):
            raise ValueError("WinGet archive does not contain the exact three-file manifest set")
        for name, expected in expected_winget.items():
            if archive.read(name).decode("utf-8") != expected:
                raise ValueError(f"generated WinGet manifest differs from its template: {name}")
            info = archive.getinfo(name)
            if info.file_size == 0 or info.CRC == 0:
                raise ValueError(f"generated WinGet manifest is empty or corrupt: {name}")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for generation or verification."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--windows-archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify existing outputs without rewriting them",
    )
    return parser.parse_args()


def main() -> int:
    """Generate package-manager metadata, validate it, and verify final bytes."""

    args = parse_args()
    if not VERSION_PATTERN.fullmatch(args.version):
        raise ValueError(f"invalid release version: {args.version!r}")
    archive = args.windows_archive.resolve()
    if not archive.is_file():
        raise FileNotFoundError(f"Windows release archive not found: {archive}")
    expected_name = f"purpleray-sbom-analyzer-v{args.version}-windows-x64.zip"
    if archive.name != expected_name:
        raise ValueError(f"Windows archive must be named {expected_name}")

    repo_root = Path(__file__).resolve().parent.parent
    output_dir = args.output_dir.resolve()
    expected_scoop, expected_winget = expected_outputs(repo_root, args.version, archive)
    digest = sha256_file(archive)
    validate_scoop(expected_scoop, args.version, digest)
    validate_winget(expected_winget, args.version, digest)

    if not args.verify_only:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "purpleray-sbom-analyzer.json").write_text(
            expected_scoop, encoding="utf-8", newline="\n"
        )
        winget_path = output_dir / f"purpleray-sbom-analyzer-v{args.version}-winget-manifests.zip"
        write_winget_zip(winget_path, expected_winget)

    verify_outputs(output_dir, args.version, expected_scoop, expected_winget)
    print(f"Validated Scoop and WinGet metadata for PurpleRay SBOM Analyzer {args.version}")
    print(f"Windows archive SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"package manifest error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
