#!/usr/bin/env python3
"""Sign a release manifest using the GitHub Actions signing secret."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path

from release_manifest import build_release_manifest, canonical_manifest_bytes, sign_manifest, verify_manifest_signature

ROOT = Path(__file__).resolve().parents[1]
REPO = "peyton2065/ZeroScript"
DEFAULT_KEY_ID = "peyton-2026"


def load_policy() -> dict:
    return json.loads((ROOT / "update_policy.json").read_text(encoding="utf-8"))


def derive_public_key(private_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes_raw()


def expected_public_key(key_id: str) -> bytes:
    data = json.loads((ROOT / "release_keys.json").read_text(encoding="utf-8"))
    entry = data.get("keys", {}).get(key_id)
    if not isinstance(entry, str):
        raise ValueError("release_keys.json does not contain the configured signing key")
    try:
        public = base64.b64decode(entry, validate=True)
    except Exception as exc:
        raise ValueError("configured signing public key is not valid base64") from exc
    if len(public) != 32:
        raise ValueError("configured Ed25519 public key must be 32 bytes")
    return public


def sign_release(version: str, archive: Path, output: Path, repository: str = REPO, key_id: str | None = None) -> tuple[Path, Path]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("version must be MAJOR.MINOR.PATCH")
    secret = os.environ.get("ZERO_SCRIPT_SIGNING_PRIVATE_KEY", "")
    if not secret:
        raise ValueError("ZERO_SCRIPT_SIGNING_PRIVATE_KEY is not available")
    private_raw = base64.b64decode(secret, validate=True)
    if len(private_raw) != 32:
        raise ValueError("signing private key must be 32 raw bytes")
    key_id = key_id or os.environ.get("ZERO_SCRIPT_SIGNING_KEY_ID", DEFAULT_KEY_ID)
    derived_public = derive_public_key(private_raw)
    if derived_public != expected_public_key(key_id):
        raise ValueError("configured signing secret does not match trusted release public key")
    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    tag = f"v{version}"
    policy = load_policy()
    manifest = build_release_manifest(version, tag, repository, archive.name, archive_sha, key_id, policy["security_patch_level"])
    signature = sign_manifest(private_raw, manifest)
    if not verify_manifest_signature(derived_public, manifest, signature):
        raise ValueError("generated release signature failed local verification")
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "release-manifest.json"
    signature_path = output / "release-manifest.sig"
    manifest_path.write_bytes(json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n")
    signature_path.write_bytes(base64.b64encode(signature) + b"\n")
    return manifest_path, signature_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repository", default=REPO)
    parser.add_argument("--key-id", default=None)
    args = parser.parse_args()
    manifest, signature = sign_release(args.version, Path(args.archive), Path(args.output), args.repository, args.key_id)
    print(manifest)
    print(signature)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
