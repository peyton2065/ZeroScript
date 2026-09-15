#!/usr/bin/env python3
"""Canonical Batch 9 release-manifest construction and Ed25519 signing."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ASSET_RE = re.compile(r"^ZeroScript-Free-v\d+\.\d+\.\d+\.zip$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def build_release_manifest(version: str, tag: str, repository: str, asset_name: str,
                           asset_sha256: str, key_id: str, security_patch_level: str) -> dict:
    if not VERSION_RE.fullmatch(version) or not TAG_RE.fullmatch(tag) or tag[1:] != version:
        raise ValueError("version and tag are invalid or inconsistent")
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository is invalid")
    if not ASSET_RE.fullmatch(asset_name):
        raise ValueError("asset name is invalid")
    if not HEX64_RE.fullmatch(asset_sha256):
        raise ValueError("asset SHA-256 is invalid")
    if not isinstance(key_id, str) or not key_id or not isinstance(security_patch_level, str) or not security_patch_level:
        raise ValueError("manifest key_id/security_patch_level are invalid")
    return {
        "schema_version": 1,
        "version": version,
        "tag": tag,
        "repository": repository,
        "asset": asset_name,
        "sha256": asset_sha256.lower(),
        "key_id": key_id,
        "security_patch_level": security_patch_level,
    }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest(private_key: bytes, manifest: dict) -> bytes:
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must be 32 raw bytes")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical_manifest_bytes(manifest))


def signature_base64(private_key: bytes, manifest: dict) -> bytes:
    return base64.b64encode(sign_manifest(private_key, manifest))


def verify_manifest_signature(public_key: bytes, manifest: dict, signature: bytes) -> bool:
    if len(public_key) != 32:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical_manifest_bytes(manifest))
        return True
    except Exception:
        return False
