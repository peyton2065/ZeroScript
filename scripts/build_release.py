#!/usr/bin/env python3
"""Build a clean, updater-compatible ZeroScript release ZIP."""
from __future__ import annotations

import argparse
import json
import shutil
import re
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {".git", ".venv", "venv", "__pycache__", "logs", ".zeroscript-update", ".github", ".pytest_cache", "dist"}
EXCLUDE_TOP = {"setup_state.json", "setup_state.json.example"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}
EXCLUDE_TEST_PREFIX = "test_"
EXCLUDE_DEV_DIRS = {"docs/superpowers", "scripts"}


def should_exclude(rel: Path) -> bool:
    posix = rel.as_posix()
    if rel.parts and rel.parts[0] in EXCLUDE_DIRS:
        return True
    if posix in EXCLUDE_TOP:
        return True
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return True
    if posix == ".DS_Store" or rel.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    if rel.parts and rel.parts[0] == "tests":
        return True
    if len(rel.parts) == 1 and rel.name.startswith(EXCLUDE_TEST_PREFIX) and rel.suffix.lower() == ".py":
        return True
    if posix == "docs/superpowers" or posix.startswith("docs/superpowers/"):
        return True
    if posix == "scripts" or posix.startswith("scripts/"):
        return True
    return False


def build_release(version: str, output: Path, source: Path = ROOT) -> Path:
    if not __import__('re').fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("version must be MAJOR.MINOR.PATCH")
    source = Path(source).resolve()
    output = Path(output).resolve()
    release_name = f"ZeroScript-Free-v{version}.zip"
    with tempfile.TemporaryDirectory(prefix="zeroscript-release-") as td:
        staging = Path(td) / "ZeroScript"
        seen_paths: set[str] = set()
        for src in source.rglob("*"):
            rel = src.relative_to(source)
            if should_exclude(rel):
                continue
            if src.is_symlink():
                raise ValueError(f"release source contains a symlink: {rel}")
            if src.is_dir():
                continue
            normalized = rel.as_posix().replace("\\", "/").casefold()
            if normalized in seen_paths:
                raise ValueError(f"release source path collision: {rel}")
            seen_paths.add(normalized)
            dst = staging / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        manifest_path = staging / "zeroscript-extension" / "manifest.json"
        if not manifest_path.is_file():
            raise ValueError("release is missing the extension manifest")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("release extension manifest is invalid JSON") from exc
        if not isinstance(manifest, dict):
            raise ValueError("release extension manifest must be an object")
        manifest["version"] = version
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        output.mkdir(parents=True, exist_ok=True)
        archive = output / release_name
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for path in sorted(staging.rglob("*"), key=lambda p: p.relative_to(staging).as_posix().casefold()):
                if path.is_file():
                    arcname = (Path("ZeroScript") / path.relative_to(staging)).as_posix()
                    zf.write(path, arcname)
        return archive


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source", default=str(ROOT))
    args = parser.parse_args()
    archive = build_release(args.version, Path(args.output), Path(args.source))
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
