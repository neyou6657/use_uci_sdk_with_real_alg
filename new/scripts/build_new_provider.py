#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

ALLOWED_CLASSES = {"kem", "signature", "stateful_signature"}


def parse_alg_id(raw: Any) -> int:
    if isinstance(raw, int):
        val = raw
    elif isinstance(raw, str):
        val = int(raw.strip(), 0)
    else:
        raise ValueError(f"unsupported alg_id type: {type(raw)!r}")

    if val < 0 or val > 0xFFFFFFFF:
        raise ValueError(f"alg_id out of range: {raw}")
    return val


def resolve_optional_path(root: Path, raw: str) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def resolve_optional_paths(root: Path, raw: Any) -> list[Path]:
    if raw in (None, ""):
        return []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError(f"unsupported path list type: {type(raw)!r}")

    resolved: list[Path] = []
    for idx, item in enumerate(items):
        if not isinstance(item, str):
            raise ValueError(f"path list item[{idx}] must be string")
        path = resolve_optional_path(root, item.strip())
        if path is None:
            continue
        resolved.append(path)
    return resolved


def resolve_source_dirs(root: Path, raw: Any) -> list[Path]:
    dirs = resolve_optional_paths(root, raw)
    for path in dirs:
        if not path.is_dir():
            raise ValueError(f"source_dir not found: {path}")
    return dirs


def normalize_config(cfg: dict[str, Any], cfg_path: Path) -> dict[str, Any]:
    repo_root = cfg_path.parents[2]
    provider = str(cfg.get("provider_name") or cfg.get("provider") or "").strip()
    provider_output_name = str(cfg.get("provider_output_name") or provider).strip()
    provider_source_raw = str(cfg.get("provider_source") or "").strip()
    provider_source = resolve_optional_path(repo_root, provider_source_raw)
    extra_sources = resolve_optional_paths(repo_root, cfg.get("extra_sources"))
    source_dirs = resolve_source_dirs(repo_root, cfg.get("source_dirs"))
    include_dirs = resolve_optional_paths(repo_root, cfg.get("include_dirs"))
    algs = cfg.get("algorithms")

    if not provider:
        raise ValueError(f"{cfg_path}: provider_name/provider is required")
    if not isinstance(algs, list) or not algs:
        raise ValueError(f"{cfg_path}: algorithms must be a non-empty list")

    normalized: list[dict[str, str]] = []
    for idx, ent in enumerate(algs):
        if not isinstance(ent, dict):
            raise ValueError(f"{cfg_path}: algorithms[{idx}] must be object")

        name = str(ent.get("name") or ent.get("algorithm") or "").strip()
        klass = str(ent.get("class") or "kem").strip().lower()
        if not name:
            raise ValueError(f"{cfg_path}: algorithms[{idx}].name is required")
        if klass not in ALLOWED_CLASSES:
            raise ValueError(
                f"{cfg_path}: algorithms[{idx}].class must be one of {sorted(ALLOWED_CLASSES)}"
            )

        raw_alg_id = ent.get("alg_id")
        if raw_alg_id is None:
            raw_alg_id = ent.get("algid")
        if raw_alg_id is None:
            raise ValueError(f"{cfg_path}: algorithms[{idx}].alg_id is required")

        alg_id = parse_alg_id(raw_alg_id)
        props = str(ent.get("properties") or "").strip() or f"provider={provider}"

        normalized.append(
            {
                "alg_id": f"0x{alg_id:08X}",
                "name": name,
                "class": klass,
                "properties": props,
            }
        )

    sources: list[Path] = []
    if provider_source is not None:
        sources.append(provider_source)
    sources.extend(extra_sources)
    for src_dir in source_dirs:
        sources.extend(sorted(src_dir.glob("*.c")))
    if not sources:
        raise ValueError(f"{cfg_path}: provider_source, extra_sources, or source_dirs is required")

    for src in sources:
        if not src.is_file():
            raise ValueError(f"{cfg_path}: source file not found: {src}")
    for inc in include_dirs:
        if not inc.is_dir():
            raise ValueError(f"{cfg_path}: include_dir not found: {inc}")

    return {
        "provider": provider,
        "provider_output_name": provider_output_name,
        "provider_source": str(provider_source) if provider_source is not None else "",
        "sources": [str(src) for src in sources],
        "include_dirs": [str(inc) for inc in include_dirs],
        "algorithms": normalized,
    }


def write_patch_conf(path: Path, manifest: dict[str, Any]) -> None:
    lines = [f"{ent['alg_id']} {ent['name']} {ent['properties']}" for ent in manifest["algorithms"]]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def openssl_build_flags() -> list[str]:
    try:
        out = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "openssl"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ["-lcrypto"]
    return shlex.split(out) if out else ["-lcrypto"]


def build_shared_library(cc: str, sources: list[Path], include_dirs: list[Path], out_so: Path) -> None:
    cmd = [
        cc,
        "-shared",
        "-fPIC",
        "-O2",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-o",
        str(out_so),
    ]
    for inc in include_dirs:
        cmd.extend(["-I", str(inc)])
    cmd.extend(str(src) for src in sources)
    cmd.extend(openssl_build_flags())
    subprocess.run(cmd, check=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build real provider example artifacts from new/ config")
    p.add_argument("--config", required=True, help="path to algorithms.json")
    p.add_argument("--out-dir", required=True, help="output directory")
    p.add_argument("--cc", default="gcc", help="C compiler")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    cfg_path = Path(args.config).resolve()
    out_dir = Path(args.out_dir).resolve()

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise ValueError(f"{cfg_path}: root must be object")

    manifest = normalize_config(cfg, cfg_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    providers_dir = out_dir / "providers"
    providers_dir.mkdir(parents=True, exist_ok=True)

    provider_so = ""
    if manifest["sources"]:
        so_path = providers_dir / f"{manifest['provider_output_name']}.so"
        build_shared_library(
            args.cc,
            [Path(x) for x in manifest["sources"]],
            [Path(x) for x in manifest["include_dirs"]],
            so_path,
        )
        provider_so = str(so_path)

    patch_out = out_dir / f"{manifest['provider']}.patch.conf"
    summary_out = out_dir / "last_build.json"

    write_patch_conf(patch_out, manifest)

    summary = {
        "provider": manifest["provider"],
        "provider_so": provider_so,
        "provider_modules_dir": str(providers_dir),
        "patch_conf": str(patch_out),
        "algorithms": manifest["algorithms"],
    }
    summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if provider_so:
        print(f"[OK] provider_so={provider_so}")
    else:
        print(f"[OK] provider_so=<external-provider>")
    print(f"[OK] patch_conf={patch_out}")
    print(f"[OK] summary={summary_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
