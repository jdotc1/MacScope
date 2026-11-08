#!/usr/bin/env python3
"""Offline, fail-closed DriverKit catalog normalizer/admission utility.

Input is an explicit, already extracted Apple-SDK fact record. This does not
parse arbitrary C++ nor claim to implement OSMetaClass binary extraction.
No SDK download, subprocess execution, login, network or target execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

MAX_INPUT = 32 * 1024 * 1024
MAX_CLASSES = 20_000
MAX_MESSAGES = 50_000
MAX_FIELDS = 8_192
MAX_TOTAL_FIELDS = 200_000
MAX_TOTAL_STRINGS = 8 * 1024 * 1024
MAX_CLASS_SIZE = 16 * 1024 * 1024


class CatalogError(ValueError):
    """Explicit refusal; never silently repair authority-bearing data."""


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_INPUT:
        raise CatalogError("missing, symlink or oversized input")
    data = path.read_bytes()
    if not data or len(data) > MAX_INPUT:
        raise CatalogError("input size")
    result = json.loads(
        data.decode("utf-8"), object_pairs_hook=unique_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(CatalogError(f"nonfinite {value}")),
    )
    if not isinstance(result, dict):
        raise CatalogError("expected JSON object")
    return result


def integer(value: Any, label: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise CatalogError(f"invalid {label}")
    return value


def name(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise CatalogError(f"invalid {label}")
    return value


def exact_keys(item: dict[str, Any], required: set[str], label: str) -> None:
    if set(item) != required:
        raise CatalogError(f"invalid {label} keys: {sorted(set(item) ^ required)}")


def canonicalize(doc: dict[str, Any]) -> dict[str, Any]:
    exact_keys(
        doc,
        {"schemaVersion", "release", "architecture", "sdkBuildIdentifier", "classes", "messages"},
        "catalog",
    )
    if integer(doc["schemaVersion"], "schema", 1, 1) != 1:
        raise CatalogError("schema")
    release = integer(doc["release"], "DriverKit release", 20, 25)
    if doc["architecture"] != "arm64":
        raise CatalogError("non-Apple-silicon catalog")
    build = name(doc["sdkBuildIdentifier"], "SDK build")
    classes, messages = doc["classes"], doc["messages"]
    if not isinstance(classes, list) or len(classes) > MAX_CLASSES:
        raise CatalogError("class count")
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGES:
        raise CatalogError("message count")

    normalized_classes: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    total_fields = 0
    total_strings = 0
    for item in classes:
        if not isinstance(item, dict):
            raise CatalogError("class not an object")
        exact_keys(item, {"name", "parentName", "sizeBytes", "fields"}, "class")
        class_name = name(item["name"], "class name")
        if class_name in seen_names:
            raise CatalogError("duplicate class")
        seen_names.add(class_name)
        parent = item["parentName"]
        if parent is not None:
            parent = name(parent, "parent")
        size = integer(item["sizeBytes"], "class size", 1, MAX_CLASS_SIZE)
        total_strings += len(class_name.encode("utf-8"))
        if parent is not None:
            total_strings += len(parent.encode("utf-8"))
        fields = item["fields"]
        if not isinstance(fields, list) or len(fields) > MAX_FIELDS:
            raise CatalogError("field count")
        normalized_fields: list[dict[str, Any]] = []
        total_fields += len(fields)
        if total_fields > MAX_TOTAL_FIELDS:
            raise CatalogError("aggregate field budget")
        seen_fields: set[str] = set()
        for field in fields:
            if not isinstance(field, dict):
                raise CatalogError("field not object")
            exact_keys(field, {"name", "typeName", "offsetBytes", "sizeBytes"}, "field")
            field_name = name(field["name"], "field name")
            if field_name in seen_fields:
                raise CatalogError("duplicate field")
            seen_fields.add(field_name)
            type_name = name(field["typeName"], "field type", 512)
            total_strings += len(field_name.encode("utf-8")) + len(type_name.encode("utf-8"))
            offset = integer(field["offsetBytes"], "field offset", 0, size)
            field_size = integer(field["sizeBytes"], "field size", 1, size)
            if field_size > size - offset:
                raise CatalogError("field outside class")
            normalized_fields.append({
                "name": field_name, "typeName": type_name,
                "offsetBytes": offset, "sizeBytes": field_size,
            })
        normalized_fields.sort(key=lambda x: (x["offsetBytes"], x["name"]))
        for prior, following in zip(normalized_fields, normalized_fields[1:]):
            if prior["offsetBytes"] + prior["sizeBytes"] > following["offsetBytes"]:
                raise CatalogError("overlapping SDK fields without union evidence")
        normalized_classes.append({
            "name": class_name, "parentName": parent,
            "sizeBytes": size, "fields": normalized_fields,
        })
    normalized_classes.sort(key=lambda x: x["name"])
    if total_strings > MAX_TOTAL_STRINGS:
        raise CatalogError("aggregate catalog string budget")

    by_name = {item["name"]: item for item in normalized_classes}
    color: dict[str, int] = {}
    for start in by_name:
        if start in color:
            continue
        chain: list[str] = []
        current: str | None = start
        while current is not None and current in by_name:
            if color.get(current) == 2:
                break
            if color.get(current) == 1:
                raise CatalogError("SDK inheritance cycle")
            color[current] = 1
            chain.append(current)
            current = by_name[current]["parentName"]
        for item_name in chain:
            color[item_name] = 2
    for item in normalized_classes:
        parent_name = item["parentName"]
        if parent_name not in by_name:
            continue
        parent_size = by_name[parent_name]["sizeBytes"]
        if item["sizeBytes"] < parent_size:
            raise CatalogError("SDK child smaller than parent")
        if any(field["offsetBytes"] < parent_size for field in item["fields"]):
            raise CatalogError("SDK child field overlaps inherited layout")

    normalized_messages: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for message in messages:
        if not isinstance(message, dict):
            raise CatalogError("message not object")
        exact_keys(message, {"id", "name"}, "message")
        message_id = integer(message["id"], "message ID", 0, (1 << 64) - 1)
        if message_id in seen_ids:
            raise CatalogError("duplicate message ID")
        seen_ids.add(message_id)
        normalized_messages.append({"id": message_id, "name": name(message["name"], "message name")})
    normalized_messages.sort(key=lambda x: x["id"])

    return {
        "schemaVersion": 1,
        "release": release,
        "architecture": "arm64",
        "sdkBuildIdentifier": build,
        "classes": normalized_classes,
        "messages": normalized_messages,
    }


def canonical_bytes(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_manifest(doc: dict[str, Any], manifest: dict[str, Any], data: bytes) -> None:
    exact_keys(
        manifest, {"schemaVersion", "release", "architecture", "catalogSHA256", "catalogBytes"},
        "manifest",
    )
    if (
        manifest["schemaVersion"] != 1
        or manifest["release"] != doc["release"]
        or manifest["architecture"] != "arm64"
        or manifest["catalogSHA256"] != digest(data)
        or manifest["catalogBytes"] != len(data)
    ):
        raise CatalogError("manifest/source identity mismatch")


def write_new(path: Path, data: bytes) -> None:
    """Do not silently overwrite a previous corpus or follow a symlink."""
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir() or path.exists() or path.is_symlink():
        raise CatalogError("output already exists or invalid parent")
    # O_EXCL makes this check race-safe. Explicit output path is the only mutation.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def create(input_path: Path, catalog_path: Path, manifest_path: Path) -> None:
    if catalog_path == manifest_path:
        raise CatalogError("catalog and manifest paths must differ")
    doc = canonicalize(load_json(input_path))
    data = canonical_bytes(doc)
    manifest = {
        "schemaVersion": 1,
        "release": doc["release"],
        "architecture": "arm64",
        "catalogSHA256": digest(data),
        "catalogBytes": len(data),
    }
    write_new(catalog_path, data)
    write_new(manifest_path, canonical_bytes(manifest))


def verify(catalog_path: Path, manifest_path: Path) -> None:
    source = load_json(catalog_path)
    canonical = canonicalize(source)
    raw = catalog_path.read_bytes()
    if raw != canonical_bytes(canonical):
        raise CatalogError("catalog is not canonical")
    validate_manifest(canonical, load_json(manifest_path), raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("create", "verify"):
        p = sub.add_parser(mode)
        p.add_argument("--catalog", required=True, type=Path)
        p.add_argument("--manifest", required=True, type=Path)
        if mode == "create":
            p.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "create":
            create(args.input, args.catalog, args.manifest)
        else:
            verify(args.catalog, args.manifest)
    except (CatalogError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(2, f"REFUSED: {exc}\n")
    print("ADMITTED: canonical local DriverKit catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
