#!/usr/bin/env python3
"""Scan published static-site files against the private privacy denylist."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PUBLIC_ALLOWED_TERMS = {"speedforge"}
TEXT_KEYS = (
    "org_product",
    "business_person",
    "internal_process",
    "counterpart_leak",
    "silence_phrase",
    "source_origin",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--denylist", required=True, type=Path)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    denylist = _load_denylist(args.denylist)
    findings = []
    for path in args.paths:
      findings.extend(_scan_path(path, denylist))

    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


def _scan_path(path: Path, denylist: dict[str, list]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    findings: list[str] = []
    for key in TEXT_KEYS:
        for term in denylist.get(key, []):
            if not isinstance(term, str):
                continue
            if term.lower() in PUBLIC_ALLOWED_TERMS:
                continue
            pattern = _term_pattern(term)
            if pattern.search(text):
                findings.append(f"{path}: blocked {key} term: {term!r}")

    for entry in denylist.get("secret_patterns", []):
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("label", "secret pattern"))
        pattern_text = entry.get("pattern")
        if not isinstance(pattern_text, str):
            continue
        flags = re.IGNORECASE if str(entry.get("flags", "")).upper() == "IGNORECASE" else 0
        if re.compile(pattern_text, flags).search(text):
            findings.append(f"{path}: blocked secret pattern: {label}")
    return findings


def _term_pattern(term: str) -> re.Pattern[str]:
    escaped = re.escape(term)
    escaped = escaped.replace(r"\ ", r"\s+")
    return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", re.IGNORECASE)


def _load_denylist(path: Path) -> dict[str, list]:
    result: dict[str, list] = {}
    current_key: str | None = None
    current_list: list | None = None
    current_dict: dict[str, str] = {}
    in_dict_item = False

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue

        if re.match(r"^[a-z_]+:\s*$", stripped):
            _flush(result, current_key, current_list, current_dict, in_dict_item)
            current_key = stripped.rstrip(":").strip()
            current_list = []
            current_dict = {}
            in_dict_item = False
            continue

        dict_item = re.match(r"^\s+-\s+(\w+):\s*(.+)$", stripped)
        list_item = re.match(r"^\s+-\s+(.+)$", stripped)
        continuation = re.match(r"^\s{4,}(\w+):\s*(.+)$", stripped)

        if dict_item and current_list is not None:
            key, val = dict_item.group(1), dict_item.group(2).strip()
            if in_dict_item and current_dict:
                current_list.append(dict(current_dict))
            current_dict = {key: _unquote(val)}
            in_dict_item = True
        elif continuation and in_dict_item:
            key, val = continuation.group(1), continuation.group(2).strip()
            current_dict[key] = _unquote(val)
        elif list_item and current_list is not None:
            if in_dict_item and current_dict:
                current_list.append(dict(current_dict))
                current_dict = {}
                in_dict_item = False
            current_list.append(_unquote(list_item.group(1).strip()))

    _flush(result, current_key, current_list, current_dict, in_dict_item)
    return result


def _flush(
    result: dict[str, list],
    key: str | None,
    values: list | None,
    current_dict: dict[str, str],
    in_dict_item: bool,
) -> None:
    if key is None or values is None:
        return
    if in_dict_item and current_dict:
        values.append(dict(current_dict))
    result[key] = values


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
