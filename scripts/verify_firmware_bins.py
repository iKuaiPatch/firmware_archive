#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FIRMWARE_DIR = ROOT_DIR / "firmware"
MAX_HEADER_LENGTH = 1024 * 1024
GZIP_HEADER = bytes.fromhex("1f8b08006f9b4b590203")
REQUIRED_HEADER_FIELDS = ("firmwareid", "md5", "sha256", "length")
HASH_CHUNK_SIZE = 1024 * 1024


@dataclass
class VerifyResult:
    path: str
    ok: bool
    reason: str = ""
    firmwareid: str = ""
    version: str = ""
    filename: str = ""
    header_length: int = 0
    payload_length: int = 0
    expected_length: str = ""
    expected_md5: str = ""
    actual_md5: str = ""
    expected_sha256: str = ""
    actual_sha256: str = ""
    sha256_mode: str = "prefix32"


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def iter_bin_files(paths: Sequence[Path]) -> tuple[list[Path], list[VerifyResult]]:
    files: list[Path] = []
    failures: list[VerifyResult] = []
    seen: set[Path] = set()

    for path in paths:
        if not path.exists():
            failures.append(VerifyResult(path=str(path), ok=False, reason="path does not exist"))
            continue
        if path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(path)
            continue
        if path.is_dir():
            for bin_file in sorted(path.rglob("*.bin"), key=lambda item: str(item).lower()):
                resolved = bin_file.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(bin_file)
            continue
        failures.append(VerifyResult(path=display_path(path), ok=False, reason="unsupported path type"))

    return files, failures


def load_firmware_header(source: Path) -> tuple[dict[str, object], int]:
    with source.open("rb") as handle:
        prefix = handle.read(4)
        if len(prefix) != 4:
            raise ValueError("file is smaller than 4 bytes")

        header_length = int.from_bytes(prefix, "big", signed=False)
        if header_length >= MAX_HEADER_LENGTH:
            raise ValueError(f"header length is too large: {header_length}")

        header_body = handle.read(header_length)
        if len(header_body) != header_length:
            raise ValueError("file ended before complete header")

    try:
        header_data = gzip.decompress(GZIP_HEADER + header_body)
    except OSError as exc:
        raise ValueError(f"header gzip decode failed: {exc}") from exc

    try:
        decoded = json.loads(header_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"header json decode failed: {exc}") from exc

    if not isinstance(decoded, dict):
        raise ValueError("header json is not an object")

    missing = [
        field
        for field in REQUIRED_HEADER_FIELDS
        if field not in decoded or decoded[field] is None or str(decoded[field]) == ""
    ]
    if missing:
        raise ValueError(f"header missing required fields: {', '.join(missing)}")

    return decoded, header_length


def hash_payload(source: Path, payload_offset: int) -> tuple[int, str, str]:
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    payload_length = 0

    with source.open("rb") as handle:
        handle.seek(payload_offset)
        while True:
            chunk = handle.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            payload_length += len(chunk)
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return payload_length, md5_hash.hexdigest(), sha256_hash.hexdigest()


def verify_file(source: Path, strict_sha256: bool = False) -> VerifyResult:
    result = VerifyResult(path=display_path(source), ok=False)
    result.sha256_mode = "full64" if strict_sha256 else "prefix32"

    try:
        header, header_length = load_firmware_header(source)
        result.header_length = header_length
        result.firmwareid = str(header["firmwareid"])
        result.version = str(header.get("version", ""))
        result.filename = str(header.get("filename", ""))
        result.expected_length = str(header["length"])
        result.expected_md5 = str(header["md5"]).lower()
        result.expected_sha256 = str(header["sha256"]).lower()

        try:
            expected_length = int(result.expected_length)
        except ValueError as exc:
            raise ValueError(f"invalid length in header: {result.expected_length}") from exc

        payload_length, actual_md5, actual_sha256 = hash_payload(source, 4 + header_length)
        result.payload_length = payload_length
        result.actual_md5 = actual_md5
        result.actual_sha256 = actual_sha256

        if payload_length != expected_length:
            raise ValueError(f"payload length mismatch: expected {expected_length}, got {payload_length}")

        if actual_md5 != result.expected_md5:
            raise ValueError(f"md5 mismatch: expected {result.expected_md5}, got {actual_md5}")

        actual_sha256_value = actual_sha256 if strict_sha256 else actual_sha256[:32]
        if actual_sha256_value != result.expected_sha256:
            raise ValueError(
                f"sha256 mismatch: expected {result.expected_sha256}, got {actual_sha256_value}"
            )

        result.ok = True
        return result
    except Exception as exc:
        result.reason = str(exc)
        return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify iKuai firmware .bin files by the device upgrade unpack/check algorithm."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[DEFAULT_FIRMWARE_DIR],
        help="Files or directories to verify. Defaults to firmware/.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print failures and summary only.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON document with all results.",
    )
    parser.add_argument(
        "--strict-sha256",
        action="store_true",
        help="Compare the full 64-character sha256 instead of the first 32 characters used by the shell code.",
    )
    return parser.parse_args(argv)


def format_ok(result: VerifyResult) -> str:
    details = [f"firmwareid={result.firmwareid}", f"length={result.payload_length}"]
    if result.version:
        details.append(f"version={result.version}")
    return f"ok: {result.path} ({', '.join(details)})"


def format_fail(result: VerifyResult) -> str:
    return f"fail: {result.path}: {result.reason}"


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    files, path_failures = iter_bin_files(args.paths)

    results: list[VerifyResult] = []
    results.extend(path_failures)
    if not args.json:
        for result in path_failures:
            print(format_fail(result))

    for source in files:
        result = verify_file(source, strict_sha256=args.strict_sha256)
        results.append(result)
        if args.json:
            continue
        if result.ok:
            if not args.quiet:
                print(format_ok(result))
        else:
            print(format_fail(result))

    ok_count = sum(1 for result in results if result.ok)
    failed_count = len(results) - ok_count
    summary = {
        "total": len(results),
        "ok": ok_count,
        "failed": failed_count,
        "sha256_mode": "full64" if args.strict_sha256 else "prefix32",
    }

    if args.json:
        print(json.dumps({"summary": summary, "results": [asdict(result) for result in results]}, indent=2))
    else:
        print(
            "summary: "
            f"total={summary['total']} ok={summary['ok']} "
            f"failed={summary['failed']} sha256_mode={summary['sha256_mode']}"
        )

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
