#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener, urlopen
from fake_useragent import UserAgent

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


VERSION_SOURCE_URL = "https://download.ikuai8.com/submit3x/Version_all"
REQUEST_TIMEOUT = 60
DEFAULT_PROXY = os.environ.get("IKUAI_PROXY", "http://127.0.0.1:7890")
DOWNLOAD_CHUNK_SIZE = int(os.environ.get("IKUAI_DOWNLOAD_CHUNK_SIZE", str(128 * 1024)))
DOWNLOAD_RETRIES = int(os.environ.get("IKUAI_DOWNLOAD_RETRIES", "4"))
DOWNLOAD_RETRY_DELAY = float(os.environ.get("IKUAI_DOWNLOAD_RETRY_DELAY", "2"))
DOWNLOAD_GWID = os.environ.get("IKUAI_DOWNLOAD_GWID", "76bb62de3dca87afa2026d83e3aa3e41")
DOWNLOAD_USER_AGENT = os.environ.get("IKUAI_DOWNLOAD_USER_AGENT", "curl/10.8")

ua = UserAgent()

ROOT_DIR = Path(__file__).resolve().parent.parent
UPDATE_CONTENT_FILE = ROOT_DIR / "state" / "update_contents.json"

ARCH_DEVICE_NAMES = {
    "x32": "x86",
    "x64": "x64",
}
VERSION_ALL_FIRMWARE_KEYS = ("firmware", "firmware_x64")
VERSION_ALL_SKIP_SECTIONS = {"GLOBAL", "APVER2"}


@dataclass(frozen=True)
class FirmwareAsset:
    edition: str
    format_name: str
    arch: str
    version: str
    filename: str
    url: str
    device_name: str = ""
    firmware_name: str = ""
    optional: bool = False

    @property
    def relative_path(self) -> Path:
        device_name = self.device_name or ARCH_DEVICE_NAMES[self.arch]
        return Path("firmware") / device_name / self.edition / self.filename


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": ua.random})
    with open_url(request, DEFAULT_PROXY) as response:
        return response.read().decode("utf-8", errors="replace")


def normalize_proxy(proxy: str | None) -> str | None:
    if proxy is None:
        return None
    value = proxy.strip()
    if value:
        return value
    return None


def open_url(request: Request, proxy: str | None):
    proxy_url = normalize_proxy(proxy)
    if proxy_url:
        opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
        return opener.open(request, timeout=REQUEST_TIMEOUT)
    return urlopen(request, timeout=REQUEST_TIMEOUT)


def parse_sections(raw_text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current_section: str | None = None

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            sections.setdefault(current_section, {})
            continue
        if "=" not in line or current_section is None:
            continue
        key, value = raw_line.split("=", 1)
        sections[current_section][key.strip()] = value.strip()

    return sections


def normalize_firmware_filename(value: str) -> str:
    filename = value.strip()
    if not filename:
        return ""
    return Path(filename.split()[0]).name


def split_section_variant(section_name: str) -> tuple[str, str | None]:
    upper_name = section_name.upper()
    for suffix, edition in (("_ALPHA", "alpha"), ("_BETA", "beta")):
        if upper_name.endswith(suffix):
            return section_name[: -len(suffix)], edition
    return section_name, None


def version_all_base_section(section_name: str) -> str:
    return split_section_variant(section_name)[0]


def version_all_edition(section_name: str) -> str:
    base_name, dev_edition = split_section_variant(section_name)
    if dev_edition:
        return dev_edition
    if base_name.upper() == "X86ENT":
        return "enterprise"
    if base_name.lower().endswith("_oem"):
        return "oem"
    return "free"


def version_all_device_name(section_name: str, key: str, filename: str) -> str:
    base_name = version_all_base_section(section_name)
    lower_name = base_name.lower()
    if base_name.upper() in {"X86", "X86ENT"} or lower_name == "x86_oem":
        if key == "firmware_x64" or "x64" in filename.lower():
            return "x64"
        return "x86"
    if lower_name.endswith("_oem"):
        return lower_name[:-4]
    return lower_name


def firmware_directory_from_filename(filename: str) -> str:
    name = Path(filename).name
    if "_sysupgrade_" in name:
        prefix = name.split("_sysupgrade_", 1)[0]
        return prefix if prefix.startswith("IK-") else f"IK-{prefix}"
    return name.rsplit(".", 1)[0]


def firmware_name_from_filename(filename: str) -> str:
    return Path(filename).name.split("_", 1)[0]


def section_firmware_name(section: dict[str, str], filename: str) -> str:
    firmware_name = section.get("firmwarename", "").strip()
    if firmware_name:
        return firmware_name.split()[0]
    return firmware_name_from_filename(filename)


def firmware_name_for_header(asset: FirmwareAsset) -> str:
    if asset.device_name in {"x86", "x64"}:
        if asset.edition == "enterprise":
            return "X86ENT"
        if asset.edition == "oem":
            return "X86_oem"
        return "X86"
    return asset.firmware_name or firmware_name_from_filename(asset.filename)


def router_version_for_header(asset: FirmwareAsset) -> str:
    if asset.version:
        return asset.version.split("_Build", 1)[0]

    match = re.search(r"(?:^|_)(\d+(?:\.\d+)+)", asset.filename)
    return match.group(1) if match else ""


def build_date_for_header(filename: str) -> str:
    match = re.search(r"_Build(\d+)", filename, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def sysbit_for_header(asset: FirmwareAsset) -> str:
    filename = asset.filename.lower()
    if asset.arch == "x32" or "_x32_" in filename:
        return "x32"
    return "x64"


def firmware_download_headers(asset: FirmwareAsset) -> dict[str, str]:
    return {
        "X-Firmware": firmware_name_for_header(asset),
        "X-Router-Ver": router_version_for_header(asset),
        "X-GWID": DOWNLOAD_GWID,
        "X-Build-Date": build_date_for_header(asset.filename),
        "X-Sysbit": sysbit_for_header(asset),
        "X-Oemname": "",
        "X-Overseas": "",
        "X-Edition-Type": "Standard",
        "User-Agent": DOWNLOAD_USER_AGENT,
    }


def version_all_url(section_name: str, key: str, filename: str) -> str:
    _ = key
    base_name = version_all_base_section(section_name)
    lower_name = base_name.lower()

    if base_name.upper() == "X86ENT":
        return f"https://patch.ikuai8.com/ent/{filename}"
    if base_name.upper() == "X86" or lower_name == "x86_oem":
        if filename.lower().endswith(".iso"):
            return f"https://patch.ikuai8.com/3.x/iso/{filename}"
        return f"https://patch.ikuai8.com/3.x/patch/{filename}"

    firmware_directory = firmware_directory_from_filename(filename)
    return f"https://patch.ikuai8.com/firmware/{firmware_directory}/{filename}"


def iso_candidate_filename(section_name: str, filename: str) -> str | None:
    base_name = version_all_base_section(section_name)
    name = Path(filename).name
    if base_name.upper() != "X86" or not name.lower().endswith(".bin"):
        return None
    return f"{name[:-4]}.iso"


def version_all_filter_matches(
    section_name: str,
    key: str,
    filename: str,
    device_filter: str | None,
) -> bool:
    if not device_filter:
        return False

    normalized = device_filter.lower()
    if normalized in {"all", "*"}:
        return True

    device_name = version_all_device_name(section_name, key, filename)
    base_name = version_all_base_section(section_name).lower()
    return normalized in {device_name, section_name.lower(), base_name}


def collect_version_all_assets(
    sections: dict[str, dict[str, str]],
    device_filter: str | None,
) -> list[FirmwareAsset]:
    assets: list[FirmwareAsset] = []
    seen: set[Path] = set()

    for section_name, section in sections.items():
        if section_name in VERSION_ALL_SKIP_SECTIONS:
            continue

        version = section.get("system_ver", "").strip()
        filenames_seen: set[str] = set()
        for key in VERSION_ALL_FIRMWARE_KEYS:
            filename = normalize_firmware_filename(section.get(key, ""))
            if not filename or filename in filenames_seen:
                continue
            filenames_seen.add(filename)

            if not version_all_filter_matches(section_name, key, filename, device_filter):
                continue

            device_name = version_all_device_name(section_name, key, filename)
            asset = FirmwareAsset(
                edition=version_all_edition(section_name),
                format_name="bin",
                arch="",
                version=version,
                filename=filename,
                url=version_all_url(section_name, key, filename),
                device_name=device_name,
                firmware_name=section_firmware_name(section, filename),
            )
            if asset.relative_path in seen:
                continue
            seen.add(asset.relative_path)
            assets.append(asset)

            iso_filename = iso_candidate_filename(section_name, filename)
            if iso_filename:
                iso_asset = FirmwareAsset(
                    edition=version_all_edition(section_name),
                    format_name="iso",
                    arch="",
                    version=version,
                    filename=iso_filename,
                    url=version_all_url(section_name, key, iso_filename),
                    device_name=device_name,
                    firmware_name=section_firmware_name(section, iso_filename),
                    optional=True,
                )
                if iso_asset.relative_path not in seen:
                    seen.add(iso_asset.relative_path)
                    assets.append(iso_asset)

    return assets


def update_content_filter_matches(
    section_name: str,
    key: str,
    filename: str,
    device_filter: str | None,
) -> bool:
    if not device_filter:
        return True
    return version_all_filter_matches(section_name, key, filename, device_filter)


def update_content_edition(section_name: str) -> str:
    return version_all_edition(section_name)


def firmware_version_key(filename: str, fallback_version: str, edition: str) -> str:
    name = Path(filename).name
    match = re.search(
        r"(?:^|_)(\d+(?:\.\d+)+(?:_(?:alpha|beta))?)(?:_Enterprise)?_Build(\d+)",
        name,
        flags=re.IGNORECASE,
    )
    if match:
        return f"{match.group(1)}-{edition}-{match.group(2)}"
    return f"{fallback_version}-{edition}" if fallback_version else edition


def decode_update_content(value: str) -> str:
    text = value.strip()
    text = text.replace("\\\\r\\\\n", "\n").replace("\\\\n", "\n")
    return text.replace("\\r\\n", "\n").replace("\\n", "\n")


def collect_update_contents(
    sections: dict[str, dict[str, str]],
    device_filter: str | None = None,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}

    for section_name, section in sections.items():
        if section_name in VERSION_ALL_SKIP_SECTIONS:
            continue

        update_content = decode_update_content(section.get("update_content", ""))
        if not update_content:
            continue

        fallback_version = section.get("system_ver", "").strip()
        filenames_seen: set[str] = set()
        for key in VERSION_ALL_FIRMWARE_KEYS:
            filename = normalize_firmware_filename(section.get(key, ""))
            if not filename or filename in filenames_seen:
                continue
            filenames_seen.add(filename)

            if not update_content_filter_matches(section_name, key, filename, device_filter):
                continue

            device_name = version_all_device_name(section_name, key, filename)
            version_key = firmware_version_key(filename, fallback_version, update_content_edition(section_name))
            result.setdefault(device_name, {})[version_key] = update_content

    return result


def load_update_contents(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}

    result: dict[str, dict[str, str]] = {}
    for device_name, versions in raw.items():
        if not isinstance(versions, dict):
            continue
        result[str(device_name)] = {
            str(version): str(content)
            for version, content in versions.items()
        }
    return result


def save_update_contents(path: Path, updates: dict[str, dict[str, str]]) -> None:
    if not updates:
        return

    current = load_update_contents(path)
    for device_name, versions in updates.items():
        device_versions = current.setdefault(device_name, {})
        for version_key in versions:
            match = re.match(r"^(.+)-(free|enterprise|oem|alpha|beta)-(\d+)$", version_key)
            if match:
                device_versions.pop(f"{match.group(1)}-{match.group(3)}", None)
        device_versions.update(versions)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fetch_text_with_proxy(url: str, proxy: str | None) -> str:
    request = Request(url, headers={"User-Agent": ua.random})
    with open_url(request, proxy) as response:
        return response.read().decode("utf-8", errors="replace")


def output_path_text(path: Path) -> str:
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return path.as_posix()


def git_tracked_paths(prefix: str) -> set[str]:
    try:
        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD", "--", prefix],
            cwd=ROOT_DIR,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return set()

    return {
        line.strip().replace("\\", "/")
        for line in result.stdout.splitlines()
        if line.strip()
    }


def response_total_bytes(response, initial_bytes: int) -> int | None:
    content_range = response.headers.get("Content-Range")
    if content_range and "/" in content_range:
        total_text = content_range.rsplit("/", 1)[-1].strip()
        if total_text.isdigit():
            return int(total_text)

    total = response.headers.get("Content-Length")
    if not total or not total.isdigit():
        return None

    length = int(total)
    status = getattr(response, "status", None)
    if initial_bytes > 0 and status == 206:
        return initial_bytes + length
    return length


def response_looks_like_html(response, first_chunk: bytes) -> bool:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True

    prefix = first_chunk.lstrip()[:64].lower()
    return prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html")


def transfer_response(response, handle, description: str, initial_bytes: int = 0) -> int:
    total_bytes = response_total_bytes(response, initial_bytes)
    written_bytes = 0

    progress = None
    if tqdm is not None:
        progress = tqdm(
            total=total_bytes,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=description,
            leave=True,
            initial=initial_bytes,
        )

    try:
        chunk = response.read(DOWNLOAD_CHUNK_SIZE)
        if chunk and response_looks_like_html(response, chunk):
            raise OSError(f"下载返回HTML页面: {description}({response.url})")

        while chunk:
            handle.write(chunk)
            written_bytes += len(chunk)
            if progress is not None:
                progress.update(len(chunk))
            chunk = response.read(DOWNLOAD_CHUNK_SIZE)
    finally:
        if progress is not None:
            progress.close()

    total_written = initial_bytes + written_bytes
    if total_bytes is not None and total_written != total_bytes:
        raise OSError(f"下载不完整: expected={total_bytes} actual={total_written}")

    return total_written


def is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, HTTPError):
        return exc.code >= 500 or exc.code == 429
    if isinstance(exc, URLError):
        reason = getattr(exc, "reason", None)
        return isinstance(reason, TimeoutError) or "timed out" in str(reason).lower()
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, OSError):
        text = str(exc).lower()
        return "timed out" in text or "timeout" in text or "incomplete" in text
    return False


def is_optional_asset_missing(exc: Exception) -> bool:
    if isinstance(exc, HTTPError):
        return exc.code in {400, 403, 404}
    if isinstance(exc, OSError):
        return "下载返回html页面" in str(exc).lower()
    return False


def download_asset(
    asset: FirmwareAsset,
    output_dir: Path,
    proxy: str | None,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[str, str]:
    destination = output_dir / asset.relative_path

    if destination.exists() and not force:
        return "skipped", output_path_text(destination)
    if dry_run:
        return "planned", output_path_text(destination)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    if force and temporary.exists():
        temporary.unlink()

    for attempt in range(1, DOWNLOAD_RETRIES + 2):
        resume_from = temporary.stat().st_size if temporary.exists() else 0
        headers = firmware_download_headers(asset)
        if resume_from > 0:
            headers["Range"] = f"bytes={resume_from}-"

        request = Request(asset.url, headers=headers)
        try:
            with open_url(request, proxy) as response:
                status = getattr(response, "status", None)
                is_resume = resume_from > 0 and status == 206
                if resume_from > 0 and not is_resume:
                    resume_from = 0
                file_mode = "ab" if is_resume else "wb"

                with temporary.open(file_mode) as handle:
                    transfer_response(response, handle, asset.filename, initial_bytes=resume_from)
            temporary.replace(destination)
            break
        except Exception as exc:
            if attempt > DOWNLOAD_RETRIES or not is_retryable_error(exc):
                if temporary.exists() and temporary.stat().st_size == 0:
                    temporary.unlink()
                raise

            delay = DOWNLOAD_RETRY_DELAY * attempt
            print(
                f"retry {attempt}/{DOWNLOAD_RETRIES}: {asset.filename} -> {exc} (wait {delay:.1f}s)",
                file=sys.stderr,
            )
            time.sleep(delay)

    return "downloaded", output_path_text(destination)


def download_assets(
    assets: Iterable[FirmwareAsset],
    output_dir: Path,
    proxy: str | None,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[list[str], list[str]]:
    saved: list[str] = []
    failures: list[str] = []

    for asset in assets:
        try:
            status, path_text = download_asset(
                asset,
                output_dir,
                proxy,
                force=force,
                dry_run=dry_run,
            )
            print(f"{status}: {asset.relative_path.as_posix()}")
            saved.append(path_text)
        except (HTTPError, URLError, OSError) as exc:
            if asset.optional and is_optional_asset_missing(exc):
                print(f"skipped: {asset.relative_path.as_posix()} (iso unavailable)")
                continue
            message = f"{asset.relative_path.as_posix()} -> {exc}({asset.url})"
            print(message, file=sys.stderr)
            failures.append(message)

    return saved, failures


def release_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_release_files(release_dir: Path, asset_paths: list[str]) -> tuple[str, str, str]:
    release_dir.mkdir(parents=True, exist_ok=True)
    timestamp = release_timestamp()

    notes_lines = [
        f"发布日期: {timestamp}",
        "",
        "新增固件:",
    ]
    for asset_path in asset_paths:
        notes_lines.append(f"- {asset_path}")

    notes_path = release_dir / "release-notes.md"
    notes_path.write_text("\n".join(notes_lines) + "\n", encoding="utf-8")

    return output_path_text(notes_path), f"ikuai-firmware-{timestamp}", f"iKuai firmware {timestamp}"


def write_github_outputs(
    has_updates: bool,
    release_notes: str | None = None,
    tag_name: str | None = None,
    release_name: str | None = None,
    asset_paths: list[str] | None = None,
) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        return

    lines = [f"has_updates={'true' if has_updates else 'false'}"]
    if release_notes is not None:
        lines.append(f"release_notes={release_notes}")
    if tag_name is not None:
        lines.append(f"tag_name={tag_name}")
    if release_name is not None:
        lines.append(f"release_name={release_name}")
    if asset_paths is not None:
        lines.append("assets<<__ASSETS__")
        lines.extend(asset_paths)
        lines.append("__ASSETS__")

    with open(output_file, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def command_download(args: argparse.Namespace) -> int:
    raw_version_all = fetch_text_with_proxy(VERSION_SOURCE_URL, args.proxy)
    sections = parse_sections(raw_version_all)
    device_filter = args.device
    if device_filter is None:
        device_filter = "all"
    save_update_contents(UPDATE_CONTENT_FILE, collect_update_contents(sections, device_filter))

    assets = collect_version_all_assets(sections, device_filter)
    if not assets:
        raise ValueError(f"Version_all 中未找到设备固件: {device_filter}")

    saved, failures = download_assets(
        assets,
        args.output_dir,
        args.proxy,
        force=args.force,
        dry_run=args.dry_run,
    )
    print(f"saved={len(saved)} failed={len(failures)}")
    return 1 if failures else 0


def command_check_release(args: argparse.Namespace) -> int:
    raw_version_all = fetch_text_with_proxy(VERSION_SOURCE_URL, args.proxy)
    sections = parse_sections(raw_version_all)
    tracked_firmware = git_tracked_paths("firmware")
    all_assets = collect_version_all_assets(sections, "all")
    assets = [
        asset
        for asset in all_assets
        if args.force or asset.relative_path.as_posix() not in tracked_firmware
    ]
    save_update_contents(UPDATE_CONTENT_FILE, collect_update_contents(sections))
    checked_devices = sorted({asset.device_name for asset in all_assets if asset.device_name})
    print(
        f"checked devices={len(checked_devices)} "
        f"firmware_candidates={len(all_assets)} new_firmware={len(assets)}"
    )
    if checked_devices:
        print("checked device list: " + ", ".join(checked_devices))

    if not assets:
        write_github_outputs(False)
        print("no new firmware")
        return 0

    saved, failures = download_assets(
        assets,
        args.output_dir,
        args.proxy,
        force=args.force,
        dry_run=args.dry_run,
    )
    if failures:
        write_github_outputs(False)
        return 1

    if not saved:
        write_github_outputs(False)
        print("no downloaded firmware")
        return 0

    release_notes, tag_name, release_name = write_release_files(args.release_dir, saved)
    write_github_outputs(
        True,
        release_notes=release_notes,
        tag_name=tag_name,
        release_name=release_name,
        asset_paths=saved,
    )
    print(f"release={tag_name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="iKuai firmware downloader")
    subparsers = parser.add_subparsers(dest="command", required=True)

    download_parser = subparsers.add_parser("download", help="下载 Version_all 设备固件")
    download_parser.add_argument("--mode", choices=("latest", "all"), required=True)
    download_parser.add_argument("--output-dir", type=Path, default=ROOT_DIR)
    download_parser.add_argument("--proxy", default=DEFAULT_PROXY)
    download_parser.add_argument("--device", default=None, help="设备名；默认下载 Version_all 中所有设备")
    download_parser.add_argument("--force", action="store_true")
    download_parser.add_argument("--dry-run", action="store_true")
    download_parser.set_defaults(handler=command_download)

    release_parser = subparsers.add_parser("check-release", help="检查新固件并生成 Release 输出")
    release_parser.add_argument("--output-dir", type=Path, default=ROOT_DIR)
    release_parser.add_argument("--release-dir", type=Path, default=ROOT_DIR / ".release")
    release_parser.add_argument("--proxy", default=DEFAULT_PROXY)
    release_parser.add_argument("--force", action="store_true")
    release_parser.add_argument("--dry-run", action="store_true")
    release_parser.set_defaults(handler=command_check_release)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
