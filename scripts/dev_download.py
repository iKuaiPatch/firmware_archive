#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import secrets
import shutil
import ssl
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SIGN_URL_API = "https://devapi.ikuai8.com/firmware/sign-url"
VERSION_ALL_API = "https://devapi.ikuai8.com/firmware/version-all"
PUBLIC_VERSION_ALL_URL = "https://download.ikuai8.com/submit3x/Version_all"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CA = SCRIPT_DIR / "mtls" / "ca.crt"
DEFAULT_CERT = SCRIPT_DIR / "mtls" / "client.crt"
DEFAULT_KEY = SCRIPT_DIR / "mtls" / "client.key"
ROOT_DIR = SCRIPT_DIR.parent
DEVICE_MAP_FILE = ROOT_DIR / "state" / "device_map.json"
MTLS_VERIFY_SERVER = False
DEVICE_GWID = secrets.token_hex(16)
DEVICE_SECRET = DEVICE_GWID[-10:]
DEFAULT_DEVICE_KEY = "x86"
VERSION_ALL_FILENAME = "Version_all.txt"
DOWNLOAD_ALL_TARGETS = {"Version_all", "all", "download-all"}
FIRMWARE_KEYS = ("firmware", "firmware_x64")
DEV_FIRMWARE_TYPES = ("ALPHA", "BETA")
DEVICE_KEY_OVERRIDES = {
    ("X86", "firmware"): "x86",
    ("X86", "firmware_x64"): "x64",
    ("X86ENT", "firmware"): "x86ent",
    ("X86ENT", "firmware_x64"): "x64ent",
}

BUILTIN_DEVICE_MAP = {
    "x86": {
        "platform": "x86",
        "system": "community",
        "model_type": "X86",
    },
    "x86ent": {
        "platform": "x86",
        "system": "enterprise",
        "model_type": "X86ENT",
    },
    "a220pro": {
        "platform": "arm",
        "system": "community",
        "model_type": "A220PRO",
    },
    "m100": {
        "platform": "arm",
        "system": "community",
        "model_type": "M100",
    },
    "m200": {
        "platform": "arm",
        "system": "community",
        "model_type": "M200",
    },
    "m5s": {
        "platform": "arm",
        "system": "community",
        "model_type": "M5S",
    },
    "m10s": {
        "platform": "arm",
        "system": "community",
        "model_type": "M10S",
    },
    "m60": {
        "platform": "arm",
        "system": "community",
        "model_type": "M60",
    },
    "m360x": {
        "platform": "arm",
        "system": "community",
        "model_type": "M360X",
    },
    "a50": {
        "platform": "arm",
        "system": "community",
        "model_type": "A50",
    },
    "a50-p": {
        "platform": "arm",
        "system": "community",
        "model_type": "A50-P",
    },
    "a100-p": {
        "platform": "arm",
        "system": "community",
        "model_type": "A100-P",
    },
    "m08": {
        "platform": "arm",
        "system": "community",
        "model_type": "M08",
    },
    "a160": {
        "platform": "arm",
        "system": "community",
        "model_type": "A160",
    },
    "q3s": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3S",
    },
    "y3000g-pro": {
        "platform": "arm",
        "system": "community",
        "model_type": "Y3000G-PRO",
    },
    "c3000": {
        "platform": "arm",
        "system": "community",
        "model_type": "C3000",
    },
    "q3000": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3000",
    },
    "q3600": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3600",
    },
    "q6000": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q6000",
    },
    "m1": {
        "platform": "mips",
        "system": "community",
        "model_type": "M1",
    },
    "m2": {
        "platform": "mips",
        "system": "community",
        "model_type": "M2",
    },
    "m5": {
        "platform": "mips",
        "system": "community",
        "model_type": "M5",
    },
    "m50": {
        "platform": "mips",
        "system": "community",
        "model_type": "M50",
    },
    "g05": {
        "platform": "mips",
        "system": "community",
        "model_type": "G05",
    },
    "a120": {
        "platform": "mips",
        "system": "community",
        "model_type": "A120",
    },
    "a125": {
        "platform": "mips",
        "system": "community",
        "model_type": "A125",
    },
    "a130": {
        "platform": "mips",
        "system": "community",
        "model_type": "A130",
    },
    "a135s": {
        "platform": "mips",
        "system": "community",
        "model_type": "A135S",
    },
    "a139s": {
        "platform": "mips",
        "system": "community",
        "model_type": "A139S",
    },
    "q50": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q50",
    },
    "q80": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q80",
    },
    "q85": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q85",
    },
    "q90": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q90",
    },
    "q1800": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q1800",
    },
    "q1800l": {
        "platform": "mips",
        "system": "community",
        "model_type": "Q1800L",
    },
    "c20": {
        "platform": "mips",
        "system": "community",
        "model_type": "C20",
    },
    "c25-g": {
        "platform": "mips",
        "system": "community",
        "model_type": "C25-G",
    },
    "c50": {
        "platform": "mips",
        "system": "community",
        "model_type": "C50",
    },
    "c90": {
        "platform": "mips",
        "system": "community",
        "model_type": "C90",
    },
    "x86_oem": {
        "platform": "x86-64",
        "system": "community",
        "model_type": "X86_oem",
    },
    "m1_oem": {
        "platform": "mips",
        "system": "community",
        "model_type": "M1_oem",
    },
    "m100_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M100_oem",
    },
    "m200_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M200_oem",
    },
    "m5s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M5S_oem",
    },
    "m10s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "M10S_oem",
    },
    "a160_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "A160_oem",
    },
    "q3s_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3S_oem",
    },
    "q3000_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q3000_oem",
    },
    "q6000_oem": {
        "platform": "arm",
        "system": "community",
        "model_type": "Q6000_oem",
    },
    "x64free": {
        "platform": "x86-64",
        "system": "community",
        "model_type": "X86",
    },
    "x64": {
        "platform": "x86-64",
        "system": "community",
        "model_type": "X86",
    },
    "x64ent": {
        "platform": "x86-64",
        "system": "enterprise",
        "model_type": "X86ENT",
    },
}


def normalize_device_map(raw_map: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    for device_name, raw_entry in raw_map.items():
        if not isinstance(raw_entry, Mapping):
            continue
        platform = str(raw_entry.get("platform") or "").strip()
        system = str(raw_entry.get("system") or "").strip()
        model_type = str(raw_entry.get("model_type") or "").strip()
        if not platform or not system or not model_type:
            continue
        normalized[str(device_name).lower()] = {
            "platform": platform,
            "system": system,
            "model_type": model_type,
        }
    return normalized


def save_device_map(path: Path, mapping: Mapping[str, Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_device_map(path: Path = DEVICE_MAP_FILE) -> dict[str, dict[str, str]]:
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise RuntimeError(f"invalid device map file: {path}")
        return normalize_device_map(raw)

    mapping = normalize_device_map(BUILTIN_DEVICE_MAP)
    save_device_map(path, mapping)
    return mapping


device_map = load_device_map()


@dataclass
class DeviceInfo:
    gwid: str
    platform: str
    secret: str
    system: str
    model_type: str


def add_device_map_entry(device_name: str, device: DeviceInfo) -> bool:
    key = device_name.lower()
    if key in device_map:
        return False

    device_map[key] = {
        "platform": device.platform,
        "system": device.system,
        "model_type": device.model_type,
    }
    save_device_map(DEVICE_MAP_FILE, device_map)
    return True


@dataclass(frozen=True)
class VersionAllFirmware:
    section: str
    key: str
    filename: str
    device_name: str


class TLSAdapter(HTTPAdapter):
    def __init__(self, ssl_context: ssl.SSLContext, **kwargs: Any) -> None:
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["ssl_context"] = self.ssl_context
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)


def debug(enabled: bool, message: str, *args: Any) -> None:
    if enabled:
        text = message % args if args else message
        print(f"[DEBUG] {text}", file=sys.stderr, flush=True)


def md5_file(path: Path) -> str | None:
    if not path.exists():
        return None

    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calc_sign(params: Mapping[str, str], secret: str, debug_enabled: bool) -> str:
    keys = sorted(key for key, value in params.items() if value)
    raw = "&".join(f"{key}={params[key]}" for key in keys)
    debug(debug_enabled, "sign string: %s", raw)
    sign = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    debug(debug_enabled, "sign result: %s", sign)
    return sign


def rand10() -> str:
    return "".join(str(random.randint(0, 9)) for _ in range(10))


def build_device_info(device_name: str) -> DeviceInfo:
    current_device = device_map.get(device_name.lower())
    if current_device is None:
        available = ", ".join(sorted(device_map))
        raise ValueError(f"unknown device: {device_name}; available devices: {available}")

    return DeviceInfo(
        gwid=DEVICE_GWID,
        platform=current_device["platform"],
        secret=DEVICE_SECRET,
        system=current_device["system"],
        model_type=current_device["model_type"],
    )


def validate_device_info(device: DeviceInfo, mode: str) -> None:
    missing = []
    if not device.gwid:
        missing.append("gwid")
    if not device.secret:
        missing.append("secret")
    if not device.model_type:
        missing.append("model_type")
    if mode not in DOWNLOAD_ALL_TARGETS and not device.platform:
        missing.append("platform")
    if mode not in DOWNLOAD_ALL_TARGETS and not device.system:
        missing.append("system")

    if missing:
        joined = ", ".join(missing)
        raise ValueError(f"missing device info: {joined}")


def new_insecure_session() -> requests.Session:
    session = requests.Session()
    session.verify = False
    return session


def new_mtls_session(ca_file: Path, cert_file: Path, key_file: Path) -> requests.Session:
    if MTLS_VERIFY_SERVER:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    session = requests.Session()
    session.verify = str(ca_file) if MTLS_VERIFY_SERVER else False
    session.mount("https://", TLSAdapter(context))
    return session


def request_api_json(
    session: requests.Session,
    method: str,
    url: str,
    headers: Mapping[str, str] | None,
    debug_enabled: bool,
) -> tuple[int, dict[str, Any]]:
    debug(debug_enabled, "%s %s", method, url)
    if headers:
        for key, value in headers.items():
            debug(debug_enabled, "header %s: %s", key, value)

    try:
        response = session.request(
            method=method,
            url=url,
            headers=dict(headers or {}),
            data="" if method == "POST" else None,
            allow_redirects=True,
            timeout=(10, 20),
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"request failed: {exc}") from exc

    debug(debug_enabled, "response [%d]: %s", response.status_code, response.text)

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{url} JSON decode error: {exc}") from exc
    return response.status_code, payload


def parse_api_data(payload: Mapping[str, Any], label: str) -> dict[str, Any]:
    code = payload.get("code")
    if code != 0:
        raise RuntimeError(f"{label} API error: code={code} message={payload.get('message', '')}")

    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} API response missing data")
    return data


def decode_version_all(content: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def parse_version_all_sections(raw_text: str) -> dict[str, dict[str, str]]:
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
        if current_section is None or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        sections[current_section][key.strip()] = value.strip()

    return sections


def firmware_keys_for_device(device: DeviceInfo) -> tuple[str, ...]:
    if device.platform == "x86":
        return ("firmware", "firmware_x64")
    if device.platform == "x86-64":
        return ("firmware_x64", "firmware")
    return ("firmware_x64", "firmware")


def select_version_all_firmware(
    sections: Mapping[str, Mapping[str, str]],
    device: DeviceInfo,
    include_beta: bool,
) -> list[VersionAllFirmware]:
    section_names = [device.model_type]
    if include_beta:
        section_names.append(f"{device.model_type}_BETA")

    result: list[VersionAllFirmware] = []
    for section_name in section_names:
        section = sections.get(section_name)
        if not section:
            if section_name == device.model_type:
                raise RuntimeError(f"Version_all missing section: {section_name}")
            continue

        for key in firmware_keys_for_device(device):
            filename = section.get(key, "").strip()
            if filename:
                result.append(VersionAllFirmware(section_name, key, Path(filename).name, device.model_type.lower()))
                break

    if not result:
        raise RuntimeError(f"Version_all missing firmware entry: {device.model_type}")
    return result


def normalize_firmware_filename(value: str) -> str:
    filename = value.strip()
    if not filename:
        return ""
    return Path(filename.split()[0]).name


def split_dev_section_type(section_name: str) -> tuple[str, str | None]:
    upper_name = section_name.upper()
    for firmware_type in DEV_FIRMWARE_TYPES:
        suffix = f"_{firmware_type}"
        if upper_name.endswith(suffix):
            return section_name[: -len(suffix)], firmware_type.lower()
    return section_name, None


def base_section_name(section_name: str) -> str:
    return split_dev_section_type(section_name)[0]


def section_device_name(section_name: str) -> str:
    return base_section_name(section_name).lower()


def version_all_edition(entry: VersionAllFirmware) -> str:
    _, dev_type = split_dev_section_type(entry.section)
    if dev_type:
        return dev_type

    base_name = base_section_name(entry.section)
    if base_name.upper() == "X86ENT":
        return "enterprise"
    if base_name.lower().endswith("_oem"):
        return "oem"
    return "free"


def version_all_device_name(entry: VersionAllFirmware) -> str:
    base_name = base_section_name(entry.section)
    lower_name = base_name.lower()
    if base_name.upper() in {"X86", "X86ENT"} or lower_name == "x86_oem":
        if entry.key == "firmware_x64" or "x64" in entry.filename.lower():
            return "x64"
        return "x86"
    if lower_name.endswith("_oem"):
        return lower_name[:-4]
    return lower_name


def version_all_relative_path(entry: VersionAllFirmware) -> Path:
    return Path("firmware") / version_all_device_name(entry) / version_all_edition(entry) / entry.filename


def entry_matches_device_filter(entry: VersionAllFirmware, normalized_filter: str | None) -> bool:
    if not normalized_filter:
        return True

    output_device_name = version_all_device_name(entry)
    if normalized_filter in {"x86", "x64"}:
        return output_device_name == normalized_filter

    return normalized_filter in {
        output_device_name,
        entry.device_name,
        entry.section.lower(),
        base_section_name(entry.section).lower(),
    }


def collect_public_version_all_firmware(
    sections: Mapping[str, Mapping[str, str]],
    include_beta: bool,
    device_filter: str | None,
    firmware_types: set[str] | None = None,
) -> list[VersionAllFirmware]:
    _ = include_beta
    normalized_filter = device_filter.lower() if device_filter else None
    if normalized_filter in {"all", "*"}:
        normalized_filter = None

    result: list[VersionAllFirmware] = []
    for section_name, section in sections.items():
        if section_name in {"GLOBAL", "APVER2"}:
            continue

        device_name = section_device_name(section_name)

        seen: set[str] = set()
        for key in FIRMWARE_KEYS:
            filename = normalize_firmware_filename(section.get(key, ""))
            if not filename or filename in seen:
                continue
            seen.add(filename)
            entry = VersionAllFirmware(section_name, key, filename, device_name)
            if firmware_types is not None and version_all_edition(entry) not in firmware_types:
                continue
            if entry_matches_device_filter(entry, normalized_filter):
                result.append(entry)

    return result


def dedupe_version_all_entries(entries: Iterable[VersionAllFirmware]) -> list[VersionAllFirmware]:
    result: list[VersionAllFirmware] = []
    seen: set[Path] = set()
    for entry in entries:
        relative_path = version_all_relative_path(entry)
        if relative_path in seen:
            continue
        seen.add(relative_path)
        result.append(entry)
    return result


def infer_system(section_name: str) -> str:
    return "enterprise" if base_section_name(section_name).upper() == "X86ENT" else "community"


def infer_platforms(entry: VersionAllFirmware) -> list[str]:
    filename = entry.filename.upper()
    if "_X64_" in filename or filename.startswith("OEM_X64_"):
        return ["x86-64", "x86"]
    if "_X32_" in filename:
        return ["x86", "x86-64"]
    if "MT762" in filename:
        return ["mips", "arm"]
    if any(token in filename for token in ("MT798", "IPQ", "MVL", "EN756", "RTL819")):
        return ["arm", "mips"]
    return ["arm", "mips", "x86-64", "x86"]


def device_info_candidates(entry: VersionAllFirmware) -> list[DeviceInfo]:
    candidates: list[DeviceInfo] = []

    def add(device: DeviceInfo) -> None:
        identity = (device.platform, device.system, device.model_type)
        if identity not in {(item.platform, item.system, item.model_type) for item in candidates}:
            candidates.append(device)

    device_key = DEVICE_KEY_OVERRIDES.get((base_section_name(entry.section), entry.key), entry.device_name)
    current_device = device_map.get(device_key)
    if current_device:
        add(build_device_info(device_key))
        if entry.section != current_device["model_type"]:
            add(
                DeviceInfo(
                    gwid=DEVICE_GWID,
                    platform=current_device["platform"],
                    secret=DEVICE_SECRET,
                    system=current_device["system"],
                    model_type=entry.section,
                )
            )

    section_model_type = entry.section
    base_model_type = base_section_name(entry.section)
    for model_type in dict.fromkeys([base_model_type, section_model_type]):
        for platform in infer_platforms(entry):
            add(
                DeviceInfo(
                    gwid=DEVICE_GWID,
                    platform=platform,
                    secret=DEVICE_SECRET,
                    system=infer_system(entry.section),
                    model_type=model_type,
                )
            )

    return candidates


def verify_device_with_cloud(args: argparse.Namespace, device: DeviceInfo) -> bool:
    try:
        request_version_all(new_insecure_session(), device, rand10(), args.debug)
        return True
    except RuntimeError as exc:
        debug(
            args.debug,
            "cloud verify failed: platform=%s system=%s modelType=%s error=%s",
            device.platform,
            device.system,
            device.model_type,
            exc,
        )
        return False


def persist_verified_new_devices(args: argparse.Namespace, entries: list[VersionAllFirmware]) -> None:
    checked: set[str] = set()
    for entry in entries:
        device_name = entry.device_name
        if device_name in device_map or device_name in checked:
            continue
        checked.add(device_name)

        for device in device_info_candidates(entry):
            if verify_device_with_cloud(args, device):
                if add_device_map_entry(device_name, device):
                    print(
                        "device-map-added: "
                        f"{device_name} platform={device.platform} "
                        f"system={device.system} model_type={device.model_type}"
                    )
                break


def collect_dev_type_firmware(args: argparse.Namespace, seed_entries: list[VersionAllFirmware]) -> list[VersionAllFirmware]:
    result: list[VersionAllFirmware] = []
    tried_model_types: set[str] = set()

    for seed_entry in seed_entries:
        for device in device_info_candidates(seed_entry):
            if device.model_type in tried_model_types:
                break
            tried_model_types.add(device.model_type)

            try:
                raw_version_all = fetch_version_all_content(args, device)
            except RuntimeError as exc:
                debug(
                    args.debug,
                    "dev Version_all failed: platform=%s system=%s modelType=%s error=%s",
                    device.platform,
                    device.system,
                    device.model_type,
                    exc,
                )
                continue

            sections = parse_version_all_sections(decode_version_all(raw_version_all))
            result.extend(
                collect_public_version_all_firmware(
                    sections,
                    include_beta=True,
                    device_filter=args.device,
                    firmware_types={"alpha", "beta"},
                )
            )
            break

    return result


def request_sign_url(
    session: requests.Session,
    device: DeviceInfo,
    firmware_name: str,
    nonce: str,
    debug_enabled: bool,
) -> dict[str, Any]:
    params = {
        "X-Device-Platform": device.platform,
        "X-Firmware-Name": firmware_name,
        "X-Gw-Id": device.gwid,
        "X-Nonce": nonce,
        "X-System-Version": device.system,
        "X-Model-Type": device.model_type,
    }
    sign = calc_sign(params, device.secret, debug_enabled)
    headers = {**params, "X-Sign": sign}

    status_code, payload = request_api_json(session, "POST", SIGN_URL_API, headers, debug_enabled)
    if status_code != 200:
        raise RuntimeError(f"sign-url HTTP error: {status_code}, body: {json.dumps(payload, ensure_ascii=False)}")
    return parse_api_data(payload, "sign-url")


def request_version_all(
    session: requests.Session,
    device: DeviceInfo,
    nonce: str,
    debug_enabled: bool,
) -> dict[str, Any]:
    params = {
        "X-Device-Platform": device.model_type,
        "X-Gw-Id": device.gwid,
        "X-Nonce": nonce,
    }
    sign = calc_sign(params, device.secret, debug_enabled)
    headers = {**params, "X-Sign": sign}

    status_code, payload = request_api_json(session, "GET", VERSION_ALL_API, headers, debug_enabled)
    if status_code != 200:
        raise RuntimeError(f"version-all HTTP error: {status_code}, body: {json.dumps(payload, ensure_ascii=False)}")
    return parse_api_data(payload, "version-all")


def fetch_version_all_content(args: argparse.Namespace, device: DeviceInfo) -> bytes:
    nonce = rand10()
    session = new_insecure_session()
    data = request_version_all(session, device, nonce, args.debug)
    file_url = data.get("fileUrl")
    if not file_url:
        raise RuntimeError("API response missing fileUrl")

    debug(args.debug, "download url: %s", file_url)
    try:
        with session.get(str(file_url), allow_redirects=True, timeout=(30, 60)) as response:
            if response.status_code != 200:
                raise RuntimeError(f"HTTP error: {response.status_code}")
            return response.content
    except requests.RequestException as exc:
        raise RuntimeError(f"download request failed: {exc}") from exc


def fetch_public_version_all_content(args: argparse.Namespace) -> bytes:
    session = new_insecure_session()
    headers = {"User-Agent": "Mozilla/5.0"}
    debug(args.debug, "GET %s", PUBLIC_VERSION_ALL_URL)
    try:
        with session.get(PUBLIC_VERSION_ALL_URL, headers=headers, allow_redirects=True, timeout=(10, 60)) as response:
            if response.status_code != 200:
                raise RuntimeError(f"HTTP error: {response.status_code}")
            return response.content
    except requests.RequestException as exc:
        raise RuntimeError(f"request failed: {exc}") from exc


def response_looks_like_html(response: requests.Response, first_chunk: bytes) -> bool:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True

    prefix = first_chunk.lstrip()[:64].lower()
    return prefix.startswith(b"<!doctype html") or prefix.startswith(b"<html")


def download_file(
    session: requests.Session,
    url: str,
    headers: Mapping[str, str] | None,
    output_file: Path,
    debug_enabled: bool,
) -> None:
    debug(debug_enabled, "download url: %s", url)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_name = tempfile.mkstemp(prefix=f"{output_file.name}.", suffix=".part", dir=str(output_file.parent))
    os.close(temp_fd)
    temp_path = Path(temp_name)

    def remove_temp_file() -> None:
        try:
            temp_path.unlink(missing_ok=True)
        except PermissionError:
            debug(debug_enabled, "cannot remove temp file: %s", temp_path)

    last_percent = -1
    try:
        with session.get(
            url,
            headers=dict(headers or {}),
            stream=True,
            allow_redirects=True,
            timeout=(30, 3600),
        ) as response:
            if response.status_code != 200:
                raise RuntimeError(f"HTTP error: {response.status_code}")

            total = int(response.headers.get("Content-Length", "0") or "0")
            downloaded = 0

            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    if downloaded == 0 and response_looks_like_html(response, chunk):
                        raise RuntimeError(f"download returned HTML: {url}")
                    handle.write(chunk)
                    downloaded += len(chunk)

                    if total > 0:
                        percent = downloaded * 100 // total
                        if percent != last_percent:
                            last_percent = percent
                            print(f"{percent}%", file=sys.stderr, flush=True)

            if total > 0 and last_percent < 100:
                print("100%", file=sys.stderr, flush=True)

        try:
            temp_path.replace(output_file)
        except PermissionError:
            shutil.copyfile(temp_path, output_file)
            remove_temp_file()
    except requests.RequestException as exc:
        remove_temp_file()
        raise RuntimeError(f"download request failed: {exc}") from exc
    except Exception:
        remove_temp_file()
        raise


def sync_version_all_file(args: argparse.Namespace, device: DeviceInfo, output_file: Path) -> None:
    local_md5 = md5_file(output_file) or ""
    if local_md5:
        debug(args.debug, "local file checksum: %s", local_md5)

    nonce = rand10()
    session = new_insecure_session()
    data = request_version_all(session, device, nonce, args.debug)

    debug(args.debug, "version-all data: %s", json.dumps(data, ensure_ascii=False))

    debug(
        args.debug,
        "versionType=%s isBeta=%s md5=%s",
        data.get("versionType"),
        data.get("isBeta"),
        data.get("md5"),
    )

    remote_md5 = str(data.get("md5") or "")
    if local_md5 and remote_md5 and local_md5.lower() == remote_md5.lower():
        return

    file_url = data.get("fileUrl")
    if not file_url:
        raise RuntimeError("API response missing fileUrl")

    download_file(session, str(file_url), None, output_file, args.debug)


def run_version_all(args: argparse.Namespace, device: DeviceInfo, device_name: str, output_dir: Path) -> int:
    if args.dry_run:
        raw_version_all = fetch_version_all_content(args, device)
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        version_all_file = output_dir / VERSION_ALL_FILENAME
        sync_version_all_file(args, device, version_all_file)
        raw_version_all = version_all_file.read_bytes()

    sections = parse_version_all_sections(decode_version_all(raw_version_all))
    entries = select_version_all_firmware(sections, device, args.include_beta)
    mtls_session: requests.Session | None = None
    failures: list[str] = []

    for entry in entries:
        output_file = output_dir / version_all_edition(entry) / entry.filename
        if output_file.exists() and not args.force:
            print(f"skipped: {output_file}")
            continue
        if args.dry_run:
            print(f"planned: {output_file}")
            continue

        try:
            nonce = rand10()
            session = new_insecure_session()
            data = request_sign_url(session, device, entry.filename, nonce, args.debug)

            sign_url = data.get("signUrl")
            token = data.get("token")
            if not sign_url:
                raise RuntimeError("sign-url API response missing signUrl")
            if not token:
                raise RuntimeError("sign-url API response missing token")

            if mtls_session is None:
                mtls_session = new_mtls_session(Path(args.ca_file), Path(args.cert_file), Path(args.key_file))
            headers = {
                "X-Auth-Token": str(token),
                "X-Gw-Id": device.gwid,
            }
            download_file(mtls_session, str(sign_url), headers, output_file, args.debug)
            print(f"downloaded: {output_file}")
        except RuntimeError as exc:
            message = f"{device_name}/{entry.filename}: {exc}"
            print(message, file=sys.stderr)
            failures.append(message)

    print(f"device={device_name} saved_dir={output_dir} planned={len(entries)} failed={len(failures)}")
    return 1 if failures else 0


def download_signed_entry(
    args: argparse.Namespace,
    entry: VersionAllFirmware,
    output_file: Path,
    mtls_session: requests.Session | None,
) -> requests.Session:
    errors: list[str] = []
    api_session = new_insecure_session()

    for device in device_info_candidates(entry):
        try:
            data = request_sign_url(api_session, device, entry.filename, rand10(), args.debug)

            sign_url = data.get("signUrl")
            token = data.get("token")
            if not sign_url:
                raise RuntimeError("sign-url API response missing signUrl")
            if not token:
                raise RuntimeError("sign-url API response missing token")

            if mtls_session is None:
                mtls_session = new_mtls_session(Path(args.ca_file), Path(args.cert_file), Path(args.key_file))
            headers = {
                "X-Auth-Token": str(token),
                "X-Gw-Id": device.gwid,
            }
            download_file(mtls_session, str(sign_url), headers, output_file, args.debug)
            return mtls_session
        except RuntimeError as exc:
            errors.append(f"{device.platform}/{device.system}/{device.model_type}: {exc}")

    raise RuntimeError("sign-url failed: " + " | ".join(errors[-3:]))


def run_public_version_all(args: argparse.Namespace, output_root: Path) -> int:
    raw_version_all = fetch_public_version_all_content(args)
    sections = parse_version_all_sections(decode_version_all(raw_version_all))
    entries = collect_public_version_all_firmware(sections, args.include_beta, args.device)
    if not entries:
        raise RuntimeError("Version_all has no firmware entries")
    persist_verified_new_devices(args, entries)
    entries = dedupe_version_all_entries([*entries, *collect_dev_type_firmware(args, entries)])

    mtls_session: requests.Session | None = None
    skipped = 0
    downloaded = 0
    failures: list[str] = []

    for entry in entries:
        relative_path = version_all_relative_path(entry)
        output_file = output_root / relative_path

        if output_file.exists() and not args.force:
            skipped += 1
            print(f"skipped: {relative_path.as_posix()}")
            continue
        if args.dry_run:
            print(f"planned: {relative_path.as_posix()} -> {output_file}")
            continue

        output_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            mtls_session = download_signed_entry(args, entry, output_file, mtls_session)
            downloaded += 1
            print(f"downloaded: {relative_path.as_posix()}")
        except RuntimeError as exc:
            message = f"{relative_path.as_posix()}: {exc}"
            print(message, file=sys.stderr)
            failures.append(message)

    print(
        f"devices={len({version_all_device_name(entry) for entry in entries})} "
        f"planned={len(entries)} downloaded={downloaded} skipped={skipped} failed={len(failures)}"
    )
    return 1 if failures else 0


def run_firmware(args: argparse.Namespace, device: DeviceInfo, firmware_name: str, output_file: Path) -> int:
    local_md5 = md5_file(output_file) or ""
    if local_md5:
        debug(args.debug, "local file checksum: %s", local_md5)

    nonce = rand10()
    session = new_insecure_session()
    data = request_sign_url(session, device, firmware_name, nonce, args.debug)

    if data.get("md5Verified") and data.get("md5Match"):
        debug(args.debug, "already up to date (md5 match, ossMD5=%s)", data.get("ossMD5"))
        return 0

    sign_url = data.get("signUrl")
    token = data.get("token")
    if not sign_url:
        raise RuntimeError("sign-url API response missing signUrl")
    if not token:
        raise RuntimeError("sign-url API response missing token")

    mtls_session = new_mtls_session(Path(args.ca_file), Path(args.cert_file), Path(args.key_file))
    headers = {
        "X-Auth-Token": str(token),
        "X-Gw-Id": device.gwid,
    }
    download_file(mtls_session, str(sign_url), headers, output_file, args.debug)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Python firmware downloader compatible with download.lua.lua",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug output")
    parser.add_argument(
        "--device",
        default=None,
        help="device profile from device_map; all/Version_all uses all devices when omitted",
    )
    parser.add_argument("target", help="firmware name, Version_all, all, or download-all")
    parser.add_argument(
        "output_path",
        nargs="?",
        help="output file path; all/Version_all mode uses this as output root",
    )
    parser.add_argument("--force", action="store_true", help="redownload existing firmware files in all/Version_all mode")
    parser.add_argument("--dry-run", action="store_true", help="parse Version_all and print firmware download plan")
    parser.add_argument("--include-beta", action="store_true", help="deprecated; alpha/beta entries are included")
    parser.add_argument("--ca-file", default=str(DEFAULT_CA), help="CA certificate for mTLS download")
    parser.add_argument("--cert-file", default=str(DEFAULT_CERT), help="client certificate for mTLS download")
    parser.add_argument("--key-file", default=str(DEFAULT_KEY), help="client private key for mTLS download")
    return parser.parse_args()


def main() -> int:
    random.seed()
    args = parse_args()
    mode = args.target

    try:
        if mode in DOWNLOAD_ALL_TARGETS:
            output_root = Path(args.output_path) if args.output_path else ROOT_DIR
            return run_public_version_all(args, output_root)

        device_name = args.device or DEFAULT_DEVICE_KEY
        device = build_device_info(device_name)
        validate_device_info(device, mode)
        debug(
            args.debug,
            "device: gwid=%s platform=%s system=%s modelType=%s",
            device.gwid,
            device.platform,
            device.system,
            device.model_type,
        )
        if not args.output_path:
            raise ValueError("missing output file path")
        output_file = Path(args.output_path)
        return run_firmware(args, device, mode, output_file)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        if mode in DOWNLOAD_ALL_TARGETS:
            if "missing fileUrl" in str(exc):
                return 3
            if "HTTP error" in str(exc):
                return 4
            return 2
        if "HTTP error" in str(exc):
            return 3
        return 2


if __name__ == "__main__":
    sys.exit(main())
