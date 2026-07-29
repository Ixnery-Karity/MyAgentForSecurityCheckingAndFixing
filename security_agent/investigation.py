from __future__ import annotations

import base64
import ipaddress
import json
from typing import Any
from urllib.request import urlopen


def decode_base64(payload: str) -> dict[str, Any]:
    if not payload:
        return {"attempted": False, "decoded": None}
    try:
        decoded_parts = []
        for part in payload.strip().split("."):
            padding = "=" * (-len(part) % 4)
            decoded_parts.append(base64.b64decode(part + padding, validate=True).decode("utf-8", errors="replace"))
        decoded = ".".join(decoded_parts)
        return {"attempted": True, "decoded": decoded}
    except Exception as exc:
        return {"attempted": True, "decoded": None, "error": str(exc)}


def get_ip_location(ip: str, allow_external_lookup: bool = False) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    base = {
        "ip": ip,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "scope": "internal" if address.is_private else "public",
    }
    if not allow_external_lookup or address.is_private:
        return base
    try:
        with urlopen(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=4) as response:
            data = json.loads(response.read().decode("utf-8"))
        if data.get("status") == "success":
            base.update(country=data.get("country"), city=data.get("city"), isp=data.get("isp"))
    except (OSError, json.JSONDecodeError) as exc:
        base["lookup_error"] = str(exc)
    return base


def investigate_iocs(
    iocs: list[str],
    payload: str = "",
    allow_external_lookup: bool = False,
) -> dict[str, Any]:
    locations = []
    for ioc in iocs:
        try:
            locations.append(get_ip_location(ioc, allow_external_lookup))
        except ValueError:
            locations.append({"ip": ioc, "error": "无效 IP 地址"})
    return {
        "ip_enrichment": locations,
        "payload_decoding": decode_base64(payload),
    }
