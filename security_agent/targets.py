from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit


DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def normalize_target(value: str) -> dict[str, Any]:
    """Parse an IPv4 address, hostname, or HTTP(S) URL without making a request."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("目标不能为空")
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"目标端口无效: {exc}") from exc
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("仅支持 http:// 和 https:// 目标 URL")
    if parsed.username or parsed.password:
        raise ValueError("目标 URL 不允许携带账号或密码")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise ValueError("无法从目标中解析主机名")

    try:
        ipaddress.ip_address(hostname)
        host_kind = "ipv4"
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("域名编码无效") from exc
        if not DOMAIN_PATTERN.fullmatch(hostname):
            raise ValueError("目标必须是 IPv4、合法域名或 http(s) URL")
        host_kind = "domain"

    is_url = bool(parsed.scheme)
    scheme = parsed.scheme.lower() if is_url else None
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return {
        "input": raw,
        "kind": "url" if is_url else host_kind,
        "host_kind": host_kind,
        "hostname": hostname,
        "scheme": scheme,
        "port": port or default_port,
        "path": parsed.path or ("/" if is_url else ""),
        "query": parsed.query,
        "is_private": ipaddress.ip_address(hostname).is_private if host_kind == "ipv4" else None,
    }


def resolve_target(target: dict[str, Any], perform_dns: bool = True) -> dict[str, Any]:
    """Resolve a hostname only; this function never connects to the target service."""
    result = dict(target)
    hostname = target["hostname"]
    if target["host_kind"] == "ipv4":
        result["resolved_ips"] = [hostname]
        result["resolution"] = "literal"
        return result
    if not perform_dns:
        result["resolved_ips"] = []
        result["resolution"] = "skipped"
        return result
    try:
        addresses = socket.getaddrinfo(hostname, target.get("port") or 0, type=socket.SOCK_STREAM)
        resolved = []
        for _, _, _, _, sockaddr in addresses:
            address = sockaddr[0]
            if address not in resolved:
                resolved.append(address)
        result["resolved_ips"] = resolved
        result["resolution"] = "resolved" if resolved else "no-record"
    except OSError as exc:
        result["resolved_ips"] = []
        result["resolution"] = "error"
        result["resolution_error"] = str(exc)
    return result
