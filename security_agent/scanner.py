from __future__ import annotations

import ipaddress
from typing import Any


LAB_ASSETS = {
    "192.168.3.73": [
        {"port": 22, "service": "SSH", "version": "OpenSSH 8.2"},
        {"port": 80, "service": "Apache HTTP Server", "version": "2.4.49"},
    ],
    "192.168.1.50": [{"port": 22, "service": "SSH", "version": "OpenSSH 8.2"}],
}

KNOWN_VULNERABILITIES = {
    "Apache HTTP Server 2.4.49": [
        {
            "cve": "CVE-2021-41773",
            "severity": "Critical",
            "summary": "路径穿越及在特定配置下的远程代码执行风险",
        }
    ]
}


def scan_lab_target(target: str, resolved_ips: list[str] | None = None) -> dict[str, Any]:
    resolved_ips = list(resolved_ips or [])
    candidates = [target, *resolved_ips]
    lab_ip = next((candidate for candidate in candidates if candidate in LAB_ASSETS), None)
    if not lab_ip:
        return {
            "target": target,
            "mode": "safe-simulation",
            "resolved_ips": resolved_ips,
            "services": [],
            "note": "安全模式仅对预置内网靶机资产返回模拟扫描结果，未执行真实网络扫描",
        }
    return {
        "target": target,
        "mode": "safe-simulation",
        "resolved_ips": resolved_ips,
        "matched_lab_ip": lab_ip,
        "services": LAB_ASSETS[lab_ip],
        "note": "已匹配预置内网靶机资产，未执行真实网络扫描",
    }


def search_vulnerabilities(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for service in scan_result.get("services", []):
        key = f"{service['service']} {service['version']}"
        for vulnerability in KNOWN_VULNERABILITIES.get(key, []):
            findings.append({"service": key, **vulnerability})
    return findings
