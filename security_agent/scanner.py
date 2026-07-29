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


def scan_lab_target(ip: str) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    if not address.is_private:
        return {
            "target": ip,
            "mode": "safe-simulation",
            "services": [],
            "note": "安全模式仅对预置内网靶机资产返回模拟扫描结果",
        }
    return {
        "target": ip,
        "mode": "safe-simulation",
        "services": LAB_ASSETS.get(ip, []),
        "note": "未执行真实网络扫描",
    }


def search_vulnerabilities(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for service in scan_result.get("services", []):
        key = f"{service['service']} {service['version']}"
        for vulnerability in KNOWN_VULNERABILITIES.get(key, []):
            findings.append({"service": key, **vulnerability})
    return findings
