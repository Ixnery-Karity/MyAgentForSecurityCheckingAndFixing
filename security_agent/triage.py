from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .llm import ask_json


SAMPLE_ALERTS = [
    {
        "alert_id": "WAF-001",
        "type": "SQL Injection Attempt",
        "source_ip": "114.114.114.114",
        "payload": "SELECT * FROM users WHERE username='admin' --",
        "target_url": "/login.php",
        "http_status": 403,
    },
    {
        "alert_id": "IDS-002",
        "type": "Multiple Failed Logins",
        "source_ip": "192.168.1.50",
        "payload": "Failed password for root from 192.168.1.50 port 55321 ssh2",
        "target_url": "SSH Service",
        "http_status": None,
    },
]


def _extract_ips(alert: dict[str, Any]) -> list[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps(alert))
    valid: list[str] = []
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            if candidate not in valid:
                valid.append(candidate)
        except ValueError:
            continue
    return valid


def _fallback_triage(alert: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(alert, ensure_ascii=False).lower()
    blocked = alert.get("http_status") in {401, 403}
    high_risk = any(token in text for token in ("sql injection", "select ", "union ", "root", "rce"))
    severity = "High" if high_risk else "Medium"
    action = "Auto-Close" if blocked and high_risk else "Escalate to L2"
    if high_risk and not blocked:
        action = "Block IP"
    return {
        "severity": severity,
        "extracted_iocs": _extract_ips(alert),
        "analysis": "规则引擎识别到高风险攻击特征" if high_risk else "需要进一步调查的异常行为",
        "action": action,
        "engine": "rules",
    }


def triage_alert(alert: dict[str, Any], use_llm: bool = True) -> dict[str, Any]:
    fallback = _fallback_triage(alert)
    if not use_llm:
        return fallback

    system_prompt = (
        "你是 SOC L1 研判专家。只输出 JSON，字段为 severity、extracted_iocs、analysis、action。"
        "severity 只能是 Low/Medium/High/Critical；action 只能是 Auto-Close、Escalate to L2、Block IP。"
    )
    try:
        result = ask_json(system_prompt, json.dumps(alert, ensure_ascii=False))
        required = {"severity", "extracted_iocs", "analysis", "action"}
        if not required.issubset(result):
            raise ValueError("模型响应缺少告警分诊字段")
        severity_map = {"低": "Low", "中": "Medium", "高": "High", "严重": "Critical"}
        result["severity"] = severity_map.get(str(result["severity"]), result["severity"])
        if result["severity"] not in {"Low", "Medium", "High", "Critical"}:
            result["severity"] = fallback["severity"]
        raw_iocs = result["extracted_iocs"]
        if not isinstance(raw_iocs, list):
            raw_iocs = list(raw_iocs.values()) if isinstance(raw_iocs, dict) else [raw_iocs]
        normalized_iocs = _extract_ips({"values": raw_iocs})
        result["extracted_iocs"] = normalized_iocs or fallback["extracted_iocs"]
        if result["action"] not in {"Auto-Close", "Escalate to L2", "Block IP"}:
            result["action"] = fallback["action"]
        result["engine"] = "llm"
        return {**fallback, **result}
    except Exception as exc:
        fallback["fallback_reason"] = str(exc)
        return fallback
