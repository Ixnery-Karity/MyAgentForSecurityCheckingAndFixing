from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from .llm import ask_json


SAMPLE_LOG = (
    '192.168.1.55 - - [10/Oct/2023:13:55:36 -0700] '
    '"GET /login.php?user=admin%27%20OR%201=1-- HTTP/1.1" 200 2326'
)


def _fallback_analysis(log_line: str) -> dict[str, Any]:
    decoded = unquote(log_line)
    signatures = {
        "SQL Injection": [r"(?i)\bor\s+1\s*=\s*1", r"(?i)union\s+select", r"--"],
        "Cross-Site Scripting": [r"(?i)<script", r"(?i)javascript:"],
        "Command Injection": [r"(?i);\s*(?:cat|id|whoami|curl|wget)\b", r"\$\("],
        "Path Traversal": [r"\.\./", r"\.\.\\"],
    }
    matched = [name for name, patterns in signatures.items() if any(re.search(pattern, decoded) for pattern in patterns)]
    malicious = bool(matched)
    return {
        "is_malicious": malicious,
        "attack_type": ", ".join(matched) if matched else "None",
        "threat_level": "High" if malicious else "Low",
        "analysis_reason": "检测到已知攻击特征" if malicious else "未匹配常见 Web 攻击特征",
        "engine": "rules",
    }


def analyze_web_log(log_line: str, use_llm: bool = True) -> dict[str, Any]:
    fallback = _fallback_analysis(log_line)
    if not use_llm:
        return fallback

    system_prompt = (
        "你是 Web 安全日志分析员。仅输出 JSON，字段必须为 is_malicious、"
        "attack_type、threat_level、analysis_reason。"
    )
    user_prompt = f"分析以下访问日志并识别 SQL 注入、XSS、命令注入或路径穿越：\n{log_line}"
    try:
        result = ask_json(system_prompt, user_prompt)
        required = {"is_malicious", "attack_type", "threat_level", "analysis_reason"}
        if not required.issubset(result):
            raise ValueError("模型响应缺少日志分析字段")
        level_map = {"低": "Low", "中": "Medium", "高": "High", "严重": "Critical"}
        result["threat_level"] = level_map.get(str(result["threat_level"]), result["threat_level"])
        result["is_malicious"] = bool(result["is_malicious"])
        result["engine"] = "llm"
        return {**fallback, **result}
    except Exception as exc:
        fallback["fallback_reason"] = str(exc)
        return fallback
