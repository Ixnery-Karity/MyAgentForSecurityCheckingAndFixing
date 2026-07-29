from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .investigation import investigate_iocs
from .log_analyzer import analyze_web_log
from .scanner import scan_lab_target, search_vulnerabilities
from .triage import triage_alert


EventCallback = Callable[[dict[str, Any]], None]


class SecurityWorkflow:
    def run(
        self,
        alert: dict[str, Any],
        log_line: str = "",
        target_ip: str = "",
        allow_external_lookup: bool = False,
        use_llm: bool = True,
        on_event: EventCallback | None = None,
    ) -> dict[str, Any]:
        workflow_id = f"WF-{uuid.uuid4().hex[:8].upper()}"
        events: list[dict[str, Any]] = []

        def emit(stage: str, detail: str, data: Any = None) -> None:
            event = {
                "stage": stage,
                "status": "completed",
                "detail": detail,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if data is not None:
                event["data"] = data
            events.append(event)
            if on_event:
                on_event(event)

        emit("ingest", "告警与日志已进入流水线")
        log_result = analyze_web_log(log_line, use_llm=use_llm) if log_line else None
        emit("analysis", "Web 日志分析完成", log_result)

        triage_result = triage_alert(alert, use_llm=use_llm)
        emit("triage", "SOC L1 告警分诊完成", triage_result)

        iocs = list(triage_result.get("extracted_iocs") or [])
        if target_ip and target_ip not in iocs:
            iocs.append(target_ip)
        investigation = investigate_iocs(iocs, str(alert.get("payload") or ""), allow_external_lookup)
        emit("investigation", "IOC 与载荷调查完成", investigation)

        scan_target = target_ip or next((ip for ip in iocs if ip.startswith(("10.", "172.", "192.168."))), "")
        scan_result = scan_lab_target(scan_target) if scan_target else None
        vulnerabilities = search_vulnerabilities(scan_result) if scan_result else []
        emit("assessment", "靶机资产与漏洞关联完成", {"scan": scan_result, "vulnerabilities": vulnerabilities})

        risk = self._risk_score(log_result, triage_result, vulnerabilities)
        report = {
            "workflow_id": workflow_id,
            "status": "completed",
            "risk_score": risk,
            "severity": self._score_to_severity(risk),
            "recommended_action": triage_result.get("action", "Escalate to L2"),
            "summary": self._summary(log_result, triage_result, vulnerabilities),
            "log_analysis": log_result,
            "triage": triage_result,
            "investigation": investigation,
            "scan": scan_result,
            "vulnerabilities": vulnerabilities,
            "events": events,
        }
        emit("report", "Manager 已生成最终安全报告")
        report["events"] = events
        return report

    @staticmethod
    def _risk_score(log_result: dict[str, Any] | None, triage: dict[str, Any], vulnerabilities: list[dict[str, Any]]) -> int:
        score = {"Low": 20, "Medium": 45, "High": 70, "Critical": 90}.get(str(triage.get("severity")), 45)
        if log_result and log_result.get("is_malicious"):
            score += 10
        if vulnerabilities:
            score += 15
        return min(score, 100)

    @staticmethod
    def _score_to_severity(score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 65:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    @staticmethod
    def _summary(log_result: dict[str, Any] | None, triage: dict[str, Any], vulnerabilities: list[dict[str, Any]]) -> str:
        parts = [str(triage.get("analysis", "告警已完成研判"))]
        if log_result and log_result.get("is_malicious"):
            parts.append(f"日志检测到 {log_result.get('attack_type')} 特征")
        if vulnerabilities:
            parts.append(f"关联到 {len(vulnerabilities)} 个已知漏洞")
        return "；".join(parts) + "。"


def main() -> None:
    parser = argparse.ArgumentParser(description="运行内网靶机安全检查 Agent")
    parser.add_argument("--target", default="192.168.3.73")
    parser.add_argument("--no-llm", action="store_true")
    args = parser.parse_args()
    alert = {
        "alert_id": "LAB-001",
        "type": "Suspicious Web Request",
        "source_ip": args.target,
        "payload": "c3lz.R2V0U2hlbGwoKQ==",
        "target_url": "/login.php?user=admin%27%20OR%201=1--",
        "http_status": 200,
    }
    log_line = f'{args.target} - - [29/Jul/2026:12:00:00 +0800] "GET {alert["target_url"]} HTTP/1.1" 200 2326'
    result = SecurityWorkflow().run(alert, log_line, args.target, use_llm=not args.no_llm)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
