"""兼容入口：演示 SOC 告警分诊模块。"""

import json
import sys

from security_agent.triage import SAMPLE_ALERTS, triage_alert


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    for alert in SAMPLE_ALERTS:
        print(json.dumps(triage_alert(alert), ensure_ascii=False, indent=2))
