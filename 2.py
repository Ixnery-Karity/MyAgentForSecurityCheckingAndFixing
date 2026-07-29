"""兼容入口：演示 Web 日志分析模块。"""

import json
import sys

from security_agent.log_analyzer import SAMPLE_LOG, analyze_web_log


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    print(json.dumps(analyze_web_log(SAMPLE_LOG), ensure_ascii=False, indent=2))
