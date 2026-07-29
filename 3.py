"""兼容入口：演示 IOC 调查工具。"""

import json
import sys

from security_agent.investigation import investigate_iocs


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    result = investigate_iocs(["8.8.8.8"], "c3lz.R2V0U2hlbGwoKQ==")
    print(json.dumps(result, ensure_ascii=False, indent=2))
