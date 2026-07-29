"""兼容入口：运行完整安全检查 Agent。"""

import sys

from security_agent.workflow import main


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    main()
