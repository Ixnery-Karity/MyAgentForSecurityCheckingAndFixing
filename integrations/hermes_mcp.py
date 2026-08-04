"""Expose SentinelFlow as a local stdio MCP server for Hermes Agent."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - depends on optional Hermes install
    FastMCP = None

from security_agent.workflow import SecurityWorkflow


def create_server():
    if FastMCP is None:
        raise RuntimeError("Hermes MCP adapter requires the optional 'mcp' package")

    server = FastMCP(
        "sentinelflow",
        instructions=(
            "Authorized security assessment tool for an isolated lab. "
            "It parses IPv4, domains, and HTTP(S) URLs, resolves DNS, "
            "runs safe simulation checks, and returns a structured report. "
            "It does not perform real network scanning."
        ),
    )

    @server.tool()
    def sentinelflow_security_assessment(
        target: str,
        alert_json: str = "",
        log_line: str = "",
        use_llm: bool = False,
        allow_external_lookup: bool = False,
    ) -> str:
        """Assess one authorized IPv4, domain, or HTTP(S) URL.

        The default is rules-only mode. Set use_llm=true only when the local
        project .env has a compatible AI endpoint configured.
        """
        if len(target) > 2048 or len(alert_json) > 100_000 or len(log_line) > 100_000:
            return json.dumps({"error": "输入长度超过安全限制"}, ensure_ascii=False)
        try:
            alert = json.loads(alert_json) if alert_json.strip() else {}
            if not isinstance(alert, dict):
                return json.dumps({"error": "alert_json 必须是 JSON 对象"}, ensure_ascii=False)
            alert.setdefault("alert_id", "HERMES-001")
            alert.setdefault("type", "Authorized target assessment")
            alert.setdefault("target", target)
            report = SecurityWorkflow().run(
                alert=alert,
                log_line=log_line,
                target=target,
                use_llm=use_llm,
                allow_external_lookup=allow_external_lookup,
            )
            return json.dumps(report, ensure_ascii=False)
        except (ValueError, json.JSONDecodeError) as exc:
            return json.dumps({"error": str(exc)}, ensure_ascii=False)
        except Exception as exc:
            return json.dumps({"error": f"工作流执行失败: {exc}"}, ensure_ascii=False)

    return server


def main() -> None:
    if FastMCP is None:
        raise SystemExit("安装 Hermes 适配依赖: python -m pip install -r requirements-hermes.txt")
    import asyncio

    async def run_server() -> None:
        await create_server().run_stdio_async()

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
