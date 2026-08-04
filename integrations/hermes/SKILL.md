---
name: sentinelflow-security
description: Run authorized SentinelFlow security assessments for IPv4, domains, and HTTP(S) URLs.
---

# SentinelFlow Security Assessment

Use the `sentinelflow_security_assessment` MCP tool when it is available. Pass
the complete target exactly as provided by the operator, including an
`http://` or `https://` scheme when present.

Use rules-only mode by default. Set `use_llm=true` only when the project has a
configured compatible AI endpoint. Ask for the scope and authorization before
any real network activity; the bundled scanner is safe simulation only and
does not run Nmap or exploit code.

If the MCP tool is unavailable, run the CLI fallback from the SentinelFlow
project root:

```bash
python 1.py --target 'https://example.internal/app' --no-llm
```

Return the structured report, including target resolution, severity, IOC data,
safe-simulation results, and recommended action. Never claim that an external
service was scanned when the report says `safe-simulation`.
