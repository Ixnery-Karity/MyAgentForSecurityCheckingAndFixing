# Kali Linux + Hermes Agent

## Conclusion

可以使用。当前项目是普通 Python Agent，Kali Linux 只需要 Python 3、虚拟环境和项目依赖。Hermes Agent 可以通过本地 stdio MCP 服务器把 SentinelFlow 注册为一个原生工具；也可以只安装一个 Hermes skill，让 Hermes 通过本地终端调用 `1.py`。

推荐 MCP 方式：它不需要把 SentinelFlow Web 端口暴露给网络，参数是结构化的，返回值是结构化 JSON，且当前扫描器默认只做安全模拟。

## 1. 安装 SentinelFlow

在 Kali 上使用非 root 用户和独立虚拟环境：

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
git clone https://github.com/Ixnery-Karity/MyAgentForSecurityCheckingAndFixing.git ~/sentinelflow
cd ~/sentinelflow
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-hermes.txt
cp .env.example .env
chmod 600 .env
```

在 `.env` 中配置项目自己的 `AI_API_KEY`、`AI_BASE_URL` 和
`AI_MODEL_NAME`。`AI_BASE_URL` 应是 OpenAI 兼容接口地址；项目会将只有
域名的地址规范化为 `/v1`。

## 2. 安装 Hermes

使用 Hermes 官方 Linux 安装器，然后执行初始化：

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
source ~/.bashrc
hermes setup
```

Hermes 的 Linux 安装、模型配置和安全设置以官方文档为准。Kali 本身不
需要特殊补丁。

## 3. 注册 MCP 工具

编辑当前 Hermes profile 的 `~/.hermes/config.yaml`，加入：

```yaml
mcp_servers:
  sentinelflow:
    command: "/home/kali/sentinelflow/.venv/bin/python"
    args:
      - "/home/kali/sentinelflow/integrations/hermes_mcp.py"
```

把路径换成实际路径，然后重新启动 Hermes，或使用 Hermes 提供的 MCP
重载命令。工具名称是 `sentinelflow_security_assessment`，例如让 Hermes
执行：

```text
在已授权的内网靶场中，使用 SentinelFlow 检查 https://lab.example/app，先使用规则模式，不要执行真实扫描。
```

首次启动如果提示缺少 MCP SDK，确认已经在 SentinelFlow 的 `.venv` 中执行
过 `pip install -r requirements-hermes.txt`。

## 4. 可选：安装 Hermes skill

skill 不是 MCP 的替代品，而是给 Hermes 的流程约束和 CLI 兜底说明：

```bash
mkdir -p ~/.hermes/skills/sentinelflow-security
cp integrations/hermes/SKILL.md ~/.hermes/skills/sentinelflow-security/SKILL.md
```

之后可以在 Hermes 中使用 `/sentinelflow-security`，或者让它在 MCP 不可用
时运行：

```bash
python 1.py --target 'https://lab.example/app' --no-llm
```

## 5. 安全边界

- 当前工具只解析目标、做 DNS 解析并查询预置靶机数据；不发起 HTTP 请求，不运行 Nmap，不执行漏洞利用。
- Hermes 建议保留 `approvals.mode: smart` 或 `manual`，不要关闭命令审批。
- 在 Kali 上不要以 root 运行 Hermes 或 SentinelFlow；靶场实验使用专用低权限账号和明确网段。
- 如果未来加入真实扫描，必须增加目标白名单、命令审批、速率限制、审计日志和单独的容器/网络命名空间。
- 不要把 stdio MCP 改成公网 HTTP；跨主机部署时需要认证、TLS、来源限制和防火墙规则。

## References

- Hermes Agent: https://github.com/NousResearch/hermes-agent
- Hermes Skills: https://hermes-agent.nousresearch.com/docs/user-guide/features/skills
- Hermes MCP: https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp
- Hermes Security: https://hermes-agent.nousresearch.com/docs/user-guide/security
- Hermes AI Providers: https://hermes-agent.nousresearch.com/docs/integrations/providers
