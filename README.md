# SentinelFlow Security Agent

一个面向已授权内网靶场的安全检查 Agent。项目将原有八个代码入口整合为完整工作流，并提供可视化 Web 控制台。目标输入同时支持 IPv4、域名和完整 `http(s)` URL，例如 `https://freemodel.dev/dashboard/usage`。

## 工作流

1. **事件接入**：规范化告警 JSON 与 Web 日志。
2. **目标解析**：识别 IPv4、域名或 URL，提取主机、端口、路径并进行 DNS 解析。
3. **日志分析**：识别 SQL 注入、XSS、命令注入和路径穿越特征。
4. **SOC 分诊**：评估严重度、提取 IOC、给出处置建议。
5. **IOC 调查**：识别 IP 范围并解码 Base64 载荷。
6. **资产评估**：对预置内网靶机执行安全模拟扫描并关联本地 CVE 数据。
7. **Manager 报告**：计算风险分数并生成最终结论。

LLM 不可用或返回格式异常时，系统会自动降级到本地规则引擎。扫描模块默认只返回预置靶场数据，不执行真实网络扫描。

## 快速启动

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python server.py
```

打开 `http://127.0.0.1:8000`。

## 命令行

```powershell
python 1.py --target 192.168.3.73
python 1.py --target 192.168.3.73 --no-llm
python 1.py --target https://freemodel.dev/dashboard/usage --no-llm
python 2.py
python 3.py
python 4.py
```

## 测试

```powershell
python -m unittest discover -s tests -v
```

## 配置

| 变量 | 说明 |
| --- | --- |
| `AI_API_KEY` | OpenAI 兼容接口密钥 |
| `AI_BASE_URL` | OpenAI 兼容接口地址 |
| `AI_MODEL_NAME` | 模型名称 |
| `AGENT_HOST` | Web 服务监听地址，默认 `127.0.0.1` |
| `AGENT_PORT` | Web 服务端口，默认 `8000` |

## 安全边界

仅在你拥有明确授权的系统和内网靶场中使用。默认扫描器为安全模拟模式；公网 IP 地理查询也需要在页面中显式启用。
