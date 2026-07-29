from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from .config import settings


def _extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```json").removeprefix("```")
        cleaned = cleaned.removesuffix("```").strip()
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        value = json.loads(cleaned[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("模型输出不是 JSON 对象")
    return value


def _response_content(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        if "choices" in response:
            return str(response["choices"][0]["message"]["content"])
        return json.dumps(response, ensure_ascii=False)
    return response.choices[0].message.content or "{}"


def ask_json(system_prompt: str, user_prompt: str) -> dict[str, Any]:
    if not settings.llm_enabled:
        raise RuntimeError("未配置 AI_API_KEY 或 AI_MODEL_NAME")

    client = OpenAI(api_key=settings.api_key, base_url=settings.base_url)
    request: dict[str, Any] = {
        "model": settings.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
    }
    try:
        response = client.chat.completions.create(
            **request,
            response_format={"type": "json_object"},
        )
    except Exception:
        response = client.chat.completions.create(**request)

    return _extract_json(_response_content(response))
