"""Non-secret project settings and a separate, private per-user API key."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pp_llm import APIConfig


def key_path():
    return Path.home() / ".config" / "packetpilot" / "secrets.env"


def api_config(root, secret_file=None):
    values = tomllib.loads((Path(root) / "settings.toml").read_text(encoding="utf-8"))["provider"]
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    path = Path(secret_file) if secret_file is not None else key_path()
    if not key and path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition("=")
            if separator and name.strip() == "DEEPSEEK_API_KEY":
                key = value.strip()
                break
    return APIConfig(values["base_url"], values["model"], key,
                     timeout=values["timeout_seconds"], thinking=values["thinking"], retries=0,
                     reasoning_effort=values.get("reasoning_effort", ""),
                     max_output_tokens=values.get("max_output_tokens"))
