"""Start PacketPilot inside Ubuntu: .venv/bin/python app.py"""
from __future__ import annotations

import os
import tomllib

import packetpilot
from pp_web import create_app

if os.name != "nt":
    os.umask(0o077)

app = create_app(packetpilot.ROOT)

if __name__ == "__main__":
    import uvicorn
    settings = tomllib.loads((packetpilot.ROOT / "settings.toml").read_text(encoding="utf-8"))
    uvicorn.run(app, host="127.0.0.1", port=settings["application"]["port"],
                access_log=False, log_level="warning")
