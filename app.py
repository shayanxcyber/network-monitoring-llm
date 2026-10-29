"""Start PacketPilot inside Ubuntu: .venv/bin/python app.py"""
from __future__ import annotations

import os
import tomllib

import packetpilot
from pp_web import create_app
from pp_response_client import ResponseClient

if os.name != "nt":
    os.umask(0o077)

settings = tomllib.loads((packetpilot.ROOT / "settings.toml").read_text(encoding="utf-8"))
app = create_app(packetpilot.ROOT,response_client=ResponseClient(enabled=settings['application'].get('lab_enabled',True)))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=settings["application"]["port"],
                access_log=False, log_level="warning")
