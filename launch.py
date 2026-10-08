"""Start the local application if necessary, then open Ubuntu's browser."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import tomllib
import webbrowser
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
PORT = tomllib.loads((ROOT / "settings.toml").read_text(encoding="utf-8"))["application"]["port"]
URL = f"http://127.0.0.1:{PORT}/"


def ready():
    try:
        with urlopen(URL + "api/config", timeout=2) as response:
            return json.loads(response.read(8192)).get("application") == "PacketPilot"
    except (OSError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not ready():
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", PORT)) == 0:
                raise SystemExit("The chosen local port is occupied by another application. Nothing was stopped.")
        if os.name != "nt":
            os.umask(0o077)
        log_dir = ROOT / "runtime"
        log_dir.mkdir(exist_ok=True)
        with (log_dir / "server.log").open("ab") as log:
            process = subprocess.Popen(
                [sys.executable, str(ROOT / "app.py")], cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True,
            )
        for _ in range(40):
            if ready():
                break
            if process.poll() is not None:
                raise SystemExit("PacketPilot could not start. Check runtime/server.log.")
            time.sleep(.25)
        else:
            raise SystemExit("PacketPilot is still starting. Try the launcher again shortly.")
    print("PacketPilot is ready at " + URL)
    if not args.no_browser:
        webbrowser.open(URL, new=2)


if __name__ == "__main__":
    main()
