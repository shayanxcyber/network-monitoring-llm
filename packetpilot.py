"""Local, offline-first entry point. No live capture or network enforcement."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for area in (
    "01-llm-interface", "02-network-simulation", "03-packet-analysis",
    "04-application-workflow", "05-safe-network-response", "06-testing-evaluation",
):
    sys.path.insert(0, str(ROOT / "components" / area))

if __name__ == "__main__":
    from pp_operator import main
    raise SystemExit(main(ROOT))
