"""Save observed test outcomes without claiming model inference or VM execution."""
from __future__ import annotations

import argparse
import io
import json
import platform
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--environment-label", default="Unspecified host; VM location not inferred")
    args = parser.parse_args()
    destination = Path(args.output)
    if destination.exists():
        raise SystemExit("Choose a new report filename; existing results are preserved.")
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_*.py")
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    record = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"os": platform.system(), "python": platform.python_version()},
        "tests_run": result.testsRun,
        "passed": result.testsRun - len(result.errors) - len(result.failures) - len(result.skipped),
        "failed": len(result.failures), "errors": len(result.errors),
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "successful": result.wasSuccessful(),
        "external_model_inference": False,
        "environment_label": args.environment_label,
        "vm_location": "Not automatically inferred; interpret the supplied environment label.",
        "scope": "Controlled host checks; loopback HTTP response stub, not external model inference.",
        "output": stream.getvalue(),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")
    print(stream.getvalue())
    print(f"Saved: {destination}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
