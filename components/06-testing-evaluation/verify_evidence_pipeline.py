"""Retain real offline extraction results; never requests a model or sends traffic."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import packetpilot
from pp_evidence import analyse_capture
from evidence_cases import case_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "upgraded"), required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {
        "recorded_at": datetime.now(timezone.utc).isoformat(), "phase": args.phase,
        "command": [sys.executable, *sys.argv], "platform": platform.platform(),
        "python": platform.python_version(), "external_model_calls": False,
        "traffic_sent": False, "source_sha256": {}, "cases": [],
        "note": "Synthetic traffic timestamps are fixture clocks, not activity dates. Results are extraction evidence, not AI detection accuracy.",
    }
    for path in sorted((ROOT / "components").rglob("*.py")):
        report["source_sha256"][path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name, (content, label) in case_bytes().items():
        target = args.output / (name + ".pcap")
        target.write_bytes(content)
        case = {"id": name, "label": label, "sha256": hashlib.sha256(content).hexdigest(), "results": {}}
        for decoder in ("scapy", "tshark"):
            if decoder == "tshark" and not shutil.which("tshark"):
                case["results"][decoder] = {"status": "skipped", "reason": "TShark not on PATH"}
                continue
            try:
                evidence = analyse_capture(target, decoder)
                filename = f"{name}-{decoder}.json"
                (args.output / filename).write_text(json.dumps(evidence, indent=2, allow_nan=False) + "\n", encoding="utf-8")
                case["results"][decoder] = {"status": "decoded", "finding": evidence["finding"], "evidence": filename}
            except ValueError as exc:
                case["results"][decoder] = {"status": "rejected", "error": str(exc)}
        report["cases"].append(case)
        if shutil.which("tshark"):
            from pp_packet_records import TSHARK_FIELDS
            command = [shutil.which("tshark"), "-n", "-r", str(target), "-o", "ip.defragment:FALSE", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
            for field in TSHARK_FIELDS:
                command.extend(["-e", field])
            raw = subprocess.run(command, capture_output=True, text=True, timeout=20, check=True)
            filename = name + "-tshark-fields.tsv"
            (args.output / filename).write_text(raw.stdout, encoding="utf-8")
            case["independent_extraction"] = {"command": command, "field_order": list(TSHARK_FIELDS), "output": filename, "returncode": raw.returncode}
    report["negative_inputs"] = []
    for name, content in (("missing", None), ("empty", b""), ("corrupt-record", case_bytes()["normal"][0][:-1])):
        target = args.output / (name + ".pcap")
        if content is not None:
            target.write_bytes(content)
        try:
            analyse_capture(target, "scapy")
            report["negative_inputs"].append({"id": name, "rejected": False})
        except ValueError as exc:
            report["negative_inputs"].append({"id": name, "rejected": True, "reason": str(exc)})
    report["validation"] = []
    if args.phase == "upgraded":
        from jsonschema import Draft202012Validator, FormatChecker
        schema = json.loads((ROOT / "components/03-packet-analysis/evidence-v2.schema.json").read_text())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for case in report["cases"]:
            for decoder, result in case["results"].items():
                if result["status"] == "skipped":
                    continue
                if result["status"] != "decoded":
                    report["validation"].append({"case": case["id"], "decoder": decoder, "passed": False, "reason": "Expected usable observations"})
                    continue
                evidence = json.loads((args.output / result["evidence"]).read_text())
                errors = [error.message for error in validator.iter_errors(evidence)]
                if case["id"].startswith("mixed-") and evidence["finding"] != "scan_like":
                    errors.append("Mixed capture erased the eight supported TCP attempts")
                report["validation"].append({"case": case["id"], "decoder": decoder, "passed": not errors, "errors": errors})
        report["successful"] = all(item["passed"] for item in report["validation"]) and all(item["rejected"] for item in report["negative_inputs"])
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"phase": args.phase, "cases": report["cases"]}, indent=2))
    if args.phase == "upgraded" and not report["successful"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
