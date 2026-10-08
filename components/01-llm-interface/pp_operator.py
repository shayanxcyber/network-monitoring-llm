"""Readable terminal workflow for capture selection, questions and evidence review."""
from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import textwrap
from pathlib import Path

from pp_evidence import analyse_capture
from pp_llm import LLMError
from pp_samples import make_samples
from pp_workflow import run_analysis

DEFAULT_QUESTION = "Does this traffic need checking, and why?"


def _paragraph(text):
    return "\n".join(textwrap.fill(line, 88) for line in str(text).splitlines())


def render_report(result, evidence, directory):
    explanation = result["explanation"]
    answer = explanation["answer"]
    if answer.get('schema_version') in ('2.0', '3.0'):
        lines = ['PACKETPILOT | Evidence-led investigation', '=' * 64, 'LIVE API RESPONSE',
                 f'Question: {result["question"]}', '', 'ASSESSMENT', answer['assessment'],
                 _paragraph(answer['summary']), '', 'OBSERVATIONS']
        for observation in answer['observations']:
            lines.extend([_paragraph(observation['text']), 'References: ' + ', '.join(observation['references'])])
        lines.extend(['', 'INTERPRETATION', _paragraph(answer['interpretation']), '', 'ALTERNATIVES',
                      *map(_paragraph, answer['alternatives']), '', 'UNCERTAINTY', *map(_paragraph, answer['uncertainty']),
                      '', 'COVERAGE: ' + answer['coverage']['status'], *map(_paragraph, answer['coverage']['limitations']),
                      '', 'ADVICE ONLY - NOTHING EXECUTED'])
        for item in answer['recommendations']:
            lines.append(_paragraph(f'{item["action"]}: {item["rationale"]}'))
        if explanation.get('harness_version'):
            lines.extend(['', 'INVESTIGATION OPERATIONS',
                          f'Model calls: {explanation["attempts"]}; tool calls: {len(explanation["tool_trace"])}; corrections: {explanation["correction_attempts"]}'])
            for step in explanation['tool_trace']:
                lines.append(f'{step["tool"]}: {"completed" if step["ok"] else "rejected"} — {step["arguments"]}')
        lines.extend(['', 'QUESTIONS FOR OPERATOR', *map(_paragraph, answer['questions']),
                      '', explanation['review_note'], f'Saved records: {directory}'])
        return '\n'.join(lines) + '\n'
    label = "LIVE API RESPONSE" if explanation["source"] == "api" else "RULE-BASED RESULT - NO LLM OUTPUT"
    if explanation["status"] == "fallback_after_api_failure":
        label = "API UNAVAILABLE - RULE-BASED FALLBACK"
    lines = [
        "PACKETPILOT | Traffic review", "=" * 64, label,
        f'Question: {result["question"]}', "",
        "WHAT THE CAPTURE SHOWS", _paragraph(answer["summary"]), "",
        "WHY", _paragraph(answer["why"]), "",
        "WHAT TO CHECK NEXT", _paragraph(answer["next_step"]), "",
        "EVIDENCE",
    ]
    for fact in evidence["facts"]:
        lines.extend([f'[{fact["id"]}]', _paragraph(fact["text"]),
                      "Packet references: " + ", ".join(map(str, fact["packet_refs"]))])
    response = result["response"]
    lines.extend([
        "", "RESPONSE PREVIEW",
        f'Type: {response["action"]} | State: {response["state"]} | Executed: NO',
        f'Target: {response["target"] or "not applicable"}',
        _paragraph(response["operator_note"]),
    ])
    lines.extend(_paragraph(reason) for reason in response["reasons"])
    if explanation.get("api_error"):
        lines.extend(["", _paragraph(explanation["api_error"]["message"])])
    lines.extend(["", "LIMITS", *[_paragraph("- " + item) for item in result["limitations"]],
                  _paragraph(explanation["review_note"]), "",
                  f'Decoder: {evidence["decoder"]["version"]}',
                  f'Run: {result["run_id"]}', f"Saved records: {directory}"])
    return "\n".join(lines) + "\n"


def _run(args, cached=None, question=None):
    client = None
    if args.provider == 'api':
        from pp_agent import AgnoClient
        from pp_settings import api_config
        import uuid
        root = Path(__file__).resolve().parents[2]
        if not hasattr(args, 'agent_session'):
            args.agent_session = str(uuid.uuid4())
        client = AgnoClient(api_config(root), root / 'runtime/agent-history.sqlite3', args.agent_session)
    result, evidence, directory = run_analysis(
        Path(args.capture), Path(args.output), question or args.question,
        args.provider, args.decoder, args.preview, args.target, args.duration, args.apply,
        cached_evidence=cached, client=client,
    )
    report = render_report(result, evidence, directory)
    (directory / "operator-report.txt").write_text(report, encoding="utf-8")
    print(report)
    if not result["response"]["allowed_preview"]:
        return 3
    if result["explanation"]["status"] == "fallback_after_api_failure":
        return 2
    return 0


def _arguments(root):
    parser = argparse.ArgumentParser(description="Review a saved, controlled lab capture.")
    sub = parser.add_subparsers(dest="command", required=True)
    samples = sub.add_parser("make-samples", help="Create the two synthetic examples; sends no traffic.")
    samples.add_argument("--output", default=str(root / "sample-data"))
    sub.add_parser("check", help="Show tool/configuration presence; never prints an API key.")
    for name in ("analyse", "chat"):
        command = sub.add_parser(name, help="Review a capture" if name == "analyse" else "Ask repeated questions about one capture")
        command.add_argument("--capture", required=True)
        command.add_argument("--output", default=str(root / "runs"))
        command.add_argument("--question", default=DEFAULT_QUESTION)
        command.add_argument("--provider", choices=("rules", "api"), default="rules")
        command.add_argument("--decoder", choices=("auto", "scapy", "tshark"), default="auto")
        command.add_argument("--preview", choices=("no_action", "investigate", "block_source"), default="investigate")
        command.add_argument("--target")
        command.add_argument("--duration", type=int, default=60)
        command.add_argument("--apply", action="store_true", help="Not supported; explicitly rejected and audited.")
    return parser


def main(root):
    args = _arguments(root).parse_args()
    try:
        if args.command == "make-samples":
            manifest = make_samples(Path(args.output))
            print("Created/verified two synthetic saved captures. No network traffic was sent.")
            for case in manifest["cases"]:
                print(f'{case["file"]}: {case["packets"]} packets; {case["purpose"]}')
            return 0
        if args.command == "check":
            print("Python Scapy:", "available" if importlib.util.find_spec("scapy") else "missing")
            print("TShark:", "available" if shutil.which("tshark") else "not on PATH")
            print("API model configured:", bool(os.environ.get("PACKETPILOT_MODEL")))
            print("API key configured:", bool(os.environ.get("PACKETPILOT_API_KEY")))
            print("No VM/SSH, external model or live network was contacted.")
            return 0
        if args.command == "analyse":
            return _run(args)
        cached = analyse_capture(Path(args.capture), args.decoder)
        print("Capture loaded once. Each question creates a new traceable run. Type quit to finish.")
        print("In rules mode, answers are fixed summaries, not open-ended LLM conversation.")
        while True:
            try:
                question = input("\nQuestion> ").strip()
            except EOFError:
                return 0
            if question.lower() in {"quit", "exit"}:
                return 0
            if not question:
                continue
            try:
                _run(args, cached, question)
            except (ValueError, LLMError) as exc:
                print(f"Could not answer: {exc}")
    except (ValueError, LLMError, ImportError) as exc:
        print(f"Stopped: {exc}")
        return 2
    except OSError:
        print("Stopped: a file or tool could not be accessed. Check the capture/output paths.")
        return 2
    except KeyboardInterrupt:
        print("\nStopped by operator. No network action was applied.")
        return 130
