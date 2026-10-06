# Harness and investigation v3

## Implemented flow

Selected saved PCAP → validated packet/flow observations → bounded context and
previously inspected evidence → Agno investigation → optional Python inspection
tools → typed final answer and evidence checks → one corrective attempt if needed
→ saved review, public trace and private continuity → operator response preview.

Python remains responsible for capture validation, extraction, normalization,
neutral calculations, storage, validation and controls. The hosted model decides
what the observations suggest and which inspection would help. It is not forced
to reproduce the legacy comparator's verdict. No model weights are trained.
Agno/SDK remain dependencies; the PacketPilot tools and wrappers were implemented
for this application, not copied from another agent's source.

## Instructions, state and tools

Agno's description/instructions composition supplies system context; there is no
overriding complete system_message. Investigator policy and reviewed-guidance
are separate versioned files. The Pydantic InvestigationAnswer schema is supplied
in JSON mode and checked again locally.

| Function | Operation | Boundary |
|---|---|---|
| get_packets | Return 1–16 selected packet records | Backend-selected capture only |
| get_flow | Flow totals and a page of up to 16 packet records | Stable alias, explicit next offset |
| summarize_connections | Directional protocol/port/flag counts, duration and payload-size/hash statistics | Validated protocol and lab-address/port filters |
| inspect_tcp_exchanges | Candidate reverse replies, raw-header sequence checks and directional SYN-service breadth | Same immutable evidence; no intent or threat verdict |

These functions run Python on immutable retained evidence. TShark/Scapy extraction
has already run; a tool call does not relaunch TShark for available fields. There
is no filename, shell, generic display-filter or live-network tool. Useful
unsupported fields remain a parser extension, not invented observations.

Small supported captures retain full detail. Initial context is bounded to 96
packet/flow records and 180,000 bytes; omissions are explicitly counted and can
be inspected with tools. Tool results are bounded to 48,000 bytes. Flow and
aggregate membership are retained in provenance. Short model-side references
map to capture-SHA-qualified IDs in answers/exports. Whole-capture aggregates
describe decoded records, never excluded frames.

Harness 3.4 adds a scalar measurement catalogue and evidence-capability flags.
The exchange tool distinguishes initiator service ports from return ephemeral
ports, and cites the SYN, candidate reply and final ACK separately. Classic PCAP
sequence/acknowledgement fields can verify header relationships. A saved field
log lacks those fields, so matching tuples, flags and times remain candidates.
Repeated/equal-time candidates are marked ambiguous. These checks do not prove
application success, authorisation, complete capture coverage or maliciousness.
Registered Agno tools return canonical JSON, not Python dictionary text. See
[answer-quality refinement and limits](ANSWER_QUALITY.md).

Successful questions save capture-scoped state: inspected IDs, bounded evidence
selectors, previous model observations, unresolved questions and pending previews.
Selectors rehydrate original facts for follow-ups, rather than using prior model
prose as evidence. Native history contains the latest three successful runs.
Session scope includes review, capture, harness version, provider/model and
reasoning settings; failed attempts do not become successful history.
Prompt/context/schema hashes are retained in each result.

## Validation and budgets

Final JSON has a typed v3 contract; tool requests have separate strict argument
checks before Agno coercion. Unknown/cross-capture citations, incorrect copied
measurements and unsafe preview parameters are rejected. One precise correction
can repair final JSON; the rejected response stays saved. Repair cannot call
tools. There are no automatic transport/authentication retries.

- Thinking remains enabled with maximum configured reasoning effort.
- Per request: 65,536 generation tokens and a 300-second caller deadline.
  Increased after repeat 32,768-token length exhaustion on a real lab question;
  see the 2 October response-milestone budget review. Maximum is an allowance,
  not a target; larger limits do not establish better semantic accuracy.
- Per investigation: six provider calls, eight tools, 600 seconds and 65,536
  cumulative completion tokens; no new call after 240,000 total usage.
- The total-usage threshold is checked between calls, not a precomputed currency
  cap. Prompt tokens count and repeated tool calls cost more.
- Timeout returns control without publishing a late result. Provider cancellation
  is best effort; a timed-out request may still finish or bill.
- Refusals, incomplete completions and exhausted limits are explicit failures,
  not silently presented as successful model assessments.

Validation is not proof of truth. An existing citation may support only part of
a sentence. Directionality, speculation and claim scope need qualitative review.

## Privacy and visibility

The configured hosted service receives structured evidence, bounded payload
previews, questions and relevant history. This is a data transfer even though the
raw PCAP is not uploaded. Use authorised lab captures.

Genuine provider reasoning is retained privately where required for tool/history
continuity; it is excluded from public request records, UI and exports. Private
history SQLite files are excluded from Git and owner-restricted on Ubuntu.
Keys remain outside source/settings. Agno telemetry, redirects, environment
proxies and SDK automatic retries are disabled.

The UI exposes actual tool names, arguments/results, correction count, failures,
timings, usage and saved state in expandable traces. References open original
records. Exports retain public trace and provenance. Traces show completed
operations, not streaming progress. Old reviews retain their original contract.

## Reviewed lessons and remaining scope

Reusable guidance covers single-service retries versus multi-port probing,
claim-level citations, coverage versus intent and concise explanations. It is
explicitly loaded, not autonomous global memory, case labels, raw failure
archives or continuous model learning.

The parser supports the documented classic Ethernet/outer IPv4 TCP/UDP subset.
Unsupported protocols, fragments, truncation and malformed data are reported.
It is not a universal decoder, stream-reassembly system or live collector.
Business authorisation cannot be established from a PCAP alone.

Approval → Linux execution → verification → rollback/expiry is now implemented
for one fixed disconnected lab service, through a separate root-owned broker.
Neither tool access nor a recommendation grants permission to act.
See [Linux response and its boundaries](LINUX_RESPONSE.md).
One typed saved-log format is implemented; see [saved field logs](SAVED_FIELD_LOGS.md).
UI redesign and broader evaluation remain separately tracked.
No generic script skills, extra model or autonomous lessons were added without
a demonstrated need.

## Reproduce checks

From the project root, using the project interpreter:

    python components/06-testing-evaluation/run_checks.py --output NEW_REPORT.json --environment-label YOUR_HOST
    python components/06-testing-evaluation/evaluate_investigator.py --suite smoke --output NEW_SMOKE_FOLDER --live
    python components/06-testing-evaluation/evaluate_investigator.py --suite comparison --output NEW_COMPARISON_FOLDER --live

Live commands use the configured API/key and incur requests. The comparison
declares six earlier cases repeated three times plus six development contrasts
before calls. Every attempt is retained. Mechanical acceptance and semantic
review are separate; these cases do not establish real-world detection accuracy.
The development completion audit holds observed results.

The 3 October quality comparison declares six new contrasts, twice per arm,
before any calls. Use the retained cases and a new output directory:

    python components/06-testing-evaluation/evaluate_quality.py --live --cases CASE_FOLDER --output NEW_OUTPUT_FOLDER --arm refined

The synthetic case expectations are evaluation material, not agent instructions.
Before/after code, inputs, settings and all attempts are retained in the dated
development pack. A combined harness/tool revision is not a model-only experiment.
