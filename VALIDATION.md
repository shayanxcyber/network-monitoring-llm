# PacketPilot validation

## Current retained verification

A clean handoff installation initially exposed a missing greenlet dependency while importing Agno's SQLite adapter. The incomplete run had 274 passing tests and one import error because the adapter test module could not load. requirements-app.txt now requests SQLAlchemy's asyncio extra so the dependency is installed explicitly. The corrected clean-install run passed all 285 tests with no failures, errors or skips. The original failure remains in the internal packaging evidence.

The latest complete Ubuntu offline regression passed 285 tests, with zero failures, errors or skips. The separate frontend regression passed 35 checks. These verify software behaviour, including controlled provider protocols, not attack-detection accuracy or newly hosted inference.

The extraction experiment compares seven labelled PCAP cases in two decoder modes, giving fourteen checks. It verifies selected Scapy/TShark fields and original-reference/coverage behaviour. Since both read the same supplied capture, agreement is not independent attack ground truth.

The answer-quality comparison uses six cases repeated twice per arm. Structural acceptance improved from 10/12 baseline responses to 12/12 refined responses. All attempts remain in the internal evidence record. One refined partial-evidence answer needed its permitted correction; semantic review still found overly broad or weakly supported wording. Accepted output is not automatically a correct interpretation.

Actual disconnected Linux block and rate-limit effects, selected/control comparisons and restoration were measured separately. Browser journeys and durable/export checks are also distinct. Do not add stage regression totals together or equate mocked response tests with real enforcement.

The current handoff guide carries readable selected screenshots and captions. Historical reports and private traces are not copied into the public code payload. Reproduce offline checks with run_checks.py using a new output path; hosted evaluators and privileged lab experiments require separate explicit execution.

## Historical August record

The complete earlier record below is retained for chronology. Its then-current capabilities, missing features, paths and counts describe that stage, not this release.


## Ubuntu result at the August checkpoint

**71 checks passed, zero failures/errors/skips.** This includes the actual
TShark/Scapy cross-check, Agno history and error handling, web routes, persistent
reviews, upload bounds, exports, request idempotency and provider-neutral UI copy.

Machine-readable record:
../validation/2026-08-31-ubuntu-final-branding.json

Earlier guest reports are retained at
../validation/2026-08-31-ubuntu-core-fixed.json (48 checks) and
../validation/2026-08-31-ubuntu-app-checks.json (70 checks).
The first guest run exposed different TShark Boolean output in Ubuntu 4.2.2;
the parser now accepts both textual and numeric Boolean representations.

Environment: Ubuntu 24.04.4 LTS, Python 3.12.3, Scapy 2.7.0,
TShark/Wireshark 4.2.2, Agno 3.0.4 and the isolated application dependencies.
See [VM checkpoint](VM_CONTINUATION.md) for the full installed-tool inventory.
Expected 401/429 and invalid-response messages in the automated suite come from
controlled local stubs, not additional paid provider requests.

## Actual hosted-model smoke check

Saved review: 42f44873-aa4d-48c4-8c78-008f4e85ad7e.
Both questions used the same generated port-check capture through the Agno-backed
application, with deepseek-v4-flash, thinking disabled and a 900-token output limit.
These are technical provenance fields, not operator-interface branding.

| Turn | Run ID | What was checked | Provider-reported tokens |
|---|---|---|---:|
| 1 | fee9101d-e4b2-4a98-b451-6ab0d2ba7df7 | Explain the eight-port pattern and retain the authorised-maintenance possibility | 938 |
| 2 | f624f3f0-d75c-4598-8d77-9aaf6662d500 | Explain SYN simply in the same conversation | 1,438 |

Total: **2,376 tokens**, two successful requests, one attempt each. The second
request contained four messages rather than two: standing instructions, the first
question and answer, and the follow-up. Saved review/answers survived a backend
restart and were displayed again in the browser.

Run JSON, evidence and audit files are retained in the matching ../runs/ folders,
copied from the guest without copying any credential. A separate Ubuntu/TShark
rules run is d80538fa-8c7c-4a1c-9477-9d8c715682ee.

The capture SHA-256 is:
d216826aafc171d40eca69695e81a41176912a6399cdb9979472e25afb1a8471

The model explanation correctly identifies the short multi-port pattern and
acknowledges a benign explanation. The SYN follow-up also exposes an improvement:
the supplied fact text does not explicitly enumerate TCP flags, so part of the
answer infers them and asks the operator to check. Add explicit flag facts and
evaluate explanation accuracy later; do not call this a perfect answer benchmark.

## Interface and safety checks

- AI and offline reviews are clearly distinguished; fallback never masquerades as AI.
- Packet evidence, both saved answers and a permitted 60-second response preview
  remain readable after restart. The preview states **NOT EXECUTED**.
- New-review controls, linked evidence and review export are available.
- The light UI has a compact desktop side-panel layout without page-wide horizontal overflow.
- Operator labels no longer show the provider brand; actual audit/configuration identifiers are preserved.
- A real UI screenshot and complete JSON review export were saved through the
  Windows SSH-forwarded preview in ../evidence/. This is the Ubuntu backend, not
  a separate host build. Native VMware UI input was unreliable, so screenshots
  use the user-approved Windows browser route; Wireshark's desktop layout was not
  separately visually signed off. Its installed process and TShark decoding work.
- No live packets were transmitted, no firewall rule was applied and no Pro request was made.
- No GitHub push, slide deck or official LabArchives entry was produced in this setup.

This verifies a bounded integration path, not general detection accuracy, useful
performance under constrained resources or a finished network-control product.
Live topology, independent scenarios, explanation-quality scoring and any future
executor/rollback remain separate work.

## Historical pre-VM validation

The following records describe the earlier host-only phase, not the current setup.

Environment: the Windows host, using the already available isolated Python
3.12.13 / Scapy 2.7.0 environment. Ubuntu was not opened or modified. No package
was installed globally and no external model call was made.

## Observed result

47 checks ran: 46 passed, 0 failed, 0 errors, 1 skipped.

The skipped check compares actual TShark and Scapy decoding. TShark is not
installed on this host and must be checked inside Ubuntu. The Windows warning
about no libpcap provider does not prevent these saved-file operations; no live
capture was attempted.

Machine-readable record: ../validation/2026-08-31-host-checks.json

The checks cover:

- deterministic fixtures; complete/invalid/truncated PCAP handling;
- normal versus port-check examples, source separation and threshold/window boundaries;
- API request construction, HTTPS configuration and redirect refusal;
- correct, malformed, oversized, incomplete and contradictory model-shaped responses;
- unknown/cross-capture evidence references and extra command fields;
- authentication failures, bounded retry and connection failure;
- protected/out-of-scope targets, durations and rejected execution;
- traceable run records, fallback labelling and preservation of earlier results.

One HTTP round trip used a local controlled response server. That verifies
transport/protocol handling, not external inference or model quality.

## Actual example runs

| Example | Result | Run ID |
|---|---|---|
| Normal | Nine packets, two destination service ports; no scan pattern found. | b41b69e8-afa4-4334-9f3e-fedd32eaef4e |
| Port check | Eight connection attempts to eight server ports in 0.7 seconds; review required. | c8cc006e-f785-49b0-9e42-344d182e92c6 |

Both are Scapy-decoded, rule-based host runs. The second includes a permitted
60-second block preview for 10.77.0.30. Neither applied a network change.
Their evidence, readable reports, JSON results and audit records are in ../runs/.

## Remaining at the pre-VM checkpoint (historical)

Ubuntu package/setup verification; SSH access; actual TShark comparison; selected
provider/model configuration; real model responses and usefulness review; browser
interface; live topology; traffic-control execution; presentation screenshots and slides.

The number of functional tests is not a detection accuracy percentage. These two
constructed examples are not independent or real-world attack benchmarking.
