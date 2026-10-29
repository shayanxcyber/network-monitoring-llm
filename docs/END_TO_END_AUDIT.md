# Historical end-to-end audit - 13 October 2026

Historical record for investigator 3.5. Results, gaps and configuration below describe that checkpoint, not current 3.25/4.16 capabilities or current suite totals. See [latest validation](VALIDATION.md) and [current integration](LLM_INTEGRATION.md).

PacketPilot was checked using six fresh synthetic PCAPs, three supported
TShark TSV exports, repeated investigations and six follow-ups. Two further
PCAP variants and one log variant were reserved until after the fixes.
Fresh traffic for response trials came only from the disconnected Linux lab.

## Changes

- TCP exchange matching retains the earliest valid final ACK. Later ACK/data
  records no longer make an otherwise matched handshake ambiguous. Repeated
  SYNs, conflicting replies and equal-time candidates remain qualified.
- Numeric source byte offsets belong in exact checked measurements rather
  than unchecked prose. Guidance and a narrow output guard enforce this for
  new answers without invalidating historical saved conversations.
- SQLAlchemy's asyncio extra supplies the missing clean-install dependency.
- Retrying an earlier question preserves the next draft, including across
  source changes and reload. Only submitting a new draft clears that draft.
- Response progression labels are contained within their own items, removing
  unintended outer-page overflow at laptop, desktop and widescreen sizes.

Harness: `packetpilot-investigator-3.5`; TCP relationships: `1.1`; reviewed
guidance: `1.4`. The provider's actual model identifier was `deepseek-flash`.
Thinking was enabled with maximum effort. The identifier alone is not a
verified numbered model release. Existing request/run/tool limits were kept.

## Evidence and verification

Ubuntu: 291 passed. Windows development checks: 289 passed with two real
TShark-unavailable skips. Frontend: 37 passed and a successful locked build.
The actual Linux decoder was independently cross-checked against TShark and
original packet/log bytes. A separate clean application environment installed,
imported, served configuration and passed dependency checks. Normal use serves
the prebuilt interface from Python; frontend rebuilding is not needed to run it.

| Phase | Accepted answers | Model calls | Evidence-tool calls |
|---|---:|---:|---:|
| Initial repeated cases and follow-ups | 24/24 | 44 | 41 |
| Affected-case retest | 6/6 | 13 | 11 |
| Guarded log-provenance retest | 2/2 | 5 | 5 |
| Final untouched variants | 3/3 | 8 | 8 |

These denominators are structural acceptance, not accuracy. All attempts are
retained, including a wrong-offset answer that survived a guidance-only fix.
The checked-measurement guard was then tested separately. Semantic review still
found occasional overbroad coverage wording, clause-local citation weaknesses,
repetition and an unverified TSV example with overly broad missing-field advice.
Use original records and analyst judgment; no universal correctness is claimed.

## Real response trials

Normal interface approval was used for an exact TCP/8080 temporary block and a
512 kbit/s service-scoped rate limit. The selected client's block took effect
while the control remained reachable. The measured selected rate was about
497.5 kbit/s; the unaffected control was about 572,469 kbit/s in that isolated
test. Both rules were manually restored and removal/effect were verified.

A further approved 60-second block expired through the independent broker
while the unprivileged web application was stopped. Restart restored access to
saved history and terminal receipts. Wrong/missing confirmation, expired
approval, stale/offline mapping, unsupported targets, cross-source requests and
duplicate/replay cases were checked. Recovery fault paths also passed in
separate controlled test instances. A new live privileged-broker restart was
not performed because administrator authentication was unavailable. It is not
presented as a fresh live crash test.

The audit ended with no audit-created active rules or pending approvals. The
broker's operation catalogue, authority boundary and SSH management path were
not widened. No arbitrary model command was executed.

The original development archive retains this checkpoint's source, traces, reports and measurements separately from the public code. Private credentials and runtime histories are not repository fixtures. This historical record does not describe the current publication or submission state.
