# PacketPilot workspace and response v4

Verified development checkpoint: 4 October 2026. This supersedes earlier
preview-only browser guidance, not the historical answers or CLI behaviour.

## Everyday workflow

1. Open the existing local application. In the current Ubuntu installation use
   `/home/capstone/packetpilot/.venv/bin/python app.py`. The Windows SSH-forwarded
   browser address is `http://127.0.0.1:8768`; the guest listens locally on 8765.
2. Choose a sample, upload a supported PCAP or eleven-field TShark TSV log, or
   reopen a saved investigation. Opening evidence does not call the model.
3. Ask a question. Ordinary greetings do not invent a packet report or action.
   Investigations use evidence, explicit coverage, original references and
   bounded inspection tools. Successful source-scoped history supports follow-ups.
4. Inspect cited packets, flows, lines or aggregates. Export keeps the source,
   public answers, traces and linked action records together, without approval
   tokens, credentials or private reasoning.

The workspace uses available desktop width with adjustable evidence/conversation
panels. Paragraph widths stay readable. The sidebar can collapse; drafts and
reading positions belong to their source. Busy feedback is attached to the
composer. Controlled retry and same-request IDs prevent accidental duplicate
turns; reloading observes a running request rather than starting another one.

## Suggestions are not execution

An investigation/no-action recommendation is useful advice, not an execution
button. Command examples include a target, assumptions, expected effect,
reversal and relevant evidence. Copy/download works, but examples are labelled
**unverified**. There is no general terminal tool and no generated-text executor.

The model can inspect current lab status and prepare a validated response-plan
template. That does not create an approval token or change the network. Current
state observations are timestamped separately from saved capture evidence.

## Supported actions

The optional privileged broker remains inside four disconnected Linux namespaces.
There is no external interface, gateway or default route. Fixed source
10.77.0.20, control 10.77.0.30 and service 10.77.0.10 TCP/8080 are the only mapping.

| Operation | Actual effect | Parameters |
|---|---|---|
| Temporary service block | Exact service INPUT drop for the selected source | 5-120 seconds |
| Temporary service rate limit | HTB/flower shapes service replies toward the selected source | 256-2048 kbit/s, 5-120 seconds |

For a current broker-issued capture, choose **Review proposed action**, then
**Prepare exact proposal**. Read the source, service, duration, rate where
relevant, exact commands, expected effect and reversal. Approval is separate and
uses the displayed phrase and one-time token. The model cannot approve it.

The application binds the saved answer/turn/recommendation, evidence, capture
hash, lab generation and exact parameters. Stale, altered, duplicate, replayed,
cross-review or out-of-scope requests are rejected. A historical upload cannot
authorise a current change; its next step is a fresh current-lab capture, not
silent address substitution. Unsupported operations remain unavailable.

Cancellation makes no change. An approved change is verified, then manually
rolled back or independently expired. Startup recovery revokes pending approvals
and reverses owned changes. Failed restoration disables further actions until
verified recovery, with bounded watchdog retries.

## Measured rate behaviour

Rate checks require the exact owned qdisc plus complete 131,072-byte HTTP
transfers with matching body hashes, source slowdown relative to a fresh
baseline, control transfer within its baseline tolerance, and reachability of
both clients. Command success alone is not effect verification.

The non-selected class has a high 10 Gbit/s ceiling, not an infinite/uncapped
claim. The final 512 kbit/s demonstration measured about 641.5 kbit/s on the
selected short transfer and 487,719.5 kbit/s on the control. Short-transfer
burst effects mean the target and measured throughput need not be identical.
Expiry removed the owned qdisc and restored both clients. This is one local
demonstration, not a production throughput benchmark.

## Checks and limits

The checkpoint retained 246 passing Ubuntu tests, 244 Windows passes with two
explicit TShark-only skips, and 11 frontend checks. Real Chrome journeys used
the Ubuntu backend, genuine hosted answers and real isolated Linux effects.
Controlled failure responses are separate. Counts do not establish detection
accuracy or certify each model claim.

Legacy v1/v2/v3 contracts and CLI preview behaviour are preserved explicitly.
The model still sometimes writes too much or uses imprecise terms. Current
tools are bounded to selected evidence and the fixed lab; no arbitrary network
targeting, generated shell execution, general live collector, multi-user
deployment or production security certification is claimed.

Engineering evidence, preserved failures, exact recovery steps and the final
requirement audit are in the Capstone Development checkpoint
`2026-10-03-workspace-response-upgrade`. The checkpoint directory retains its
3 October stage name; empirical records keep their actual timestamps.
