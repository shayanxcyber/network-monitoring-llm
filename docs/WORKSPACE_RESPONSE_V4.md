# Workspace and response workflow

This filename follows the workspace answer-contract generation. Current implementation is workspace 4.16 and investigator 3.25. It includes the later case, collection, comparison and final interaction fixes; it is not limited to the original 4 October checkpoint.

## Everyday investigation

1. Launch the complete local application using [SETUP.md](../SETUP.md). The normal loopback address is http://127.0.0.1:8765.
2. Import a supported PCAP or exact TShark TSV, use a sample, reopen a review or collect current lab evidence when the broker is enabled. Opening evidence is offline.
3. Send a question. The message appears immediately, public activity follows the actual run and a separate next draft is preserved. A stopped request is not a completed answer.
4. Inspect original records and references. Viewing evidence does not attach it to a later question unless explicitly selected as context.
5. Link/select related evidence, apply a comparison pair/port and ask a follow-up. Earlier answers retain the scope used at generation time.
6. Export the applied investigation state and available response receipts.

The React workspace retains source-specific history, drafts and preferences. Navigation/reload observes a running request rather than automatically starting another one. Source-keyed inspectors and revision guards prevent outgoing or late state crossing a source boundary.

## Advice and approval

Explanations, no-action recommendations and command examples can be useful without a network change. Generated code is reviewable advice, not an executable permission. There is no general terminal tool.

The model can inspect supported current lab observations and prepare a validated plan. It cannot create its own approval or apply a rule. A response proposal binds the saved recommendation, original source identity, current lab generation and exact parameters.

## Supported operations

| Operation | Scope | Parameters |
|---|---|---|
| Temporary service block | Selected source 10.77.0.20 to service 10.77.0.10 TCP/8080 | 5-120 seconds |
| Temporary service-reply rate limit | Replies toward the same selected source | 256-2048 kbit/s, 5-120 seconds |

Control 10.77.0.30 is not an action target. The lab is disconnected, with no external gateway or host-management target. Uploaded evidence, case selection and plausible model wording do not provide fresh broker authority.

Review target, duration/rate, commands, expected effect and reversal before the separate exact confirmation. Missing, wrong, stale, altered, cancelled, expired, duplicate/replayed and cross-source authority is rejected. If a pending proposal expires, the interface reads its real receipt rather than inventing a cancellation.

## Effect, measurement and recovery

Enforcement, selected/control observations and restoration are separate recorded states. Command success alone does not prove a useful outcome. Health and complete-transfer profiles measure different things; failed/incomplete measurements remain failures.

Diagnostic comparisons use explicit baseline/after identities and validate chronology, profile, objective, source, target/client identities, generation and completion. An old baseline cannot be combined with a new cycle merely because the labels match.

Manual restoration and independent expiry remove the broker's owned change. Startup recovery handles known state; failed restoration disables additional responses until resolved. See [Linux response](LINUX_RESPONSE.md) and [calculation rules](INVESTIGATION_DEPTH.md).

## Recorded verification and history

The latest recorded implementation checks are summarised in [validation](VALIDATION.md): 376 backend checks on deployed and clean Ubuntu, 61 frontend checks and actual browser/approved-response/restoration journeys. Counts are not detection accuracy.

The original 4 October checkpoint recorded 246 Ubuntu passes, 244 Windows passes with two TShark skips and 11 frontend checks. Its short rate demonstration measured approximately 641.5 kbit/s selected and 487,719.5 kbit/s control. Those are historical checkpoint outcomes, not current suite totals or a production throughput claim. Later measurements are separately identified in validation.

Legacy CLI preview and v2/v3 contracts remain compatibility/history paths. They do not override the implemented current workspace. The scope remains fixed-lab, single-operator investigation and controlled response, not general network automation or production security certification.
