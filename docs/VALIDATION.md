# PacketPilot validation

## Latest recorded implementation checks - 23 October 2026

The delivered implementation is investigator 3.25 / workspace 4.16. Documentation-only publication revisions do not change the executable source, dependencies, tests or built interface. These are retained implementation results, not new tests claimed to have run during documentation editing.

| Evidence category | Recorded result | Meaning |
|---|---|---|
| Deployed Ubuntu backend | 376 passed, no skips | Complete backend suite in the actual Linux environment |
| Separate clean Ubuntu installation | The same 376 passed, no skips | Repeatable installation/suite, not 752 distinct tests |
| Frontend | 61 passed on the development host and in separate Ubuntu verification | One suite in two environments, not an accuracy denominator |
| Production build | Three rebuilt JS/CSS assets byte-identical to the delivered build | Reproducible interface assets; normal users do not rebuild them |
| Focused hosted review | Six complete attempts and one deliberately stopped attempt | Functional/qualitative evidence, not detection accuracy |

The six completed focused requests took approximately 11.0419-60.1707 seconds in that small development set. Max thinking remained enabled. The model can still phrase a fact loosely, provide a citation supporting only part of a sentence or suggest an unproven alternative. Software passes and valid JSON do not eliminate those limitations.

## Browser, state and lab acceptance

Real browser journeys covered immediate submission, a separate next draft, pending navigation/reload, completion, follow-up, Stop/Ask again, references, original packet/log inspection, search, preferences, case corrections and diagnostic cycles. The clean installation began without inherited reviews, served the built assets/fonts and imported supported PCAP/TSV inputs.

A composer update-depth failure was isolated with a causal reversal: removing duplicate count state preserved all 169 characters with zero errors, restoring it reproduced six errors/text loss, and removing it again restored the clean result. No vendor patch or console suppression was used.

Explicit diagnostic baseline/after identities reject cross-cycle or incomparable measurements. Applied source/port comparisons and exports retain the computed snapshot. Earlier answers retain their original selected-source scope after later case changes.

Actual fixed-lab trials verified separate exact approval, selected/control block effect, manual restoration, normal-browser rate approval and restoration, and independent block expiry with the web application stopped. Negative approvals included wrong/missing/replayed/cancelled/stale/offline and protected-target cases.

The final short rate probe observed selected 641.5 kbit/s and control 543,912.9 kbit/s. This demonstrates a selective lab effect, not an exact long-run 512 kbit/s average or production benefit. Final administrator readback found no experimental shaper/rule, managed capture process, active response or broker fault; both clients returned HTTP 200.

All 61 earlier original evidence files and pre-existing application rows were preserved, with SQLite integrity OK. Private live histories and databases are not shipped as public fixtures.

## Reproduce software checks

Follow [SETUP.md](../SETUP.md), then from the complete source root:

    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -p "test_*.py"

A new machine-readable report can be generated with run_checks.py as described in [the test component](../components/06-testing-evaluation/README.md). That output is created by the command; this source package does not pretend an unshipped validation/ report already exists. Live evaluation and actual broker operations are separate explicit workflows, not automatic offline-suite actions.

## Historical checkpoints

The following results belong to earlier versions. Preserve their settings, failures and denominators; do not pool them into current accuracy or silently relabel them as current-model tests.

| Checkpoint | Retained outcome |
|---|---|
| 31 August pre-VM host | 47 checks: 46 passed, one actual TShark-unavailable skip |
| 31 August Ubuntu | 71 passed, no failures/errors/skips; earlier guest stages recorded 48 and 70 checks |
| 13 October audit, investigator 3.5 | Ubuntu 291 passed; Windows 289 passed/two TShark skips; frontend 37 passed |
| 18 October model evaluation | Ubuntu 298 passed; Windows 296 passed/two TShark skips; frontend 37 passed; its own 73-attempt development set |

The 31 August Ubuntu environment recorded Python 3.12.3, Scapy 2.7.0, TShark/Wireshark 4.2.2 and Agno 3.0.4. An early TShark Boolean-format difference was corrected. The host-only stage used Python 3.12.13/Scapy 2.7.0 and did not perform a live capture or network response.

The early hosted review contained two successful questions in one persisted conversation, using deepseek-v4-flash with thinking disabled and a 900-token setting. Provider-reported usage was 938 and 1,438 tokens, total 2,376. The follow-up used four messages rather than two and survived application restart. Those settings and two questions are historical, not the current enabled/max configuration.

Historical review ID: 42f44873-aa4d-48c4-8c78-008f4e85ad7e. Request IDs: fee9101d-e4b2-4a98-b451-6ab0d2ba7df7 and f624f3f0-d75c-4598-8d77-9aaf6662d500. Capture SHA256: d216826aafc171d40eca69695e81a41176912a6399cdb9979472e25afb1a8471.

The early normal example contained nine packets and two destination service ports. The port-check example contained eight attempts across eight ports in 0.7 seconds. Their direct-client rule results and 60-second preview did not execute a network change. The absence of explicit flag detail motivated richer evidence; those preliminary results were not a perfect-answer benchmark.

The complete [13 October audit](END_TO_END_AUDIT.md) and [18 October evaluation](MODEL_EVALUATION_2026_10_18.md) retain their dated results and limitations. Versioned technical documents distinguish old contracts from [current integration](LLM_INTEGRATION.md). Raw reports, screenshots and original development records are retained separately in the delivery evidence archive, not linked as nonexistent source-tree evidence/ or private runs/ files.

## Interpreting the evidence

Extraction agreement checks fields. Protocol tests check handling. Structural answer acceptance checks a contract. Prose/reference review checks support. Selected/control measurements check a scoped lab effect. None alone proves universal attack detection, complete capture coverage, business intent or production effectiveness.
