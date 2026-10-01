# PacketPilot validation

## Windows host audit — 7 September 2026

71 checks ran: **70 passed, zero failures/errors, one skipped**. The skipped check compares TShark and Scapy because TShark was not installed on the Windows host.

[Machine-readable host audit](../validation/2026-09-07-host-audit.json)

This was an offline functional suite with controlled local HTTP responses, not external model inference. It covers packet inputs and rule boundaries, response validation, API error handling, history/session isolation, browser routes, exports and response-preview restrictions.

## Historical Ubuntu checkpoint — 31 August 2026

The retained source validation documentation records 71 checks passing with no skips on Ubuntu, including the TShark comparison. It also records two real hosted-model questions in one saved review, with persistence through a backend restart.

Those older raw VM reports and saved review artifacts remain in the original local project archive and are not included in this seven-file-per-member handoff. This document does not present the Windows record as proof of Ubuntu execution or claim a fresh VM test.

## Interpretation and limits

- Functional test counts are not detection-accuracy scores.
- Synthetic normal and port-check examples are not independent real-world attack benchmarks.
- The model sees selected packet facts, not a complete interpretation of every protocol or payload.
- Current validation requires the model to retain the coded finding. Broader independent analysis remains future work.
- Mixed unsupported traffic can cause insufficient evidence despite useful TCP packets remaining.
- Response previews are not executed. No live firewall or traffic-shaping action is validated by these tests.
- Linux-specific topology, enforcement, rollback and constrained-resource behaviour require separate Linux integration testing.

Run the current suite from the repository root:

```bash
python -m unittest discover -s components/06-testing-evaluation -v
```

To save a new record, choose a new filename rather than overwriting historical results:

```bash
python components/06-testing-evaluation/run_checks.py --output validation/new-host-checks.json --environment-label "Describe the actual host used"
```
