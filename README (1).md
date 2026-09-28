# Evaluation, Testing and Reproducibility

test_packetpilot.py checks constructed captures, rule boundaries, malformed
inputs, API response handling, evidence references, safe previews and audit output.
A loopback HTTP stub verifies the request/response protocol without external
inference. The TShark cross-check is explicitly skipped when TShark is unavailable.

Run all checks:

    python -m unittest discover -s components/06-testing-evaluation -v

Save a machine-readable record:

    python components/06-testing-evaluation/run_checks.py --output validation/host-checks.json

test_agent.py checks the actual Agno/SDK path against controlled local HTTP
responses, including history persistence/isolation and failure handling.
test_web.py checks the UI/API storage workflow, uploads, export, policy previews,
CSRF/origin protections and provider-neutral interface copy.

Historical Ubuntu checkpoint (31 August): 71 checks passed, including TShark.
The 7 September Windows audit passed 70 checks and skipped the TShark check.
See ../../docs/VALIDATION.md for the distinction and evidence included here.
Next: add independent cases and evaluate explanation usefulness and resource
behaviour. Test counts are not detection accuracy or a model-quality benchmark.
