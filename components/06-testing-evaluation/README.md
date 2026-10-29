# Evaluation, Testing and Reproducibility

Role member: Antonio Dormido.

The test suite checks supported evidence, reference integrity, application state, provider handling, response boundaries and recovery. [Validation](../../docs/VALIDATION.md) identifies the latest recorded results and separates them from historical checkpoints.

## Offline software checks

Use the complete project environment described in [SETUP.md](../../SETUP.md). From the project root:

    .venv/bin/python -m pip install -r requirements-dev.txt
    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -p "test_*.py"

A machine-readable run can be saved to a new output path:

    .venv/bin/python components/06-testing-evaluation/run_checks.py --output validation/local-checks.json --environment-label Ubuntu

That command creates its output; the source package does not contain an existing local-checks.json report. Expected provider-error and unavailable-tool fixtures are not live inference failures. TShark-dependent tests need the actual executable; a skip is not a pass. The offline suite does not automatically perform paid model evaluations or privileged lab responses.

## Coverage

- test_packetpilot.py and evidence/log/quality tests cover inputs, provenance, relationships, ambiguity, supported calculations and compatibility.
- test_agent.py and test_investigator.py exercise checked provider/tool behaviour with controlled responses.
- test_web.py and test_react_runs.py cover API, state, runs, history and failure/retry paths.
- Response/workspace tests cover policy, approval replay/expiry and recovery using controlled lab doubles.
- test_investigation_depth.py and test_review_fixes.py cover case scope, applied comparisons, diagnostic pairing and final boundary corrections.
- frontend/tests/ retains interface checks. Normal operators use the prebuilt UI; frontend build tools are not an installation prerequisite.

## Extraction and hosted evaluation

verify_evidence_pipeline.py produces a new labelled extraction output when explicitly run. Comparison with TShark checks field extraction, not a model's attack interpretation.

evaluate_llm.py, evaluate_investigator.py, evaluate_quality.py and evaluate_response_refinement.py support their declared cases and output contracts. Live evaluation requires the explicit live option and the operator's configured provider key. Keep every attempt and its settings; review prose and supporting evidence separately from structural acceptance. Older runners remain version-specific, not automatic tests of every current feature.

## Real lab evidence

Portable tests are not real firewall operations. Actual approval/effect/restoration and app-off expiry were checked separately in the fixed disconnected lab. Use the normal interface and [response guide](../../docs/LINUX_RESPONSE.md) for that workflow. The retained exercise_linux_response.py helper defaults to loopback port 8768 and is an explicit test harness, not the normal 8765 launcher.

Test counts, extraction agreement, valid references, answer quality and measured response effect are different evidence categories. Historical results stay dated; they are not summed into detection accuracy.
