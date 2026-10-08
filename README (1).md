# Evaluation, Testing and Reproducibility

Role member: Antonio Dormido.

Run the complete offline Python suite from the project root:

    python -m pip install -r requirements-dev.txt
    python -m unittest discover -s components/06-testing-evaluation -v

run_checks.py records actual environment, outcomes and output without overwriting earlier reports. The latest retained Ubuntu run passed 285 tests with no failures, errors or skips. The separate frontend suite passed 35. Controlled HTTP/provider responses verify protocol behaviour, not real inference.

The focused test files cover packet/log decoding, references and measurements, Agno tools/output repair, source history, web protections, durable streaming/cancellation, evidence views and reversible response controls. verify_evidence_pipeline.py compares selected decoded fields across seven labelled PCAP cases and two decoder modes. TShark comparisons require the installed tool.

evaluate_llm.py, evaluate_investigator.py, evaluate_quality.py and evaluate_response_refinement.py are explicit hosted experiments, not part of ordinary offline checks. They retain attempts, declared case/repeat configuration, acceptance failures, time and provider usage. inspect_evaluation.py summarises them for review.

The retained answer-quality comparison accepted 10 of 12 baseline and 12 of 12 refined responses structurally. Semantic review still found weaknesses; these fractions are not detection accuracy. exercise_linux_response.py separately verifies actual fixed-lab effects when explicitly executed. Do not confuse controlled lifecycle tests with a real firewall experiment.

[Validation](../../docs/VALIDATION.md) preserves stage-specific counts and failures. [Answer quality](../../docs/ANSWER_QUALITY.md) explains the distinction between valid format and supported meaning.
