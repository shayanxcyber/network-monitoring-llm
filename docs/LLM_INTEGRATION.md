# Model and interface integration

## Application flow

The browser sends a capture selection or upload and a question to the Python web application. The workflow decodes supported packets, computes the rule finding and prepares linked evidence. An Agno agent sends the configured hosted model the standing instructions, current evidence and successful conversation history for that review. Checked answers are saved and displayed beside the evidence.

## Files

- components/01-llm-interface/pp_agent.py: Agno adapter and conversation instructions.
- components/01-llm-interface/prompts/system.txt: versioned explanation/response instructions.
- components/01-llm-interface/pp_llm.py: API client and response validation, including the older CLI path.
- components/01-llm-interface/pp_web.py: HTTP routes and browser integration.
- components/03-packet-analysis/pp_evidence.py: capture facts and coded findings.
- components/04-application-workflow/pp_workflow.py: request processing and audit records.
- components/04-application-workflow/pp_sessions.py: saved reviews and turns.
- components/04-application-workflow/pp_settings.py: settings and external key loading.
- web/: the operator interface.

## Instructions and history

The application supplies instructions and evidence with requests automatically; the operator only types their question. Instructions are loaded by the code, not implicitly read by the model. Successful conversation history is scoped to the current review and persisted in local SQLite storage. Failed responses are recorded but not reused as successful model history.

The current agent has no model tools, a bounded output, timeout and no automatic provider retries. Invalid or unavailable answers are visibly distinguished from successful AI responses and can fall back to a rule-based result.

## Configuration

Use settings.toml for the non-secret endpoint/model settings. Run configure_key.py with the project interpreter to enter your own key privately. The browser application reads DEEPSEEK_API_KEY from the environment or the external ~/.config/packetpilot/secrets.env file. No live key is included in this package.

The older packetpilot.py CLI uses the PACKETPILOT_* environment options shown in .env.example. That file is a reference template, not an automatically loaded browser configuration. The CLI can reuse a capture but does not provide the browser's full persisted conversation behaviour.

## Current limits

Validation checks response structure, known evidence references and agreement with the coded finding. It does not prove every explanation is correct. The current agent is not an independent unrestricted detector, does not inspect arbitrary files and cannot execute commands. The operator chooses a response preview, which is checked separately; there is no firewall executor.

Broader packet facts, clearer coverage reporting, independent scenario tests and coordinated changes to agent instructions and response validation are planned improvements, not features added by this upload.

See [Validation](VALIDATION.md) for dated results and remaining gaps and the [root README](../README.md) for setup.
