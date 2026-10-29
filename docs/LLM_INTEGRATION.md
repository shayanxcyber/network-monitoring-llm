# Model integration

PacketPilot uses Agno and the configured hosted model to investigate retained network evidence. Python prepares observations and tools, checks the returned answer and connects it to the operator interface. The model is not a traffic decoder or a privileged Linux executor.

The current workspace is version 4.16 and the investigator is version 3.25. See [SETUP.md](../SETUP.md) for installation and key configuration, [the investigation-depth guide](INVESTIGATION_DEPTH.md) for source and measurement rules, and [the component map](HANDOFF_MAP.md) for the connected modules.

## Current configuration

The supplied settings use `deepseek-flash`, thinking enabled and `reasoning_effort = "max"`. There is no optional application generation-token override. Provider limits still apply.

An investigation has a 300-second overall deadline, at most six model calls, at most eight tool calls and one corrective attempt. These are bounds, not an expected response time. Network/provider failure, cancellation and invalid output remain distinct outcomes. A stopped or rejected investigation is not stored as a completed answer.

Provider settings are read from settings.toml. The key loader checks the operator's environment or private per-user configuration. Configure a key with configure_key.py; do not place credentials in source, Drive, screenshots or exports.

## Evidence and context

The parser retains the original supported capture or field log, its hash, usable decoded records and coverage. Context includes relevant observations, the operator's current question, selected source scope and bounded conversation history.

Previous answers help interpret follow-up questions but are not new packet evidence. Missing, excluded, unreadable, encrypted or truncated material remains a limitation. A saved field log has physical-line provenance; it is not a raw packet capture.

Related-evidence cases can select multiple sources. References retain source identity, so packet 1 in one capture cannot silently become packet 1 in another. Earlier answers retain their saved scope when the current selection changes.

## Investigation loop

1. The backend validates the question, selected evidence and context.
2. pp_investigator.py constructs the current Agno/provider interaction and registered workspace tools.
3. The model may request a supported inspection with typed arguments.
4. Python validates and executes that inspection against the allowed evidence or fixed workspace capability.
5. The returned observations and references become tool results for the continuing investigation.
6. The final structured answer passes reference, domain and output checks before it is saved.

Packet, flow, log, service and selected-case inspection tools are bounded to their supported inputs. Current-lab observations and response-plan preparation have separate constraints. A tool call is not general access to the operating system.

## Instructions and validation

Versioned instructions are loaded explicitly from the prompt files under components/01-llm-interface/prompts/. The current workspace instructions and reviewed guidance define the evidence-led approach. Older prompt variants remain connected to their corresponding legacy paths and tests.

pp_investigation_contract.py defines typed answer structures and references. pp_claim_checks.py and pp_semantics.py check selected grounding and domain mistakes. pp_code_reference.py supports bounded advisory-code checks.

If a final answer fails validation, the backend may request one targeted correction. A second failure is rejected. Typed output and valid reference IDs do not prove every sentence is correct; a reference may still support only part of a claim. Operators can inspect the original records and uncertainty.

Code examples are reviewable advice. They do not authorise or automatically execute a Linux response.

## Conversation, progress and storage

The application retains review-scoped conversations, source selections, run states and public tool activity. The interface displays submitted questions immediately, preserves a separate next draft and supports follow-up, Stop and Ask again.

Private provider continuity is separate from public activity and exports. The application sanitises private reasoning and credentials from exportable records. Sharing source does not mean sharing a live database or private provider history.

A streamed provisional summary is not a validated final answer. Completion, cancellation, correction and failure remain visible lifecycle states.

## Network response boundary

The model may suggest an allowed response or prepare a scoped plan. Separate operator approval is required before the response engine requests execution from the root-owned broker.

The permitted lab target, current capture binding, one-time confirmation, effect checks and restoration are enforced outside the model. Uploaded offline evidence and case membership do not grant live authority. See [Linux response](LINUX_RESPONSE.md) and [workspace response](WORKSPACE_RESPONSE_V4.md).

## Main integration files

- pp_investigator.py: current tool-enabled provider loop, budgets, correction and checked final output.
- pp_agent.py: integration selector and retained checked legacy conversation adapter.
- pp_llm.py: shared provider/request/configuration and sanitisation helpers.
- pp_context.py: bounded evidence and history context.
- pp_investigation_tools.py, pp_log_tools.py and pp_case_tools.py: source-scoped inspection.
- pp_workspace_tools.py: constrained workspace observations and non-executing plan preparation.
- pp_investigation_contract.py, pp_claim_checks.py, pp_semantics.py and pp_code_reference.py: output, reference, domain and advisory-code checks.
- pp_web.py: application routes joining evidence, runs, model interaction and the browser.
- pp_sessions.py and pp_runs.py: retained review/case state and public run lifecycle.
- pp_response_engine.py: proposal, approval, effect and restoration orchestration.

The older no-tool adapter and direct-client entry point are retained compatibility paths. Their comments, schemas and tests must not be mistaken for restrictions on the current investigator.

## Evaluation and limits

The final implementation passed 376 backend checks on deployed Ubuntu and the same 376 checks in a separate clean installation. The frontend suite passed 61 checks, and the three rebuilt JS/CSS assets matched the delivered build.

The final focused hosted review retained six completed answers and one deliberately stopped attempt. These are functional and qualitative development results, not a detection-accuracy percentage or a speed guarantee.

Historical evaluation documents keep the tested versions and outcomes they describe. Use this guide for the current integration; use those records to understand its development, rather than combining different harness versions into a single result.
