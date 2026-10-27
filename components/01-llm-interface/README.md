# LLM Integration and Operator Interface

Role member: Shayan Ali.

This component connects retained traffic evidence, hosted investigation, checked answers and the operator workspace. Current integration uses investigator 3.25 and workspace 4.16. See [model integration](../../docs/LLM_INTEGRATION.md), [component map](../../docs/HANDOFF_MAP.md) and [setup](../../SETUP.md).

## Main responsibilities

- pp_web.py joins imports, reviews, conversations, runs, cases, current-lab collection and response records.
- pp_agent.py selects the current investigator or retained legacy adapter. pp_investigator.py manages Agno/provider calls, tools, deadlines, cancellation and one bounded correction.
- pp_context.py prepares bounded evidence/history. The prompt files are explicitly loaded guidance, not an automatically read agent directory.
- pp_investigation_tools.py, pp_log_tools.py and pp_case_tools.py inspect selected original evidence through validated arguments and source-qualified references.
- pp_investigation_contract.py, pp_claim_checks.py, pp_semantics.py and pp_code_reference.py check output, measurements, references, domain wording and advisory code.
- pp_capture_api.py and pp_case_api.py connect managed collection, comparable measurements, related sources and readable reports to the application.
- pp_workspace_tools.py supplies constrained workspace observations and plan preparation, without approval or arbitrary execution.

Python supplies observations; the model interprets them without a compulsory rule verdict. Previous model prose is conversation context, not new packet evidence. Changing case selection does not rewrite the scope of an earlier answer.

## Interface and response integration

The React source is under frontend/src/ and the prebuilt interface is under web/react/. It supports immediate submission, a separate next draft, public progress, originals, follow-ups, saved history and applied comparisons. Normal users do not rebuild the frontend.

Suggestions and code examples do not authorise network changes. The separate response engine requires a current lab binding and exact operator approval before the privileged broker can perform a supported action. See [workspace workflow](../../docs/WORKSPACE_RESPONSE_V4.md).

## Compatibility and verification

Earlier prompt/schema variants, the direct client and the older no-tool conversation adapter remain for compatible paths and tests. Their restrictions are not the capabilities of the current workspace. [The v2 record](../../docs/LLM_INVESTIGATION_V2.md) is explicitly historical.

See [validation](../../docs/VALIDATION.md) for the latest recorded software/browser/lab results. Valid structure and references do not guarantee that every sentence is supported; [answer-quality guidance](../../docs/ANSWER_QUALITY.md) describes that limitation.
