# Harness and investigation architecture

This filename is retained from the introduction of the v3 tool loop. The current implementation uses investigator 3.25, workspace 4.16 and the workspace answer contract 4.0. It is not the earlier no-tool v2 adapter. See [current model integration](LLM_INTEGRATION.md) and [validation](VALIDATION.md).

## Investigation flow

    Selected retained evidence and question
      -> bounded context and source-scoped history
      -> Agno / hosted provider
      -> validated tool request and Python observation
      -> typed final answer and evidence/domain checks
      -> at most one correction
      -> saved answer, public activity and original references

Python validates inputs, preserves original bytes, extracts and organises fields, calculates neutral observations and manages the application. The model chooses useful supported inspections and interprets observations without a compulsory threat-rule verdict. No model weights are trained.

## Tools and scope

| Tool area | Purpose | Boundary |
|---|---|---|
| Packet and flow inspection | Selected records, flow members, connections and candidate TCP exchanges | Backend-selected retained capture, validated arguments and bounded results |
| Saved-log inspection | Physical lines, totals and candidate header relationships | Exact retained field log; no invented raw packets or payload |
| Case inspection/comparison | Selected source-qualified observations and service comparisons | Explicit source selection; earlier answer scope remains unchanged |
| Workspace observations/plans | Supported fixed-lab status/diagnostics and typed response-plan preparation | Constrained current capability; no approval or arbitrary shell executor |

Existing decoded evidence is reused. A tool request does not automatically rerun a universal decoder or browse the host filesystem. Omitted initial detail remains disclosed and can be inspected within the tool limits. Original record membership and source identity support final references.

## Instructions, history and checks

Agno's description/instructions composition supplies system context. Versioned prompt files, reviewed guidance and typed contracts are explicitly loaded. Reviewed guidance contains reusable domain lessons, not raw failed answers, hidden case labels or autonomous global learning.

Successful history is source/session scoped. Inspected selectors rehydrate original facts rather than treating previous model prose as new evidence. Case selections and earlier answer snapshots remain distinct. Failed or stopped attempts are not successful answer history.

Tool arguments are checked before execution. Final checks cover structure, reference membership, supplied scalar measurements, coverage, selected domain wording and supported advisory-code examples. One targeted correction may repair invalid output; repeated invalid output is rejected. These checks reduce known failures but cannot establish the truth of every sentence.

## Configuration and public progress

Thinking is enabled and max is the default. There is no optional application generation-token override. An investigation is bounded by six provider calls, eight tools, one correction and a 300-second overall deadline. Provider limits still apply; cancellation is best effort and does not guarantee that an upstream provider stops billing or processing.

The interface reports real public activity and may show a provisional summary. A provisional stream is not a validated final answer. Public traces contain inspectable operations/results, timing and failure states, not private reasoning. Late timed-out results cannot be published as completed investigations.

## Privacy and response separation

Hosted questions transfer selected structured evidence, bounded previews, question and relevant context. Use authorised evidence. Credentials and private provider continuity stay outside source and public exports. Original payload text is data, not application instructions.

The model may prepare a permitted plan, but the response engine and independent broker enforce separate current-lab authority, exact operator approval, effect checks and restoration. See [response workflow](WORKSPACE_RESPONSE_V4.md). Tool access is not approval authority.

## Historical development and reproduction

The v3 introduction added bounded tool use and saved investigation state. Later refinements added canonical JSON tool results, scalar measurement catalogues, short source-qualified aliases, clearer direction/coverage semantics and coordinated output checks. These were harness/tool revisions, not model-only experiments.

[The v2 contract](LLM_INVESTIGATION_V2.md), [13 October audit](END_TO_END_AUDIT.md) and [18 October evaluation](MODEL_EVALUATION_2026_10_18.md) describe their own checkpoints. Older token limits, no-tool restrictions, pending UI work and test counts are not current settings. [Answer quality](ANSWER_QUALITY.md) explains remaining semantic limits.

The offline suite and explicit evaluation runners are described in [the test component](../components/06-testing-evaluation/README.md). Live runners require their live option and provider configuration; they are not invoked merely by reading documentation or running the offline suite. Raw private histories are not repository fixtures.
