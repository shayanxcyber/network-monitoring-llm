# LLM Integration and Operator Interface

## Files

- pp_agent.py: the Agno-backed model adapter, standing conversation instructions,
  SQLite history, provider-error sanitising and checked responses.
- pp_web.py: local HTTP routes joining the operator UI to the evidence workflow.
- pp_llm.py: configurable API connection, prompt construction, output validation,
  timeouts, bounded retry, error handling and rule-based fallback.
- pp_operator.py: command-line controls, readable result, evidence references,
  repeated questions about a cached capture and response previews.
- prompts/system.txt: versioned plain-language explanation instructions.
- ../../docs/LLM_INTEGRATION.md: walkthrough, request/response boundary and setup.

## Implemented preparation

One provider connection, structured JSON answers, evidence-reference checks,
finding-consistency checks, protected credentials, redirect refusal, bounded input,
model/usage/timing metadata and clear separation between model and rule output.
The operator can ask questions and inspect the evidence without reading raw packets.

## Current checkpoint and next work

The light browser UI and two-turn real API check now work in Ubuntu, with saved
history surviving restart. Use the browser for multi-turn questions; the terminal
loop is an older capture-reuse route. Review the retained answers and improve
explanation quality against independent cases. Explain what HTTP, the prompt,
history, validation and the response boundary do before presenting them.

Protocol tests use controlled responses; they do not establish real model quality.
