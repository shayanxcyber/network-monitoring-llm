# Model integration — Shayan's working area

## Current investigation loop — 2 October 2026

Use [Harness and investigation v3](HARNESS_INVESTIGATION_V3.md) for the active
saved-capture route. It supersedes the no-tool v2 route described below, without
changing the provider-neutral operator identity. Native Agno composition, typed
answers, scoped Python tools, a bounded corrective attempt, reviewed guidance
and rehydrated investigation state are implemented. Older evaluations remain
historical evidence; current live outcomes are recorded separately.

## Current configuration — 1 October 2026 follow-up

Use [the evidence-led v2 contract](LLM_INVESTIGATION_V2.md) for the current implementation. The dated August sections below describe the original prototype, not the active evidence/response contract.

Current browser settings explicitly use `deepseek-flash` (V4.1 Flash), thinking enabled and `reasoning_effort=max`, with a 32,768-token generation budget, 180-second timeout and no automatic provider retry. Agno sends the effort setting; the final answer still passes the same evidence/schema checks. Temperature is omitted in thinking mode. The environment-variable example gives equivalent settings for the direct diagnostic client; it is not loaded automatically by the browser application.

The two retained October 18-run batches preceded this correction and used thinking disabled. One separate max-reasoning live check returned reasoning-token usage and a checked final answer; it does not establish general quality or erase the earlier limitations. API credentials remain in the private key file, outside project settings.

## Implemented application — 31 August 2026

The Ubuntu application now uses **one Agno agent**, the configured hosted model,
SQLite-backed conversation history and our own light PacketPilot browser UI.
Two real questions succeeded in one review and persisted through a restart.
The final Ubuntu suite passed 71 checks. See [validation](VALIDATION.md).

The operator interface says PacketPilot/AI, not the provider name. Technical
configuration and audit records still retain the real model and provider.

### Where instructions and context are handled

- Standing evidence/JSON rules: components/01-llm-interface/prompts/system.txt.
- Conversation instructions and Agno configuration: components/01-llm-interface/pp_agent.py.
- Current capture, rule finding and linked packet facts: pp_evidence.py and pp_workflow.py.
- Successful prior turns for this capture/session: Agno's local SQLite storage.
- Browser review index, questions, request IDs and previews: pp_sessions.py.
- HTTP interface and validation: pp_web.py; visible interface: web/.
- Provider/model settings: settings.toml; key loader: pp_settings.py.

The operator types only a question. The backend supplies the standing instructions,
current evidence and successful conversation history automatically on every request.
History is scoped to one review; failed/invalid responses are not reused as model
history. The full stored review remains available after the app closes. No agent
file is magically read by the model: the application explicitly loads its prompt.

The current bounded setup has thinking disabled, no model tools, a 900-token
output limit, a 25-second configured timeout and no automatic provider retries.
SDK/framework retry paths are also disabled. Invalid or unavailable model output
falls back visibly to a rule-based result. No model-generated command is executed.

The user has already saved the key in
/home/capstone/.config/packetpilot/secrets.env (owner-only mode 600).
Open PacketPilot with /home/capstone/packetpilot/launch.py using the project's
Python interpreter. Do not repeat key entry or install another model runner.

### Current versus legacy entry points

Use the browser for saved multi-turn conversations. The older packetpilot.py
terminal command remains a direct-client diagnostic path: it reuses a capture
but not complete prior question/answer history, uses separate environment-variable
configuration and retains its older explicit 429/503 retry policy.
Do not confuse that legacy behaviour with the Agno-backed application.

## Current model research and runtime direction - 31 August 2026

Shayan is using the current hosted DeepSeek Flash/Pro API family and prefers
Flash because it is cheaper. Treat Flash as the first model to configure and Pro
as an optional, explicit comparison, not a second model that must run alongside it.
The dated source research below informed the now-working configuration above.
The two successful calls establish connection/history handling, not comparative
model quality or suitability for every scenario.

### Verified model names and capacity

| Model | API model ID | Published revision | Context window |
|---|---|---|---|
| Flash | deepseek-v4-flash | DeepSeek-V4-Flash-0731 | 1 million tokens |
| Pro | deepseek-v4-pro | DeepSeek-V4-Pro-0813 | 1 million tokens |

Use the API IDs, not the dated revision names, in requests. DeepSeek says those
IDs follow the current revisions. Both support JSON output, tool calls, thinking
and non-thinking modes; the published maximum output is 384K tokens, not a target
response length for this application.
[Current model IDs](https://api-docs.deepseek.com/) and
[model specifications](https://api-docs.deepseek.com/quick_start/pricing/).

### Published API costs

Provider-listed dollars per 1 million tokens, checked 31 August 2026:

| Token category | Flash off-peak | Flash peak | Pro off-peak | Pro peak |
|---|---:|---:|---:|---:|
| Input, cache hit | $0.007 | $0.014 | $0.022 | $0.044 |
| Input, cache miss | $0.22 | $0.44 | $0.66 | $1.32 |
| Output | $0.66 | $1.32 | $1.98 | $3.96 |

Peak periods are Monday-Friday 01:00-04:00 and 06:00-10:00 UTC; other times are
off-peak. Uncached input and output cost three times as much on Pro as Flash.
These are published rates, not an estimate of this learner's usage or a bill.
[Pricing and deduction rules](https://api-docs.deepseek.com/quick_start/pricing/).

### What the context window means for PacketPilot

The initial capture/question workflow should be comfortably below this capacity.
Do not assume an obsolete small-model window or silently discard useful context.
Equally, the window is a per-request capacity, not permanent memory, an accuracy
guarantee, or a reason to send the whole USB, raw packet bytes and every old log.
Keep the full conversation record locally; supply the relevant conversation,
current evidence and instructions, leaving room for the configured output.
Associate chats with their capture/session so follow-up questions do not pick up
another capture's evidence. Make any truncation or summarisation visible.

Chat Completions is stateless: the client/framework supplies the messages for
each turn. The current terminal prototype only reuses the capture, not the full
previous question/answer history. The Agno-backed browser application now retains
and supplies it. [Conversation API](https://api-docs.deepseek.com/guides/multi_round_chat/).

DeepSeek's prefix cache is automatic, but a hit depends on matching a persisted
prefix. Stable standing instructions and correctly preserved chat history can
benefit; reuse is not guaranteed or free permanent memory. Do not remove needed
instructions to try to avoid resending them. Inspect returned cache-hit and
cache-miss usage rather than assuming every repeated token is cached.
[Context caching](https://api-docs.deepseek.com/guides/kv_cache/).

### Integration details that must be tested

1. Base URL: https://api.deepseek.com; Chat Completions uses /chat/completions.
   Choose deepseek-v4-flash explicitly. Older framework examples may use different
   model names; do not copy those defaults without checking the provider.
2. Thinking is enabled by default at high effort. Set the intended mode explicitly.
   A first transport/JSON check can use non-thinking mode; then compare an
   appropriate thinking setting on the actual questions if it adds useful accuracy.
   Do not treat a successful connection as evidence of analytical quality.
3. In thinking mode, temperature/top_p and the documented penalty parameters do
   not control the result. For requests carrying tools, DeepSeek requires prior
   reasoning_content to be preserved through subsequent requests, including turns
   without a tool call; omitting it can produce HTTP 400. Verify the installed
   framework handles this before enabling tool-assisted thinking. This protocol
   field is not something the operator must type or include in the presentation.
   [Thinking-mode requirements](https://api-docs.deepseek.com/guides/thinking_mode/).
4. JSON mode also needs a JSON instruction/example and adequate output allowance.
   Reject empty, truncated or invalid responses and retain the existing evidence
   and policy checks. Valid JSON alone does not establish factual correctness.
   [JSON output](https://api-docs.deepseek.com/guides/json_mode/).
5. A normal one-user prototype is far below the published account concurrency
   ceilings, but still handle 429, unavailable balance, timeouts and provider
   errors. Bound retries/tool rounds and record actual usage; do not assume an
   unlimited service. [Rate limits](https://api-docs.deepseek.com/quick_start/rate_limit/).

### Framework decision and setup history

The implemented choice is one local Agno agent, SQLite-backed session history,
and our own PacketPilot interface served by FastAPI; AgentOS was not needed.
Agno is an installable Python framework, not a model downloader. The local runtime
is free; the paid management platform is unnecessary for this prototype. This
is now installed in the isolated project environment. The legacy direct client
remains available separately.
[Agno runtime](https://docs.agno.com/agent-os/introduction),
[history configuration](https://docs.agno.com/context/agent/overview),
[DeepSeek connector](https://docs.agno.com/models/providers/native/deepseek/overview),
[runtime pricing](https://www.agno.com/pricing).

The completed setup followed this order: verify the existing VM
and network, retain the already-created recovery snapshot, establish verified key-based SSH if
needed, create the isolated project environment and install missing tools, run
offline Scapy/TShark checks, then configure the agent/API and test a follow-up
conversation through the interface. The API key was entered inside the
VM. Desktop authentication dialogs need direct user entry; normal sudo through
non-UI terminal/SSH is learner-authorised without credential retention. The
current tool inventory and no-new-snapshot instruction are in VM_CONTINUATION.md.

Record requested model ID, returned model field, UTC date, prompt/config version,
thinking setting, usage and actual outcome for each evaluated run. Because the
API IDs are moving aliases, a repeat later may use a changed provider revision.
Compare Pro only when there is a specific reason; do not silently escalate.
Remote inference is not a measurement of the VM's model CPU/RAM usage.

The research-only phase did not call the model. Subsequent approved setup did,
as recorded above. GitHub and LabArchives remain unchanged. The earlier pre-VM ZIP
is a historical snapshot, not the current application. The legacy instructions
below describe the retained direct-client diagnostic route.

## The simple explanation

The model is the language engine. Our application supplies the interface and
decides what evidence to send. An API is the connection between our Python program
and the provider: Python sends an HTTPS request containing JSON, then receives JSON.
The API key authorises that request. The URL and key are connection settings;
the rest of the integration handles inputs, prompts, outputs, errors and evidence.

An API route does not require Ollama. We are not running two models: the
deterministic rule is ordinary Python, and only one configured model explains it.

## Legacy direct-client features

1. Provider settings: API base URL, model ID, key, timeout and optional thinking mode.
2. A versioned system prompt explaining the evidence-only role and JSON format.
3. A request builder sending the question, finding and bounded fact list.
4. An HTTPS connection that will not forward credentials to a redirect destination.
5. Checks for incomplete responses, malformed JSON, extra fields, wrong findings,
   invalid references and excessive text.
6. A cautious retry for explicit HTTP 429/503 errors, but no retry of an ambiguous
   timeout that might already have consumed a provider request.
7. A readable result showing the explanation and its packet references.
8. A fallback that remains visibly rule-based if the API cannot be used.
9. Run metadata: prompt/request hashes, returned model, elapsed time and reported
   token usage when available.
10. An interactive terminal loop that reuses the loaded capture across questions,
    but does not yet send previous question/answer turns as conversation history.

These are substantive integration features, not just a URL/key pasted into a file.
They are retained code and controlled tests. The later actual provider check used
the Agno/browser application, not this legacy terminal entry point.

## Optional legacy terminal configuration

Choose the actual model ID from the provider's current documentation/account.
No dated model nickname has been silently assumed.

    export PACKETPILOT_API_BASE_URL=https://api.deepseek.com
    export PACKETPILOT_MODEL=YOUR_ACTUAL_MODEL_ID
    export PACKETPILOT_THINKING=disabled
    read -rsp 'API key: ' PACKETPILOT_API_KEY
    export PACKETPILOT_API_KEY

The key entry is hidden and not part of the command itself. Do not put the real
key into screenshots, the example file, a Git commit or a journal entry.

Then:

    python packetpilot.py analyse --capture sample-data/port-check.pcap --provider api
    python packetpilot.py chat --capture sample-data/port-check.pcap --provider api

Every question in API mode may incur a provider charge and sends the bounded
synthetic evidence plus question to that provider. Rules mode performs no model
request. Remove the key from the shell when finished:

    unset PACKETPILOT_API_KEY

The optional thinking setting is provider-specific. Leave it unset when using
a compatible endpoint that does not support that parameter.

## Useful questions to test

- Does this traffic need checking, and why?
- Which computer should I look at?
- What do the packet references show?
- What should I check before blocking anything?
- Can this capture tell us whether the website is slow? (It should acknowledge
  that this first version lacks service-performance evidence.)

## What validation does and does not prove

The program checks that the response has the expected shape, cites existing
facts and does not change the rule's finding. It does not mathematically prove
that every sentence is correct. The operator still compares the explanation
with the evidence, especially when the question is outside this small scenario.

The model cannot call tools or execute commands. It does not choose a firewall
target directly. The operator chooses a typed preview, which the response module
checks independently.

## How to explain your work

Walk through pp_agent.py, pp_web.py, prompts/system.txt, pp_llm.py and the
session/workflow modules, then demonstrate:
an ordinary result, a helpful answer, a rejected bad response and a failed API
falling back without pretending it was successful. Record the review, changes and
actual provider results you complete, rather than using a file count as evidence
of understanding.

## References checked 31 August 2026

- [DeepSeek chat-completions request/response format](https://api-docs.deepseek.com/api/create-chat-completion/)
- [Scapy saved-PCAP operations](https://scapy.readthedocs.io/en/latest/usage.html)
- [TShark field output and saved-capture options](https://www.wireshark.org/docs/man-pages/tshark.html)
