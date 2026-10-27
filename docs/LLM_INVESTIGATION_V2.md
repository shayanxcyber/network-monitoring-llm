# Historical evidence-led v2 investigation contract

Historical design record for response 2.0/context 2.1. The no-tool path, token/timeout values and outstanding work below refer to that prototype. Current tool-enabled investigator 3.25, workspace 4.16 and response execution are documented in [model integration](LLM_INTEGRATION.md), [workspace response](WORKSPACE_RESPONSE_V4.md) and [validation](VALIDATION.md).

## Request to result

1. A selected saved PCAP is validated and decoded into evidence v2. Original bytes and SHA-256 remain available; packet/flow IDs bind observations to that capture.
2. `pp_context.py` selects copied evidence fields, not legacy findings, expected labels, file names or arbitrary metadata. Context 2.1 includes capture metadata, overview, coverage, packet records and flow records. `overview.packet_count` is copied from the real capture count, not inferred. Business context is explicitly unverified.
3. `pp_llm.build_request` combines the versioned standing instructions with the operator question and evidence. `pp_agent.AgnoClient` adds the last three successful conversational runs from this review/capture/contract namespace. Original saved history is retained; v1 and 2.0 model histories are not injected into contract 2.1.
4. Agno calls the existing hosted provider once. No execution tools, cross-session search, filesystem browsing or network inspection tools are registered. At the v2 checkpoint, configuration explicitly enabled thinking at max effort, with a 32,768-token generation budget and a 180-second timeout. Temperature is omitted in thinking mode because the provider ignores it. The checked final answer remains bounded to 32,000 UTF-8 bytes. Evaluation runs each use a fresh session; switching to thinking mode starts a separate history namespace, preserving old records without injecting their answers. Reasoning presence and provider-reported token usage are recorded, not private reasoning text.
5. Strict JSON and schema validation check the answer. Capture/reference membership, exact supplied scalar measurements, coverage status, duplicate IDs and typed preview policy are checked separately. Invalid answers do not enter successful Agno history. Requests/replies and sanitised failure metadata are retained; provider error bodies and credentials are not logged.
6. Browser/terminal views distinguish observations, interpretation, alternatives, uncertainty, coverage, questions and advice. Reference buttons open the corresponding retained record. Exports contain evidence and all saved turns. A fallback is labelled as a legacy fixed-rule result, never an AI answer.

## Versions and bounds

- Evidence format: 2. Response format: 2.0. Context/instructions/schema revision: 2.1. Response structure did not change between schema revisions; field-path grammar was corrected to accept actual names such as `ipv4.total_bytes` and `protocol_counts.TCP`. Source/schema hashes identify exact revisions.
- At most 96 detailed packets and 96 complete-member flows, with a 180,000-byte UTF-8 context bound; whole-capture overview/coverage remains separate. Selection is a capture-order prefix, not a claim of relevance optimisation. Omitted detail/counts are disclosed. Full evidence remains saved.
- Complete API request including bounded history: at most 900,000 UTF-8 bytes in the Agno adapter. This is an engineering bound, not a token count or the provider's advertised window.
- Questions: 600 characters. Checked answer: 32,000 UTF-8 bytes. Captures: 8 MiB/10,000 frames under the existing pipeline. Payload previews: up to 64 bytes.
- Supported detail remains classic Ethernet PCAP with outer unfragmented lab IPv4 TCP/UDP. No general text-log ingestion, stream/fragment reassembly, decryption or full application-protocol decoding is implied. An unsupported/malformed frame does not erase other valid observations.

## What validation does and does not prove

JSON structure and real references do not prove a sentence is true. Narrative counts, causality, citation relevance, omissions and recommendation usefulness still need semantic review. Command-pattern rejection is a limited extra guard, not a complete natural-language safety classifier. The stronger execution boundary is that no executor exists in this phase.

The model may disagree with the old TCP rule. No threshold or rule finding is supplied in independent requests. Legacy findings remain stored only as labelled comparisons/fallbacks and to preserve old reviews. Old v1 inputs retain their old prompt/validator rather than being silently reinterpreted.

Typed actions are investigate, no_action or block_source. A block can only be previewed for an observed source in the lab subnet, excluding protected hosts, for 1–120 seconds. The operator selects a saved recommendation; policy rechecks it. Nothing changes on the network. Offline traffic cannot establish current authorisation or endpoint mapping. Approval/execution/effect-check/rollback was outstanding at that checkpoint and is implemented in the current separate broker workflow.

## Reproducibility and limits

`components/06-testing-evaluation/evaluate_llm.py --live --output NEW_DIRECTORY` runs six predeclared development cases three times each, with one request per attempt and immutable result paths. Without `--live`, it prepares cases/rubric only. `run_checks.py --output NEW_JSON --environment-label LABEL` exercises offline contracts and controlled loopback failures. Preserve failures and distinguish them from successful replies; never use stub answers as model-quality evidence.

The October phase folder contains original source snapshots, transfer hashes, both actual live batches, semantic reviews and Goal 1 mapping. A six-case synthetic development test cannot establish broad real-world detection accuracy or independent generalisation.

Both retained phase-2 batches used thinking disabled, temperature zero and a 4,000-token generation budget. Do not relabel those results as max-reasoning evaluation. The subsequent reasoning-mode review records the configuration correction separately; a bounded live smoke test is not a replacement 18-run evaluation or evidence of broad quality improvement.
