# Evidence-led answer quality

## Why this revision exists

The earlier tools supplied counts and individual records, but did not calculate
how a SYN related to its reverse reply and final ACK. Responses also sometimes
mixed service breadth with repeated attempts, interpreted a decoded subset as
complete evidence, or used one citation for a sentence containing several claims.
More reasoning alone did not solve these problems.

## Coordinated changes

- `pp_tcp_relationships.py` calculates neutral header relationships from retained
  evidence. It is not a signature detector or an instruction to agree with a verdict.
- `inspect_tcp_exchanges` is available for both PCAP and the supported field log.
  PCAP raw sequence/acknowledgement checks and log-only candidates are distinct.
- Context and results name actual scalar measurement paths and decoding limits.
  A measurement must copy a supplied value exactly. Arrays are not scalar paths.
- Tools return JSON through the installed Agno interface. Argument validation,
  selected-source scope, public traces, budgets and private reasoning controls remain.
- Instructions ask for a short direct answer, atomic observations, qualified
  interpretations and unresolved business context. Optional lists may be empty.
- Reviewed guidance addresses capability matching, clause-level support and
  answering the question without repeating the same evidence in every section.

Matching uses direction, tuples, ordering, flags and, where present, raw sequence
and acknowledgement values. Retransmissions, equal-time replies and multiple
candidates may be ambiguous. A three-way header relationship is not proof of an
application transaction. No matching reply in the decoded window is not proof
that no reply occurred elsewhere. Unknown frames remain unknown.

## Boundaries

These are read-only Python operations on the backend-selected immutable input.
There is no filename, shell, display-filter, live probe or network-control argument.
The model still interprets observations and can be wrong. It cannot authorise an
action. Execution uses the separate fixed-lab approval broker.

The parser is not universal or a stream-reassembly engine. Logs retain only their
declared fields. References resolve to original packets or physical log lines,
not interchangeable evidence. Raw source hashes, trace membership and repeated
run results remain necessary for review.

## Verification, not an accuracy claim

`test_quality.py` checks relationship calculations, ambiguity, missing coverage,
measurement paths, bounded arguments and saved-state rehydration. A native Agno
protocol test verifies JSON tool dispatch and the final aggregate reference.
These checks use controlled inputs and do not measure threat-detection accuracy.

`evaluate_quality.py` supplies six separately declared synthetic contrasts,
two independent repetitions per arm. It retains inputs, initial context, settings,
source/schema/prompt hashes, every public provider result, failed corrections,
usage and tool traces. Expected interpretations are withheld from the model.
Review final prose separately from structural acceptance. A valid reference can
still support only part of a claim; a small comparison is not representative of
real networks or a causal model-only benchmark.

## Official resources

Agno, *Tools overview*: https://docs.agno.com/tools/overview

DeepSeek, *Thinking mode*: https://api-docs.deepseek.com/guides/thinking_mode/

Wireshark Foundation, *tshark(1)*: https://www.wireshark.org/docs/man-pages/tshark.html

Consulted 3 October 2026. The installed Agno version and observed SDK/tool
behaviour are recorded with the development comparison, rather than assumed
from the latest documentation alone.
