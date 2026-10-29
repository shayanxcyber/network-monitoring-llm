# Packet evidence v2: extraction contract and field dictionary

This is the retained packet evidence format and field dictionary, introduced on 1 October 2026. It describes offline extraction, not a universal detector. Current model tools, saved-log import, managed collection and approved responses build on it; see [model integration](LLM_INTEGRATION.md), [saved logs](SAVED_FIELD_LOGS.md) and [investigation depth](INVESTIGATION_DEPTH.md). The original capture remains authoritative. Parsing an existing file does not transmit traffic or change network configuration.

## Processing and provenance

`analyse_capture` validates bounded classic-PCAP framing, snapshots its bytes, decodes outer Ethernet/IPv4/TCP or UDP with Scapy, accounts for every frame, creates bidirectional flow groups, then adds the old TCP-only compatibility view. `auto` selects TShark verification when installed. In TShark mode, the same immutable bytes are independently read by TShark and selected fields are compared to Scapy/container records. TShark is not represented as a second independent normalisation implementation: `decoder.normalizer` explicitly identifies Scapy in both modes. No silent decoder fallback occurs after disagreement or failure.

The packet fields checked against TShark are enumerated in `pp_packet_records.TSHARK_FIELDS`: frame number/time/captured and wire length, IPv4 endpoints/TTL/ID/header length/total length/protocol, TCP ports/flags/raw sequence/raw acknowledgement/window/header length, UDP ports/length. Unsupported or malformed frames are checked at container level only; checksums, option bytes and payload previews are not independently verified by that comparison.

## Top-level contract

The machine-readable contract is `components/03-packet-analysis/evidence-v2.schema.json` (JSON Schema Draft 2020-12). Development tests validate schema syntax, all labelled cases, and invalid outputs. Cross-record relationships require the additional reference/count tests; JSON Schema alone cannot establish packet truth or referential completeness.

| Field | Meaning |
|---|---|
| `schema_version` | String `2`; old stored v1 investigations are not rewritten. |
| `capture` | Original SHA-256, file size, frame count, format/link type, snapshot length, timestamp resolution. Filename is not an outcome label. |
| `decoder` | Selected mode, real installed versions, normalizer, optional independent verification method/count/field list. |
| `packets` | One ordered record per original frame, including unusable frames. Never limited to the legacy first 24 references. |
| `flows` | Supported decoded frames grouped by protocol plus an unordered pair of IP/port endpoints. |
| `coverage` | Counts of mutually exclusive decoded/unsupported/malformed/truncated statuses; issue codes point to affected packet numbers. |
| `overview` | Protocol counts (including declared protocols of problematic frames), separately decoded counts, flow count, byte totals, first/last times, duration and capture-order timestamp warning. |
| `legacy_assessment` | Explicitly labelled old TCP-rule scope/result/references, not the evidence-led model's assessment. |
| `facts`, `finding`, `rule`, `candidate_source`, `distinct_ports`, `lab_server` | Compatibility fields for retained legacy consumers, not the current investigator's compulsory verdict. These remain a narrow TCP view. |
| `limitations` | Persisted coverage/interpretation constraints; retain alongside any later model context. |

## Packet record dictionary

| Field group | Meaning / units / absence |
|---|---|
| `id`, `packet` | Full capture SHA-256 plus `:pN`; one-based original frame number. Changing the capture changes IDs. |
| `timestamp`, `time` | Exact decimal epoch-seconds string at source micro/nanosecond precision, plus a convenient floating-point seconds value. Use the string for exact timestamp comparisons; floats/summaries may round submicrosecond intervals. Traffic times are not work-session dates. |
| `file_offset`, `captured_bytes`, `wire_bytes`, `frame_sha256` | Byte offset to frame data in the original PCAP, bytes actually saved, reported original frame length and hash of saved frame bytes. Captured/wire differences are explicit snapshot truncation. |
| `status`, `issues` | `decoded`, `unsupported`, `malformed` or `truncated`; machine-readable reasons. `decoded` means supported headers decoded, not proven benign or checksum-valid. |
| `protocol`, `ethernet` | Outer/declarative protocol label; MAC endpoints and EtherType. Null Ethernet means no complete header. VLAN, IPv6 and ARP remain explicitly unsupported. |
| `ipv4` | Outer source/destination, protocol number, TTL, identification, header and total byte counts, fragment offset (8-byte units), more-fragments Boolean, stored header checksum, raw option bytes in hex. Null when no usable IPv4 header. |
| `tcp` | Ports; numeric flag mask and names FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS; raw sequence and acknowledgement numbers; unscaled advertised window; header length; stored checksum; urgent pointer; raw options hex; declared payload byte length. Null for non-TCP or unusable TCP. |
| `udp` | Ports, UDP datagram byte length including its 8-byte header, stored checksum and payload length. Null for non-UDP or unusable UDP. A checksum of zero is recorded as zero, not interpreted as validation. |
| `payload` | Present for parsed transport: byte length, first at most 64 captured payload bytes in hex, explicit limit and preview-truncated flag. Full payload stays in the original capture. This preview field itself does not interpret or execute text; bounded optional HTTP/DNS observations are produced separately by the service evidence module. |
| `flow_id` | Matching flow ID for decoded supported records; null otherwise. A partial frame may retain readable header metadata but does not contribute to flow calculations. |

Physically incomplete PCAP records are rejected: the next frame boundary cannot be trusted. A complete container with a snapshot-shortened or malformed frame is accounted for per frame while other valid frames remain useful. Reported lengths and header fields are observations, not proof that captured traffic was authentic.

## Flow dictionary and interpretation

`id` combines the full capture hash with a deterministic endpoint-key hash. `endpoint_a`/`endpoint_b` are sorted address/port pairs, not client/server role assertions. `packet_refs` lists every contributing original frame. Counts and captured bytes are sums of those frames; direction counts distinguish A→B and B→A. First/last times and duration use observed capture timestamps. TCP flag counts count presence per packet, not reconstructed connection states.

This is a capture-wide bidirectional five-tuple group, not TCP stream reassembly. Reused connections with the same endpoints can be grouped together. SYN/ACK observations do not establish application success; absence from a capture does not establish absence from the network. Packet loss, capture location, authorization, business intent and encryption remain external context.

## Limits and preserved compatibility

- Packet input is at most 8 MiB and 10,000 frames, classic PCAP with Ethernet link type 1. PCAPNG is unsupported. Managed lab collection produces a supported capture for this parser; exact TSV ingestion is a separate path.
- Supported transport records: outer unfragmented IPv4/TCP and UDP within the configured 10.77.0.0/24 lab. Out-of-scope IPv4 addresses reject the input rather than bypassing the existing lab boundary.
- Unsupported protocols/fragments/tunnels retain frame identity and available outer metadata. They are not attributed to nested transport endpoints.
- No decryption, TCP/fragment reassembly or checksum validation. Optional bounded visible HTTP/1 and UDP DNS fields do not make this a universal application decoder.
- Adding unsupported traffic no longer forces an all-capture insufficient-evidence result. UDP-only captures contain useful observations even though the compatibility TCP finding remains `insufficient_evidence`; it means “no input for this TCP rule,” not “nothing can be learned.”
- Saved reviews retain their original schema. v1 reopening, answering and history are regression-tested; v2 uploads, history and exports preserve the new fields.
- The earlier compatibility payload used facts/finding fields. The current investigator uses richer observations and source-qualified tools without a compulsory legacy verdict. Separate approved lab responses are documented outside this extraction contract.

## Evidence-to-model boundary

Current integration builds model context from `capture`, `overview`, `coverage`, `packets` and `flows`, retaining IDs and explicit limits. Keep any legacy rule result separate and exclude it from independent LLM-only experiments. Coordinate Agno instructions, context, response schema, validators and UI references together. Require evidence-backed claims without forcing agreement with `finding`; validate referenced capture/packet/flow IDs and separate advice from approved execution. Treat payloads and any decoded text as untrusted data, not instructions. Keep case labels outside model context. Preserve capture-scoped conversation/history and error handling. The current contract no longer requires agreement with the legacy finding.

## Reproduction and resources

Install the test-only schema dependency with the project's virtual environment and `python -m pip install -r requirements-dev.txt`. Do not install globally. Run from the application root:

    python components/06-testing-evaluation/run_checks.py --output validation/new-checks.json
    python components/06-testing-evaluation/verify_evidence_pipeline.py --phase upgraded --output validation/new-extraction

Both output targets must be new; earlier evidence is preserved. The extraction pack retains labelled PCAPs, hashes, decoded JSON, commands, raw TShark TSV where available, schema checks and negative-input outcomes. Windows without TShark reports that skip; Ubuntu supplies the independent comparison. No live model calls are made.

Official references consulted 1 October 2026 (online versions can differ from the installed versions recorded in evidence):

- Wireshark, [tshark(1) Manual Page](https://www.wireshark.org/docs/man-pages/tshark.html), options `-r`, `-n`, `-T fields`, `-e`, `-E`, `-o`: offline reads and explicit field extraction. Agreement validates extraction, not attack interpretation.
- Scapy, [scapy.utils API](https://scapy.readthedocs.io/en/latest/api/scapy.utils.html) and [Usage](https://scapy.readthedocs.io/en/latest/usage.html): established packet/capture handling. Project framing validation surrounds library protocol decoding; it does not replace Scapy with a universal decoder.
- python-jsonschema, [Schema Validation](https://python-jsonschema.readthedocs.io/en/stable/validate/), `Draft202012Validator`, `check_schema` and `FormatChecker`: structural validation with explicit formats. Reference/count tests supply separate semantic checks.
