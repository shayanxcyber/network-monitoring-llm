# Saved network field logs

PacketPilot accepts a bounded **TShark field-log TSV**, separately from a classic PCAP. The saved-log importer does not accept arbitrary text, Zeek connection logs or a continuous log stream. Managed lab capture is a separate application capability. This format is not a universal log parser; see [current integration](LLM_INTEGRATION.md) and [validation](VALIDATION.md).

## Produce the format

Use a controlled lab capture. The following command writes a UTF-8, tab-separated file with the exact header; the shell redirection is only the operator's export step, never a model tool.

```sh
tshark -r sample-data/normal.pcap -T fields -E header=y -E quote=n -E occurrence=f -e frame.number -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.flags -e udp.srcport -e udp.dstport > normal.tsv
```

Default TShark field separation is a tab. Field order is fixed. No payload/free-form message field is imported. Use **Import evidence** to select the `.tsv`, then ask a question after import. Importing does not call the model; sending a question does. Offline mode reports observations with no model or rule verdict.

## Data dictionary / version 1.0

| Field | Interpretation and bounds |
|---|---|
| frame.number | Positive original export identifier; duplicates become malformed. Not an independently verified raw frame. |
| frame.time_epoch | Finite decimal seconds, 0–253402300799. |
| frame.len | Reported length, 1–16777216; does not prove payload content. |
| ip.src / ip.dst | Lab IPv4 endpoints, 10.77.0.0/24. Recognisable out-of-lab addresses reject the file. |
| ip.proto | TCP 6 / UDP 17 supported; other values disclosed as unsupported. |
| tcp.srcport / tcp.dstport | Required for TCP, 0–65535; must be empty on UDP. |
| tcp.flags | Required hexadecimal TCP flags, 0–511; names are calculated header observations. |
| udp.srcport / udp.dstport | Required for UDP, 0–65535; must be empty on TCP. |

The original file is retained unchanged. `capture.sha256` is the **log file** hash (backward-compatible identity field), `packet_count=0`, `record_count` is the number of data lines. `input_kind=network_log`, `log_schema_version=1.0`. `log_records` are not placed in `packets` or converted into invented raw frames. A data line's reference is `<file-sha256>:lN`, where N is its original physical line number, including header line 1. Each has original byte offset, byte length and SHA-256 of its exact line bytes; `source_frame_number` is separately recorded.

## Coverage, context and tools

Limits: 8 MiB, 10000 rows, 4096 bytes/line; exact header; UTF-8 only. Valid neighbours survive malformed/unsupported rows, which remain counted with bounded reasons. All-invalid files fail. Only validated fields—not arbitrary source text—enter model context. The overview covers the whole log. Initial details are at most 96 rows / 180000 UTF-8 bytes. Omitted records remain in the evidence and are retrievable.

`get_log_records(line_numbers)` retrieves 1–16 original lines. `summarize_log_records(protocol, source, destination, destination_port)` computes neutral directional totals over all usable rows, not merely the initial prefix. `inspect_tcp_exchanges(source, destination, destination_port)` identifies candidate SYN/reply/ACK relationships from exported tuples, flags and times. It does not invent missing sequence numbers or turn an exported line into an independently checked packet. All three reuse call/byte/deadline/trace controls and return JSON. At most 8 read-only tool calls per investigation; paths, shells, network probes and raw-packet tools are not available for log reviews. Prior inspected selectors are rehydrated from this exact file hash. Typed answers resolve `lN` to supplied canonical IDs; cross-file/invented IDs, incorrect measurements and false complete-coverage declarations fail validation.

The context and tool results list available scalar measurement paths. Log totals
use `record_count`, not an invented raw-packet count. Aggregate references retain
membership. Valid references and correctly copied values still do not establish
that every clause in an answer is supported. See [answer-quality limits](ANSWER_QUALITY.md).

The log cannot establish omitted payload, export completeness, application success, permission or current traffic. A conditional block suggestion is still **preview only**; an uploaded field log has no fresh Linux lab binding. Approval and execution remain separate from the model.

## Verification and resource

Unit/protocol/web tests: `components/06-testing-evaluation/test_logs.py`. Recorded real TShark export, Windows/Ubuntu import comparison and hosted model answer belong to the dated development evidence pack; a passing structural test is not detection accuracy.

Wireshark Foundation. (n.d.). *tshark(1) manual page*. https://www.wireshark.org/docs/man-pages/tshark.html (consulted 3 October 2026).
