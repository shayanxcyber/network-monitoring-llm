# Packet Analysis and Deterministic Detection

Role member: Martin Huynh.

The role title is retained from the proposal. The current investigator uses evidence-led model assessment, not a compulsory deterministic verdict.

pp_packet_records.py validates classic PCAP records and decodes bounded outer lab IPv4/TCP and UDP. Packet identities retain the original capture hash and frame number. Coverage records unsupported, malformed and snapshot-truncated frames without discarding valid neighbours. TShark independently compares selected decoded fields.

pp_evidence.py supplies both detailed observations and the legacy TCP-rule compatibility view. pp_tcp_relationships.py calculates supported request/reply relationships and distinguishes a service destination port from its source port on replies.

pp_logs.py imports the documented eleven-field TShark TSV format. Physical line number, byte range and line hash are separate from the exported source frame number. pp_evidence_views.py builds paginated records, timelines, maps and chart aggregates from retained evidence, not invented events.

The evidence and log schemas describe these boundaries. See [field dictionary](../../docs/EVIDENCE_V2.md) and [saved logs](../../docs/SAVED_FIELD_LOGS.md). Extraction agreement is not proof of an attack or authorisation.
