# Packet Analysis and Deterministic Detection

Role member: Martin Huynh. The submitted role label is retained; the current investigation is evidence-led rather than forced to repeat a detector verdict.

## Evidence pipeline

pp_packet_records.py validates and retains supported original packet records. Scapy normalises supported outer Ethernet/IPv4 TCP/UDP fields; the TShark mode independently checks selected fields against the same immutable capture. Decoder agreement validates extraction, not attack interpretation.

pp_evidence.py retains the narrow legacy TCP assessment for compatibility, separately from detailed observations. pp_evidence_views.py supplies inspectable views, and pp_tcp_relationships.py calculates qualified visible request/reply/header relationships.

pp_logs.py imports the exact supported saved TSV format. Physical line number, original byte offset, line hash and separately reported source frame number remain distinct. A derived field log is not independent raw-packet corroboration.

pp_service_evidence.py adds bounded visible HTTP/1 and UDP DNS observations, candidate timings and neutral source comparisons. It does not reassemble streams, establish business success or supply a compulsory threat verdict.

## Limits and consumers

Inputs are bounded to the documented classic PCAP or exact TSV subset within the lab address scope. Malformed, unsupported and truncated records are reported; one unusable record does not erase other supported observations. Full details are in the [field dictionary](../../docs/EVIDENCE_V2.md) and [saved-log guide](../../docs/SAVED_FIELD_LOGS.md).

The model tools and interface consume these observations with original references and coverage. Service comparisons preserve each source's units, denominator and exclusions. Explicit diagnostic identities prevent measurements from different cycles being paired. See [calculation and comparison rules](../../docs/INVESTIGATION_DEPTH.md).

Current software results and their interpretation limits are in [validation](../../docs/VALIDATION.md).
