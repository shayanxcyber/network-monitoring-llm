# Related evidence and service investigation

The investigation-depth upgrade adds case grouping without replacing existing reviews. Each source keeps its original bytes, SHA256, coverage, raw packet or physical-line references, conversations and response binding. A case supports six sources with operator-assigned baseline, problem, after or reference roles.

New questions use only the selected case sources. The current source must be selected. Historical answers keep their saved scope; changing selection does not rewrite earlier answers. Source inspection tools return source-qualified original records through aggregate references, avoiding collisions between different sources' packet 1 or line 2.

## Calculations

- Counts describe selected decoded records, not unique attempts or all traffic on a network.
- Observed span is the latest timestamp minus the earliest selected timestamp. A zero or unavailable span has no calculable rate.
- Record rate is selected record count divided by observed span.
- PCAP byte rate uses captured frame bytes; TSV byte rate uses reported frame lengths. Their byte-rate delta is unavailable because the units have different evidence meaning.
- Direction counts use observed source and destination addresses. A service-port filter includes either direction involving that port.
- Candidate HTTP reply timing uses reversed tuples, order and a single pending visible request. DNS additionally matches transaction ID, query and query type. This does not reassemble streams or establish pure server processing time.
- The comparison preserves each source's denominator, exclusions and references. Unequal windows, short spans, missing content and coincident records are qualified. Normalised timestamp precision allows a derived TSV to be flagged as potentially coincident evidence, not independent corroboration.

Visible application fields are optional additions to the existing evidence schema. HTTP inspection is bounded to an HTTP/1 start line in one saved TCP segment. DNS inspection is bounded to a saved unencrypted UDP datagram. Existing records without these optional fields remain valid.

## Collection and current checks

Managed collection runs in the independent root-owned broker, not in a browser timer. The fixed observation point is pp-lab-service eth0, with a TCP/8080 filter, 2-20-second duration, 5,000-packet cap and 1 MiB cap. The fixed profile generates authorised service health requests. Start/status/stop/cancel/import are distinct operations. Duplicate starts are rejected; import retries reuse the same retained review. Interrupted broker state cannot be relabelled successful collection.

A current diagnostic sends one bounded HTTP request from each fixed client. It records observed time, target, path, connection/first-byte/total time, received prefix size, response status or failure type. It is active traffic, not a passive file inspection. A saved timestamp or uploaded capture never grants approval.

The operator can instead select a complete 128 KiB transfer check. It verifies the
fixed response body and records completion time and payload goodput separately
for both clients, including the control check if the selected client fails. It
does not call that full-transfer duration first-byte time. The before/after view
only compares the same check profile and objective. The model's no-argument
diagnostic tool remains the smaller health request.

Before/during/after observations attach to the review and optionally its actual response action. Successful blocking or shaping is not the same as solving the user's service problem. The comparison of single probes is descriptive, not a performance benchmark or proof of cause. A shared-contention mitigation claim needs a real shared bottleneck and matching measurements, not just a slower selected client.

Explicit baseline and after observation IDs bind each diagnostic comparison. The backend checks chronology, objective, profile, review/source, lab generation, clients/target and completed measurements. Incompatible or cross-cycle pairs return a reason instead of a numerical delta. Source comparisons also retain their applied pair/port; unsent control edits and late responses cannot silently redefine an exported snapshot.

See [current integration](LLM_INTEGRATION.md), [response workflow](WORKSPACE_RESPONSE_V4.md) and [recorded validation](VALIDATION.md).

## Reports

Readable HTML reports are self-contained and escape input text. They include source identities, selection, baseline comparisons, service calculations, questions, supported findings, uncertainty, diagnostic observations and linked action/restoration records. Original details include cited records; structured JSON retains the complete evidence. No provider key, approval token/hash or private reasoning is included. If the broker is unavailable, action history is explicitly unavailable, not assumed restored.

The report is an operational export, not the university assessment report. The frontend source and built assets remain part of the runnable application; end users do not rebuild them.
