# Network Environment and Traffic Simulation

Role member: Mohamed Khamis.

pp_samples.py constructs the supplied normal.pcap and port-check.pcap plus their label manifest. It uses explicit addresses and Scapy-built packets; that generator itself never transmits traffic.

From the complete project root:

    .venv/bin/python packetpilot.py make-samples

## Constructed and collected evidence

Small constructed samples support repeatable import, extraction and expected-observation checks. They are not real attacks or proof of detection accuracy. Additional scenario definitions and fixtures are under components/06-testing-evaluation/.

The application also has real bounded collection in the disconnected Linux lab. pp_lab_capture.py in the response component and pp_capture_api.py in the interface component implement start/status/stop/cancel/import and current diagnostics. The existing functional paths are retained; no Mininet installation is required by this release.

The lab uses selected client 10.77.0.20, control 10.77.0.30 and service 10.77.0.10:8080. Current collection and diagnostic observations remain distinct from uploaded historical evidence. A reboot changes lab generation and can invalidate action authority without invalidating the saved capture for analysis.

See [lab operation](../../docs/VM_CONTINUATION.md), [collection and comparison definitions](../../docs/INVESTIGATION_DEPTH.md) and [recorded validation](../../docs/VALIDATION.md). The complete application requires all components, not this sample generator alone.
