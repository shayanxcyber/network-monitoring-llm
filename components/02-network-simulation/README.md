# Network Environment and Traffic Simulation

Role member: Mohamed Khamis.

pp_samples.py uses Scapy to construct normal.pcap, port-check.pcap and their manifest. It does not transmit traffic. Regenerate with python packetpilot.py make-samples.

Contrasting cases in components/06-testing-evaluation provide normal traffic, multi-port probing, single-port retries, replies, mixed TCP/UDP and incomplete-evidence examples. Their expected labels are declared separately from the model output.

The optional live response lab uses fixed disconnected namespaces: service 10.77.0.10:8080, selected source 10.77.0.20, control 10.77.0.30 and the lab gateway. record_lab_network.py records the mapping; exercise_linux_response.py is a separate explicitly executed Linux experiment. Do not describe constructed examples as live captures.

The cases feed Martin's decoder/evidence calculations, Shayan's investigator and Antonio's evaluation. settings.toml supplies non-secret runtime defaults. See [evidence](../../docs/ROADSHOW_EVIDENCE.md), [lab setup](../../docs/LINUX_RESPONSE.md) and [current allocation](../../docs/HANDOFF_MAP.md).
