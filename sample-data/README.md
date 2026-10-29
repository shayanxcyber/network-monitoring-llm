# Sample traffic

These small synthetic captures make the import and investigation workflow easy to try. They contain no collected personal traffic and use the fixed `10.77.0.0/24` lab network.

| Capture | Records | What it contains |
|---|---:|---|
| [normal.pcap](normal.pcap) | 9 | Three TCP handshakes involving two service ports. |
| [port-check.pcap](port-check.pcap) | 8 | Connection attempts to eight server ports within 0.7 seconds. |

[manifest.json](manifest.json) records the expected construction and file hashes. Its labels describe the synthetic cases, not proof of intent in an unfamiliar capture. Packet timestamps use a fixed synthetic clock.

The application accepts classic PCAP and the documented saved-field TSV format, not PCAPNG. See [Import evidence](../SETUP.md#import-evidence) for the supported fields and export command. More detailed controlled cases are defined in the testing component.
