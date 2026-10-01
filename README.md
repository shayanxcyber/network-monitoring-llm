# PacketPilot

A network-traffic review prototype for Cybersecurity Capstone Studio (41909).

PacketPilot helps an operator inspect a saved capture, ask questions about the observed traffic, and review evidence-linked explanations and response previews. The proposed wider product supports investigating network issues in a small-business environment; the current implementation is a bounded synthetic-capture prototype.

## Current implementation

- Scapy or TShark decodes supported saved PCAPs into structured packet facts.
- A deterministic rule flags one source trying at least six server ports within ten seconds.
- Our browser interface uses one Agno agent with a hosted model, standing instructions and saved conversation history.
- Reviews preserve evidence references, answers, errors, exports and audit records.
- Response policies validate temporary-block previews. They do **not** execute firewall changes.

Current evidence coverage is deliberately narrow: supported Ethernet/IPv4/TCP lab captures, bounded file size and packet count, and header facts rather than complete payload analysis. Unsupported traffic can currently cause an insufficient-evidence result, including mixed captures. The model's checked response must agree with the rule finding; independent broader AI detection is not implemented. Mininet integration, live enforcement, rollback and broader scenario evaluation remain future work.

## Team

| Team member | Role |
|---|---|
| Shayan Ali | LLM Integration and Operator Interface |
| Mohamed Khamis | Network Environment and Traffic Simulation |
| Martin Huynh | Packet Analysis and Deterministic Detection |
| Laurence Lau | Application Workflow, Audit and Data |
| Ryea Dsouza | Safe Network Response and Control |
| Antonio Dormido | Evaluation, Testing and Reproducibility |

## Project structure

| Path | Purpose |
|---|---|
| components/01-llm-interface/ | Model adapters, prompt, web routes and terminal interface |
| components/02-network-simulation/ | Synthetic PCAP generation |
| components/03-packet-analysis/ | Packet decoding and rule-based evidence |
| components/04-application-workflow/ | Processing, configuration, sessions and audit storage |
| components/05-safe-network-response/ | Bounded response-preview validation |
| components/06-testing-evaluation/ | Offline tests and result reporting |
| web/ | Browser interface |
| sample-data/ | Synthetic captures and manifest |
| validation/ | Dated test records |
| docs/ | Integration and validation documentation |

The existing TEAM_ROLES.md, PROJECT_DECISIONS.md, docs/setup.md and sample-data/README.md remain in the repository. Historical planning text should be read in its dated context.

## Ubuntu setup

Use the complete repository after all six uploads are merged. The desktop shortcut expects the agreed installation directory `/home/capstone/packetpilot`; a different path requires adjusting that shortcut.

With Python 3.12, venv support and the repository in that directory:

```bash
cd /home/capstone/packetpilot
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-app.txt
.venv/bin/python configure_key.py
.venv/bin/python launch.py
```

The key helper prompts privately and saves the key outside the project at `~/.config/packetpilot/secrets.env`. Do not commit or share that file. Set the non-secret provider/model options in settings.toml. The browser opens the local application on port 8765. API reviews send selected synthetic evidence and questions to the configured provider and may incur charges; offline rule reviews do not.

TShark is optional for Scapy-based saved-file operation but required for the decoder cross-check. The original Ubuntu environment's dependencies are recorded in requirements-ubuntu-verified.txt. This package does not install or configure Mininet, firewall execution or a live network.

## Testing

```bash
.venv/bin/python -m unittest discover -s components/06-testing-evaluation -v
```

Run from the repository root. Tests use controlled responses, not paid model inference. A missing TShark installation is reported as a skip. Historical Ubuntu and Windows outcomes are distinguished in [Validation](docs/VALIDATION.md); test counts are not detection accuracy.

## Further reading

- [Model and interface integration](docs/LLM_INTEGRATION.md)
- [Validation and limitations](docs/VALIDATION.md)

## Repository workflow

Keep changes on task branches, review diffs and merge agreed changes into main. Preserve existing project decisions and team credits. Commit useful scripts, synthetic captures and selected test evidence. Keep API keys, credentials and private key files out of Git.
