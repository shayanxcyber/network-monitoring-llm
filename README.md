# PacketPilot

PacketPilot is a local network investigation workspace for Linux administrators. Import a saved capture or supported network log, ask questions about the traffic, inspect the original evidence and consider a response. The project uses a small-business lab scenario, with an isolated service, a selected client and an independent control client.

## Run the application

Use Ubuntu with Python 3.12, python3-venv and TShark installed. From the complete project folder:

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-app.txt
    .venv/bin/python configure_key.py
    .venv/bin/python launch.py

The browser opens at http://127.0.0.1:8765. The interface is already built and included in web/react; Node and Vite are not needed to use PacketPilot. The desktop launcher uses the agreed installation path /home/capstone/packetpilot.

configure_key.py asks for the hosted-model key without displaying it and stores it outside the repository, in ~/.config/packetpilot/secrets.env. Keep that file private. settings.toml contains non-secret defaults. .env.example shows optional environment overrides; the application does not automatically load it.

## Investigate evidence

1. Import a classic PCAP, a supported TShark TSV log, or one of the synthetic examples.
2. Ask a question. Your message appears immediately while the application reports genuine inspection progress.
3. Read the answer, its supporting observations and coverage. Open a packet, flow, log line or tool result to inspect the underlying record.
4. Add a selected record as question context only when useful. Follow up in the same source-scoped conversation or export the investigation.

Python validates and decodes inputs, retains original identities and calculates factual observations. Agno connects the model to bounded packet, flow, log and current-lab inspection tools. The model interprets this evidence rather than copying a compulsory rule verdict. Its structured output is checked for valid references and reported measurements; a passing check still does not guarantee that every sentence is correct.

Code suggestions are useful unverified examples, not instructions automatically passed to a shell. The older terminal commands remain available through packetpilot.py; their rule explanation and preview-only response are compatibility routes, not the current browser investigator.

## Controlled Linux responses

The optional response service creates a disconnected lab. Its fixed operations are a temporary TCP/8080 block or a service-reply rate limit for one selected client. The workflow is proposal, separate exact operator approval, execution, selected/control effect checks and restoration.

Saved or uploaded evidence cannot authorise a current network change. Use a fresh broker-issued lab capture and the linked recommendation, review its scope and commands, then approve separately. Cancellation, manual rollback, expiry and restart recovery are supported. The model cannot approve its own action or execute arbitrary commands.

See [Linux setup](docs/LINUX_RESPONSE.md) and [current response workflow](docs/WORKSPACE_RESPONSE_V4.md) before installing the privileged service. Allowed durations are 5-120 seconds; rate limits are 256-2048 kbit/s.

## Project layout and team

| Member and project role | Functional component |
|---|---|
| Shayan Ali, LLM Integration and Operator Interface | components/01-llm-interface |
| Mohamed Khamis, Network Environment and Traffic Simulation | components/02-network-simulation |
| Martin Huynh, Packet Analysis and Deterministic Detection | components/03-packet-analysis |
| Laurence Lau, Application Workflow, Audit and Data | components/04-application-workflow |
| Ryea Dsouza, Safe Network Response and Control | components/05-safe-network-response |
| Antonio Dormido, Evaluation, Testing and Reproducibility | components/06-testing-evaluation |

These are connected parts of one application. The current upload allocation crosses component boundaries where integration requires it; [handoff map](docs/HANDOFF_MAP.md) explains those connections. Combine all six packages before running the project.

## Checks

    .venv/bin/python -m pip install -r requirements-dev.txt
    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -v

The latest retained Ubuntu offline regression has 285 passing tests, and the frontend regression has 35 passing checks. These are software checks, not attack-detection accuracy. TShark is needed for the independent extraction comparisons. Controlled provider responses in the offline suite are not new hosted-model calls.

[Validation](docs/VALIDATION.md) separates regression, extraction agreement, model-format acceptance, answer-quality review and actual Linux effects. It preserves earlier results and failures instead of adding test-stage totals together.

## Coverage

The saved-capture decoder supports classic Ethernet PCAP and outer lab IPv4/TCP and UDP inside 10.77.0.0/24. Valid traffic is retained beside unsupported, malformed or truncated records. Inputs are bounded to 8 MiB and 10,000 records. One documented eleven-field TShark TSV format is supported.

PCAPNG, general text logs, stream reassembly, decryption and application-layer analysis are not implemented. Header evidence alone cannot establish business authorisation, malicious intent or events outside the capture. The response lab is fixed and disconnected; this is not a production firewall manager, general traffic collector or multi-user service.

## Further reading

- [Packet evidence and fields](docs/EVIDENCE_V2.md)
- [Saved network logs](docs/SAVED_FIELD_LOGS.md)
- [Investigation harness](docs/HARNESS_INVESTIGATION_V3.md)
- [Answer quality](docs/ANSWER_QUALITY.md)
- [VM continuation](docs/VM_CONTINUATION.md)
- [Third-party notices](web/react/THIRD_PARTY_NOTICES.txt)

Keep credentials, runtime databases, private provider continuity and local environments out of Git.
