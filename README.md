# PacketPilot

PacketPilot helps Linux administrators investigate saved network evidence and review a controlled response. Import a supported capture or network log, ask questions, inspect the original records and compare related sources. The hosted model can request bounded inspection tools; Python supplies the observations and checks the returned references.

## Run locally

Use Ubuntu with Python 3.12, TShark and the supplied Python dependencies. The React interface is already built. You do not need Node, Vite or a frontend build to use the release.

See [SETUP.md](SETUP.md) for installation, API configuration and launch instructions.

    .venv/bin/python launch.py

The browser opens at http://127.0.0.1:8765. Import your own supported evidence or use the optional samples. Opening evidence does not call the hosted model. Sending a question in hosted mode does.

## Investigate a service problem

1. Import a classic PCAP or the documented TShark TSV log.
2. Ask what the records support. Open a cited record to inspect its original fields.
3. Use Related evidence & compare to group a baseline, problem and follow-up source. Select which sources the next question may use.
4. Choose two selected sources and a service port to compare their observed counts, rates and candidate reply timing.
5. Ask a follow-up. Previous answers retain their original source scope.
6. Download a readable case report or the structured evidence export.

Cases support up to six sources. Each review keeps its own original file, hash, packet or physical-line identifiers and conversation. Derived TSV records are not independent corroboration of their source capture.

## Current-lab checks and responses

The optional broker controls one disconnected lab service. It is not required for saved-file investigation.

- Collect a bounded real classic-PCAP session at the service interface, stop and keep the evidence, or cancel import. The fixed profile generates authorised health requests from both lab clients.
- Record current HTTP reachability and first-byte timing before, during and after a response.
- Review a temporary source block or service reply rate limit. Inspect the target, duration, commands and reversal, then separately approve the exact one-time proposal.
- Check the selected and control clients, actual enforcement and restoration. Roll back manually or let the independent broker expire its change.

The action scope is source 10.77.0.20 to service 10.77.0.10 TCP/8080. Control 10.77.0.30 is not an action target. Uploaded files and case membership never grant live execution authority. A fresh broker-issued capture, matching lab identity and separate operator approval are required.

The model cannot approve a response, run arbitrary shell text or manage other networks. Suggested command examples remain reviewable text, not executable authority.

## Evidence and interpretation

Supported input is classic Ethernet PCAP with outer unfragmented IPv4 TCP/UDP records in 10.77.0.0/24, or the exact eleven-field UTF-8 TShark TSV format. Limits include 8 MiB per input and 10,000 records. Unsupported, missing, malformed and truncated content is reported rather than silently treated as complete evidence.

HTTP inspection recognises bounded visible HTTP/1 start lines in saved TCP segments. DNS inspection covers bounded visible UDP DNS datagrams. There is no stream reassembly, decryption or universal protocol decoder. TSV logs contain no application payload.

Timing pairs are candidates based on visible relationships. Rates use each source's first-to-last observed record span, not an assumed collection interval. A TCP handshake, an HTTP status line and business success are separate observations. Missing replies do not establish network-wide absence. Current probes cannot recover a historical capture's missing direction.

Keep real-data permission and provider handling in mind before sending evidence to a hosted service. The included lab inputs are synthetic or from the disconnected test lab.

## Source and verification

Python source is separated by functional components under components/. The frontend source and lockfile are under frontend/; the distributable interface is under web/react/. Existing team/source notices are retained.

[Investigation-depth guide](docs/INVESTIGATION_DEPTH.md) explains calculation definitions, source boundaries, capture lifecycle and report contents. Historical evaluation records under docs/ describe the versions they tested. Software passes and valid output structure are not detection accuracy or a guarantee of every interpretation.

To run the Python suite:

    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -p "test_*.py"

Tests requiring TShark need the actual executable. An unavailable dependency is a skipped test, not a successful check.

This is a local, single-operator application. It is not a production multi-user monitoring service or a replacement for analyst judgement.

## Documentation

- [Setup](SETUP.md) and [Ubuntu lab operation](docs/VM_CONTINUATION.md): installation, file-only use and optional lab prerequisites.
- [Component map](docs/HANDOFF_MAP.md) and [current model integration](docs/LLM_INTEGRATION.md): architecture, tools, state and validation.
- [Evidence dictionary](docs/EVIDENCE_V2.md), [saved logs](docs/SAVED_FIELD_LOGS.md) and [service investigation](docs/INVESTIGATION_DEPTH.md): provenance, supported fields and comparison rules.
- [Workspace workflow](docs/WORKSPACE_RESPONSE_V4.md) and [Linux response](docs/LINUX_RESPONSE.md): suggestions, approval, measured effect and restoration.
- [Validation](docs/VALIDATION.md), [answer quality](docs/ANSWER_QUALITY.md) and [demonstration evidence](docs/ROADSHOW_EVIDENCE.md): recorded checks, interpretation limits and reproducible journeys.

The v2 investigation contract, 13 October audit and 18 October evaluation are explicitly historical records. Their older limits and test totals do not override current setup or capabilities. Evidence images and raw development receipts are supplied separately; private runtime databases are not part of this source package.
