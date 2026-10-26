# Ubuntu lab operation

PacketPilot runs locally on Ubuntu with Python 3.12 and TShark. The built browser interface is included. Node and Vite are not required for ordinary use.

See [SETUP.md](../SETUP.md) for the complete installation procedure and [README.md](../README.md) for supported inputs and the operator workflow.

## File-only investigation

From the complete project folder, create the Python environment and install the supplied requirements:

    sudo apt update
    sudo apt install python3-venv tshark
    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-ubuntu-verified.txt

Set `lab_enabled = false` under `[application]` in settings.toml for file-only operation. This also prevents this application from contacting an optional broker already installed on the machine.

Start the application:

    .venv/bin/python launch.py

The normal browser address is http://127.0.0.1:8765. Keep the service on loopback. The launcher may reuse an existing local server; it does not replace an unrelated program using the port.

Opening saved evidence is offline. Sending a hosted question requires the operator's own provider key. Run `.venv/bin/python configure_key.py` to configure it privately. Credentials, private conversation databases and local environments are not part of the source release.

## Optional disconnected response lab

The broker uses a dedicated local operator account named `capstone`. Install it only in a separate authorised lab VM, not on a shared production host. While signed in as that operator, follow SETUP.md, including:

    sudo apt install iproute2 iptables tcpdump
    sudo python3 components/05-safe-network-response/install_response_service.py --install

Then set `lab_enabled = true` and restart the application. Run only one broker for the reserved namespaces. A second application may use the existing broker; it must not start another broker against the same lab.

The fixed lab has a selected client at 10.77.0.20, a control client at 10.77.0.30 and a service at 10.77.0.10:8080. Its reserved namespaces are disconnected from external networks. The broker rejects unexpected existing namespace or traffic-control state rather than adopting it.

## Collection and diagnostics

Managed collection observes the fixed service interface and TCP/8080 profile. Start, stop, cancel and import are distinct operations. The limits are 2-20 seconds, 5,000 packets and 1 MiB. Cancelled or interrupted collection is not successful evidence acquisition.

Current health and complete-transfer checks generate active requests from the fixed clients. The interface shows the target, control and check profile before execution. Compare only measurements with matching source, target, objective, profile, lab generation and explicit baseline association.

A reboot can change lab identity. Old retained evidence remains useful for offline analysis, but it does not automatically retain authority for a current response.

## Approval and restoration

Review the proposal's exact target, duration, commands and reversal. A separate one-time operator approval is required. The model cannot approve itself or execute arbitrary shell text.

After an allowed block or rate limit, inspect both selected-client and control results. Use the restoration control when appropriate. Independent broker expiry removes its own change even when the web application is stopped.

If the application reports `rollback_failed` or a broker fault, do not begin another response. Inspect the actual status and resolve restoration first. Do not delete unknown firewall or traffic-control rules.

## Local state and recovery

Application reviews, retained originals, private continuity and logs are stored under runtime/ and runs/. These directories are ignored by Git and are not included in the source handoff. Preserve them separately when upgrading.

Stop the application before making an ordinary database copy, or use SQLite's backup API. A source rollback must be compatible with the retained database. Do not replace the original bytes of an existing evidence identity.

For a foreground server, Ctrl+C stops the Python process. Broker lifetime and response expiry are separate from the browser or application process.

## Verification

Run the documented checks from the complete project folder:

    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -p "test_*.py"

TShark-dependent checks need the real executable. An unavailable dependency is a skip, not a pass. Some tests deliberately simulate provider errors or unavailable tools. Read the suite result and the expected case, not isolated negative-test log messages.

This guide describes a portable operator procedure. It does not depend on a particular host's VM path, SSH key, address or saved credentials.
