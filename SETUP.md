# Set up PacketPilot

Use a local Ubuntu machine or VM with Python 3.12. Keep the application on loopback. The included interface is ready to use, so Node and Vite are not needed.

## Install and open

Extract the release into a folder you own, then run:

    sudo apt update
    sudo apt install python3-venv tshark
    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements-ubuntu-verified.txt

Saved-file analysis does not require permission to capture from host interfaces. You do not need to enable unprivileged host capture during TShark installation.

For file-only operation, set `lab_enabled = false` under `[application]` in settings.toml. This prevents this application from contacting the optional response broker, even if a broker is already installed on the machine.

    .venv/bin/python launch.py

Open http://127.0.0.1:8765 if the browser does not open automatically. To stop a foreground server, use Ctrl+C in the terminal running `.venv/bin/python app.py`. The launcher can reuse a server that is already running; it does not replace a different program on the same port.

## Hosted questions

Evidence browsing and offline inspection work without an API key. To enable hosted conversations, run:

    .venv/bin/python configure_key.py

Enter your own key locally when prompted. It is saved outside the release in your user's private configuration. Do not put a key in Git, Drive, a screenshot or an export. The supplied settings use deepseek-flash, thinking enabled and max reasoning. Investigations retain a 300-second overall deadline, six model calls, eight evidence tools and a bounded correction attempt. These limits are not a prediction that every question will take that long.

## Import evidence

Use Import evidence for a classic `.pcap` or the exact supported `.tsv` format. The current analysis scope is outer unfragmented Ethernet/IPv4 TCP/UDP traffic inside 10.77.0.0/24, up to 8 MiB and 10,000 records. Other formats and networks are not silently accepted.

Create a compatible saved field log from a supported capture:

    tshark -r capture.pcap -T fields -E header=y -E separator=/t -E quote=n -E occurrence=f -e frame.number -e frame.time_epoch -e frame.len -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e tcp.flags -e udp.srcport -e udp.dstport > capture.tsv

Preserve the original file. A TSV is derived evidence and does not contain raw packets or application payload. Opening a saved review is offline. A hosted question transmits its selected evidence and context to the configured provider.

## Optional disconnected Linux lab

This part requires administrator installation and the dedicated local operator account `capstone`. Use the project's existing isolated VM, or create that dedicated account in a separate lab VM. Do not install the broker on a shared production host. A general username-configurable or multi-user broker is not included.

Install the tools and, while signed in as capstone, run the explicit installer from this release:

    sudo apt install iproute2 iptables tcpdump
    sudo python3 components/05-safe-network-response/install_response_service.py --install

Set `lab_enabled = true` and restart the application. The root-owned systemd service creates only the reserved disconnected namespaces, with no gateway or external interface. It rejects an unexpected existing namespace or shaper rather than adopting it. Installation preserves the previous known broker code and stops the previous service so it can restore its own changes.

Use Current lab capture to collect real bounded traffic, then open the retained evidence. Ask for an investigation or an explicitly scoped test plan. Review a proposed action and its reversal before typing the exact confirmation. Closing a pending proposal cancels it; it does not approve anything. Existing receipts show enforcement, manual rollback and expiry separately.

Run only one installed broker for these namespaces. A second application can use the same existing broker, but never start a second broker against the same lab. Disabling lab access in one application's settings does not stop the shared broker or its independent expiry protection.

## Checks and recovery

    .venv/bin/python -m unittest discover -s components/06-testing-evaluation -p "test_*.py"

Some tests deliberately simulate provider failures or unavailable tools. Read the result summary instead of treating those expected error messages as live failures. Actual TShark checks run only when TShark is installed.

Reviews and private provider continuity are stored under runtime/ and runs/. Keep those folders and your private key configuration when upgrading. Stop the application before copying a database backup, or use SQLite's backup API. Do not overwrite a current source file with a different input under the same identity.

If a response shows rollback_failed, do not propose another action. Inspect the broker status and resolve restoration first. Do not delete unknown firewall rules or traffic controls. The application never changes the host-management firewall, default route or external networks.
