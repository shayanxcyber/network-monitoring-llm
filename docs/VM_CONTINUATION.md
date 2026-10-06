# Ubuntu setup and continuation

Verified: 31 August 2026. The approved setup is complete for the first saved-capture
prototype. Start from this checkpoint; do not reinstall Ubuntu or repeat API setup.

## Open PacketPilot

In Ubuntu, open the application menu and choose **PacketPilot**, or run:

    cd /home/capstone/packetpilot
    .venv/bin/python launch.py

The launcher starts the local backend if needed and opens
http://127.0.0.1:8765/ in the guest browser. It also supports `--no-browser`.
The application keeps running independently of the setup SSH terminal.

The Windows in-app preview uses an SSH forward to the same guest application.
A Windows preview connection is optional; the product itself runs inside Ubuntu.
If a preview becomes unavailable, first verify that the VM, application and
forward are running. Do not assume localhost is blocked.

## Verified environment

| Item | Actual state |
|---|---|
| Guest | Ubuntu 24.04.4 LTS; kernel 7.0.0-28-generic |
| Allocated resources | 6 vCPUs, 12 GB RAM; about 11 GiB visible in Linux |
| Network | VMware NAT; guest 192.168.37.128 at this checkpoint |
| Disk | About 49 GB root filesystem, about 35 GB free during setup |
| Core tools | Git 2.43.0, Python 3.12.3, pip 24.0, tcpdump 4.99.4 |
| VMware integration | open-vm-tools 13.0.0 package active; desktop integration package installed |
| SSH | OpenSSH 9.6p1 package; verified dedicated-key login working |
| Packet tools | TShark and Wireshark 4.2.2 installed; saved-capture decoder checks pass |
| Python application | Isolated /home/capstone/packetpilot/.venv |
| Framework | Agno 3.0.4, OpenAI SDK 2.54.0, SQLAlchemy 2.0.52 |
| Web stack | FastAPI 0.141.1, Uvicorn 0.52.4, HTTPX 0.28.1, python-multipart 0.0.32 |
| Packet library | Scapy 2.7.0 |
| Existing snapshot | Preserved unchanged; no additional snapshot or restore performed |
| Mininet | Not installed in this setup; reserved for the live-topology phase |

Observed direct Python versions are retained in `requirements-ubuntu-verified.txt`.
This is not a complete transitive lockfile. Use `requirements-app.txt` for a fresh
project environment and rerun the checks after dependency changes.

## Where things live

- Canonical source:
  D:/Cybersecurity Learning System/Current Semester/Subjects/cybersecurity-capstone-studio/Roadshow/PacketPilot
- Guest working copy: /home/capstone/packetpilot
- Application menu launcher: /home/capstone/.local/share/applications/packetpilot.desktop
- Non-secret settings: /home/capstone/packetpilot/settings.toml
- API key: /home/capstone/.config/packetpilot/secrets.env
- Conversations and review index: /home/capstone/packetpilot/runtime/
- Per-run evidence, answers and audit records: /home/capstone/packetpilot/runs/
- Backend log: /home/capstone/packetpilot/runtime/server.log
- Host VM configuration: C:/Users/User/Downloads/capstone vm/Cybersecurity Capstone Ubuntu.vmx
- Team Git checkout, deliberately separate:
  D:/Cybersecurity Learning System/Current Semester/Subjects/cybersecurity-capstone-studio/Team Repository/network-monitoring-llm

The user entered the API key successfully. Its file is owner-only (mode 600).
Do not ask for it again unless a real authentication failure requires a change.
If replacement is necessary, run `.venv/bin/python configure_key.py` inside the
guest. Input stays hidden; never print or export the saved key.

## SSH continuation from Windows

Dedicated private key path: C:/Users/User/.ssh/packetpilot_vm_ed25519.
Do not read, display or include this key in a handoff package.

Verified guest ED25519 fingerprint:

    SHA256:59KVDrWmYqaivTDxSP0EVvs446eR2r5/4TYFrJ0XJus

The Windows client required an explicit compatible key-exchange selection:

    ssh -i C:/Users/User/.ssh/packetpilot_vm_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 capstone@192.168.37.128

For the optional Windows browser forward, use the same options with:

    -N -L 127.0.0.1:8765:127.0.0.1:8765

Retain strict host-key checking. If the DHCP address changes, identify the VM
again rather than trusting an arbitrary replacement at the old address.
Normal authorised sudo over SSH does not require repeated permission questions.
User authentication dialogs and Windows UAC remain direct-user handoffs. No VM
password belongs in these files, command arguments or logs.

## What passed

- Both generated PCAPs decode with TShark and agree with Scapy.
- Initial Ubuntu checking exposed a TShark Boolean-format mismatch; it was fixed
  and covered by a regression test.
- Final suite: **71 passed, zero failures/errors/skips**.
- Two real AI questions succeeded in one saved review; the second request carried
  the preceding question and answer. Total reported usage: 2,376 tokens.
- Saved reviews and both answers survived backend restart.
- The application shows evidence links, saved conversations, clear rules-only
  fallback and a bounded source-block preview. No network action executes.
- The operator UI uses PacketPilot/AI labels. Actual provider/model identifiers
  remain in technical configuration and audit records.

See [Validation](VALIDATION.md) for exact run IDs and retained records. Opening a
review or inspecting evidence does not call the model; submitting an AI question does.

## Next action

Use the verified result for the 8–10-minute proposal roadshow. Explain what exists
and what is still planned. Do not extend the implementation merely to fill slides.

Later work includes a justified live topology, additional independent traffic
cases, stronger explanation-quality evaluation, resource measurements and any
separately agreed network-control executor/rollback. Those are not completed by
this setup. No GitHub push, slides or official LabArchives entry has been made.

## Setup history and boundaries

The original OS/core-package checkpoint was preserved. After the user installed
and started OpenSSH, the fingerprint was matched and key access established.
Only missing first-prototype dependencies were added. TShark/Wireshark were
installed from Ubuntu packages; non-root live-capture permissions were not enabled.
The app binds only to guest loopback. There was no router forwarding, root-login
enablement, passwordless sudo or firewall disabling.

Computer-use Escape cancelled a desktop check; the user explicitly resumed and
later unlocked Ubuntu. Background SSH/application work remained available.
Earlier `PacketPilot-pre-VM-2026-08-31.zip` and transfer archives are dated
snapshots, not the current canonical source.

[Ubuntu OpenSSH documentation](https://ubuntu.com/server/docs/how-to/security/openssh-server/) ·
[TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
