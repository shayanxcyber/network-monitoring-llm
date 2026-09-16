# Safe Network Response and Control

pp_policy.py supports no-action, investigation and a typed temporary-block preview.
It checks the evidence finding, target, protected addresses and bounded duration.
It rejects execution and contains no shell/firewall executor.

Example:

    python packetpilot.py analyse --capture sample-data/port-check.pcap --preview block_source --target 10.77.0.30

Next: review the approval and target boundaries. Later, separately implement a
lab-only executor with expiry, rollback and verification; demonstrate it only
inside the agreed isolated network. A permitted preview is not an applied block.
