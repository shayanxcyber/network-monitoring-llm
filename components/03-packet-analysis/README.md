# Packet Analysis and Deterministic Detection

pp_evidence.py validates and decodes a saved PCAP, preserves its hash and packet
numbers, and applies one explicit rule: at least six server ports tried by one
source within ten seconds. It reads only packet-header fields, not payload text.

The decoder is selected with --decoder scapy or --decoder tshark. Auto uses
TShark when installed, otherwise Scapy; the chosen decoder is recorded.

Next: repeat the earlier Ubuntu TShark/Scapy check, inspect the referenced packets and
test legitimate maintenance/near-threshold examples. The threshold is illustrative,
not a claim that every matching source is malicious.
