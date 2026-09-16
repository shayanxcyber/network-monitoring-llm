"""Typed response previews only. There is deliberately no command executor."""
from __future__ import annotations

import ipaddress

LAB = ipaddress.ip_network("10.77.0.0/24")
PROTECTED = {"10.77.0.1", "10.77.0.10", "10.77.0.0", "10.77.0.255"}


def preview_response(evidence, action="investigate", target=None, duration=60, apply=False):
    reasons = []
    if apply:
        reasons.append("Execution is not implemented; this version only previews responses.")
    if action not in {"no_action", "investigate", "block_source"}:
        reasons.append("Unknown response type.")
    if action == "no_action" and evidence["finding"] != "no_scan_pattern":
        reasons.append("Uncertain or flagged evidence needs review.")
    if action == "block_source":
        if evidence["finding"] != "scan_like":
            reasons.append("A block preview requires the supported port-check finding.")
        if target != evidence.get("candidate_source"):
            reasons.append("Target must be the source associated with the finding.")
        try:
            address = ipaddress.IPv4Address(target)
            if address not in LAB or str(address) in PROTECTED:
                reasons.append("Target is outside the permitted lab scope or is protected.")
        except (ipaddress.AddressValueError, TypeError):
            reasons.append("Target is not a valid IPv4 address.")
        if type(duration) is not int or not 1 <= duration <= 120:
            reasons.append("Preview duration must be an integer from 1 to 120 seconds.")
    elif target is not None:
        reasons.append("Only a block preview takes a target address.")
    return {
        "action": action, "target": target,
        "duration_seconds": duration if action == "block_source" else None,
        "allowed_preview": not reasons, "executed": False,
        "state": "preview_only" if not reasons else "rejected",
        "reasons": reasons,
        "operator_note": "Review context before any future network change. No firewall rule was applied.",
    }
