# Controlled Linux lab response

The current application supports a complete temporary block and service-reply rate-limit workflow in one disconnected lab. It is not a general host firewall or production network controller. [SETUP.md](../SETUP.md) covers installation; [workspace workflow](WORKSPACE_RESPONSE_V4.md) describes the operator journey.

## Fixed scope and privilege boundary

The selected source is 10.77.0.20, control is 10.77.0.30 and service is 10.77.0.10 TCP/8080. Allowed responses last 5-120 seconds. Service-reply shaping accepts 256-2048 kbit/s. The control is not an action target, and an uploaded capture cannot substitute a different address into the live lab.

The unprivileged application communicates with a separate root-owned systemd broker over a local Unix socket. Peer identity, socket permissions, typed operations and server-side checks constrain the request. There is no caller-supplied shell, arbitrary namespace, external interface or destination port.

Four reserved namespaces and their veth connections form a disconnected topology. The host management interface, default route and root-namespace firewall are not response targets. Root-owned fixed code remains a trust boundary, not a claim of a fully sandboxed multi-user service.

## Proposal to verified restoration

1. Collect and retain a supported current-lab capture through the application.
2. Investigate the source and review a typed proposal, exact scope, duration, rate where relevant, expected effect and reversal.
3. Supply separate exact one-time approval. Preparing advice or closing a dialog is not approval.
4. The broker validates current capture/lab identity, allowed parameters and baseline conditions, then applies its own precisely identified operation.
5. Inspect selected-client, control and enforcement observations. A command exit code alone is not effect verification or proof of solving the reported service problem.
6. Restore manually or allow independent expiry, then verify removal and recovery. Failed restoration blocks further responses until resolved.

Current capture eligibility is bounded and proposals have short one-time deadlines, displayed by the application. Wrong, stale, altered, cancelled, replayed, cross-source and out-of-scope authority is rejected. A reboot changes lab generation; old evidence remains analysable but is not current execution authority.

## Installation and lifecycle

Use the dedicated local capstone operator in a separate authorised lab VM. Install the service explicitly from the complete source as described in SETUP.md. Run one broker for its reserved namespace names; do not start another against the same lab.

The installer places root-owned code under /usr/local/lib/packetpilot-response, its systemd unit under /etc/systemd/system and private state under /var/lib/packetpilot-response. The control socket is /run/packetpilot-response/control.sock. Unexpected existing namespace or traffic-control state is rejected rather than adopted or deleted.

Response ownership is retained before applying the change. Exact rollback, watchdog expiry and recovery are independent of browser lifetime. Broker startup revokes pending authority and recovers known owned state. A broker/system/kernel outage can delay recovery; a whole VM reboot destroys the ephemeral topology. No uninterrupted protection during an outage is promised.

## Collection and current outcome checks

Managed capture is bounded to the service TCP/8080 profile, 2-20 seconds, 5,000 packets and 1 MiB. Start, stop, cancel and import remain separate. Diagnostics generate current requests and do not recover missing historical traffic.

Health and complete 128 KiB transfer checks have different objectives. A timeout remains a failed/incomplete measurement. Explicit baseline and after identities, matching objective/profile/source/generation/target and complete observations are required for a comparison. See [measurement rules](INVESTIGATION_DEPTH.md).

## Records and verification

Public records distinguish proposal, approval, application, effect and restoration. Exports exclude approval tokens, keys and private reasoning. If broker history is unavailable, the report says so rather than assuming restoration.

[Validation](VALIDATION.md) summarises actual block/negative-approval, browser shaping/manual restoration and app-off expiry checks. Portable unit tests use lab doubles and are not real firewall operations. The older CLI policy path remains preview-only, independently of the implemented browser response chain.

The retained exercise helper is an explicit integration harness with a loopback 8768 default; ordinary application launch uses 8765. Use the normal UI for an operator demonstration unless deliberately configuring a test harness. Administrator crash/recovery exercises must not target unrelated services.

The supported scope excludes arbitrary topologies, unrestricted capture, generated-text execution, multi-user authorisation and production-security or attack-prevention guarantees.

## References

- [Linux network namespaces](https://man7.org/linux/man-pages/man8/ip-netns.8.html)
- [iptables operations](https://man7.org/linux/man-pages/man8/iptables.8.html)
