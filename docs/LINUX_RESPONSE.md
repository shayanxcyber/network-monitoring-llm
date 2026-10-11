# Isolated Linux response

## What is implemented

This is one complete lab workflow, not a production firewall product:

1. Capture six authorised HTTP connection attempts in a disconnected Linux lab.
2. Parse the real capture and investigate it through the normal AI interface.
3. The operator prepares a fixed service-block proposal with a reason and duration.
4. A separate dialog requires an exact scope confirmation. Preparation and model
   recommendations do not apply a rule.
5. The broker checks the current capture/lab identity and that both clients can
   reach the service. It inserts one uniquely tagged rule inside the service
   namespace only.
6. Verify the source no longer reaches the service, the control client still does,
   and the exact rule exists.
7. Remove the exact rule on manual rollback or expiry, then verify both clients
   work again. Broker restart rolls back known active actions and revokes proposals.

The only executable scope is source **10.77.0.20** to service **10.77.0.10
TCP/8080**, for 5–120 seconds (UI choices 20/60/120). The control is 10.77.0.30.
These are known test clients, not identified attackers. Saved/uploaded PCAP
reviews have previews only; they cannot be relabelled as a current lab capture.
AI recommendations are advice. The operator selects and confirms the action;
there is no model-callable executor.

## Host and privilege separation

PacketPilot runs unprivileged as capstone. A separate root-owned systemd service
accepts strict JSON over a local Unix socket. Linux peer credentials, socket
permissions, fixed operations, strict field checks and server-side scope checks
bound this path. No caller-supplied shell, namespace, destination port or path is
accepted. Approval tokens are one-time and excluded from public audit/export.

Four named network namespaces hold the source, control, service and switch.
Three veth pairs connect only those namespaces. There is no host bridge,
external interface, default gateway or NAT. The VM management/SSH interface,
Windows network and root-namespace firewall are not action targets.

This helper still runs as root: root-owned fixed code is a trust boundary, not
proof of a fully sandboxed production security service. There is one local
operator identity, not multi-user authentication or approval separation.

## Setup on the agreed Ubuntu VM

Prerequisites: Python 3, iproute2, iptables, tcpdump and systemd. Install the
reviewed source once from the project root:

    sudo python3 components/05-safe-network-response/install_response_service.py --install
    systemctl status packetpilot-response.service
    .venv/bin/python launch.py

The installer writes root-owned helper files to /usr/local/lib/packetpilot-response,
the unit to /etc/systemd/system, and private state to /var/lib/packetpilot-response.
The socket is /run/packetpilot-response/control.sock. An existing unrecognised lab
namespace or veth name is not adopted/deleted. Investigate setup errors first.
The helper is specifically configured for the existing capstone account.

Open the Ubuntu application via its local browser, or use the existing SSH tunnel
from Windows. A Windows-only app cannot execute the Linux response; the browser
is merely viewing the Ubuntu backend.

Select **Capture isolated Linux lab**, investigate it, then prepare the response.
Captures are eligible for ten minutes. Proposals expire after sixty seconds.
Type the exact confirmation shown; approval cannot be replayed. Manual rollback
is available while active; expiry runs independently of the browser/app.

## Failure handling and records

Changed capture hashes, stale captures, wrong lab generations, bad approvals,
out-of-scope targets, unexpected interfaces/routes and unhealthy baselines reject
execution. Failed effect verification attempts rollback. Failed rollback raises
a fault, disables new responses and is retried by the watchdog.

State is flushed before execution, exact commands are bounded by subprocess
timeouts, and expiry checks wall and monotonic time. Systemd restarts the broker
after a crash; recovery removes known active rules. Expiry is not a kernel timer:
if the broker/systemd or kernel is unable to run, recovery can be delayed. A whole
VM reboot destroys this ephemeral topology; the next boot creates a new generation.
Do not promise uninterrupted protection during a VM/host outage.

Audit transitions include proposal, approval, applied rule/counters, verified
effect and restored connectivity. Current review exports include linked action
records. A broker-unavailable export says so instead of inventing action status.
Real timestamps remain intact. Root private state is not a teammate upload file.

## Verification

Portable checks:

    python components/06-testing-evaluation/run_checks.py --output NEW_REPORT.json

Real integration (explicitly applies then removes this isolated test rule):

    python components/06-testing-evaluation/exercise_linux_response.py --execute --phase normal --output NEW_FOLDER

Run against the Ubuntu app on loopback port 8768 as used by the exercise script.
The normal phase covers wrong confirmation, target rejection, approval replay,
effect verification, manual rollback and timed expiry. Separate prepare-restart /
verify-restart phases surround an administrator-triggered broker crash to verify
recovery; never crash arbitrary services. The 2 October development evidence
retains the actual commands/results and before/after host configuration.

Not yet implemented: arbitrary topologies/targets, traffic throttling, general
live capture, deployment to production hosts, multi-user authorization, exhaustive
fault/security testing or demonstrated attack-prevention accuracy.

## Official references

- Linux network namespace administration: https://man7.org/linux/man-pages/man8/ip-netns.8.html
- iptables rule operations: https://man7.org/linux/man-pages/man8/iptables.8.html
