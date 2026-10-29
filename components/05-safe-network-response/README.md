# Safe Network Response and Control

Role member: Ryea Dsouza.

This component implements the optional fixed disconnected Linux lab, separate operator approval, selective responses, effect checks and restoration. See [Linux response](../../docs/LINUX_RESPONSE.md) and [workspace workflow](../../docs/WORKSPACE_RESPONSE_V4.md).

## Boundary and operations

pp_response_engine.py orchestrates proposals, exact one-time approval and lifecycle records. pp_response_client.py connects the unprivileged application to pp_response_broker.py. The root-owned broker and pp_linux_lab.py carry out only fixed validated operations. pp_response_operations.py defines supported parameters and commands.

The executable target is source 10.77.0.20 to service 10.77.0.10 TCP/8080; 10.77.0.30 is the control, not an action target. Temporary blocks and service-reply rate limits use 5-120 seconds; rates are 256-2048 kbit/s. There is no arbitrary shell or external-network executor.

Current broker-issued evidence and matching lab identity are required. Uploaded files, model advice and case membership do not grant execution authority. The operator separately reviews target, duration, rate, commands and reversal, then supplies the exact confirmation.

## Effect and recovery

The broker checks selected/control observations and owned enforcement state. Manual restoration, independent expiry and recovery of owned changes are supported. Failed restoration blocks new responses until resolved. A command exit code alone is not proof that the service problem was solved.

pp_lab_capture.py supplies bounded service-interface collection with separate start/status/stop/cancel/import operations. Diagnostics are active current observations, not a reconstruction of missing historical capture traffic. See [measurement and capture definitions](../../docs/INVESTIGATION_DEPTH.md).

## Setup and compatibility

Install the service explicitly using [SETUP.md](../../SETUP.md), only in the dedicated authorised lab environment. Keep one broker for its reserved namespaces.

pp_policy.py and the retained CLI provide legacy non-executing preview behaviour. That compatibility path does not describe the current browser's approved response capability. Actual test/effect/restoration evidence is summarised in [validation](../../docs/VALIDATION.md).
