# Application Workflow, Audit and Data

Role member: Laurence Lau.

pp_workflow.py joins input processing, model or compatibility explanation, response preview and per-run storage. pp_sessions.py stores browser sources, turns and previews. pp_runs.py manages durable investigation jobs, progress, cancellation and reconnect behaviour. pp_settings.py combines safe configuration with a private external key.

A source, request and run retain separate identities. Repeating an existing request does not silently create another paid investigation. Conversations remain source-scoped, and exports keep useful evidence and public results together without credentials or private reasoning.

app.py, launch.py, packetpilot.py and packetpilot.desktop load the integrated application. frontend/src/api.js and refinement.jsx connect browser events, inspectors and exports; the landing styles organise history and navigation.

Tests cover persistence, duplicate requests, interrupted/streamed work, source isolation, uploads and export. Actual run/audit times remain genuine. Application append-only logging is not tamper-proof storage. See [workspace](../../docs/WORKSPACE_RESPONSE_V4.md) and [handoff](../../docs/HANDOFF_MAP.md).
