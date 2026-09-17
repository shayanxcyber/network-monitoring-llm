# Application Workflow, Audit and Data

pp_workflow.py joins capture parsing, explanation, response checks and storage.
Each request receives its own run ID and directory containing evidence.json,
result.json, operator-report.txt (when run through the CLI) and audit.jsonl.

Audit entries record actual execution times, capture/evidence hashes, completion
or failure and the response preview. Old runs are not overwritten. Credentials
and raw HTTP error bodies are not written into the audit.

pp_sessions.py stores the browser's reviews, request IDs, turns and previews in
SQLite. pp_settings.py loads non-secret settings and the private external key.
The browser uses this same workflow; saved history/review persistence is tested.
Next: trace one successful and failed run, inspect an export, and maintain
consistent capture/session boundaries as more scenarios are added.
The local audit is append-only by application convention, not tamper-proof storage.
