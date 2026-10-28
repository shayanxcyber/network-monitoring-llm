# Application Workflow, Audit and Data

Role member: Laurence Lau.

This component retains source identity, application state and the connection between evidence, questions, answers and response records.

## Storage and runs

pp_sessions.py stores reviews, originals, requests, conversations, case roles/selections and linked records in SQLite. pp_runs.py coordinates public pending, completed, stopped and failed request states. pp_settings.py loads non-secret settings and the operator's private external key.

pp_workflow.py supports the retained analysis/CLI workflow. Its run directory may contain evidence.json, result.json, an operator report and audit records. The browser's current investigation also uses source-scoped jobs, case snapshots and public progress; it is not limited to the older CLI report shape.

Audit events preserve actual timing and identity. Credentials and raw provider error bodies are excluded. Local append-only conventions are not tamper-proof forensic storage.

## State integrity and reports

Each source keeps its original bytes/hash. Earlier answers retain the scope used at generation time even when case links or the current selection change. Original inspection is separate from explicitly attaching question context.

The case API and panel preserve the applied comparison pair/port rather than unsent control edits. Asynchronous source transitions must not display the outgoing source's inspector against the new source. Reports combine retained evidence, public answers, comparisons, diagnostics and available response receipts.

Private runtime and provider-continuity databases are not distributed with source. Preserve them separately with compatible source/database recovery procedures. See [setup and recovery](../../SETUP.md), [case/report semantics](../../docs/INVESTIGATION_DEPTH.md) and [validation](../../docs/VALIDATION.md).
