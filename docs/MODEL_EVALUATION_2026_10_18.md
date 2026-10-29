# Historical updated-model evaluation - 18 October 2026

This is the frozen 18 October evaluation record. Its effort comparisons, software counts, configuration and statements about that session's final harness are historical, not a claim about every later revision. Original results below are preserved. See [latest recorded validation](VALIDATION.md) and [current model integration](LLM_INTEGRATION.md) for the delivered implementation.

Requested/returned model: deepseek-flash. DeepSeek documents the alias routing
to V4.1-Flash-1017; a returned alias alone does not independently pin its weights.
Agno 3.0.4 and SDK 2.54.0; no framework or weight-training change.

Thirty balanced sequential investigations compared thinking-enabled low, high
and max on five source/question pairs, twice each. Each arm accepted 8/10, with
different connection/output failures. Successful medians were 13.60, 17.77 and
27.65 seconds respectively; ranges 10.07-20.74, 11.12-22.78 and 20.50-51.99.
These survivor timings and contract counts are not an accuracy ranking. The
final harness was not retested across all three effort settings; max remains
the default, not silently changed to favour speed.

The full declared CLI work retained 73 attempts: 63 accepted, three connection
failures and seven output rejections, with zero 300-second timeouts. It includes
initials, follow-ups, new questions, two refinement cycles, two matched retests
and three previously unused final variants. Do not pool these as a single
detection-accuracy result. Final variants completed in 35.83, 31.56 and 26.67
seconds without repair. Initial historical and new results differ in model
routing, harness, quotas, cache/load and instrumentation, so the model update
alone cannot be credited with the timing differences.

Changes include shorter aggregate references, explicit current coverage,
clearer TCP initiator/reply roles and elapsed-time definitions, better correction
context, log-line/frame separation, tighter offset checks and a lint for known
incorrect TShark field names. No fixed threat verdict was introduced. Provider
stream timings are recorded; the UI receives useful public activity, not private
chain of thought or a guarantee of phrase-by-phrase final-answer streaming.

Software regressions: Ubuntu 298 passed, Windows 296 passed/two TShark-dependent
skips, frontend 37 passed and the locked frontend build succeeded. Source-byte
and TShark checks made 4,458 assertions on reused fixtures and 1,251 on new ones.

Limits remain: an accepted citation can support only part of a sentence;
transport completion is not application success; small synthetic cases do not
prove general detection ability. Three generated Python advice examples were
checked on four scratch fixtures each. They exposed blank-line, missing-field
and CRLF/UDP weaknesses. Generated code remains illustrative and unverified,
never executable broker authority. Final answers were not tuned afterward.

Policy: thinking enabled/max, no optional max_tokens override, no cumulative
application token stop, six model calls/eight tools and a shared 300-second
deadline including correction. Finite provider defaults still apply. A shorter
180-second demonstration limit is a recommendation for a later selected policy,
not faster inference or a guarantee that every future question will finish.

Official references: [updates](https://api-docs.deepseek.com/updates),
[chat completion API](https://api-docs.deepseek.com/api/create-chat-completion/),
[thinking mode](https://api-docs.deepseek.com/guides/thinking_mode).
Detailed immutable inputs/answers, timing and release records are retained in
the project's 2026-10-18 development evidence directory, not private runtime DBs.
