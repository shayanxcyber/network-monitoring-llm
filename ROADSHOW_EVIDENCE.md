# What the early demonstration can show

Keep the presentation at the user's 8–10-minute target. The first example answers
one simple question: does this traffic need checking, and why?

## Real artifacts now available

- Two synthetic PCAP files and a separate explanation/label manifest.
- Packet-derived findings, exact packet references and readable rule-based results,
  verified through both Scapy and Ubuntu TShark.
- A typed response preview and actual timestamped host/guest audit records.
- A working light browser interface, saved reviews and linked evidence.
- Two actual hosted-model answers in one conversation, including a follow-up;
  both remained available after a backend restart.
- A 71-pass Ubuntu functional/negative test record, separate from the real API check.

These are genuine preliminary results from saved synthetic captures. They are
not a live attack demonstration, production deployment or broad accuracy benchmark.
Open the saved AI review and [validation record](VALIDATION.md); do not make
extra paid calls merely to recreate evidence that is already retained.

## Useful screenshots for the slide-making step

The Windows preview is forwarded over SSH to the actual Ubuntu backend. The user
explicitly approved this capture route; it is not a second Windows implementation.
Screenshot records are under ../evidence/screenshots/ and the exported saved AI
review is ../evidence/2026-08-31-ai-review.json. The first capture is a compact
browser-panel view; the complete answer/history remains in the export and live UI.

The user requested a small, practical set for the slides: retain these two
screenshots, without building a larger screenshot collection.

1. The port-check review: a real AI explanation, source/port evidence and the
   non-executing response preview in one view.
2. The normal comparison: the fixed-rule explanation that no port-check pattern
   was found, clearly labelled as an offline rules result rather than an AI answer.

Use only a readable portion that supports the slide's point. Re-capture from the
same saved review at presentation-window size only if needed for legibility.
Keep the saved reviews/exports as a fallback and label results as recorded. Do
not describe a controlled HTTP test response as model inference.

## Simple speaking sequence

1. PacketPilot: who the operator is and why packet evidence is hard to interpret.
2. The small-business setting and one server used for the first test.
3. Normal traffic versus a computer trying several ports.
4. How the capture becomes evidence, an explanation and a reviewed response.
5. What currently works, with actual screenshots.
6. What still needs building/testing and the six role responsibilities.

Retain the assessment's resource, risk, evaluation and milestone points when
turning this outline into slides. Keep PacketPilot/AI branding in the presentation
interface; preserve accurate provider metadata in the technical evidence.
Slide production and rehearsal are the next task, not completed by this setup.
