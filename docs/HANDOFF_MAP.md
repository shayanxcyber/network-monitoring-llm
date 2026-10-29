# Component and dependency map

PacketPilot is one local application divided into functional components. A component folder is not a standalone program. The complete source, configuration, dependencies and built interface are required for a runnable installation.

See [README.md](../README.md) for the product workflow and [SETUP.md](../SETUP.md) for installation.

## 01 - Model and operator integration

Location: components/01-llm-interface/.

pp_web.py connects HTTP routes to evidence import, conversations, runs, cases, collection and response records. pp_investigator.py supplies the current Agno/tool-enabled investigation loop. Context, prompts, typed contracts and claim/domain checks prepare and validate the interaction.

Packet, log and case tools consume the selected retained evidence. Workspace tools expose only supported observations and plan preparation. They do not give the model arbitrary shell access or approval authority.

## 02 - Network simulation

Location: components/02-network-simulation/, with repeatable inputs under sample-data/ and scenario fixtures in the evaluation component.

The scenario generator creates small known packet constructions. Labelled fixtures support extraction, relationship and interpretation tests. Constructed examples are not real incidents or independent evidence of detection accuracy.

## 03 - Packet and log evidence

Location: components/03-packet-analysis/.

Packet records, evidence views, TCP relationships and saved-log handling preserve supported original fields, source identity and coverage. Service calculations add bounded visible HTTP/DNS observations and qualified source comparisons.

These observations feed the model tools and the interface. Missing fields are not inferred into existence. PCAP packet references and TSV physical-line references remain distinct.

## 04 - Application workflow and data

Location: components/04-application-workflow/.

Review/session storage retains originals, conversations, case roles/selections and response links. Run management coordinates pending, completed, stopped and failed investigations. Workflow/settings modules connect these responsibilities to the web and command-line entry points.

Each saved answer retains the source scope used to produce it. An export reports the applied comparison snapshot, not unsent control edits.

## 05 - Controlled Linux responses

Location: components/05-safe-network-response/.

The response engine manages proposal, exact approval, action state, effect checks and restoration. An independent root-owned broker performs only allowed operations in the fixed disconnected lab.

Managed collection and diagnostics use the broker's bounded lab capabilities. Uploaded evidence alone is not current execution authority. Manual restoration and independent expiry remain distinct recovery paths.

## 06 - Testing and evaluation

Location: components/06-testing-evaluation/, with interface checks under frontend/tests/.

The tests cover extraction, references, case scope, run state, contracts, approval boundaries and recovery. Evaluation runners retain model outputs for structural and semantic review.

Software pass counts, decoder agreement, answer quality, selected/control effect and browser journeys are separate forms of evidence. They are not interchangeable accuracy measures.

## Interface and entry points

frontend/src/ contains the React workspace, conversation/composer, originals, charts, cases, managed capture and action/outcome panels. frontend/ also retains build configuration, dependency lock and component notices.

web/react/ contains the matching prebuilt interface; web/vendor/ contains local assets and notices. Ordinary operators serve these through Python without a frontend build. Retained earlier web files remain connected to fallback/compatibility paths.

app.py, launch.py and packetpilot.py provide the web, desktop/launcher and command-line entry paths. settings.toml supplies non-secret configuration; configure_key.py configures the operator's key outside source.

## End-to-end flow

    Original PCAP or supported TSV
      -> validated records, relationships and coverage
      -> selected source context and bounded inspection tools
      -> Agno / hosted model investigation
      -> checked answer with original references
      -> operator review of a typed response
      -> separate exact approval
      -> fixed Linux broker operation
      -> selected/control effect and restoration records

No model answer bypasses the approval boundary. Private runtime data, credentials and local environments are not part of the repository. Administrative upload allocations are maintained separately in the team handoff.
