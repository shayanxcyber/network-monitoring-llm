# Design decisions

PacketPilot developed from a saved-capture prototype into a connected investigation and controlled-response workflow. These are the decisions implemented in the delivered application.

| Decision | Implementation and reason |
|---|---|
| Hosted inference | DeepSeek handles model computation through the API. Python processing, evidence storage and Linux controls remain local. The tested workflow ran on a 2-vCPU, 3.95-GB Ubuntu VM. |
| Evidence-led investigation | Python supplies measurements and original records. The model investigates them through bounded tools instead of being required to repeat a rule-generated verdict. |
| Original record references | Explanations link back to packets or physical TSV lines so an operator can check what supports a claim. Partial coverage remains visible. |
| Related sources | Baseline, problem and follow-up captures can be compared without changing the source selection retained by an earlier answer. |
| React workspace | Interface concepts and browser prototypes led to a workspace that keeps conversation, evidence, comparisons and responses together. A prebuilt interface is shipped for ordinary use. |
| Separate response service | A root-owned broker applies only permitted actions in disconnected namespaces. Model suggestions cannot approve or execute themselves. |
| Measured recovery | The selected and control clients are checked around an action. Manual rollback and independent expiry provide separate restoration paths. |
| Connected release | Functional components are integrated into one runnable source tree. Original member commits remain in repository history. |

See the [component map](docs/HANDOFF_MAP.md), [validation](docs/VALIDATION.md) and [setup guide](SETUP.md) for the corresponding implementation and checks.
