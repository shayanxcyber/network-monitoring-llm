# Team Roles

| Team member | Role | Main responsibility |
|---|---|---|
| Shayan Ali | LLM Integration and Operator Interface | Configure and integrate the model/API, develop prompts and structured outputs, and build the operator interface |
| Mohamed Khamis | Network Environment and Traffic Simulation | Configure the Linux network environment, simulate topologies and generate labelled network traffic |
| Martin Huynh | Packet Analysis and Deterministic Detection | Process PCAPs/logs, extract structured evidence and implement transparent detection rules |
| Laurence Lau | Application Workflow, Audit and Data | Connect non-LLM components, manage application data and maintain timestamped audit records |
| Ryea Dsouza | Safe Network Response and Control | Validate recommendations and implement dry-run, approval, verification and rollback controls |
| Antonio Dormido | Evaluation, Testing and Reproducibility | Evaluate the application, maintain tests, measure performance and verify reproducibility |

All members also contribute to documentation, integration, project reporting and evidence of individual work.

The role titles retain the original proposal wording. In the current design, packet analysis supplies measurements, relationships and coverage to an evidence-led investigation rather than forcing the model to repeat a deterministic verdict. Response work includes actual fixed-lab execution, measured effect, manual rollback and independent expiry. Components depend on one another, so responsibilities overlap at their integration points.
