# Network Monitoring and Traffic Manipulations Using LLM

Private team repository for the 41909 Cybersecurity Capstone Studio project.

## Project Purpose

Develop a prototype that processes network captures or logs, identifies relevant network activity, explains the
evidence using an LLM and provides safe network-response recommendations through an operator interface.

## Current Stage

The project is currently in Week 4 planning and environment setup. Tools and technical architecture are still being
discussed. The prepared folders do not represent completed implementation.

## Team

| Team member | Role |
|---|---|
| Shayan Ali | LLM Integration and Operator Interface |
| Mohamed Khamis | Network Environment and Traffic Simulation |
| Martin Huynh | Packet Analysis and Deterministic Detection |
| Laurence Lau | Application Workflow, Audit and Data |
| Ryea Dsouza | Safe Network Response and Control |
| Antonio Dormido | Evaluation, Testing and Reproducibility |

## Repository Structure

- `components/` contains one working area for each project role.
- `sample-data/` contains synthetic captures, logs and testing data.
- `docs/setup.md` contains confirmed project setup instructions.
- `TEAM_ROLES.md` records the team allocation.
- `PROJECT_DECISIONS.md` records confirmed technical decisions.

## Team Workflow

1. Create a separate branch for each task.
2. Add code and tests to the relevant component folder.
3. Review changes before merging them into `main`.
4. Update the project instructions when setup or dependencies change.

## Repository Rules

- Keep API keys and credentials private and never commit them to Git.
- Commit project scripts, synthetic PCAPs, logs, test inputs and useful evaluation results.
- Each member is responsible for testing and explaining their own component.
