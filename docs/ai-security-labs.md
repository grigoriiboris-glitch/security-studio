# AI Security labs: current scope

The AI Security Engineer track currently includes three interactive training fixtures:

1. **Indirect prompt injection** — treats retrieved text as untrusted input and demonstrates output-policy enforcement.
2. **RAG tenant isolation** — demonstrates why authorization must be applied to retrieval and context assembly, not only to the prompt.
3. **Agent tool authorization** — demonstrates least privilege, server-side policy checks, and approval for consequential actions.

## How to run

Open Security Studio, switch to **AI Security Engineer**, and use the **Practical AI Security labs** section. For each scenario run the attack probe, apply the teaching fix, then run the independent retest. Evidence is shown as a timeline; each scenario can be reset and repeated.

## Safety and scope

These are deterministic, local training fixtures using synthetic markers and simulated actions. They do not call an external LLM, retrieve real documents, use credentials, send payments, execute arbitrary tools, or contact external hosts. The retest checks the fixture's configured control independently of the displayed attack narrative, but the fixture's state is intentionally simplified.

**Important limitation:** these first labs are interactive educational models, not a production-grade AI red-team harness or proof of real model behavior. The UI must not claim that a real model has been tested. Future server-backed labs should add adversarial test sets, repeatable model/provider adapters, authorization-enforced synthetic RAG, tool-call traces, and regression tests before being described as live runtime verification.
