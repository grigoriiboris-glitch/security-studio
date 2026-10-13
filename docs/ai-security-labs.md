# AI Security labs: implemented scope

The **AI Security Engineer** track now has nine interactive, server-managed deterministic training fixtures aligned to all nine categories shown in the learning-track UI.

1. **AI Security Foundations — Trust boundaries:** separate trusted instructions from user/retrieved data and map the data-flow boundary.
2. **Prompt Injection & Jailbreaks — Indirect prompt injection:** prevent retrieved instructions from overriding policy or exposing a synthetic marker.
3. **RAG & Knowledge Security — Tenant isolation:** prevent cross-tenant document retrieval and enforce ACLs before context assembly.
4. **AI Agents & Tools — Tool authorization:** demonstrate least privilege, server-side policy checks, and approval for consequential actions.
5. **Data Privacy & Leakage — Sensitive output:** prevent synthetic PII and secret markers from appearing in responses.
6. **Model & ML Security — Artifact provenance:** require source, version, and integrity checks before trusting model/dataset artifacts.
7. **AI Red Teaming & Evaluation — Regression suite:** pin a reproducible adversarial case and expected pass/fail criterion.
8. **AI Infrastructure & Governance — Inference API:** demonstrate authentication, request limits, audit, and secret handling.
9. **AI Security Interview Lab — Architecture review:** assess threat model, prioritized risks, evidence-backed mitigations, and residual risk.

## How to run

Open Security Studio, switch to **AI Security Engineer**, and use **Practical AI Security labs**. Select any of the nine categories and run **Attack probe → Apply teaching fix → Independent retest**. Each lab has a server-issued run ID, reset action, server-side evidence timeline, deterministic control check, and local UI progress persistence. Sessions are held in backend memory and are lost on backend restart; no account-based progress sync is implemented. The E2E suite exercises the complete lifecycle for all nine labs. Session state is held in backend memory and is lost on backend restart; only the browser-side view of progress is stored locally. Account-based progress sync is not implemented.

## Safety and honest scope

All nine are deterministic server-side teaching fixtures using synthetic data. They do not call an external LLM, retrieve real documents, use credentials, send payments, execute arbitrary tools, connect to an inference endpoint, or contact external hosts. No user editor code is executed. The retest checks the fixture's explicit server-side control state independently of the UI phase and attack narrative.

These are functional educational simulations, **not live tests of a model or production AI service**. They do not prove a mitigation would stop a real model. Live model testing remains a separate future stage and would require an explicit provider integration, isolated test credentials/data, provider-specific adversarial datasets, trace capture, repeatable evaluation criteria, and safety limits. Do not describe this stage as production AI red teaming.
