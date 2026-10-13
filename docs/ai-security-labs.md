# AI Security labs: implemented scope

The **AI Security Engineer** track now has nine interactive, local training fixtures aligned to all nine categories shown in the learning-track UI.

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

Open Security Studio, switch to **AI Security Engineer**, and use **Practical AI Security labs**. Select any of the nine categories and run **Attack probe → Apply teaching fix → Independent retest**. Each lab has a server-issued run ID, reset action, server-side evidence timeline, deterministic control check, and local UI progress persistence. Session state and evidence are persisted in SQLite; no account-based progress sync is implemented. The E2E suite exercises the complete lifecycle for all nine labs.

## Safety and honest scope

All nine are deterministic server-side teaching fixtures using synthetic data. They do not call an external LLM, retrieve real documents, use credentials, send payments, execute arbitrary tools, connect to an inference endpoint, or contact external hosts. No user editor code is executed. The retest checks the fixture's explicit server-side control state independently of the UI phase and attack narrative.

These are functional educational simulations, **not live tests of a model or production AI service**. They do not prove a mitigation would stop a real model. ## Opt-in live model smoke evaluation

A first, deliberately narrow live-provider evaluation endpoint is available for two synthetic cases. It uses the existing OpenAI-compatible provider configuration and never targets an external application:

- `GET /api/ai-security/live-eval/status` reports whether the feature is enabled and configured.
- `POST /api/ai-security/live-eval/run` accepts only `indirect-prompt-injection` or `synthetic-secret-leak`.
- Set `AI_SECURITY_LIVE_TESTS_ENABLED=true` in the backend environment to opt in. It is disabled by default and rate-limited to three requests per minute.
- Configure `OPENCODE_GO_API_KEY`, `OPENCODE_GO_BASE_URL`, and `OPENCODE_GO_MODEL` as for the existing assistant.

The route uses fixed synthetic prompts, a short timeout, a small output budget, and deterministic case-specific checks. It does not accept arbitrary prompts, model names, URLs, tools, documents, or targets. The provider may receive the synthetic test prompts, so review provider terms before enabling it. This is only a smoke evaluation—not a comprehensive red-team suite or evidence that a model is secure. Provider output is returned as evidence and should be treated as untrusted text.
