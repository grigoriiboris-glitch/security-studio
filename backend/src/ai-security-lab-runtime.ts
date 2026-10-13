import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { getAISecurityLabRun, saveAISecurityLabRun } from "./database.js";

export const aiSecurityLabCatalog = [
  { id: "foundations", title: "AI Security Foundations", control: "trustSeparated", attack: "Untrusted content is mixed with privileged instructions.", fix: "Keep retrieved and user content explicitly untrusted; preserve instruction/data boundaries.", verifier: "Trust boundary remains enforced." },
  { id: "prompt-injection", title: "Prompt Injection & Jailbreaks", control: "promptIsolated", attack: "A synthetic retrieved document asks to override policy and reveal a training marker.", fix: "Treat retrieved instructions as data and enforce output policy outside the model.", verifier: "Retrieved instructions cannot override policy." },
  { id: "rag-isolation", title: "RAG & Knowledge Security", control: "tenantScoped", attack: "Tenant A requests a synthetic private document belonging to tenant B.", fix: "Apply tenant and user ACLs before retrieval results enter context.", verifier: "Cross-tenant retrieval is denied." },
  { id: "agent-tools", title: "AI Agents & Tools", control: "toolAuthorized", attack: "A synthetic consequential tool action is requested without authorization or approval.", fix: "Enforce server-side authorization, least privilege, and approval for consequential actions.", verifier: "Unauthorized tool actions are rejected." },
  { id: "privacy", title: "Data Privacy & Leakage", control: "sensitiveOutputFiltered", attack: "A response attempts to expose synthetic PII and secret markers.", fix: "Minimize context and filter sensitive output before returning it.", verifier: "Sensitive synthetic markers are filtered." },
  { id: "model-security", title: "Model & ML Security", control: "provenanceVerified", attack: "An artifact without trusted provenance or integrity evidence is submitted.", fix: "Require approved source, pinned version, and integrity verification before promotion.", verifier: "Unverified artifacts remain quarantined." },
  { id: "red-team", title: "AI Red Teaming & Evaluation", control: "evalRegressionPresent", attack: "A known adversarial case has no pinned expected result or regression check.", fix: "Store a reproducible case and enforce a measurable pass/fail criterion in CI.", verifier: "Regression case and expected result are present." },
  { id: "infrastructure", title: "AI Infrastructure & Governance", control: "endpointProtected", attack: "An anonymous client calls a synthetic inference endpoint without limits.", fix: "Require access checks, request limits, safe secret handling, and audit events.", verifier: "Anonymous access is denied and controls are enabled." },
  { id: "interview", title: "AI Security Interview Lab", control: "reportEvidenceComplete", attack: "An architecture review lacks prioritized risks, evidence, and residual-risk ownership.", fix: "Document trust boundaries, prioritized risks, evidence, owners, and residual risk.", verifier: "Review contains risks, evidence, and residual risk." }
] as const;

type LabId = typeof aiSecurityLabCatalog[number]["id"];
type Controls = Record<string, boolean>;
type Phase = "ready" | "exploited" | "fixed" | "passed";
type Session = { runId: string; labId: LabId; phase: Phase; controls: Controls; evidence: Array<{ step: string; message: string; passed: boolean }>; createdAt: string };
const sessions = new Map<string, Session>();
const catalogById = new Map<string, typeof aiSecurityLabCatalog[number]>(aiSecurityLabCatalog.map((lab) => [lab.id, lab]));
const controlsFor = (): Controls => Object.fromEntries(aiSecurityLabCatalog.map((lab) => [lab.control, false]));
const keyFor = (labId: string, runId: string) => labId + ":" + runId;
function findSession(labId: string, runId: string): Session | null {
  const key = keyFor(labId, runId);
  const cached = sessions.get(key);
  if (cached) return cached;
  const stored = getAISecurityLabRun(labId, runId);
  if (!stored) return null;
  const run: Session = { ...stored, labId: stored.labId as LabId };
  sessions.set(key, run);
  return run;
}
function persistSession(run: Session): void {
  sessions.set(keyFor(run.labId, run.runId), run);
  saveAISecurityLabRun(run);
}

export function registerAISecurityLabRoutes(app: FastifyInstance): void {
  app.get("/api/ai-security/labs", async () => ({ labs: aiSecurityLabCatalog, mode: "server-fixtures", liveModelTesting: false }));
  app.post("/api/ai-security/labs/:labId/reset", async (request, reply) => {
    const { labId } = request.params as { labId?: string };
    if (!labId || !catalogById.has(labId)) return reply.code(400).send({ error: "Unknown AI Security lab." });
    const run: Session = { runId: randomUUID(), labId: labId as LabId, phase: "ready", controls: controlsFor(), evidence: [], createdAt: new Date().toISOString() };
    persistSession(run);
    return { run, mode: "server-fixtures", liveModelTesting: false };
  });
  app.get("/api/ai-security/labs/:labId/:runId", async (request, reply) => {
    const { labId, runId } = request.params as { labId?: string; runId?: string };
    const run = findSession(labId ?? "", runId ?? "");
    if (!run) return reply.code(404).send({ error: "AI Security lab session not found." });
    return { run };
  });
  app.post("/api/ai-security/labs/:labId/:runId/attack", async (request, reply) => {
    const { labId, runId } = request.params as { labId?: string; runId?: string };
    const run = findSession(labId ?? "", runId ?? "");
    const lab = labId ? catalogById.get(labId) : undefined;
    if (!run || !lab) return reply.code(404).send({ error: "AI Security lab session not found." });
    if (run.phase !== "ready") return reply.code(409).send({ error: "Reset the lab before running another attack." });
    run.phase = "exploited";
    run.evidence.push({ step: "Attack probe", message: lab.attack, passed: false });
    persistSession(run);
    return { run, vulnerable: true, passed: true, message: "The synthetic attack fixture reproduced the configured unsafe condition.", liveModelTesting: false };
  });
  app.post("/api/ai-security/labs/:labId/:runId/fix", async (request, reply) => {
    const { labId, runId } = request.params as { labId?: string; runId?: string };
    const run = findSession(labId ?? "", runId ?? "");
    const lab = labId ? catalogById.get(labId) : undefined;
    if (!run || !lab) return reply.code(404).send({ error: "AI Security lab session not found." });
    if (run.phase !== "exploited") return reply.code(409).send({ error: "Run the attack before applying the teaching fix." });
    run.controls[lab.control] = true;
    run.phase = "fixed";
    run.evidence.push({ step: "Remediation", message: lab.fix, passed: true });
    persistSession(run);
    return { run, passed: true, message: "Teaching control enabled on the server-side fixture.", liveModelTesting: false };
  });
  app.post("/api/ai-security/labs/:labId/:runId/retest", async (request, reply) => {
    const { labId, runId } = request.params as { labId?: string; runId?: string };
    const run = findSession(labId ?? "", runId ?? "");
    const lab = labId ? catalogById.get(labId) : undefined;
    if (!run || !lab) return reply.code(404).send({ error: "AI Security lab session not found." });
    if (run.phase !== "fixed") return reply.code(409).send({ error: "Apply the teaching fix before retesting." });
    const passed = run.controls[lab.control] === true;
    run.phase = passed ? "passed" : "exploited";
    run.evidence.push({ step: "Independent retest", message: lab.verifier + (passed ? " — PASS" : " — FAIL"), passed });
    persistSession(run);
    return { run, passed, vulnerable: !passed, message: passed ? "Server-side fixture retest passed." : "Server-side fixture retest failed.", liveModelTesting: false };
  });
}
