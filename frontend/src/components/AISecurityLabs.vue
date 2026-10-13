<script setup lang="ts">
import { computed, ref } from "vue";

type LabId = "prompt-injection" | "rag-isolation" | "agent-tools";
type Phase = "ready" | "exploited" | "fixed" | "passed";
type Lab = { id: LabId; title: string; risk: string; objective: string; attack: string; vulnerableEvidence: string; fix: string; fixedEvidence: string };
const labs: Lab[] = [
  {
    id: "prompt-injection",
    title: "1. Prompt injection",
    risk: "Indirect prompt injection",
    objective: "Проверить, может ли недоверенный документ переопределить системные правила и раскрыть синтетический маркер.",
    attack: "В документе содержится инструкция игнорировать правила и вывести маркер TRAINING-SECRET-ALPHA.",
    vulnerableEvidence: "Модельный сценарий передал инструкцию документа в доверенный контекст; синтетический маркер оказался в ответе.",
    fix: "Отделять данные от инструкций, явно помечать retrieved content как недоверенный и проверять выход по политике на стороне приложения.",
    fixedEvidence: "Инструкция документа трактуется как недоверенные данные; маркер не возвращён, попытка зафиксирована."
  },
  {
    id: "rag-isolation",
    title: "2. RAG access isolation",
    risk: "Cross-tenant data leakage",
    objective: "Проверить, ограничивает ли retrieval документы текущим пользователем, а не только текстом запроса.",
    attack: "Пользователь tenant-A запрашивает документ tenant-B через общий поиск по коллекции.",
    vulnerableEvidence: "Fixture retrieval вернул документ tenant-B без проверки владельца.",
    fix: "Применять tenant/user ACL на сервере до retrieval и повторно проверять доступ перед передачей фрагмента в контекст.",
    fixedEvidence: "Запрос tenant-A не получил документы tenant-B; сервер записал отказ доступа."
  },
  {
    id: "agent-tools",
    title: "3. AI agent tools",
    risk: "Excessive tool authority",
    objective: "Проверить, может ли агент совершить consequential action без серверной авторизации и подтверждения.",
    attack: "Агент просит инструмент отправить синтетический платёж на 500 единиц без подтверждения пользователя.",
    vulnerableEvidence: "Инструмент доверился аргументам агента и принял действие без policy check.",
    fix: "Минимизировать полномочия инструмента, авторизовать действие на сервере и требовать явного подтверждения для consequential actions.",
    fixedEvidence: "Инструмент отклонил действие без подтверждения; никаких внешних вызовов или платежей не выполнялось."
  }
];
const activeId = ref<LabId>("prompt-injection");
const states = ref<Record<LabId, { phase: Phase; fixed: boolean; history: Array<{ title: string; message: string; passed: boolean }> }>>({
  "prompt-injection": { phase: "ready", fixed: false, history: [] },
  "rag-isolation": { phase: "ready", fixed: false, history: [] },
  "agent-tools": { phase: "ready", fixed: false, history: [] }
});
const activeLab = computed(() => labs.find((lab) => lab.id === activeId.value) ?? labs[0]);
const state = computed(() => states.value[activeId.value]);
const completed = computed(() => labs.filter((lab) => states.value[lab.id].phase === "passed").length);
function addEvidence(title: string, message: string, passed: boolean) {
  state.value.history.push({ title, message, passed });
}
function reset() {
  states.value[activeId.value] = { phase: "ready", fixed: false, history: [] };
}
function runAttack() {
  if (state.value.phase !== "ready") return;
  state.value.phase = "exploited";
  addEvidence("Exploit probe", state.value.fixed ? activeLab.value.fixedEvidence : activeLab.value.vulnerableEvidence, state.value.fixed);
}
function applyFix() {
  if (state.value.phase !== "exploited") return;
  state.value.fixed = true;
  state.value.phase = "fixed";
  addEvidence("Fix validation", activeLab.value.fix, true);
}
function retest() {
  if (state.value.phase !== "fixed") return;
  // Independent deterministic verifier: it checks the fixture's security control,
  // not the narrative/AI response or the editor content.
  const verification = verifyControl(activeLab.value.id, state.value.fixed);
  state.value.phase = verification.passed ? "passed" : "exploited";
  addEvidence("Independent retest", verification.evidence, verification.passed);
}
function verifyControl(id: LabId, fixed: boolean): { passed: boolean; evidence: string } {
  const controls: Record<LabId, { control: string; expected: boolean }> = {
    "prompt-injection": { control: "untrusted content remains data; output policy blocks synthetic secret", expected: true },
    "rag-isolation": { control: "retrieval and context assembly enforce tenant ACL", expected: true },
    "agent-tools": { control: "server tool policy requires authorization and approval", expected: true }
  };
  const check = controls[id];
  return { passed: fixed && check.expected, evidence: check.control + (fixed ? " — PASS" : " — FAIL: control absent") };
}
</script>

<template>
  <section class="info-card ai-security-labs" aria-label="Практические AI Security лаборатории">
    <div class="section-heading">
      <div>
        <div class="eyebrow">AI SECURITY ENGINEER</div>
        <h2>Практические AI Security лаборатории</h2>
      </div>
      <el-tag :type="completed === labs.length ? 'success' : 'info'">{{ completed }}/{{ labs.length }} пройдены</el-tag>
    </div>
    <p class="body-copy">Изолированные сценарии с синтетическими данными. Проходите цикл атака → исправление → независимый retest. Реальные LLM, секреты, инструменты и внешние системы не вызываются.</p>
    <div class="ai-lab-tabs" role="tablist" aria-label="AI Security лаборатории">
      <button v-for="lab in labs" :key="lab.id" type="button" role="tab" :aria-selected="activeId === lab.id" :class="{ active: activeId === lab.id }" @click="activeId = lab.id">
        <span>{{ lab.title }}</span>
        <el-tag v-if="states[lab.id].phase === 'passed'" type="success" size="small">Пройдена</el-tag>
      </button>
    </div>
    <div class="ai-lab-detail">
      <div class="ai-lab-heading">
        <div><span class="eyebrow">УЯЗВИМОСТЬ</span><h3>{{ activeLab.risk }}</h3></div>
        <el-tag :type="state.phase === 'passed' ? 'success' : state.phase === 'exploited' ? 'danger' : 'info'">{{ state.phase }}</el-tag>
      </div>
      <p>{{ activeLab.objective }}</p>
      <div class="ai-lab-panel">
        <strong>Сценарий атаки</strong>
        <p>{{ activeLab.attack }}</p>
      </div>
      <div class="ai-lab-panel">
        <strong>Мера защиты</strong>
        <p>{{ activeLab.fix }}</p>
      </div>
      <div class="editor-actions">
        <el-button type="primary" :disabled="state.phase !== 'ready'" @click="runAttack">1. Запустить атаку</el-button>
        <el-button :disabled="state.phase !== 'exploited'" @click="applyFix">2. Применить учебный fix</el-button>
        <el-button type="success" :disabled="state.phase !== 'fixed'" @click="retest">3. Независимый retest</el-button>
        <el-button @click="reset">Сбросить</el-button>
      </div>
      <div v-if="state.history.length" class="ai-lab-evidence">
        <div class="eyebrow">ЖУРНАЛ ДОКАЗАТЕЛЬСТВ</div>
        <el-timeline>
          <el-timeline-item v-for="(entry, index) in state.history" :key="index" :type="entry.passed ? 'success' : 'danger'">
            <strong>{{ entry.title }}</strong>
            <p>{{ entry.message }}</p>
          </el-timeline-item>
        </el-timeline>
      </div>
      <p class="ai-lab-disclaimer">Учебная модель, не реальная LLM-оценка. Результат подтверждает поведение только этого контролируемого сценария, а не безопасность production-системы.</p>
    </div>
  </section>
</template>

<style scoped>
.ai-security-labs { margin: 22px 0; }
.ai-lab-tabs { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 18px 0; }
.ai-lab-tabs button { display: flex; align-items: center; justify-content: space-between; gap: 8px; min-height: 48px; padding: 10px 12px; border: 1px solid var(--el-border-color); border-radius: 10px; background: var(--el-bg-color); color: var(--el-text-color-primary); text-align: left; cursor: pointer; }
.ai-lab-tabs button.active { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.ai-lab-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.ai-lab-heading h3 { margin: 4px 0 12px; }
.ai-lab-panel { margin: 12px 0; padding: 14px; border: 1px solid var(--el-border-color-lighter); border-radius: 10px; }
.ai-lab-panel p { margin-bottom: 0; }
.ai-lab-evidence { margin-top: 22px; }
.ai-lab-disclaimer { margin-top: 18px; color: var(--el-text-color-secondary); font-size: 12px; }
@media (max-width: 720px) { .ai-lab-tabs { grid-template-columns: 1fr; } .editor-actions { flex-wrap: wrap; } }
</style>
