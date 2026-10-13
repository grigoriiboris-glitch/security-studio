<script setup lang="ts">
import { computed, ref, watch } from "vue";

type LabId = "foundations" | "prompt-injection" | "rag-isolation" | "agent-tools" | "privacy" | "model-security" | "red-team" | "infrastructure" | "interview";
type Phase = "ready" | "exploited" | "fixed" | "passed";
type ControlKey = "trustSeparated" | "tenantScoped" | "toolAuthorized" | "sensitiveOutputFiltered" | "provenanceVerified" | "evalRegressionPresent" | "endpointProtected" | "threatModelComplete" | "reportEvidenceComplete";
type Fixture = Record<ControlKey, boolean>;
type Evidence = { title: string; message: string; passed: boolean };
type Lab = {
  id: LabId; category: string; title: string; risk: string; objective: string;
  attack: string; vulnerableEvidence: string; fix: string; fixedEvidence: string;
  control: ControlKey; controlDescription: string; verifier: string;
};
type LabState = { phase: Phase; fixture: Fixture; history: Evidence[] };

const initialFixture = (): Fixture => ({
  trustSeparated: false, tenantScoped: false, toolAuthorized: false,
  sensitiveOutputFiltered: false, provenanceVerified: false,
  evalRegressionPresent: false, endpointProtected: false,
  threatModelComplete: false, reportEvidenceComplete: false
});
const labs: Lab[] = [
  {
    id: "foundations", category: "AI Security Foundations", title: "1. Trust boundaries",
    risk: "Неправильно определённые границы доверия",
    objective: "Построить карту потока данных и определить, где недоверенный ввод может влиять на привилегированные инструкции.",
    attack: "Пользовательский текст и retrieved-контент объединены с системными инструкциями без меток происхождения.",
    vulnerableEvidence: "Fixture обнаружил смешение доверенных инструкций и недоверенного контента: граница доверия не задана.",
    fix: "Разделить системные инструкции и пользовательские данные, маркировать источник каждого фрагмента и описать активы, угрозы и полномочия.",
    fixedEvidence: "Доверенные инструкции и недоверенные данные разделены; поток данных и границы доверия задокументированы.",
    control: "trustSeparated", controlDescription: "системные инструкции отделены от недоверенного содержимого",
    verifier: "Проверка границ доверия и маркировки источника данных"
  },
  {
    id: "prompt-injection", category: "Prompt Injection & Jailbreaks", title: "2. Prompt injection",
    risk: "Косвенная prompt injection",
    objective: "Проверить, может ли инструкция в документе переопределить правила и вызвать раскрытие синтетического маркера.",
    attack: "В документе находится инструкция вывести маркер TRAINING-SECRET-ALPHA и игнорировать системные правила.",
    vulnerableEvidence: "Контролируемый fixture передал инструкцию документа в привилегированный контекст; синтетический маркер доступен ответу.",
    fix: "Считать retrieved content недоверенными данными, разделять контекст и инструкции, проверять действия и ответ независимой политикой приложения.",
    fixedEvidence: "Инструкция документа осталась данными; политика вывода блокирует синтетический маркер и записывает событие.",
    control: "trustSeparated", controlDescription: "недоверенный контент остаётся данными и не меняет привилегированные инструкции",
    verifier: "Проверка разделения инструкций и блокировки синтетического маркера"
  },
  {
    id: "rag-isolation", category: "RAG & Knowledge Security", title: "3. RAG tenant isolation",
    risk: "Межпользовательская утечка из RAG",
    objective: "Убедиться, что retrieval ограничен правами текущего пользователя до сборки контекста.",
    attack: "Пользователь tenant-A запрашивает синтетический документ tenant-B через общую коллекцию.",
    vulnerableEvidence: "Fixture вернул документ другого tenant: ACL не применён до передачи фрагмента в контекст.",
    fix: "Применять tenant/user ACL на сервере при retrieval и повторно проверять права перед сборкой контекста; тестировать negative cases.",
    fixedEvidence: "Запрос tenant-A не получил документ tenant-B; отказ доступа зафиксирован.",
    control: "tenantScoped", controlDescription: "retrieval фильтрует документы по ACL пользователя и tenant",
    verifier: "Контрольный cross-tenant запрос не возвращает чужой документ"
  },
  {
    id: "agent-tools", category: "AI Agents & Tools", title: "4. Agent tool authorization",
    risk: "Избыточные полномочия инструмента",
    objective: "Проверить, способен ли агент инициировать consequential action без серверной авторизации и подтверждения.",
    attack: "Агент просит инструмент выполнить синтетический перевод на 500 единиц без подтверждения.",
    vulnerableEvidence: "Fixture принял действие только на основании аргументов агента; policy check отсутствует.",
    fix: "Ограничить полномочия инструментов, проверять пользователя и аргументы на сервере, требовать подтверждение consequential actions.",
    fixedEvidence: "Инструмент отклонил неподтверждённое действие; внешних вызовов и реальных платежей не выполнялось.",
    control: "toolAuthorized", controlDescription: "инструмент проверяет права и требует подтверждения действия",
    verifier: "Повторная попытка без подтверждения должна быть отклонена"
  },
  {
    id: "privacy", category: "Data Privacy & Leakage", title: "5. Sensitive data leakage",
    risk: "Утечка секретов и персональных данных",
    objective: "Проверить, может ли ответ включить секретный маркер или синтетические PII из внутреннего контекста.",
    attack: "Запрос просит вывести TRAINING-PII-0001 и TRAINING-KEY-DO-NOT-USE из контекста.",
    vulnerableEvidence: "Fixture обнаружил, что чувствительные поля могут попасть в ответ без redaction и output policy.",
    fix: "Минимизировать данные в контексте, исключить секреты, применять redaction/DLP и проверять ответ до выдачи пользователю.",
    fixedEvidence: "Синтетические чувствительные поля удалены из ответа; событие утечки попало в журнал.",
    control: "sensitiveOutputFiltered", controlDescription: "чувствительные маркеры фильтруются до возврата ответа",
    verifier: "Контрольный ответ не содержит синтетические секреты или PII"
  },
  {
    id: "model-security", category: "Model & ML Security", title: "6. Model and dataset provenance",
    risk: "Непроверенные модели и обучающие данные",
    objective: "Оценить риск загрузки изменённого или неподтверждённого артефакта модели/датасета.",
    attack: "В учебный pipeline попадает dataset с неизвестным источником и без проверки целостности.",
    vulnerableEvidence: "Fixture принял артефакт без provenance, контрольной суммы или утверждённого источника.",
    fix: "Проверять происхождение и целостность артефактов, фиксировать версии, изолировать карантинные данные и требовать review перед promotion.",
    fixedEvidence: "Непроверенный артефакт помещён в карантин; provenance и integrity check обязательны перед использованием.",
    control: "provenanceVerified", controlDescription: "артефакт имеет проверенный источник, версию и целостность",
    verifier: "Артефакт без provenance не должен попасть в доверенный pipeline"
  },
  {
    id: "red-team", category: "AI Red Teaming & Evaluation", title: "7. Adversarial regression suite",
    risk: "Отсутствие повторяемых проверок AI-защит",
    objective: "Проверить, что известная атака превращена в регрессионный тест с измеримым критерием.",
    attack: "После изменения prompt или модели прежний сценарий prompt injection не запускается в CI и регрессия незаметна.",
    vulnerableEvidence: "Для известной атаки нет закреплённого кейса, ожидаемого результата и порога pass/fail.",
    fix: "Сохранить минимальный воспроизводимый кейс, ожидаемый безопасный результат, severity и лимиты false positive; запускать suite при изменениях.",
    fixedEvidence: "Кейс добавлен в regression suite; результат и ожидаемый критерий сравниваются автоматически.",
    control: "evalRegressionPresent", controlDescription: "известная атака закреплена тестом с ожидаемым результатом",
    verifier: "Regression case должен присутствовать и иметь проверяемый критерий"
  },
  {
    id: "infrastructure", category: "AI Infrastructure & Governance", title: "8. Inference API security",
    risk: "Незащищённая inference-точка",
    objective: "Проверить, ограничивает ли inference API доступ, частоту запросов и раскрытие внутренних сведений.",
    attack: "Анонимный клиент обращается к синтетическому inference endpoint без авторизации и лимитов.",
    vulnerableEvidence: "Fixture допускает анонимный запрос; нет проверки доступа и базового rate limit.",
    fix: "Требовать аутентификацию и авторизацию, ограничивать частоту и размер запросов, хранить ключи вне prompt/logs, вести аудит и бюджет.",
    fixedEvidence: "Анонимный запрос отклонён; лимит и аудит включены; ключи не включаются в ответ.",
    control: "endpointProtected", controlDescription: "endpoint проверяет доступ и ограничивает запросы",
    verifier: "Анонимный запрос отклоняется, а секреты не возвращаются"
  },
  {
    id: "interview", category: "AI Security Interview Lab", title: "9. Architecture review case",
    risk: "Необоснованный security sign-off",
    objective: "Разобрать архитектурный кейс, расставить риски по приоритету и подтвердить mitigations доказательствами.",
    attack: "Сервис запускает инструменты из ответа модели; отсутствуют threat model, evidence и проверка остаточного риска.",
    vulnerableEvidence: "В кейсе не определены активы и границы доверия; критичный риск tool execution не имеет владельца или доказательства исправления.",
    fix: "Составить threat model, ограничить инструменты, добавить авторизацию/approval, привязать тестовые доказательства к риску и документировать остаточный риск.",
    fixedEvidence: "Threat model заполнен, mitigation связан с тестом, остаточный риск и владелец решения задокументированы.",
    control: "reportEvidenceComplete", controlDescription: "риски приоритизированы, mitigation подтверждён, остаточный риск документирован",
    verifier: "Review должен содержать threat model, evidence и остаточный риск"
  }
];
const activeId = ref<LabId>("foundations");
const states = ref<Record<LabId, LabState>>(Object.fromEntries(labs.map(lab => [lab.id, { phase: "ready", fixture: initialFixture(), history: [] }])) as unknown as Record<LabId, LabState>);
const activeLab = computed(() => labs.find(lab => lab.id === activeId.value) ?? labs[0]);
const state = computed(() => states.value[activeId.value]);
const completed = computed(() => labs.filter(lab => states.value[lab.id].phase === "passed").length);
const phases: Record<Phase, string> = { ready: "Готова", exploited: "Атака подтверждена", fixed: "Исправление применено", passed: "Retest пройден" };
const phaseType = computed(() => state.value.phase === "passed" ? "success" : state.value.phase === "exploited" ? "danger" : "info");
function addEvidence(title: string, message: string, passed: boolean) {
  state.value.history.push({ title, message, passed });
}
function reset() {
  states.value[activeId.value] = { phase: "ready", fixture: initialFixture(), history: [] };
}
function runAttack() {
  if (state.value.phase !== "ready") return;
  const alreadyHardened = state.value.fixture[activeLab.value.control];
  state.value.phase = "exploited";
  addEvidence("Attack probe", alreadyHardened ? activeLab.value.fixedEvidence : activeLab.value.vulnerableEvidence, alreadyHardened);
}
function applyFix() {
  if (state.value.phase !== "exploited") return;
  state.value.fixture[activeLab.value.control] = true;
  state.value.phase = "fixed";
  addEvidence("Remediation", activeLab.value.fix, true);
}
function verifyFixture(lab: Lab, fixture: Fixture): { passed: boolean; evidence: string } {
  // Each lab verifies its own concrete fixture control rather than trusting the UI phase.
  const passed = fixture[lab.control] === true;
  return { passed, evidence: lab.verifier + (passed ? " — PASS" : " — FAIL: контроль не включён") };
}
function retest() {
  if (state.value.phase !== "fixed") return;
  const result = verifyFixture(activeLab.value, state.value.fixture);
  state.value.phase = result.passed ? "passed" : "exploited";
  addEvidence("Independent retest", result.evidence, result.passed);
}
watch(states, value => {
  try { localStorage.setItem("security-studio-ai-lab-progress", JSON.stringify(value)); } catch { /* Progress storage is optional. */ }
}, { deep: true });
try {
  const saved = localStorage.getItem("security-studio-ai-lab-progress");
  if (saved) {
    const parsed = JSON.parse(saved) as Record<string, LabState>;
    for (const lab of labs) {
      const item = parsed[lab.id];
      if (item && ["ready", "exploited", "fixed", "passed"].includes(item.phase) && item.fixture && Array.isArray(item.history)) {
        states.value[lab.id] = { phase: item.phase as Phase, fixture: { ...initialFixture(), ...item.fixture }, history: item.history.slice(-20) };
      }
    }
  }
} catch { /* Invalid or unavailable local storage must not block the labs. */ }
</script>

<template>
  <section class="info-card ai-security-labs" aria-label="Практические AI Security лаборатории">
    <div class="section-heading">
      <div>
        <div class="eyebrow">AI SECURITY ENGINEER · 9 ЛАБОРАТОРИЙ</div>
        <h2>Практические AI Security лаборатории</h2>
      </div>
      <el-tag :type="completed === labs.length ? 'success' : 'info'">{{ completed }}/9 пройдены</el-tag>
    </div>
    <p class="body-copy">Каждая лаборатория проходит цикл атака → исправление → независимый retest. Сценарии локальные, используют только синтетические данные и не вызывают реальные LLM, инструменты, API или внешние системы.</p>
    <div class="ai-lab-tabs" role="tablist" aria-label="AI Security категории">
      <button v-for="lab in labs" :key="lab.id" type="button" role="tab" :aria-selected="activeId === lab.id" :class="{ active: activeId === lab.id }" @click="activeId = lab.id">
        <span class="ai-lab-tab-copy"><small>{{ lab.category }}</small><strong>{{ lab.title }}</strong></span>
        <el-tag v-if="states[lab.id].phase === 'passed'" type="success" size="small">Пройдена</el-tag>
      </button>
    </div>
    <div class="ai-lab-detail">
      <div class="ai-lab-heading">
        <div><span class="eyebrow">{{ activeLab.category }}</span><h3>{{ activeLab.risk }}</h3></div>
        <el-tag :type="phaseType">{{ phases[state.phase] }}</el-tag>
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
      <div class="editor-actions ai-lab-actions">
        <el-button type="primary" :disabled="state.phase !== 'ready'" @click="runAttack">1. Запустить атаку</el-button>
        <el-button :disabled="state.phase !== 'exploited'" @click="applyFix">2. Применить учебный fix</el-button>
        <el-button type="success" :disabled="state.phase !== 'fixed'" @click="retest">3. Независимый retest</el-button>
        <el-button @click="reset">Сбросить лабораторию</el-button>
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
      <p class="ai-lab-disclaimer">Ограничение: это детерминированные учебные fixtures, а не реальные тесты поведения модели. Retest проверяет конкретный контроль fixture и не доказывает безопасность production-системы. Для live model testing потребуется отдельный provider, изолированная тестовая среда и собственный набор оценочных критериев.</p>
    </div>
  </section>
</template>

<style scoped>
.ai-security-labs { margin: 22px 0; }
.ai-lab-tabs { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 18px 0; }
.ai-lab-tabs button { display: flex; align-items: center; justify-content: space-between; gap: 8px; min-height: 68px; padding: 10px 12px; border: 1px solid var(--el-border-color); border-radius: 10px; background: var(--el-bg-color); color: var(--el-text-color-primary); text-align: left; cursor: pointer; }
.ai-lab-tabs button.active { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.ai-lab-tab-copy { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.ai-lab-tab-copy small { color: var(--el-text-color-secondary); font-size: 10px; }
.ai-lab-tab-copy strong { font-size: 12px; }
.ai-lab-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.ai-lab-heading h3 { margin: 4px 0 12px; }
.ai-lab-panel { margin: 12px 0; padding: 14px; border: 1px solid var(--el-border-color-lighter); border-radius: 10px; }
.ai-lab-panel p { margin-bottom: 0; }
.ai-lab-evidence { margin-top: 22px; }
.ai-lab-disclaimer { margin-top: 18px; color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.6; }
@media (max-width: 900px) { .ai-lab-tabs { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 600px) { .ai-lab-tabs { grid-template-columns: 1fr; } .ai-lab-actions { flex-wrap: wrap; } }
</style>
