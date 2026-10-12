<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import AssistantChat from "./components/AssistantChat.vue";
import CodeEditor from "./components/CodeEditor.vue";
import { lessons } from "./data/lessons";
import { fetchHealth, fetchProgress, fetchExerciseCode, saveProgress, saveExerciseCode, runSqlInjectionDemo, createSyntheticRun, exploitSyntheticRun, fixSyntheticRun, retestSyntheticRun, resetSyntheticRun, type DemoResult, type SyntheticRun, type SyntheticEvidence } from "./services/api";
import { useLabsStore } from "./stores/labs";

const labs = useLabsStore();
const selectedLessonId = ref<string>("sql-injection");
const lesson = computed(() => lessons.find((item) => item.id === selectedLessonId.value) ?? lessons[0]);
const apiOnline = ref(false);
const aiConfigured = ref(false);
const demoBusy = ref(false);
const savingCode = ref(false);
const demoResult = ref<DemoResult | null>(null);
const selectedExample = ref<"vulnerable" | "fixed">("vulnerable");
const runtimeBusy = ref(false);
const runtimeRun = ref<SyntheticRun | null>(null);
const httpRuntimeLessonIds = new Set(["xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf", "broken-access-control", "broken-authentication", "session-fixation", "password-reset", "file-upload", "command-injection", "xxe", "ssti", "open-redirect", "cors", "clickjacking", "security-headers", "secrets-exposure", "sensitive-data", "jwt-validation", "mass-assignment", "rate-limiting", "business-logic", "prototype-pollution", "nosql-injection", "ldap-injection", "insecure-deserialization"]);
const runtimeEvidence = ref<SyntheticEvidence | null>(null);
const hintLevel = ref(0);
const runtimeHistory = ref<Array<{ step: string; phase: string; message: string; evidence: string[] }>>([]);
const availableHints = computed(() => [lesson.value.objectives[0], lesson.value.objectives[1], lesson.value.mitigation].filter((item): item is string => Boolean(item)));
const labOptions = [
  { label: "OWASP Juice Shop", value: "juice-shop" },
  { label: "OWASP NodeGoat", value: "nodegoat" }
];
const activeLabLabel = computed(() => labs.activeLab?.name ?? "Остановлена");
const progressReady = ref(false);
const switchingLesson = ref(false);
let progressSaveTimer: ReturnType<typeof setTimeout> | undefined;

watch(
  () => [labs.editorCode, labs.selectedLabId, labs.checkResult] as const,
  () => {
    if (!progressReady.value || switchingLesson.value) return;
    if (progressSaveTimer) clearTimeout(progressSaveTimer);
    progressSaveTimer = setTimeout(() => {
      void saveProgress(lesson.value.id, {
        editorCode: labs.editorCode,
        selectedLabId: labs.selectedLabId,
        checkResult: labs.checkResult
      }).catch(() => ElMessage.warning("Не удалось сохранить прогресс в локальную базу."));
    }, 700);
  },
  { deep: true }
);

onBeforeUnmount(() => {
  if (progressSaveTimer) clearTimeout(progressSaveTimer);
});

onMounted(async () => {
  try {
    const saved = await fetchProgress(lesson.value.id);
    if (saved) {
      labs.editorCode = saved.editorCode;
      labs.selectedLabId = saved.selectedLabId;
      labs.checkResult = saved.checkResult;
      selectedExample.value = saved.editorCode === lesson.value.fixedCode ? "fixed" : "vulnerable";
    }
  } catch { /* The health indicator reports API connection failures. */ }
  progressReady.value = true;
  await labs.refresh();
  try {
    const health = await fetchHealth();
    apiOnline.value = health.status === "ok";
    aiConfigured.value = health.aiConfigured;
  } catch { apiOnline.value = false; }
});

function revealHint() {
  hintLevel.value = Math.min(hintLevel.value + 1, availableHints.value.length);
}
function recordRuntimeStep(step: string, evidence: SyntheticEvidence) {
  runtimeHistory.value.unshift({ step, phase: evidence.phase, message: evidence.message, evidence: [...evidence.evidence] });
}
function loadExample(kind: "vulnerable" | "fixed") {
  selectedExample.value = kind;
  labs.loadExample(kind, lesson.value.id);
}
async function selectLesson(id: string) {
  selectedLessonId.value = id;
  runtimeRun.value = null;
  runtimeEvidence.value = null;
  runtimeHistory.value = [];
  hintLevel.value = 0;
  const selected = lessons.find((item) => item.id === id) ?? lessons[0];
  switchingLesson.value = true;
  labs.checkResult = null;
  selectedExample.value = "vulnerable";
  try {
    const saved = await fetchProgress(selected.id);
    if (saved) {
      labs.editorCode = saved.editorCode;
      labs.selectedLabId = saved.selectedLabId;
      labs.checkResult = saved.checkResult;
      selectedExample.value = saved.editorCode === selected.fixedCode ? "fixed" : "vulnerable";
    } else {
      const savedCode = await fetchExerciseCode(selected.id);
      if (typeof savedCode === "string") {
        labs.editorCode = savedCode;
        selectedExample.value = savedCode === selected.fixedCode ? "fixed" : "vulnerable";
      } else {
        labs.loadExample("vulnerable", selected.id);
        selectedExample.value = "vulnerable";
      }
      labs.checkResult = null;
    }
  } catch {
    labs.loadExample("vulnerable", selected.id);
    labs.checkResult = null;
    selectedExample.value = "vulnerable";
  } finally {
    switchingLesson.value = false;
  }
}
async function runDemo() {
  demoBusy.value = true;
  demoResult.value = null;
  try {
    demoResult.value = await runSqlInjectionDemo();
    ElMessage({
      type: demoResult.value.passed ? "success" : "warning",
      message: demoResult.value.message,
      duration: 5000
    });
  } catch {
    demoResult.value = {
      passed: false,
      message: "Демонстрация не выполнена. Проверьте, что Juice Shop запущен.",
      evidence: []
    };
  } finally {
    demoBusy.value = false;
  }
}
async function runCheck() {
  await labs.verifyCode(lesson.value.id);
  if (labs.checkResult) {
    ElMessage({
      type: labs.checkResult.passed ? "success" : "warning",
      message: labs.checkResult.message,
      duration: 4500
    });
  }
}
async function saveCode() {
  savingCode.value = true;
  try {
    await saveExerciseCode(labs.editorCode, lesson.value.id);
    ElMessage.success("Код сохранён в рабочую область урока.");
  } catch {
    ElMessage.error("Не удалось сохранить код. Проверьте подключение к API.");
  } finally {
    savingCode.value = false;
  }
}
async function startSyntheticRun() {
  runtimeBusy.value = true;
  runtimeEvidence.value = null;
  try {
    runtimeRun.value = await createSyntheticRun(lesson.value.id);
    ElMessage.success("Синтетическая лаборатория подготовлена.");
  } catch {
    ElMessage.error("Не удалось подготовить сценарий. Проверьте подключение к API.");
  } finally { runtimeBusy.value = false; }
}
async function runSyntheticExploit() {
  if (!runtimeRun.value) return;
  runtimeBusy.value = true;
  try {
    runtimeEvidence.value = await exploitSyntheticRun(lesson.value.id, runtimeRun.value.runId);
    recordRuntimeStep("Exploit probe", runtimeEvidence.value);
    runtimeRun.value.phase = runtimeEvidence.value.phase;
    runtimeRun.value.fixed = runtimeEvidence.value.phase === "fixed" || runtimeEvidence.value.phase === "passed";
  } catch { ElMessage.error("Не удалось выполнить контрольный probe."); }
  finally { runtimeBusy.value = false; }
}
async function applySyntheticFix() {
  if (!runtimeRun.value) return;
  runtimeBusy.value = true;
  try {
    runtimeEvidence.value = await fixSyntheticRun(lesson.value.id, runtimeRun.value.runId, labs.editorCode);
    recordRuntimeStep("Проверка исправления", runtimeEvidence.value);
    runtimeRun.value.phase = runtimeEvidence.value.phase;
    runtimeRun.value.fixed = runtimeEvidence.value.phase === "fixed" || runtimeEvidence.value.phase === "passed";
  } catch { ElMessage.error("Не удалось проверить исправление в лаборатории."); }
  finally { runtimeBusy.value = false; }
}
async function runSyntheticRetest() {
  if (!runtimeRun.value) return;
  runtimeBusy.value = true;
  try {
    runtimeEvidence.value = await retestSyntheticRun(lesson.value.id, runtimeRun.value.runId);
    recordRuntimeStep("Независимый retest", runtimeEvidence.value);
    runtimeRun.value.phase = runtimeEvidence.value.phase;
    runtimeRun.value.fixed = runtimeEvidence.value.phase === "fixed" || runtimeEvidence.value.phase === "passed";
  } catch { ElMessage.error("Не удалось выполнить runtime retest."); }
  finally { runtimeBusy.value = false; }
}
async function resetSynthetic() {
  runtimeBusy.value = true;
  try {
    if (runtimeRun.value) runtimeRun.value = await resetSyntheticRun(lesson.value.id, runtimeRun.value.runId);
    else runtimeRun.value = await createSyntheticRun(lesson.value.id);
    runtimeEvidence.value = null;
    runtimeHistory.value = [];
    ElMessage.success("Сценарий сброшен в исходное состояние.");
  } catch { ElMessage.error("Не удалось сбросить сценарий."); }
  finally { runtimeBusy.value = false; }
}
async function toggleLab() {
  if (labs.activeLab) await labs.stopActiveLab();
  else await labs.startSelectedLab();
}
async function resetLab() {
  await labs.resetActiveLab();
  if (!labs.lastError) ElMessage.success("Лаборатория перезапущена, временные данные сброшены.");
}
</script>

<template>
  <el-container class="studio-shell">
    <el-header class="topbar">
      <div class="brand">
        <div class="brand-mark">S</div>
        <div><div class="brand-name">Security Studio</div><div class="brand-caption">Локальная лаборатория веб-безопасности</div></div>
      </div>
      <div class="topbar-status">
        <span class="status-indicator" :class="{ online: apiOnline }"></span>
        <span>API {{ apiOnline ? "подключён" : "не подключён" }}</span>
        <el-divider direction="vertical" />
        <el-tag size="small" :type="aiConfigured ? 'success' : 'info'">AI {{ aiConfigured ? "настроен" : "без ключа" }}</el-tag>
      </div>
    </el-header>

    <el-main class="workspace">
      <aside class="lesson-rail">
        <div class="eyebrow">ОБУЧЕНИЕ</div>
        <el-select v-model="selectedLessonId" class="lesson-selector" filterable size="large" aria-label="Выбор урока" @change="selectLesson">
          <el-option v-for="item in lessons" :key="item.id" :label="item.title" :value="item.id" />
        </el-select>
        <div class="selected-lesson-summary"><strong>{{ lesson.title }}</strong><small>{{ lesson.level }} · {{ lessons.length }} уроков в программе</small></div>
        <div class="rail-note"><div class="eyebrow">ЦЕЛЬ УРОКА</div><p>Понять причину уязвимости и подтвердить исправление независимой проверкой.</p></div>
        <div class="rail-footer"><span class="tiny-dot"></span>Среда локальная</div>
      </aside>

      <section class="lesson-workspace">
        <div class="page-heading">
          <div>
            <div class="eyebrow">УРОК {{ String(lessons.findIndex((item) => item.id === lesson.id) + 1).padStart(2, "0") }} / ВЕБ-БЕЗОПАСНОСТЬ</div>
            <h1>{{ lesson.title }}</h1>
            <p>{{ lesson.summary }}</p>
          </div>
          <el-tag type="warning" effect="dark">{{ lesson.level }}</el-tag>
        </div>

        <div class="lab-toolbar">
          <div class="lab-picker">
            <span class="toolbar-label">Учебное приложение</span>
            <el-select v-model="labs.selectedLabId" size="large" aria-label="Выбор учебного приложения" :disabled="labs.busy || Boolean(labs.activeLab)">
              <el-option v-for="option in labOptions" :key="option.value" :label="option.label" :value="option.value" />
            </el-select>
          </div>
          <div class="lab-actions">
            <div class="active-lab-state"><span class="status-indicator" :class="{ online: Boolean(labs.activeLab) }"></span><span>{{ activeLabLabel }}</span></div>
            <el-button :type="labs.activeLab ? 'danger' : 'primary'" size="large" :loading="labs.busy" @click="toggleLab">
              {{ labs.activeLab ? "Остановить" : "Запустить лабораторию" }}
            </el-button>
            <el-button v-if="labs.activeLab" tag="a" :href="labs.activeLab.url" target="_blank" rel="noopener noreferrer" size="large">Открыть приложение ↗</el-button>
            <el-button v-if="labs.activeLab" size="large" :loading="labs.busy" @click="resetLab">Сбросить лабораторию</el-button>
            <el-button v-if="labs.activeLab?.id === 'juice-shop' && lesson.id === 'sql-injection'" type="warning" size="large" :loading="demoBusy" @click="runDemo">Запустить пример SQLi</el-button>
          </div>
        </div>

        <el-alert v-if="labs.lastError" class="inline-alert" :title="labs.lastError" type="error" show-icon :closable="false" />
        <el-alert v-if="demoResult" class="inline-alert" :title="demoResult.message" :description="demoResult.evidence.join(' ')" :type="demoResult.passed ? 'success' : 'warning'" show-icon :closable="false" />
        <div class="main-grid">
          <div class="lesson-column">
            <section class="info-card">
              <div class="section-heading">
                <div><div class="eyebrow">01 / ИЗУЧИТЕ</div><h2>Как возникает {{ lesson.title }}</h2></div>
                <span class="step-count">3 шага</span>
              </div>
              <p class="body-copy">{{ lesson.explanation }}</p>
              <ol class="objective-list"><li v-for="objective in lesson.objectives" :key="objective">{{ objective }}</li></ol>
            </section>

            <section class="info-card hint-card">
              <div class="section-heading">
                <div><div class="eyebrow">ПОДСКАЗКИ</div><h2>Найдите решение самостоятельно</h2></div>
                <el-tag effect="plain">{{ hintLevel }} / {{ availableHints.length }}</el-tag>
              </div>
              <p class="body-copy">Открывайте подсказки по одной. Последняя содержит направление исправления, поэтому попробуйте сначала найти источник проблемы самостоятельно.</p>
              <ol v-if="hintLevel > 0" class="objective-list">
                <li v-for="(hint, index) in availableHints.slice(0, hintLevel)" :key="index">{{ hint }}</li>
              </ol>
              <div class="editor-actions">
                <el-button type="primary" plain :disabled="hintLevel >= availableHints.length" @click="revealHint">{{ hintLevel >= availableHints.length ? "Все подсказки открыты" : "Открыть следующую подсказку" }}</el-button>
                <el-button :disabled="hintLevel === 0" @click="hintLevel = 0">Скрыть подсказки</el-button>
              </div>
            </section>
            <section class="editor-card">
              <div class="editor-titlebar">
                <div><div class="eyebrow">02 / ИССЛЕДУЙТЕ</div><h2>Фрагмент приложения</h2></div>
                <div class="editor-actions">
                  <el-button size="small" :type="selectedExample === 'vulnerable' ? 'warning' : 'info'" @click="loadExample('vulnerable')">Уязвимый</el-button>
                  <el-button size="small" :type="selectedExample === 'fixed' ? 'success' : 'info'" @click="loadExample('fixed')">Исправленный</el-button>
                </div>
              </div>
              <div class="editor-meta"><span class="file-dot"></span><span>solution.js</span><span class="editor-language">JavaScript</span></div>
              <CodeEditor v-model="labs.editorCode" />
              <div class="editor-footer">
                <span>Сохраняйте свой фрагмент в изолированной рабочей области урока.</span>
                <div class="editor-actions">
                  <el-button :loading="savingCode" @click="saveCode">Сохранить код</el-button>
                  <el-button type="primary" :loading="labs.busy" @click="runCheck">Проверить исправление</el-button>
                </div>
              </div>
              <div v-if="labs.checkResult" class="check-result" :class="{ passed: labs.checkResult.passed }">
                <div class="check-result-title"><span>{{ labs.checkResult.passed ? "✓" : "!" }}</span>{{ labs.checkResult.passed ? "Проверка пройдена" : "Нужно исправить" }}</div>
                <p>{{ labs.checkResult.message }}</p>
                <ul><li v-for="item in labs.checkResult.evidence" :key="item">{{ item }}</li></ul>
              </div>
            </section>

            <section class="fix-card"><div class="fix-icon">✓</div><div><div class="eyebrow">03 / ЗАКРЕПИТЕ</div><h2>Как исправить</h2><p>{{ lesson.mitigation }}</p></div></section>

            <section class="info-card runtime-card">
              <div class="section-heading">
                <div><div class="eyebrow">04 / ПРОВЕРЬТЕ В ДЕЙСТВИИ</div><h2>Runtime-цикл уязвимости</h2></div>
                <el-tag :type="runtimeRun?.phase === 'passed' ? 'success' : runtimeRun ? 'warning' : 'info'">{{ runtimeRun?.phase ?? "не запущен" }}</el-tag>
              </div>
              <p class="body-copy">{{ httpRuntimeLessonIds.has(lesson.id) ? "Контролируемая HTTP-мишень: реальные запросы к учебным обработчикам, затем независимый retest. Используются только синтетические данные; внешние хосты не вызываются." : "Синтетическая модель: exploit → проверка кода исправления → повторный probe. Код из редактора не исполняется, а проверяется backend-verifier-ом." }}</p>
              <div class="editor-actions runtime-actions">
                <el-button v-if="!runtimeRun" type="primary" :loading="runtimeBusy" @click="startSyntheticRun">{{ httpRuntimeLessonIds.has(lesson.id) ? "Подготовить HTTP-мишень" : "Подготовить сценарий" }}</el-button>
                <template v-else>
                  <el-button :disabled="runtimeRun.phase !== 'ready' && runtimeRun.phase !== 'exploited'" :loading="runtimeBusy" @click="runSyntheticExploit">1. Exploit probe</el-button>
                  <el-button type="primary" :disabled="runtimeRun.phase !== 'exploited'" :loading="runtimeBusy" @click="applySyntheticFix">2. Проверить fix</el-button>
                  <el-button type="success" :disabled="runtimeRun.phase !== 'fixed'" :loading="runtimeBusy" @click="runSyntheticRetest">3. Retest</el-button>
                  <el-button :loading="runtimeBusy" @click="resetSynthetic">Сбросить</el-button>
                </template>
              </div>
              <section v-if="runtimeHistory.length" class="runtime-history">
                <div class="eyebrow">ИСТОРИЯ ДОКАЗАТЕЛЬСТВ</div>
                <el-timeline>
                  <el-timeline-item v-for="(item, index) in runtimeHistory" :key="`${item.step}-${index}`" :type="item.phase === 'passed' || item.phase === 'fixed' ? 'success' : item.phase === 'exploited' ? 'danger' : 'primary'" :timestamp="item.phase">
                    <strong>{{ item.step }}</strong>
                    <p>{{ item.message }}</p>
                    <ul v-if="item.evidence.length"><li v-for="detail in item.evidence" :key="detail">{{ detail }}</li></ul>
                  </el-timeline-item>
                </el-timeline>
              </section>
              <div v-if="runtimeEvidence" class="check-result" :class="{ passed: runtimeEvidence.passed && !runtimeEvidence.vulnerable }">
                <div class="check-result-title"><span>{{ runtimeEvidence.passed ? "✓" : "!" }}</span>{{ runtimeEvidence.message }}</div>
                <ul><li v-for="item in runtimeEvidence.evidence" :key="item">{{ item }}</li></ul>
                <p v-if="runtimeEvidence.remediation">{{ runtimeEvidence.remediation.message }}</p>
                <ul
                  v-if="runtimeEvidence.remediation && runtimeEvidence.remediation.evidence.length"
                >
                  <li
                    v-for="item in runtimeEvidence.remediation.evidence"
                    :key="item"
                  >
                    {{ item }}
                  </li>
                </ul>
              </div>
            </section>
          </div>

          <div class="assistant-column">
            <AssistantChat :key="lesson.id" :lesson-id="lesson.id" />
            <section class="context-card">
              <div class="eyebrow">КОНТЕКСТ AI</div>
              <div class="context-row"><span>Урок</span><strong>{{ lesson.title }}</strong></div>
              <div class="context-row"><span>Код</span><strong>Текущий фрагмент</strong></div>
              <div class="context-row"><span>Оценивание</span><strong>Независимая проверка</strong></div>
              <p>AI объясняет подход. Результат проверки рассчитывается backend-правилом отдельно от модели.</p>
            </section>
          </div>
        </div>
      </section>
    </el-main>
  </el-container>
</template>
