<script setup lang="ts">
import { onMounted, ref } from "vue";

type EvalCase = "indirect-prompt-injection" | "synthetic-secret-leak";
type EvalStatus = { enabled: boolean; providerConfigured: boolean; model: string; cases: string[]; note: string };
type EvalResult = { caseId: EvalCase; title: string; passed: boolean; verdict: "pass" | "fail"; output: string; evidence: string[]; model: string };

const selectedCase = ref<EvalCase>("indirect-prompt-injection");
const status = ref<EvalStatus | null>(null);
const result = ref<EvalResult | null>(null);
const busy = ref(false);
const error = ref("");

async function refreshStatus() {
  try {
    const response = await fetch("/api/ai-security/live-eval/status");
    if (!response.ok) throw new Error("status");
    status.value = await response.json() as EvalStatus;
  } catch {
    error.value = "Не удалось получить статус live evaluation API.";
  }
}
async function runEvaluation() {
  busy.value = true;
  error.value = "";
  result.value = null;
  try {
    const response = await fetch("/api/ai-security/live-eval/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ caseId: selectedCase.value })
    });
    const data = await response.json() as EvalResult | { error?: string };
    if (!response.ok) throw new Error("error" in data && data.error ? data.error : "Не удалось выполнить проверку.");
    result.value = data as EvalResult;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Ошибка live evaluation.";
  } finally {
    busy.value = false;
    await refreshStatus();
  }
}
onMounted(refreshStatus);
</script>

<template>
  <section class="info-card live-eval" aria-label="Проверка реальной модели">
    <div class="section-heading">
      <div>
        <div class="eyebrow">ОПЦИОНАЛЬНО · ВНЕШНИЙ PROVIDER</div>
        <h2>Live model smoke evaluation</h2>
      </div>
      <el-tag :type="status?.enabled ? 'success' : 'info'">{{ status?.enabled ? 'Включено' : 'Выключено' }}</el-tag>
    </div>
    <p class="body-copy">Два фиксированных синтетических теста для настроенной модели. По умолчанию выключено; произвольные промпты и внешние цели запрещены.</p>
    <div class="eval-controls">
      <el-select v-model="selectedCase" aria-label="Сценарий live evaluation">
        <el-option label="Indirect prompt injection" value="indirect-prompt-injection" />
        <el-option label="Synthetic secret leakage" value="synthetic-secret-leak" />
      </el-select>
      <el-button type="primary" :loading="busy" :disabled="busy || !status?.enabled" @click="runEvaluation">Запустить проверку модели</el-button>
      <el-button :disabled="busy" @click="refreshStatus">Обновить статус</el-button>
    </div>
    <p v-if="status" class="eval-meta">Модель: {{ status.model }} · Provider: {{ status.providerConfigured ? 'настроен' : 'не настроен' }}</p>
    <p v-if="!status?.enabled" class="eval-note">Чтобы включить: задайте AI_SECURITY_LIVE_TESTS_ENABLED=true и OPENCODE_GO_API_KEY в окружении backend, затем перезапустите API.</p>
    <p v-if="error" class="ai-lab-error" role="alert">{{ error }}</p>
    <div v-if="result" class="eval-result" aria-live="polite">
      <div class="section-heading">
        <strong>{{ result.title }}</strong>
        <el-tag :type="result.passed ? 'success' : 'danger'">{{ result.passed ? 'PASS' : 'FAIL' }}</el-tag>
      </div>
      <p><strong>Ответ модели:</strong></p>
      <pre>{{ result.output }}</pre>
      <ul><li v-for="item in result.evidence" :key="item">{{ item }}</li></ul>
    </div>
    <p class="eval-note">Результат — только smoke test с простым правилом оценки, не доказательство безопасности. Синтетические промпты передаются выбранному провайдеру.</p>
  </section>
</template>

<style scoped>
.live-eval { margin: 22px 0; }
.eval-controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.eval-controls .el-select { min-width: 240px; }
.eval-meta, .eval-note { color: var(--el-text-color-secondary); font-size: 12px; line-height: 1.6; margin-top: 12px; }
.eval-result { margin-top: 18px; padding: 14px; border: 1px solid var(--el-border-color); border-radius: 10px; }
.eval-result pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 13px; }
@media (max-width: 600px) { .eval-controls { align-items: stretch; flex-direction: column; } .eval-controls .el-select { width: 100%; } }
</style>
