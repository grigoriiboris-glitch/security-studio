<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import { parse } from "yaml";

type LessonSummary = { id: string; title: string; level: string };
type Chain = { id: string; title: string; description: string; steps: string[] };
type ApiOperation = { method: string; path: string; summary: string; operationId: string; recommendations: string[] };
const props = defineProps<{ lessons: LessonSummary[] }>();
const emit = defineEmits<{ selectLesson: [id: string] }>();

const chains: Chain[] = [
  { id: "account-takeover", title: "Захват учётной записи", description: "От слабого восстановления пароля к злоупотреблению сессией и контролем доступа.", steps: ["password-reset", "broken-authentication", "session-fixation", "broken-access-control"] },
  { id: "data-exposure", title: "Утечка данных", description: "От обхода авторизации к инъекциям и раскрытию чувствительных данных.", steps: ["idor", "broken-access-control", "sql-injection", "sensitive-data"] },
  { id: "browser-to-server", title: "От браузера к серверу", description: "Связать клиентский XSS, CSRF и небезопасные серверные сетевые запросы.", steps: ["xss-reflected", "xss-dom", "csrf", "ssrf"] }
];
const selectedChainId = ref(chains[0].id);
const selectedChain = computed(() => chains.find((chain) => chain.id === selectedChainId.value) ?? chains[0]);
const apiOperations = ref<ApiOperation[]>([]);
const apiFilename = ref("");
const apiError = ref("");
const apiVersion = ref("");
const busy = ref(false);
const lessonTitle = (id: string) => props.lessons.find((lesson) => lesson.id === id)?.title ?? id;

const recommendationRules: Array<{ pattern: RegExp; lessons: string[] }> = [
  { pattern: /auth|login|sign.?in|credential|password|session|token|oauth|sso|account\/me/i, lessons: ["broken-authentication", "session-fixation", "password-reset", "jwt-validation"] },
  { pattern: /admin|role|permission|privilege|access|authori[sz]/i, lessons: ["broken-access-control", "mass-assignment"] },
  { pattern: /user|profile|account|order|invoice|document|tenant|project|customer|member|resource|object|report/i, lessons: ["idor", "sensitive-data", "broken-access-control"] },
  { pattern: /search|query|filter|lookup|find|sql|database/i, lessons: ["sql-injection", "nosql-injection"] },
  { pattern: /ldap|directory/i, lessons: ["ldap-injection"] },
  { pattern: /upload|attachment|file|media|image/i, lessons: ["file-upload", "path-traversal"] },
  { pattern: /url|fetch|webhook|proxy|callback|import|preview/i, lessons: ["ssrf"] },
  { pattern: /redirect|return.?to|continue|next/i, lessons: ["open-redirect"] },
  { pattern: /comment|message|content|html|render|markup|feedback/i, lessons: ["xss-reflected", "xss-stored", "xss-dom"] },
  { pattern: /xml|soap/i, lessons: ["xxe"] },
  { pattern: /template|view|render/i, lessons: ["ssti"] },
  { pattern: /export|download|attachment|document|report/i, lessons: ["sensitive-data", "path-traversal"] },
  { pattern: /payment|checkout|transfer|coupon|discount|balance|purchase|order/i, lessons: ["business-logic", "rate-limiting"] }
];
function recommendLessons(operation: Pick<ApiOperation, "method" | "path" | "summary" | "operationId">) {
  const searchable = [operation.path, operation.summary, operation.operationId].join(" ");
  const matches = new Set<string>();
  for (const rule of recommendationRules) {
    if (rule.pattern.test(searchable)) rule.lessons.forEach((id) => matches.add(id));
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(operation.method)) {
    matches.add("csrf");
    matches.add("broken-access-control");
  }
  if (/^\/(api\/)?(health|status|docs?)(\/|$)/i.test(operation.path)) matches.clear();
  return [...matches].filter((id) => props.lessons.some((lesson) => lesson.id === id)).slice(0, 5);
}


function selectChain(id: string) { selectedChainId.value = id; }
async function importOpenApi(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  busy.value = true;
  apiError.value = "";
  apiOperations.value = [];
  apiFilename.value = file.name;
  try {
    if (file.size > 2 * 1024 * 1024) throw new Error("Файл больше 2 МБ. Выберите меньшую спецификацию.");
    const raw = await file.text();
    const parsed: unknown = parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Ожидался OpenAPI-объект.");
    const spec = parsed as { openapi?: unknown; swagger?: unknown; paths?: unknown };
    if ((typeof spec.openapi !== "string" || !/^3\.\d+\.\d+(?:[-+].*)?$/.test(spec.openapi)) && spec.swagger !== "2.0") throw new Error("Не найдена поддерживаемая версия OpenAPI 3.x или Swagger 2.0.");
    if (!spec.paths || typeof spec.paths !== "object" || Array.isArray(spec.paths)) throw new Error("В спецификации отсутствует объект paths.");
    const operations: Array<Omit<ApiOperation, "recommendations">> = [];
    for (const [path, value] of Object.entries(spec.paths as Record<string, unknown>)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      for (const [method, details] of Object.entries(value as Record<string, unknown>)) {
        if (!["get", "post", "put", "patch", "delete", "options", "head"].includes(method.toLowerCase())) continue;
        const detail = details && typeof details === "object" ? details as Record<string, unknown> : {};
        operations.push({
          method: method.toUpperCase(), path,
          summary: typeof detail.summary === "string" ? detail.summary : "",
          operationId: typeof detail.operationId === "string" ? detail.operationId : "",
        });
      }
    }
    if (!operations.length) throw new Error("В paths не найдено HTTP-операций.");
    apiVersion.value = typeof spec.openapi === "string" ? spec.openapi : "Swagger 2.0";
    apiOperations.value = operations.map((operation) => ({ ...operation, recommendations: recommendLessons(operation) })).sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
    ElMessage.success("Импортировано операций: " + operations.length + ". Запросы к API не выполнялись.");
  } catch (error) {
    apiError.value = error instanceof Error ? error.message : "Не удалось разобрать спецификацию.";
  } finally {
    busy.value = false;
    input.value = "";
  }
}
function exportOperations() {
  const rows = [["method", "path", "summary", "operationId"], ...apiOperations.value.map(({ method, path, summary, operationId }) => [method, path, summary, operationId])];
  const csv = rows.map((row) => row.map((cell) => { const safe = /^[=+\-@\t\r]/.test(cell) ? "'" + cell : cell; return '"' + safe.replace(/"/g, '""') + '"' }).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "openapi-endpoints.csv";
  anchor.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <section class="info-card attack-tools-card" aria-label="Цепочки атак и импорт OpenAPI">
    <div class="section-heading">
      <div><div class="eyebrow">ПРАКТИКА</div><h2>Цепочки атак и OpenAPI</h2></div>
      <el-tag effect="plain">Учебный режим</el-tag>
    </div>
    <p class="body-copy">Изучайте, как несколько слабых мест могут усиливать друг друга. Импорт OpenAPI только разбирает локальный файл и показывает маршруты — запросы к указанным серверам не выполняются.</p>
    <div class="chain-picker" role="group" aria-label="Выбор цепочки атак">
      <button v-for="chain in chains" :key="chain.id" type="button" :class="{ active: selectedChainId === chain.id }" @click="selectChain(chain.id)">{{ chain.title }}</button>
    </div>
    <div class="chain-detail">
      <strong>{{ selectedChain.title }}</strong>
      <p>{{ selectedChain.description }}</p>
      <ol>
        <li v-for="id in selectedChain.steps" :key="id">
          <button type="button" class="chain-lesson-link" @click="emit('selectLesson', id)">{{ lessonTitle(id) }} ↗</button>
        </li>
      </ol>
    </div>
    <el-divider />
    <div class="openapi-import">
      <div><strong>Импорт OpenAPI / Swagger</strong><p>JSON или YAML · максимум 2 МБ · локальная обработка</p></div>
      <label class="openapi-file-label">
        <input type="file" accept=".json,.yaml,.yml,application/json,text/yaml,application/yaml" :disabled="busy" @change="importOpenApi" />
        {{ busy ? "Читаю спецификацию…" : "Выбрать файл" }}
      </label>
    </div>
    <el-alert v-if="apiError" :title="apiError" type="error" :closable="false" show-icon />
    <div v-if="apiOperations.length" class="openapi-results">
      <div class="openapi-results-head"><div><strong>{{ apiFilename }}</strong><small>{{ apiVersion }} · {{ apiOperations.length }} операций</small></div><el-button size="small" @click="exportOperations">Экспорт CSV</el-button></div>
      <div class="openapi-endpoint-list">
        <div v-for="(operation, index) in apiOperations" :key="operation.method + '-' + operation.path + '-' + index" class="openapi-endpoint">
          <span class="http-method" :class="'method-' + operation.method.toLowerCase()">{{ operation.method }}</span>
          <code>{{ operation.path }}</code>
          <small v-if="operation.summary">{{ operation.summary }}</small>
          <div v-if="operation.recommendations.length" class="operation-recommendations">
            <span>Проверить:</span>
            <button v-for="lessonId in operation.recommendations" :key="lessonId" type="button" class="recommendation-link" @click="emit('selectLesson', lessonId)">{{ lessonTitle(lessonId) }} ↗</button>
          </div>
          <small v-else class="no-recommendations">Подходящие уроки автоматически не определены — выберите их вручную.</small>
        </div>
      </div>
      <p class="openapi-safety-note">Импорт не подтверждает наличие уязвимостей и не отправляет трафик. Маршруты можно использовать как основу для планирования проверок.</p>
    </div>
  </section>
</template>
