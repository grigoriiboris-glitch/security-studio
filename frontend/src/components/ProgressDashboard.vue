<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { fetchProgress, type SavedProgress } from "../services/api";

type LessonSummary = { id: string; title: string; level: string };
const props = defineProps<{ lessons: LessonSummary[]; selectedLessonId: string }>();
const emit = defineEmits<{ selectLesson: [id: string] }>();
const saved = ref<Record<string, SavedProgress | null>>({});
const loading = ref(false);
const loadError = ref(false);

const rows = computed(() => props.lessons.map((lesson) => {
  const progress = saved.value[lesson.id];
  const status = !progress?.checkResult ? "not-started" : progress.checkResult.passed ? "passed" : "review";
  return { ...lesson, progress, status };
}));
const passedCount = computed(() => rows.value.filter((row) => row.status === "passed").length);
const attemptedCount = computed(() => rows.value.filter((row) => row.status !== "not-started").length);
const percent = computed(() => props.lessons.length ? Math.round(passedCount.value / props.lessons.length * 100) : 0);

async function refresh() {
  loading.value = true;
  loadError.value = false;
  try {
    const results = await Promise.all(props.lessons.map(async (lesson) => {
      try { return [lesson.id, await fetchProgress(lesson.id)] as const; }
      catch { loadError.value = true; return [lesson.id, null] as const; }
    }));
    saved.value = Object.fromEntries(results);
  } finally { loading.value = false; }
}
function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
function handleExport(command: string) {
  if (command === "json") exportJson();
  else exportCsv();
}
function exportJson() {
  const data = {
    format: "security-studio-progress-v1",
    exportedAt: new Date().toISOString(),
    summary: { total: rows.value.length, attempted: attemptedCount.value, passed: passedCount.value, completionPercent: percent.value },
    lessons: rows.value.map(({ id, title, level, status, progress }) => ({
      lessonId: id, title, level, status,
      updatedAt: progress?.updatedAt ?? null,
      checkResult: progress?.checkResult ?? null,
      selectedLabId: progress?.selectedLabId ?? null
    }))
  };
  download("security-studio-progress.json", JSON.stringify(data, null, 2), "application/json;charset=utf-8");
  ElMessage.success("Экспорт прогресса подготовлен.");
}
function exportCsv() {
  const escape = (value: unknown) => { let raw = String(value ?? ""); if (/^[=+\-@\t\r]/.test(raw)) raw = "'" + raw; return '"' + raw.replace(/"/g, '""') + '"' };
  const lines = [
    ["lessonId", "title", "level", "status", "passed", "message", "updatedAt"].map(escape).join(","),
    ...rows.value.map((row) => [
      row.id, row.title, row.level, row.status,
      row.progress?.checkResult?.passed ?? "",
      row.progress?.checkResult?.message ?? "",
      row.progress?.updatedAt ?? ""
    ].map(escape).join(","))
  ];
  download("security-studio-progress.csv", "\uFEFF" + lines.join("\r\n"), "text/csv;charset=utf-8");
  ElMessage.success("CSV-экспорт подготовлен.");
}
onMounted(() => { void refresh(); });
</script>

<template>
  <section class="progress-dashboard" aria-label="Карта навыков и прогресс обучения">
    <div class="progress-dashboard-head">
      <div>
        <div class="eyebrow">КАРТА НАВЫКОВ</div>
        <h2>Прогресс по 30 уязвимостям</h2>
        <p>Статус отражает сохранённый результат backend-проверки кода, а не подтверждение безопасности приложения.</p>
      </div>
      <div class="progress-dashboard-actions">
        <el-button size="small" :loading="loading" @click="refresh">Обновить</el-button>
        <el-dropdown trigger="click" @command="handleExport">
          <el-button type="primary" size="small">Экспорт прогресса ▾</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="json">JSON — сводка и статусы</el-dropdown-item>
              <el-dropdown-item command="csv">CSV — таблица уроков</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </div>
    <div class="progress-overview">
      <div class="progress-stat"><strong>{{ passedCount }} / {{ lessons.length }}</strong><span>проверка пройдена</span></div>
      <div class="progress-stat"><strong>{{ attemptedCount }}</strong><span>попыток с результатом</span></div>
      <div class="progress-stat"><strong>{{ percent }}%</strong><span>пройдено по проверкам</span></div>
      <div class="progress-track" role="progressbar" :aria-valuenow="percent" aria-valuemin="0" aria-valuemax="100" :aria-label="'Пройдено ' + percent + '%'">
        <span :style="{ width: percent + '%' }"></span>
      </div>
    </div>
    <el-alert v-if="loadError" title="Не все результаты удалось загрузить. Проверьте соединение с API и обновите карту." type="warning" :closable="false" show-icon />
    <div class="skill-map">
      <button v-for="(row, index) in rows" :key="row.id" type="button" class="skill-map-item" :class="['skill-' + row.status, { 'skill-selected': row.id === selectedLessonId }]" :aria-current="row.id === selectedLessonId ? 'step' : undefined" @click="emit('selectLesson', row.id)">
        <span class="skill-map-number">{{ String(index + 1).padStart(2, "0") }}</span>
        <span class="skill-map-copy"><strong>{{ row.title }}</strong><small>{{ row.level }}</small></span>
        <span class="skill-map-status">{{ row.status === "passed" ? "Пройдена" : row.status === "review" ? "Повторить" : "Не начат" }}</span>
      </button>
    </div>
    <div class="skill-map-legend"><span><i class="legend-dot legend-passed"></i>Проверка пройдена</span><span><i class="legend-dot legend-review"></i>Нужно исправление</span><span><i class="legend-dot legend-new"></i>Нет результата</span></div>
  </section>
</template>
