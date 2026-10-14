<script setup lang="ts">
import { computed, ref, watch } from "vue";

type LessonSummary = { id: string; title: string; level: string; summary?: string };
type Track = "appsec" | "ai-security";
type Props = { lessons: LessonSummary[]; selectedLessonId: string };
const props = defineProps<Props>();
const emit = defineEmits<{ selectLesson: [id: string] }>();

const tracks: Array<{ id: Track; title: string; subtitle: string }> = [
  { id: "appsec", title: "Middle AppSec", subtitle: "Защита приложений, API, архитектуры и SDLC" },
  { id: "ai-security", title: "AI Security Engineer", subtitle: "LLM, RAG, AI-агенты и безопасность моделей" }
];
const categories: Record<Track, Array<{ id: string; title: string; description: string; lessonIds?: string[] }>> = {
  appsec: [
    { id: "web", title: "Web Security", description: "Инъекции, XSS, сессии и браузерная безопасность", lessonIds: ["sql-injection", "xss-reflected", "xss-stored", "xss-dom", "csrf", "broken-authentication", "session-fixation", "password-reset", "open-redirect", "cors", "clickjacking", "security-headers"] },
    { id: "api", title: "API & Access Control", description: "Авторизация, BOLA/IDOR, JWT и бизнес-логика", lessonIds: ["idor", "broken-access-control", "jwt-validation", "mass-assignment", "rate-limiting", "business-logic", "sensitive-data"] },
    { id: "injection", title: "Injection & Input Handling", description: "Серверные инъекции, файлы и небезопасная обработка данных", lessonIds: ["nosql-injection", "ldap-injection", "command-injection", "xxe", "ssti", "insecure-deserialization", "prototype-pollution", "path-traversal", "file-upload"] },
    { id: "architecture", title: "Infrastructure & Data", description: "SSRF, конфигурация и утечки секретов", lessonIds: ["ssrf", "secrets-exposure"] },
    { id: "interview", title: "Interview & Secure Design", description: "Threat modeling, code review, DevSecOps, риск и отчётность" }
  ],
  "ai-security": [
    { id: "foundations", title: "AI Security Foundations", description: "Архитектура LLM, потоки данных, границы доверия и threat modeling" },
    { id: "prompt", title: "Prompt Injection & Jailbreaks", description: "Прямые и косвенные инъекции, недоверенный контент и проверка защит" },
    { id: "rag", title: "RAG & Knowledge Security", description: "Утечки между пользователями, доступ к документам, poisoning и retrieval" },
    { id: "agents", title: "AI Agents & Tools", description: "Избыточные полномочия, небезопасные инструменты и подтверждение действий" },
    { id: "privacy", title: "Data Privacy & Leakage", description: "PII, секреты в контексте, изоляция арендаторов и хранение данных" },
    { id: "models", title: "Model & ML Security", description: "Data poisoning, adversarial inputs, model extraction и supply chain" },
    { id: "redteam", title: "AI Red Teaming & Evaluation", description: "Наборы атак, измеримые критерии, регрессии и повторная проверка" },
    { id: "infra", title: "AI Infrastructure & Governance", description: "Inference API, ключи, инфраструктура моделей, инвентаризация и риски" },
    { id: "interview", title: "AI Security Interview Lab", description: "Разбор архитектуры, расследование инцидентов и проектирование защиты" }
  ]
};
const activeTrack = ref<Track>("appsec");
const activeCategory = ref("web");
const completed = ref<Record<string, boolean>>({});
try {
  const savedTrack = localStorage.getItem("security-studio-learning-track");
  if (savedTrack === "appsec" || savedTrack === "ai-security") activeTrack.value = savedTrack;
  const savedProgress = localStorage.getItem("security-studio-track-checklist");
  if (savedProgress) completed.value = JSON.parse(savedProgress) as Record<string, boolean>;
} catch { /* Storage may be unavailable in private browsing. */ }
watch(activeTrack, (value) => {
  activeCategory.value = categories[value][0].id;
  try { localStorage.setItem("security-studio-learning-track", value); } catch { /* Optional preference. */ }
});
watch(completed, (value) => {
  try { localStorage.setItem("security-studio-track-checklist", JSON.stringify(value)); } catch { /* Optional progress. */ }
}, { deep: true });
const category = computed(() => categories[activeTrack.value].find((item) => item.id === activeCategory.value) ?? categories[activeTrack.value][0]);
const categoryLessons = computed(() => (category.value.lessonIds ?? []).map((id) => props.lessons.find((lesson) => lesson.id === id)).filter((item): item is LessonSummary => Boolean(item)));
const trackCount = (track: Track) => track === "appsec" ? props.lessons.length : categories[track].length;
const roadmapKey = (categoryId: string, index: number) => `ai-security:${categoryId}:${index}`;
const aiOutcomes: Record<string, string[]> = {
  foundations: ["Map model, application, tools and data trust boundaries", "Identify assets, attackers and realistic abuse cases"],
  prompt: ["Distinguish direct from indirect prompt injection", "Test whether untrusted content can influence privileged actions"],
  rag: ["Enforce document permissions at retrieval time", "Test cross-user leakage and poisoned source content"],
  agents: ["Apply least privilege to tools", "Require server-side authorization and approval for consequential actions"],
  privacy: ["Prevent secrets and personal data entering unauthorized contexts", "Verify tenant isolation and retention controls"],
  models: ["Explain poisoning, evasion and model extraction risks", "Assess model and dataset provenance"],
  redteam: ["Create repeatable attack cases and safety regressions", "Report evidence, impact, limitations and residual risk"],
  infra: ["Protect inference endpoints, credentials and deployment boundaries", "Build an AI system inventory and risk register"],
  interview: ["Review an AI architecture and prioritize its risks", "Defend mitigations with evidence and trade-offs"]
};
function toggleOutcome(key: string) { completed.value[key] = !completed.value[key]; }
</script>

<template>
  <section class="info-card learning-tracks" aria-label="Профессиональные учебные треки">
    <div class="section-heading">
      <div><div class="eyebrow">ПОДГОТОВКА К СОБЕСЕДОВАНИЮ</div><h2>Выберите профессиональный трек</h2></div>
      <el-tag effect="plain">Прогресс сохраняется локально</el-tag>
    </div>
    <div class="track-switch" role="group" aria-label="Профессиональный трек">
      <button v-for="track in tracks" :key="track.id" type="button" :class="{ active: activeTrack === track.id }" @click="activeTrack = track.id">
        <strong>{{ track.title }}</strong><span>{{ track.subtitle }}</span><small>{{ trackCount(track.id) }} {{ track.id === "appsec" ? "уроков" : "категорий" }}</small>
      </button>
    </div>
    <div class="track-layout">
      <nav class="track-categories" aria-label="Категории учебного трека">
        <button v-for="item in categories[activeTrack]" :key="item.id" type="button" :class="{ active: activeCategory === item.id }" @click="activeCategory = item.id">
          <strong>{{ item.title }}</strong>
          <small>{{ item.description }}</small>
          <el-tag v-if="activeTrack === 'appsec' && item.lessonIds" size="small" effect="plain">{{ item.lessonIds.length }} уроков</el-tag>
          <el-tag v-else size="small" type="success" effect="plain">Лаборатория</el-tag>
        </button>
      </nav>
      <div class="track-content">
        <h3>{{ category.title }}</h3>
        <p class="body-copy">{{ category.description }}</p>
        <template v-if="activeTrack === 'appsec' && category.lessonIds">
          <div class="track-lesson-list">
            <div v-for="item in categoryLessons" :key="item.id" class="track-lesson">
              <div><strong>{{ item.title }}</strong><small>{{ item.level }}<template v-if="item.summary"> · {{ item.summary }}</template></small></div>
              <el-button size="small" :type="selectedLessonId === item.id ? 'primary' : 'default'" @click="emit('selectLesson', item.id)">{{ selectedLessonId === item.id ? "Выбран" : "Открыть урок" }}</el-button>
            </div>
          </div>
        </template>
        <template v-else-if="activeTrack === 'appsec'">
          <p>Эта категория объединяет задания по моделированию угроз, анализу кода, DevSecOps и оценке рисков. Это следующий этап расширения программы; существующие лаборатории не дублируются.</p>
          <ul class="track-outcomes"><li>Threat modeling и trust boundaries</li><li>SAST, DAST, SCA и безопасность CI/CD</li><li>Severity, доказательства и отчёт об уязвимости</li><li>Разбор архитектурных компромиссов на интервью</li></ul>
        </template>
        <template v-else>
          <div class="track-roadmap-note"><strong>Учебный план AI Security</strong><p>Все девять категорий AI Security теперь имеют интерактивную учебную лабораторию ниже на этой странице. Чек-лист помогает отмечать освоенные результаты, а лаборатории используют синтетические данные и независимую проверку контрольного состояния.</p></div>
          <div class="track-outcome-list">
            <label v-for="(outcome, index) in (aiOutcomes[category.id] ?? [])" :key="outcome" class="track-outcome">
              <input type="checkbox" :checked="Boolean(completed[roadmapKey(category.id, index)])" @change="toggleOutcome(roadmapKey(category.id, index))" />
              <span>{{ outcome }}</span>
            </label>
          </div>
          <div class="track-progress"><span>{{ (aiOutcomes[category.id] ?? []).filter((_, index) => completed[roadmapKey(category.id, index)]).length }} из {{ (aiOutcomes[category.id] ?? []).length }} целей отмечено</span></div>
        </template>
      </div>
    </div>
  </section>
</template>
