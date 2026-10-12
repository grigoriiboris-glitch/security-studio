<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, useTemplateRef } from "vue";

type ProbeMode = "vulnerable" | "fixed";
type ProbeMessage = { type: "render-complete" | "payload-executed"; mode?: ProbeMode };

const frame = useTemplateRef<HTMLIFrameElement>("probe-frame");
const mode = ref<ProbeMode>("vulnerable");
const status = ref("Проверка ещё не запускалась.");
const running = ref(false);

function handleMessage(event: MessageEvent<ProbeMessage>) {
  if (!frame.value || event.source !== frame.value.contentWindow || !event.data || typeof event.data !== "object") return;
  if (event.data.type === "payload-executed") {
    status.value = "Атака подтверждена: HTML-ввод выполнил событие внутри изолированного iframe.";
    running.value = false;
  } else if (event.data.type === "render-complete" && event.data.mode === "fixed") {
    status.value = "Защита подтверждена: ввод отображён как текст, событие не выполняется.";
    running.value = false;
  } else if (event.data.type === "render-complete" && event.data.mode === "vulnerable") {
    status.value = "HTML вставлен в DOM. Ожидается результат контрольного события…";
  }
}

function runProbe(nextMode: ProbeMode) {
  mode.value = nextMode;
  running.value = true;
  status.value = nextMode === "vulnerable" ? "Запускаем контролируемую XSS-мишень…" : "Проверяем безопасный вывод…";
  const payload = '<img src="blocked-by-csp" onerror="parent.postMessage({type:\'payload-executed\'}, \'*\')">';
  const render = nextMode === "vulnerable" ? "target.innerHTML = payload;" : "target.textContent = payload;";
  const source = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none'; script-src 'unsafe-inline'"></head><body><p id="target"></p><script>const payload = ${JSON.stringify(payload)}; const target = document.getElementById('target'); ${render} parent.postMessage({type:'render-complete', mode:${JSON.stringify(nextMode)}}, '*');<\/script></body></html>`;
  if (frame.value) frame.value.srcdoc = source;
}

onMounted(() => window.addEventListener("message", handleMessage));
onBeforeUnmount(() => window.removeEventListener("message", handleMessage));
</script>

<template>
  <section class="info-card browser-probe-card">
    <div class="section-heading">
      <div><div class="eyebrow">ИЗОЛИРОВАННЫЙ БРАУЗЕР</div><h2>DOM XSS: проверка в браузере</h2></div>
      <el-tag type="warning" effect="plain">Sandbox</el-tag>
    </div>
    <p class="body-copy">Запускается только встроенная демонстрационная мишень. Код редактора не исполняется; iframe изолирован атрибутом sandbox, а изображения заблокированы CSP.</p>
    <div class="editor-actions">
      <el-button type="warning" :loading="running && mode === 'vulnerable'" @click="runProbe('vulnerable')">Проверить уязвимый вывод</el-button>
      <el-button type="success" plain :loading="running && mode === 'fixed'" @click="runProbe('fixed')">Проверить textContent</el-button>
    </div>
    <el-alert class="browser-probe-status" :title="status" :type="status.startsWith('Атака подтверждена') ? 'error' : status.startsWith('Защита подтверждена') ? 'success' : 'info'" :closable="false" show-icon />
    <iframe ref="probe-frame" class="browser-probe-frame" title="Изолированная DOM XSS учебная мишень" sandbox="allow-scripts" referrerpolicy="no-referrer" />
  </section>
</template>
