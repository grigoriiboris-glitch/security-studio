<script setup lang="ts">
import * as monaco from "monaco-editor";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps<{ modelValue: string }>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();
const host = ref<HTMLElement | null>(null);
let editor: monaco.editor.IStandaloneCodeEditor | undefined;
let syncing = false;

onMounted(() => {
  if (!host.value) return;
  editor = monaco.editor.create(host.value, {
    value: props.modelValue,
    language: "javascript",
    theme: "vs-dark",
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 13,
    lineNumbers: "on",
    scrollBeyondLastLine: false,
    tabSize: 2,
    wordWrap: "on"
  });
  editor.onDidChangeModelContent(() => {
    if (!syncing && editor) emit("update:modelValue", editor.getValue());
  });
});
watch(() => props.modelValue, (value) => {
  if (!editor || editor.getValue() === value) return;
  syncing = true;
  editor.setValue(value);
  syncing = false;
});
onBeforeUnmount(() => { editor?.dispose(); editor = undefined; });
</script>
<template><div ref="host" class="monaco-host" aria-label="Редактор учебного кода"></div></template>
