<script setup lang="ts">
import { onMounted, shallowRef } from "vue";
import type { UIMessage } from "ai";
import {
  AuiConfig, AuiProvider, ComposerPrimitiveInput, ComposerPrimitiveSend,
  MessagePrimitiveParts, ThreadPrimitiveMessages, ThreadPrimitiveViewport
} from "@assistant-ui/vue";
import { AISDKChat, AssistantChatTransport } from "@assistant-ui/ai-sdk";
import { ElMessage } from "element-plus";
import { fetchChatHistory } from "../services/api";
import { useLabsStore } from "../stores/labs";

const props = defineProps<{ lessonId: string }>();
const labs = useLabsStore();
const conversationId = "security-studio-" + props.lessonId;
const config = shallowRef<ReturnType<typeof AuiConfig> | null>(null);

onMounted(async () => {
  let messages: UIMessage[] = [];
  try {
    messages = await fetchChatHistory(conversationId);
  } catch {
    // Start with an empty chat if the local API/history is temporarily unavailable.
  }
  config.value = AuiConfig({
    threads: AISDKChat({
      id: conversationId,
      messages,
      transport: new AssistantChatTransport({
        api: "/api/assistant/chat",
        body: () => ({ lessonId: props.lessonId, code: labs.editorCode.slice(0, 12000) }),
        credentials: "same-origin"
      }),
      onError: () => ElMessage.error("AI недоступен. Проверьте OPENCODE_GO_API_KEY в .env.")
    })
  });
});
</script>
<template>
  <section class="assistant-panel">
    <div class="assistant-heading">
      <div><div class="eyebrow">AI TUTOR</div><h2>Помощник по коду</h2></div>
      <el-tag effect="plain" type="info">MiMo Flash</el-tag>
    </div>
    <AuiProvider v-if="config" :config="config">
      <div class="chat-layout">
        <ThreadPrimitiveViewport class="chat-viewport" aria-label="Сообщения чата">
          <ThreadPrimitiveMessages><div class="chat-message"><MessagePrimitiveParts /></div></ThreadPrimitiveMessages>
        </ThreadPrimitiveViewport>
        <div class="composer">
          <ComposerPrimitiveInput class="composer-input" placeholder="Спросите об уязвимости или исправлении…" aria-label="Сообщение AI-ассистенту" />
          <ComposerPrimitiveSend class="composer-send" aria-label="Отправить сообщение">Отправить</ComposerPrimitiveSend>
        </div>
      </div>
    </AuiProvider>
    <div v-else class="chat-layout chat-loading" role="status">Загружаем историю диалога…</div>
    <p class="chat-note">История диалога сохраняется в локальной SQLite-базе. Передаются текущий урок и фрагмент кода; ключ API остаётся на backend.</p>
  </section>
</template>
