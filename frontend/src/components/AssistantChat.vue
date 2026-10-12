<script setup lang="ts">
import {
  AuiConfig, AuiProvider, ComposerPrimitiveInput, ComposerPrimitiveSend,
  MessagePrimitiveParts, ThreadPrimitiveMessages, ThreadPrimitiveViewport
} from "@assistant-ui/vue";
import { AISDKChat, AssistantChatTransport } from "@assistant-ui/ai-sdk";
import { ElMessage } from "element-plus";
import { useLabsStore } from "../stores/labs";

const labs = useLabsStore();
const config = AuiConfig({
  threads: AISDKChat({
    transport: new AssistantChatTransport({
      api: "/api/assistant/chat",
      body: () => ({ lessonId: "sql-injection", code: labs.editorCode.slice(0, 12000) }),
      credentials: "same-origin"
    }),
    onError: () => ElMessage.error("AI недоступен. Проверьте OPENCODE_GO_API_KEY в .env.")
  })
});
</script>
<template>
  <section class="assistant-panel">
    <div class="assistant-heading">
      <div><div class="eyebrow">AI TUTOR</div><h2>Помощник по коду</h2></div>
      <el-tag effect="plain" type="info">MiMo Flash</el-tag>
    </div>
    <AuiProvider :config="config">
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
    <p class="chat-note">Передаются текущий урок и фрагмент кода. Ключ API остаётся на backend.</p>
  </section>
</template>
