import { defineStore } from "pinia";
import { ref } from "vue";
import { checkCode, fetchLabStatus, startLab, stopLab, type ActiveLab, type CheckResult, type LabId } from "../services/api";
import { lessons } from "../data/lessons";

export const useLabsStore = defineStore("labs", () => {
  const selectedLabId = ref<LabId>("juice-shop");
  const activeLab = ref<ActiveLab | null>(null);
  const editorCode = ref(lessons[0].vulnerableCode);
  const checkResult = ref<CheckResult | null>(null);
  const busy = ref(false);
  const lastError = ref("");

  async function refresh() {
    try {
      const status = await fetchLabStatus();
      activeLab.value = status.activeLab;
      if (!status.available) lastError.value = status.message ?? "Docker недоступен.";
    } catch {
      lastError.value = "API недоступен. Запустите backend командой npm run dev.";
    }
  }
  async function startSelectedLab() {
    busy.value = true;
    lastError.value = "";
    try { activeLab.value = await startLab(selectedLabId.value); }
    catch (error) { lastError.value = messageFrom(error, "Не удалось запустить лабораторию."); }
    finally { busy.value = false; }
  }
  async function stopActiveLab() {
    busy.value = true;
    try { await stopLab(); activeLab.value = null; }
    catch (error) { lastError.value = messageFrom(error, "Не удалось остановить лабораторию."); }
    finally { busy.value = false; }
  }
  async function verifyCode() {
    busy.value = true;
    lastError.value = "";
    try { checkResult.value = await checkCode(editorCode.value); }
    catch (error) { lastError.value = messageFrom(error, "Проверка кода не выполнена."); }
    finally { busy.value = false; }
  }
  function loadExample(kind: "vulnerable" | "fixed") {
    editorCode.value = kind === "fixed" ? lessons[0].fixedCode : lessons[0].vulnerableCode;
    checkResult.value = null;
  }
  return { selectedLabId, activeLab, editorCode, checkResult, busy, lastError, refresh, startSelectedLab, stopActiveLab, verifyCode, loadExample };
});

function messageFrom(error: unknown, fallback: string): string {
  if (typeof error === "object" && error !== null && "message" in error && typeof error.message === "string") return error.message;
  return fallback;
}
