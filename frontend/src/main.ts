import { createApp } from "vue";
import { createPinia } from "pinia";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import "monaco-editor/min/vs/editor/editor.main.css";
import App from "./App.vue";
import "./styles.css";

createApp(App).use(createPinia()).use(ElementPlus).mount("#app");
