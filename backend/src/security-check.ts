export type SecurityCheckResult = {
  passed: boolean;
  message: string;
  evidence: string[];
};

// Heuristic only: reject SQL keywords joined to dynamic values in either order.
const unsafeConcatenation = /(?:\b(?:select|update|delete|insert)\b[\s\S]{0,400}\+\s*[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*\+[\s\S]{0,400}\b(?:select|update|delete|insert)\b)/i;
const unsafeTemplateInterpolation = new RegExp("(?:select|update|delete|insert)[\\s\\S]{0,400}?\\x60[^\\x60]*\\$\\{[^}]+\\}[^\\x60]*\\x60", "i");
const parameterizedQuery = /(?:query|execute|prepare|all|get|run)\s*\(\s*["'\x60][\s\S]{0,500}?(?:\?|\$\d+|:[a-z_]\w*|@[a-z_]\w*)[\s\S]{0,100}["'\x60]\s*,\s*\[/i;
const explicitPreparedStatement = /\.prepare\s*\(\s*["'\x60][\s\S]{0,500}?["'\x60]\s*\)/i;

function removeComments(code: string): string {
  return code
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/.*$/gm, "$1 ");
}

export function checkSqlInjectionFix(code: string): SecurityCheckResult {
  if (!code.trim()) {
    return { passed: false, message: "Редактор пуст. Добавьте реализацию запроса для проверки.", evidence: ["Не найден код SQL-запроса."] };
  }

  const source = removeComments(code);
  const unsafeConcat = unsafeConcatenation.test(source);
  const unsafeTemplate = unsafeTemplateInterpolation.test(source);
  const parameterized = parameterizedQuery.test(source) || explicitPreparedStatement.test(source);
  const evidence: string[] = [];

  if (unsafeConcat) evidence.push("Обнаружено построение SQL через конкатенацию строки и переменной.");
  if (unsafeTemplate) evidence.push("Обнаружена интерполяция значения в шаблонную строку SQL.");
  if (parameterized) evidence.push("Найден признак параметризованного запроса или подготовленного выражения.");
  else evidence.push("Не найден узнаваемый шаблон передачи параметров отдельно от SQL.");

  if (!unsafeConcat && !unsafeTemplate && parameterized) {
    evidence.push("В проверенном фрагменте не найдено известных признаков опасной интерполяции.");
    evidence.push("Это эвристический анализ фрагмента, а не доказательство безопасности всего приложения.");
    return { passed: true, message: "Базовая статическая проверка прошла: запрос выглядит параметризованным.", evidence };
  }

  return {
    passed: false,
    message: "Исправление не подтверждено. Передавайте пользовательские значения отдельно от SQL-строки.",
    evidence
  };
}
