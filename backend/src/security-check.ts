import { type LessonId } from "./lessons.js";

export type SecurityCheckResult = { passed: boolean; message: string; evidence: string[] };
const unsafeConcatenation = /(?:\b(?:select|update|delete|insert)\b[\s\S]{0,400}\+\s*[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*\s*\+[\s\S]{0,400}\b(?:select|update|delete|insert)\b)/i;
const unsafeTemplateInterpolation = /(?:select|update|delete|insert)[\s\S]{0,400}?\x60[^\x60]*\$\{[^}]+\}[^\x60]*\x60/i;
const parameterizedQuery = /(?:query|execute|prepare|all|get|run)\s*\(\s*["'\x60][\s\S]{0,500}?(?:\?|\$\d+|:[a-z_]\w*|@[a-z_]\w*)[\s\S]{0,100}["'\x60]\s*,\s*\[/i;
const explicitPreparedStatement = /\.prepare\s*\(\s*["'\x60][\s\S]{0,500}?["'\x60]\s*\)/i;
function removeComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/.*$/gm, "$1 ");
}
function fail(message: string, evidence: string[]): SecurityCheckResult {
  return { passed: false, message, evidence };
}
export function checkSqlInjectionFix(code: string): SecurityCheckResult {
  if (!code.trim()) return fail("Редактор пуст.", ["Не найден код для проверки."]);
  const source = removeComments(code);
  const unsafeConcat = unsafeConcatenation.test(source);
  const unsafeTemplate = unsafeTemplateInterpolation.test(source);
  const parameterized = parameterizedQuery.test(source) || explicitPreparedStatement.test(source);
  const evidence: string[] = [];
  if (unsafeConcat) evidence.push("Обнаружена конкатенация SQL с динамическим значением.");
  if (unsafeTemplate) evidence.push("Обнаружена интерполяция значения в SQL-шаблон.");
  if (parameterized) evidence.push("Найден признак параметризованного запроса или prepared statement.");
  else evidence.push("Не найден узнаваемый шаблон параметризации.");
  if (!unsafeConcat && !unsafeTemplate && parameterized) {
    evidence.push("В проверенном фрагменте не найдено известных признаков опасной интерполяции.");
    evidence.push("Эвристическая проверка фрагмента не доказывает безопасность всего приложения.");
    return { passed: true, message: "Базовая проверка SQLi пройдена.", evidence };
  }
  return fail("Исправление SQLi не подтверждено: передавайте значения отдельно от SQL.", evidence);
}
type Rule = { safe: RegExp; unsafe: RegExp; safeEvidence: string; unsafeEvidence: string };
const rules: Partial<Record<LessonId, Rule>> = {
  "xss-reflected": { safe: /escapeHtml|encodeHTML|textContent/i, unsafe: /(?:\+\s*req\.(query|params|body)\.[A-Za-z_$][\w$]*\s*\+|\b(?:res|reply)\.(?:send|write|end)\s*\(\s*(?:String\s*\(\s*)?req\.(?:query|params|body)\.[A-Za-z_$][\w$]*)/i, safeEvidence: "Найдено экранирование/безопасный вывод.", unsafeEvidence: "Ввод отражается в HTML-строке или напрямую отправляется в ответ." },
  "xss-stored": { safe: /textContent|escapeHtml|sanitizeHtml/i, unsafe: /innerHTML\s*=\s*[^;]*(comment|post|message|body)/i, safeEvidence: "Найден безопасный sink или санитайзер.", unsafeEvidence: "Сохранённый контент попадает в innerHTML." },
  "xss-dom": { safe: /textContent|createTextNode|sanitizeHtml/i, unsafe: /innerHTML\s*=\s*[^;]*location\./i, safeEvidence: "DOM-значение выводится как текст.", unsafeEvidence: "Источник из URL попадает в innerHTML." },
  csrf: { safe: /verifyCsrfToken|csrfProtection|csrf\.protect/i, unsafe: /app\.(post|put|patch|delete)\s*\((?![^;\n]*(verifyCsrfToken|csrfProtection|csrf\.protect))[^;\n]*(update|change|delete|email|password)/i, safeEvidence: "Найдена CSRF-проверка.", unsafeEvidence: "Изменяющий маршрут без распознаваемой CSRF-защиты." },
  idor: { safe: /ownerId\s*:\s*req\.user\.id|authorizeResource|canAccessResource/i, unsafe: /\b(?:findUnique|findFirst|findOne|findById)\s*\(\s*\{(?![^}]*\bownerId\s*:)[^}]*\b(?:id|_id)\s*:\s*req\.(?:params|query|body)\.id/i, safeEvidence: "Найдено ограничение по владельцу.", unsafeEvidence: "Объект ищется только по ID из запроса." },
  "broken-access-control": { safe: /requireRole\s*\(|authorize\s*\(|checkPermission\s*\(/i, unsafe: /app\.(get|post|put|patch|delete)\s*\(\s*["'][^"']*admin[^"']*["']\s*,\s*(?!\s*(?:requireRole|authorize|checkPermission)\b)/i, safeEvidence: "Найден middleware авторизации.", unsafeEvidence: "Административный маршрут без видимой проверки роли." },
  "broken-authentication": { safe: /argon2\.verify|bcrypt\.compare|scryptVerify|verifyPassword\s*\(/i, unsafe: /password\s*===\s*user\.password|user\.password\s*===\s*password/i, safeEvidence: "Найден verifier хеша пароля.", unsafeEvidence: "Пароль сравнивается напрямую." },
  "session-fixation": { safe: /session\.regenerate|rotateSession|regenerateSession/i, unsafe: /session\.userId\s*=\s*user\.id/i, safeEvidence: "Найдена ротация сессии.", unsafeEvidence: "Сессия назначается без видимой ротации." },
  "password-reset": { safe: /createRandomExpiringSingleUseToken|randomBytes|randomUUID/i, unsafe: /resetToken\s*=\s*user\.resetToken|token\s*=\s*user\.resetToken/i, safeEvidence: "Найден генератор случайного токена; TTL и одноразовость требуют отдельных тестов.", unsafeEvidence: "Используется существующий/предсказуемый токен." },
  ssrf: { safe: /validateAllowlistedHttpsUrl|allowlistedUrl|assertAllowedDestination/i, unsafe: /fetch\s*\(\s*req\.(body|query)\.url|axios\.(get|request)\s*\(\s*req\.(body|query)\.url/i, safeEvidence: "Найден allowlist назначения.", unsafeEvidence: "Сетевой запрос использует URL из ввода напрямую." },
  "path-traversal": { safe: /basename\s*\(|isPathInside|safeResolveWithin/i, unsafe: /\b(?:readFile|createReadStream|sendFile)\s*\(\s*(?:(?:join|resolve)\s*\([^;]{0,200}req\.(?:query|params|body)|req\.(?:query|params|body)\.)/i, safeEvidence: "Найдено ограничение пути.", unsafeEvidence: "Путь строится из пользовательского ввода." },
  "file-upload": { safe: /saveValidatedFileOutsideWebRoot|validateFileContent|randomUUID\s*\(/i, unsafe: /join\s*\(\s*publicDir\s*,\s*file\.(?:filename|originalname|name|path)\b/i, safeEvidence: "Найдена проверка файла/случайное имя/хранение вне web-root.", unsafeEvidence: "Оригинальное имя используется в публичном каталоге." },
  "command-injection": { safe: /execFile\s*\([^;]*shell\s*:\s*false|spawn\s*\([^;]*shell\s*:\s*false/i, unsafe: /\bexec\s*\([^;\n]*req\.(?:body|query|params)\./i, safeEvidence: "Найден запуск без shell.", unsafeEvidence: "В shell-команду конкатенируется ввод." },
  xxe: { safe: /disableDoctype\s*:\s*true|externalEntities\s*:\s*false|resolveExternals\s*:\s*false/i, unsafe: /processEntities\s*:\s*true|externalEntities\s*:\s*true/i, safeEvidence: "Внешние сущности/DTD отключены.", unsafeEvidence: "XML parser разрешает внешние сущности." },
  ssti: { safe: /renderTemplate\s*\(\s*["'][^"']+["']/i, unsafe: /renderTemplate\s*\(\s*req\.body\.template/i, safeEvidence: "Имя шаблона фиксировано.", unsafeEvidence: "Текст шаблона берётся из запроса." },
  "open-redirect": { safe: /allowedLocalPath|isAllowedRedirect|allowedRedirectOrigins/i, unsafe: /redirect\s*\(\s*(String\s*\()?\s*req\.(query|body)\.(next|url|redirect)/i, safeEvidence: "Найден allowlist пути назначения.", unsafeEvidence: "Redirect использует параметр запроса напрямую." },
  cors: { safe: /allowedOrigins\.has|corsAllowlist|isAllowedOrigin/i, unsafe: /Access-Control-Allow-Origin[^\n]{0,100}req\.headers\.origin|origin\s*:\s*req\.headers\.origin/i, safeEvidence: "Origin проверяется по allowlist.", unsafeEvidence: "Origin отражается без проверки." },
  clickjacking: { safe: /frame-ancestors|X-Frame-Options/i, unsafe: /allow-from\s+\*|frame-ancestors\s+[^;]*\*|x-frame-options[^;\n]{0,80}(?:allowall|allow-from)/i, safeEvidence: "Найдено ограничение встраивания.", unsafeEvidence: "Обнаружена небезопасная frame policy." },
  "security-headers": { safe: /helmet\s*\(|Content-Security-Policy|X-Content-Type-Options/i, unsafe: /disable\s*:\s*true|contentSecurityPolicy\s*:\s*false|frameguard\s*:\s*false|hsts\s*:\s*false|xContentTypeOptions\s*:\s*false|referrerPolicy\s*:\s*false/i, safeEvidence: "Найдена настройка security headers.", unsafeEvidence: "Похоже, защитные заголовки отключаются." },
  "secrets-exposure": { safe: /process\.env\.[A-Z0-9_]+|secretStore|vault\./i, unsafe: /(api[_-]?key|secret|password)\s*=\s*["'][A-Za-z0-9_./+=-]{8,}["']/i, safeEvidence: "Секрет читается из серверной конфигурации.", unsafeEvidence: "Похоже на секрет, зашитый в код." },
  "sensitive-data": { safe: /return\s+res\.json\s*\(\s*\{[^}]+(id|name|email)\s*:/i, unsafe: /\b(?:res\.json|reply\.send|res\.send)\s*\(\s*user\s*\)|\bJSON\.stringify\s*\(\s*user\s*\)|return\s+user\s*;/i, safeEvidence: "Ответ формируется через явный DTO.", unsafeEvidence: "API возвращает всю модель пользователя." },
  "jwt-validation": { safe: /jwt\.verify|verifyJwt|validateJwt/i, unsafe: /jwt\.decode\s*\(/i, safeEvidence: "Найдено проверяющее JWT API.", unsafeEvidence: "Токен только декодируется." },
  "mass-assignment": { safe: /schema\.parse|pickAllowedKeys|allowedFields/i, unsafe: /data\s*:\s*req\.body/i, safeEvidence: "Вход проходит schema/allowlist.", unsafeEvidence: "Тело запроса напрямую передаётся в update." },
  "rate-limiting": { safe: /rateLimit\s*\(|rateLimiter|limitLoginAttempts/i, unsafe: /app\.post\s*\(\s*["']\/login["']\s*,\s*loginHandler/i, safeEvidence: "Найдено ограничение частоты.", unsafeEvidence: "Login endpoint использует handler без лимитера." },
  "business-logic": { safe: /calculateCartTotalFromCatalog|calculateServerTotal|recalculateOrder/i, unsafe: /Number\s*\(\s*req\.body\.total\s*\)/i, safeEvidence: "Итог рассчитывается на сервере.", unsafeEvidence: "Итог заказа берётся из клиентского ввода." },
  "prototype-pollution": { safe: /pickAllowedKeys|Object\.create\s*\(\s*null\s*\)|rejectDangerousKeys/i, unsafe: /Object\.assign\s*\(\s*\{\s*\}\s*,[^;]*JSON\.parse|\.\.\.\s*JSON\.parse\s*\(|\b(?:merge|deepMerge|extend)\s*\([^;]*JSON\.parse\s*\(/i, safeEvidence: "Используется allowlist/объект без prototype.", unsafeEvidence: "Недоверенный JSON сливается с обычным объектом." },
  "nosql-injection": { safe: /String\s*\(\s*req\.body\.[A-Za-z_$][\w$]*\s*\)|typeof\s+req\.body\.[A-Za-z_$][\w$]*\s*===?\s*["']string["']/i, unsafe: /findOne\s*\(\s*\{[^}]*:\s*req\.body\.[A-Za-z_$][\w$]*[^}]*\}/i, safeEvidence: "Значение приводится/проверяется как ожидаемый тип.", unsafeEvidence: "Ввод напрямую попадает в NoSQL-фильтр." },
  "ldap-injection": { safe: /escapeLdapFilter|escapeLDAP|ldapEscape/i, unsafe: /(?:uid=|\(uid=)[^;\n]{0,160}\+\s*username\b/i, safeEvidence: "Найдено LDAP escaping.", unsafeEvidence: "LDAP filter строится конкатенацией без escaping." },
  "insecure-deserialization": { safe: /JSON\.parse\s*\([^)]*\)[\s\S]{0,160}validateSchema|validateSchema\s*\(/i, unsafe: /\bdeserialize\s*\(/i, safeEvidence: "Данные валидируются по схеме в безопасном формате.", unsafeEvidence: "Недоверенный ввод передаётся в deserialize()." }
};
export function checkLessonFix(lessonId: LessonId, code: string): SecurityCheckResult {
  if (lessonId === "sql-injection") return checkSqlInjectionFix(code);
  if (!code.trim()) return fail("Редактор пуст. Добавьте код для проверки.", ["Не найден код для проверки."]);
  const rule = rules[lessonId];
  if (!rule) return fail("Для урока не настроено правило проверки.", ["Нет verifier для выбранного урока."]);
  const source = removeComments(code);
  let hasUnsafe = rule.unsafe.test(source);
  if (lessonId === "session-fixation") {
    const rotateAt = source.search(/session\.regenerate|rotateSession|regenerateSession/i);
    const assignAt = source.search(/session\.userId\s*=\s*user\.id/i);
    const rotations = source.match(/session\.regenerate|rotateSession|regenerateSession/gi)?.length ?? 0;
    const assignments = source.match(/session\.userId\s*=\s*user\.id/gi)?.length ?? 0;
    // One rotated session cannot secure an additional assignment in another route.
    if (rotateAt >= 0 && assignAt >= 0 && rotateAt < assignAt && rotations >= assignments) hasUnsafe = false;
  }
  const hasSafe = rule.safe.test(source);
  const evidence = [
    hasSafe ? rule.safeEvidence : "Не найден ожидаемый защитный шаблон.",
    hasUnsafe ? rule.unsafeEvidence : "Определённый опасный шаблон не обнаружен.",
    "Проверка эвристическая и анализирует только предоставленный фрагмент; это не доказательство безопасности."
  ];
  if (hasSafe && !hasUnsafe) return { passed: true, message: "Базовая проверка урока пройдена.", evidence };
  return fail("Исправление не подтверждено. Сопоставьте код с защитным шаблоном и повторите проверку.", evidence);
}
