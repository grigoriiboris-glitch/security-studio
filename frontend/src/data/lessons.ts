export type LessonId = "sql-injection" | "xss-reflected" | "xss-stored" | "xss-dom" | "csrf" | "idor" | "broken-access-control" | "broken-authentication" | "session-fixation" | "password-reset" | "ssrf" | "path-traversal" | "file-upload" | "command-injection" | "xxe" | "ssti" | "open-redirect" | "cors" | "clickjacking" | "security-headers" | "secrets-exposure" | "sensitive-data" | "jwt-validation" | "mass-assignment" | "rate-limiting" | "business-logic" | "prototype-pollution" | "nosql-injection" | "ldap-injection" | "insecure-deserialization";

export type Lesson = {
  id: LessonId;
  title: string;
  level: string;
  summary: string;
  objectives: string[];
  vulnerableCode: string;
  fixedCode: string;
  explanation: string;
  mitigation: string;
};

export const lessons: Lesson[] = [
  {
    id: "sql-injection", title: "SQL Injection", level: "Начальный",
    summary: "Конкатенация пользовательского ввода меняет структуру SQL-запроса.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\ndb.query(query);",
    fixedCode: "db.query(\"SELECT * FROM users WHERE name = ?\", [username]);",
    explanation: "Передавайте SQL и значения отдельно через параметры драйвера.", mitigation: "Параметризация SQL"
  },
  {
    id: "xss-reflected", title: "Reflected XSS", level: "Начальный",
    summary: "Отражённый ввод становится HTML-контентом ответа.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "res.send(\"<p>Search: \" + req.query.q + \"</p>\");",
    fixedCode: "res.send(\"<p>Search: \" + escapeHtml(String(req.query.q ?? \"\")) + \"</p>\");",
    explanation: "Кодируйте значение для конкретного HTML-контекста.", mitigation: "Контекстное кодирование"
  },
  {
    id: "xss-stored", title: "Stored XSS", level: "Начальный",
    summary: "Сохранённый пользовательский текст остаётся опасным при отображении.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "element.innerHTML = comment.body;",
    fixedCode: "element.textContent = comment.body;",
    explanation: "Сохранённые данные тоже недоверенные: используйте безопасный DOM sink.", mitigation: "Безопасный вывод"
  },
  {
    id: "xss-dom", title: "DOM-based XSS", level: "Средний",
    summary: "Данные из URL напрямую интерпретируются как HTML.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "result.innerHTML = location.hash.slice(1);",
    fixedCode: "result.textContent = location.hash.slice(1);",
    explanation: "Не вставляйте URL-ввод в innerHTML.", mitigation: "Безопасный DOM API"
  },
  {
    id: "csrf", title: "CSRF", level: "Средний",
    summary: "Браузер автоматически прикладывает cookie к запросу изменения состояния.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "app.post(\"/email\", requireLogin, updateEmail);",
    fixedCode: "app.post(\"/email\", requireLogin, verifyCsrfToken, updateEmail);",
    explanation: "Защищайте изменяющие состояние действия CSRF-токеном и подходящими cookie.", mitigation: "CSRF-токен"
  },
  {
    id: "idor", title: "IDOR / BOLA", level: "Средний",
    summary: "ID объекта из запроса не доказывает право пользователя на него.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const doc = await db.document.findUnique({ where: { id: req.params.id } });",
    fixedCode: "const doc = await db.document.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });",
    explanation: "Проверяйте владение объектом на сервере при каждом запросе.", mitigation: "Проверка владельца"
  },
  {
    id: "broken-access-control", title: "Broken Access Control", level: "Средний",
    summary: "Скрытая кнопка не является контролем доступа.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "app.delete(\"/admin/users/:id\", deleteUser);",
    fixedCode: "app.delete(\"/admin/users/:id\", requireRole(\"admin\"), deleteUser);",
    explanation: "Проверяйте роль или policy на сервере для каждого защищённого действия.", mitigation: "Серверная авторизация"
  },
  {
    id: "broken-authentication", title: "Broken Authentication", level: "Начальный",
    summary: "Сравнение пароля с хранимым открытым текстом создаёт риск утечки.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "if (password === user.password) return createSession(user);",
    fixedCode: "if (await argon2.verify(user.passwordHash, password)) return createSession(user);",
    explanation: "Храните стойкий password hash и используйте проверенную библиотеку.", mitigation: "Безопасная проверка пароля"
  },
  {
    id: "session-fixation", title: "Session Fixation", level: "Средний",
    summary: "Старая сессия сохраняется после успешного входа.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "if (validPassword) { req.session.userId = user.id; }",
    fixedCode: "if (validPassword) { await req.session.regenerate(); req.session.userId = user.id; }",
    explanation: "Регенерируйте идентификатор сессии после аутентификации.", mitigation: "Ротация сессии"
  },
  {
    id: "password-reset", title: "Password Reset", level: "Средний",
    summary: "Постоянный токен восстановления можно использовать повторно.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const token = user.resetToken;",
    fixedCode: "const token = await createRandomExpiringSingleUseToken(user.id);",
    explanation: "Используйте случайный одноразовый токен с коротким сроком действия.", mitigation: "Одноразовый токен"
  },
  {
    id: "ssrf", title: "SSRF", level: "Продвинутый",
    summary: "Сервер запрашивает адрес, полностью контролируемый пользователем.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "return fetch(req.body.url);",
    fixedCode: "const url = validateAllowlistedHttpsUrl(req.body.url); return fetch(url);",
    explanation: "Разрешайте только ожидаемые назначения и блокируйте внутренние адреса на сетевом уровне.", mitigation: "Allowlist назначения"
  },
  {
    id: "path-traversal", title: "Path Traversal", level: "Средний",
    summary: "Пользовательский путь может выйти за каталог файлов.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "return readFile(join(uploadDir, req.query.file));",
    fixedCode: "const path = resolve(uploadDir, basename(String(req.query.file))); return readFile(path);",
    explanation: "Ограничивайте операции фиксированным корнем и проверяйте итоговый путь.", mitigation: "Ограничение пути"
  },
  {
    id: "file-upload", title: "Unrestricted File Upload", level: "Средний",
    summary: "Оригинальное имя и расширение файла считаются доверенными.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "await file.toFile(join(publicDir, file.filename));",
    fixedCode: "const name = randomUUID(); await saveValidatedFileOutsideWebRoot(file, name);",
    explanation: "Проверяйте содержимое, размер, тип и генерируйте имя на сервере.", mitigation: "Безопасная загрузка"
  },
  {
    id: "command-injection", title: "OS Command Injection", level: "Продвинутый",
    summary: "Пользовательский ввод попадает в shell-команду.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "exec(\"convert \" + req.body.filename);",
    fixedCode: "execFile(\"convert\", [validatedPath], { shell: false });",
    explanation: "Избегайте shell-интерпретации; используйте фиксированную программу и аргументы.", mitigation: "Вызов без shell"
  },
  {
    id: "xxe", title: "XXE", level: "Продвинутый",
    summary: "XML-парсер может разрешать внешние сущности.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "parseXml(xml, { processEntities: true });",
    fixedCode: "parseXml(xml, { disableDoctype: true, externalEntities: false });",
    explanation: "Отключайте DTD и внешние сущности в XML-парсере.", mitigation: "Безопасный XML parser"
  },
  {
    id: "ssti", title: "SSTI", level: "Продвинутый",
    summary: "Ввод пользователя используется как исходный текст шаблона.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "renderTemplate(req.body.template, data);",
    fixedCode: "renderTemplate(\"welcome\", { name: String(req.body.name) });",
    explanation: "Выбирайте шаблоны из приложения, передавайте ввод только как данные.", mitigation: "Фиксированный шаблон"
  },
  {
    id: "open-redirect", title: "Open Redirect", level: "Начальный",
    summary: "Параметр redirect может увести пользователя на произвольный сайт.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "res.redirect(String(req.query.next));",
    fixedCode: "res.redirect(allowedLocalPath(req.query.next) ?? \"/\");",
    explanation: "Разрешайте только безопасные локальные пути или строгий allowlist.", mitigation: "Проверка redirect"
  },
  {
    id: "cors", title: "Misconfigured CORS", level: "Средний",
    summary: "Любой Origin отражается в ответе с разрешением credentials.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "res.header(\"Access-Control-Allow-Origin\", req.headers.origin).header(\"Access-Control-Allow-Credentials\", \"true\");",
    fixedCode: "if (allowedOrigins.has(origin)) res.header(\"Access-Control-Allow-Origin\", origin);",
    explanation: "Используйте точный allowlist и не сочетайте wildcard с credentials.", mitigation: "Точный allowlist"
  },
  {
    id: "clickjacking", title: "Clickjacking", level: "Начальный",
    summary: "Страница разрешает встраивание в произвольный iframe.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "res.sendFile(\"account.html\");",
    fixedCode: "res.setHeader(\"Content-Security-Policy\", \"frame-ancestors 'none'\"); res.sendFile(\"account.html\");",
    explanation: "Ограничьте встраивание через CSP frame-ancestors.", mitigation: "Защита от iframe"
  },
  {
    id: "security-headers", title: "Security Headers", level: "Начальный",
    summary: "Ответ не задаёт базовые браузерные ограничения.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "app.use((req, res, next) => next());",
    fixedCode: "app.use(helmet());",
    explanation: "Настройте CSP и другие заголовки под приложение, не включая их вслепую.", mitigation: "HTTP security headers"
  },
  {
    id: "secrets-exposure", title: "Secrets Exposure", level: "Начальный",
    summary: "Секрет встроен в код, который попадёт в репозиторий/бандл.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const apiKey = \"prod-secret-123\";",
    fixedCode: "const apiKey = process.env.API_KEY;",
    explanation: "Храните секреты в серверной конфигурации и не отдавайте их клиенту.", mitigation: "Секрет из env"
  },
  {
    id: "sensitive-data", title: "Sensitive Data Exposure", level: "Средний",
    summary: "API возвращает всю запись пользователя, включая секретные поля.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "return res.json(user);",
    fixedCode: "return res.json({ id: user.id, name: user.name, email: user.email });",
    explanation: "Формируйте ответ через явный DTO allowlist.", mitigation: "Минимальный DTO"
  },
  {
    id: "jwt-validation", title: "JWT Validation", level: "Средний",
    summary: "Токен декодируется без проверки подписи и claims.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const claims = jwt.decode(token);",
    fixedCode: "const claims = jwt.verify(token, publicKey, { algorithms: [\"RS256\"], issuer, audience });",
    explanation: "Проверяйте подпись, алгоритм, issuer, audience и срок действия.", mitigation: "Полная проверка JWT"
  },
  {
    id: "mass-assignment", title: "Mass Assignment", level: "Средний",
    summary: "Весь объект запроса напрямую обновляет модель.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "await db.user.update({ where: { id }, data: req.body });",
    fixedCode: "const { displayName } = schema.parse(req.body); await db.user.update({ where: { id }, data: { displayName } });",
    explanation: "Разрешайте только поля, которые пользователь вправе менять.", mitigation: "Allowlist полей"
  },
  {
    id: "rate-limiting", title: "Missing Rate Limiting", level: "Начальный",
    summary: "Endpoint входа принимает неограниченное число попыток.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "app.post(\"/login\", loginHandler);",
    fixedCode: "app.post(\"/login\", rateLimit({ max: 5, timeWindow: \"1 minute\" }), loginHandler);",
    explanation: "Ограничивайте частоту чувствительных операций и дополняйте мониторингом.", mitigation: "Ограничение частоты"
  },
  {
    id: "business-logic", title: "Business Logic Flaw", level: "Средний",
    summary: "Клиент сам определяет цену заказа.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const total = Number(req.body.total);",
    fixedCode: "const total = await calculateCartTotalFromCatalog(req.user.id, req.body.items);",
    explanation: "Суммы, права и переходы состояний пересчитывайте на сервере.", mitigation: "Серверные инварианты"
  },
  {
    id: "prototype-pollution", title: "Prototype Pollution", level: "Продвинутый",
    summary: "Слияние недоверенного объекта может менять prototype.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const config = Object.assign({}, defaults, JSON.parse(input));",
    fixedCode: "const config = pickAllowedKeys(JSON.parse(input), [\"theme\", \"locale\"]);",
    explanation: "Используйте allowlist ключей и безопасные структуры для недоверенных объектов.", mitigation: "Фильтрация ключей"
  },
  {
    id: "nosql-injection", title: "NoSQL Injection", level: "Средний",
    summary: "Объект запроса напрямую становится фильтром MongoDB.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "users.findOne({ email: req.body.email, password: req.body.password });",
    fixedCode: "users.findOne({ email: String(req.body.email), passwordHash: storedHash });",
    explanation: "Принимайте ожидаемые типы, не позволяйте клиенту задавать операторы запросов.", mitigation: "Типизированный ввод"
  },
  {
    id: "ldap-injection", title: "LDAP Injection", level: "Продвинутый",
    summary: "Ввод пользователя встраивается в LDAP filter.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const filter = \"(uid=\" + username + \")\";",
    fixedCode: "const filter = \"(uid=\" + escapeLdapFilter(username) + \")\";",
    explanation: "Экранируйте специальные символы по правилам LDAP и используйте API библиотеки.", mitigation: "LDAP escaping"
  },
  {
    id: "insecure-deserialization", title: "Insecure Deserialization", level: "Продвинутый",
    summary: "Недоверенные данные восстанавливаются как исполняемый объект.",
    objectives: ["Найти источник недоверенных данных", "Показать риск на учебном примере", "Подтвердить исправление независимой проверкой"],
    vulnerableCode: "const value = deserialize(req.body.payload);",
    fixedCode: "const value = JSON.parse(req.body.payload); validateSchema(value);",
    explanation: "Предпочитайте простой формат данных и проверяйте схему после разбора.", mitigation: undefined
  }
];

export function getLesson(id: string): Lesson | undefined {
  return lessons.find((lesson) => lesson.id === id);
}
