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
    objectives: ["Найти SQL-конкатенацию", "Заменить её параметризованным запросом", "Проверить отсутствие опасного запроса"],
    vulnerableCode: "const query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";\ndb.query(query);",
    fixedCode: "db.query(\"SELECT * FROM users WHERE name = ?\", [username]);",
    explanation: "Передавайте SQL и значения отдельно через параметры драйвера.", mitigation: "Передавайте SQL и значения отдельно через параметры драйвера."
  },
  {
    id: "xss-reflected", title: "Reflected XSS", level: "Начальный",
    summary: "Отражённый ввод становится HTML-контентом ответа.",
    objectives: ["Проследить ввод до HTML-ответа", "Экранировать значение для HTML-контекста", "Проверить безопасный вывод"],
    vulnerableCode: "res.send(\"<p>Search: \" + req.query.q + \"</p>\");",
    fixedCode: "res.send(\"<p>Search: \" + escapeHtml(String(req.query.q ?? \"\")) + \"</p>\");",
    explanation: "Кодируйте значение для конкретного HTML-контекста.", mitigation: "Кодируйте значение для конкретного HTML-контекста."
  },
  {
    id: "xss-stored", title: "Stored XSS", level: "Начальный",
    summary: "Сохранённый пользовательский текст остаётся опасным при отображении.",
    objectives: ["Найти отображение сохранённого контента", "Заменить опасный DOM sink", "Проверить отображение сохранённых данных"],
    vulnerableCode: "element.innerHTML = comment.body;",
    fixedCode: "element.textContent = comment.body;",
    explanation: "Сохранённые данные тоже недоверенные: используйте безопасный DOM sink.", mitigation: "Сохранённые данные тоже недоверенные: используйте безопасный DOM sink."
  },
  {
    id: "xss-dom", title: "DOM-based XSS", level: "Средний",
    summary: "Данные из URL напрямую интерпретируются как HTML.",
    objectives: ["Определить источник данных из URL", "Использовать безопасный DOM API", "Проверить отсутствие HTML-интерпретации"],
    vulnerableCode: "result.innerHTML = location.hash.slice(1);",
    fixedCode: "result.textContent = location.hash.slice(1);",
    explanation: "Не вставляйте URL-ввод в innerHTML.", mitigation: "Не вставляйте URL-ввод в innerHTML."
  },
  {
    id: "csrf", title: "CSRF", level: "Средний",
    summary: "Браузер автоматически прикладывает cookie к запросу изменения состояния.",
    objectives: ["Найти изменяющий состояние маршрут", "Добавить CSRF-проверку", "Проверить отклонение запроса без токена"],
    vulnerableCode: "app.post(\"/email\", requireLogin, updateEmail);",
    fixedCode: "app.post(\"/email\", requireLogin, verifyCsrfToken, updateEmail);",
    explanation: "Защищайте изменяющие состояние действия CSRF-токеном и подходящими cookie.", mitigation: "Защищайте изменяющие состояние действия CSRF-токеном и подходящими cookie."
  },
  {
    id: "idor", title: "IDOR / BOLA", level: "Средний",
    summary: "ID объекта из запроса не доказывает право пользователя на него.",
    objectives: ["Найти объект, загружаемый по ID", "Ограничить выборку текущим владельцем", "Проверить отказ в доступе к чужому объекту"],
    vulnerableCode: "const doc = await db.document.findUnique({ where: { id: req.params.id } });",
    fixedCode: "const doc = await db.document.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });",
    explanation: "Проверяйте владение объектом на сервере при каждом запросе.", mitigation: "Проверяйте владение объектом на сервере при каждом запросе."
  },
  {
    id: "broken-access-control", title: "Broken Access Control", level: "Средний",
    summary: "Скрытая кнопка не является контролем доступа.",
    objectives: ["Найти административный маршрут", "Добавить серверную проверку роли", "Проверить запрет для обычного пользователя"],
    vulnerableCode: "app.delete(\"/admin/users/:id\", deleteUser);",
    fixedCode: "app.delete(\"/admin/users/:id\", requireRole(\"admin\"), deleteUser);",
    explanation: "Проверяйте роль или policy на сервере для каждого защищённого действия.", mitigation: "Проверяйте роль или policy на сервере для каждого защищённого действия."
  },
  {
    id: "broken-authentication", title: "Broken Authentication", level: "Начальный",
    summary: "Сравнение пароля с хранимым открытым текстом создаёт риск утечки.",
    objectives: ["Найти прямое сравнение паролей", "Проверять стойкий хеш пароля", "Проверить корректный путь аутентификации"],
    vulnerableCode: "if (password === user.password) return createSession(user);",
    fixedCode: "if (await argon2.verify(user.passwordHash, password)) return createSession(user);",
    explanation: "Храните стойкий password hash и используйте проверенную библиотеку.", mitigation: "Храните стойкий password hash и используйте проверенную библиотеку."
  },
  {
    id: "session-fixation", title: "Session Fixation", level: "Средний",
    summary: "Старая сессия сохраняется после успешного входа.",
    objectives: ["Определить момент создания сессии", "Регенерировать сессию после входа", "Проверить смену идентификатора"],
    vulnerableCode: "if (validPassword) { req.session.userId = user.id; }",
    fixedCode: "if (validPassword) { await req.session.regenerate(); req.session.userId = user.id; }",
    explanation: "Регенерируйте идентификатор сессии после аутентификации.", mitigation: "Регенерируйте идентификатор сессии после аутентификации."
  },
  {
    id: "password-reset", title: "Password Reset", level: "Средний",
    summary: "Постоянный токен восстановления можно использовать повторно.",
    objectives: ["Найти токен восстановления", "Добавить случайность, срок действия и одноразовость", "Проверить повторное использование токена"],
    vulnerableCode: "const token = user.resetToken;",
    fixedCode: "const token = await createRandomExpiringSingleUseToken(user.id);",
    explanation: "Используйте случайный одноразовый токен с коротким сроком действия.", mitigation: "Используйте случайный одноразовый токен с коротким сроком действия."
  },
  {
    id: "ssrf", title: "SSRF", level: "Продвинутый",
    summary: "Сервер запрашивает адрес, полностью контролируемый пользователем.",
    objectives: ["Проследить пользовательский URL до сетевого запроса", "Проверить разрешённое назначение", "Проверить блокировку внутренних адресов"],
    vulnerableCode: "return fetch(req.body.url);",
    fixedCode: "const url = validateAllowlistedHttpsUrl(req.body.url); return fetch(url);",
    explanation: "Разрешайте только ожидаемые назначения и блокируйте внутренние адреса на сетевом уровне.", mitigation: "Разрешайте только ожидаемые назначения и блокируйте внутренние адреса на сетевом уровне."
  },
  {
    id: "path-traversal", title: "Path Traversal", level: "Средний",
    summary: "Пользовательский путь может выйти за каталог файлов.",
    objectives: ["Найти путь из пользовательского ввода", "Ограничить путь фиксированным каталогом", "Проверить отказ при выходе за корень"],
    vulnerableCode: "return readFile(join(uploadDir, req.query.file));",
    fixedCode: "const path = resolve(uploadDir, basename(String(req.query.file))); return readFile(path);",
    explanation: "Ограничивайте операции фиксированным корнем и проверяйте итоговый путь.", mitigation: "Ограничивайте операции фиксированным корнем и проверяйте итоговый путь."
  },
  {
    id: "file-upload", title: "Unrestricted File Upload", level: "Средний",
    summary: "Оригинальное имя и расширение файла считаются доверенными.",
    objectives: ["Найти доверие к имени и типу файла", "Проверить содержимое и генерировать имя", "Проверить хранение вне web-root"],
    vulnerableCode: "await file.toFile(join(publicDir, file.filename));",
    fixedCode: "const name = randomUUID(); await saveValidatedFileOutsideWebRoot(file, name);",
    explanation: "Проверяйте содержимое, размер, тип и генерируйте имя на сервере.", mitigation: "Проверяйте содержимое, размер, тип и генерируйте имя на сервере."
  },
  {
    id: "command-injection", title: "OS Command Injection", level: "Продвинутый",
    summary: "Пользовательский ввод попадает в shell-команду.",
    objectives: ["Найти строковую сборку shell-команды", "Использовать запуск без shell и фиксированные аргументы", "Проверить ввод со спецсимволами"],
    vulnerableCode: "exec(\"convert \" + req.body.filename);",
    fixedCode: "execFile(\"convert\", [validatedPath], { shell: false });",
    explanation: "Избегайте shell-интерпретации; используйте фиксированную программу и аргументы.", mitigation: "Избегайте shell-интерпретации; используйте фиксированную программу и аргументы."
  },
  {
    id: "xxe", title: "XXE", level: "Продвинутый",
    summary: "XML-парсер может разрешать внешние сущности.",
    objectives: ["Проверить настройки XML parser", "Отключить DTD и внешние сущности", "Проверить безопасный разбор XML"],
    vulnerableCode: "parseXml(xml, { processEntities: true });",
    fixedCode: "parseXml(xml, { disableDoctype: true, externalEntities: false });",
    explanation: "Отключайте DTD и внешние сущности в XML-парсере.", mitigation: "Отключайте DTD и внешние сущности в XML-парсере."
  },
  {
    id: "ssti", title: "SSTI", level: "Продвинутый",
    summary: "Ввод пользователя используется как исходный текст шаблона.",
    objectives: ["Найти шаблон, управляемый пользователем", "Использовать фиксированный шаблон и данные", "Проверить, что ввод не интерпретируется как шаблон"],
    vulnerableCode: "renderTemplate(req.body.template, data);",
    fixedCode: "renderTemplate(\"welcome\", { name: String(req.body.name) });",
    explanation: "Выбирайте шаблоны из приложения, передавайте ввод только как данные.", mitigation: "Выбирайте шаблоны из приложения, передавайте ввод только как данные."
  },
  {
    id: "open-redirect", title: "Open Redirect", level: "Начальный",
    summary: "Параметр redirect может увести пользователя на произвольный сайт.",
    objectives: ["Найти redirect, управляемый запросом", "Разрешить только локальные/allowlist назначения", "Проверить отказ для внешнего адреса"],
    vulnerableCode: "res.redirect(String(req.query.next));",
    fixedCode: "res.redirect(allowedLocalPath(req.query.next) ?? \"/\");",
    explanation: "Разрешайте только безопасные локальные пути или строгий allowlist.", mitigation: "Разрешайте только безопасные локальные пути или строгий allowlist."
  },
  {
    id: "cors", title: "Misconfigured CORS", level: "Средний",
    summary: "Любой Origin отражается в ответе с разрешением credentials.",
    objectives: ["Проверить отражение Origin", "Ввести точный allowlist origin", "Проверить отказ для неизвестного origin"],
    vulnerableCode: "res.header(\"Access-Control-Allow-Origin\", req.headers.origin).header(\"Access-Control-Allow-Credentials\", \"true\");",
    fixedCode: "if (allowedOrigins.has(origin)) res.header(\"Access-Control-Allow-Origin\", origin);",
    explanation: "Используйте точный allowlist и не сочетайте wildcard с credentials.", mitigation: "Используйте точный allowlist и не сочетайте wildcard с credentials."
  },
  {
    id: "clickjacking", title: "Clickjacking", level: "Начальный",
    summary: "Страница разрешает встраивание в произвольный iframe.",
    objectives: ["Проверить возможность iframe-встраивания", "Настроить frame-ancestors", "Проверить браузерное ограничение встраивания"],
    vulnerableCode: "res.sendFile(\"account.html\");",
    fixedCode: "res.setHeader(\"Content-Security-Policy\", \"frame-ancestors 'none'\"); res.sendFile(\"account.html\");",
    explanation: "Ограничьте встраивание через CSP frame-ancestors.", mitigation: "Ограничьте встраивание через CSP frame-ancestors."
  },
  {
    id: "security-headers", title: "Security Headers", level: "Начальный",
    summary: "Ответ не задаёт базовые браузерные ограничения.",
    objectives: ["Проверить защитные HTTP-заголовки", "Настроить CSP и связанные заголовки", "Проверить заголовки ответа"],
    vulnerableCode: "app.use((req, res, next) => next());",
    fixedCode: "app.use(helmet());",
    explanation: "Настройте CSP и другие заголовки под приложение, не включая их вслепую.", mitigation: "Настройте CSP и другие заголовки под приложение, не включая их вслепую."
  },
  {
    id: "secrets-exposure", title: "Secrets Exposure", level: "Начальный",
    summary: "Секрет встроен в код, который попадёт в репозиторий/бандл.",
    objectives: ["Найти секрет в исходном коде", "Перенести секрет в серверную конфигурацию", "Проверить отсутствие секрета в клиентском коде"],
    vulnerableCode: "const apiKey = \"prod-secret-123\";",
    fixedCode: "const apiKey = process.env.API_KEY;",
    explanation: "Храните секреты в серверной конфигурации и не отдавайте их клиенту.", mitigation: "Храните секреты в серверной конфигурации и не отдавайте их клиенту."
  },
  {
    id: "sensitive-data", title: "Sensitive Data Exposure", level: "Средний",
    summary: "API возвращает всю запись пользователя, включая секретные поля.",
    objectives: ["Определить лишние поля в API-ответе", "Формировать ответ через DTO allowlist", "Проверить отсутствие чувствительных полей"],
    vulnerableCode: "return res.json(user);",
    fixedCode: "return res.json({ id: user.id, name: user.name, email: user.email });",
    explanation: "Формируйте ответ через явный DTO allowlist.", mitigation: "Формируйте ответ через явный DTO allowlist."
  },
  {
    id: "jwt-validation", title: "JWT Validation", level: "Средний",
    summary: "Токен декодируется без проверки подписи и claims.",
    objectives: ["Найти декодирование без верификации JWT", "Проверять подпись и обязательные claims", "Проверить отказ для неверного токена"],
    vulnerableCode: "const claims = jwt.decode(token);",
    fixedCode: "const claims = jwt.verify(token, publicKey, { algorithms: [\"RS256\"], issuer, audience });",
    explanation: "Проверяйте подпись, алгоритм, issuer, audience и срок действия.", mitigation: "Проверяйте подпись, алгоритм, issuer, audience и срок действия."
  },
  {
    id: "mass-assignment", title: "Mass Assignment", level: "Средний",
    summary: "Весь объект запроса напрямую обновляет модель.",
    objectives: ["Найти прямую передачу req.body в update", "Разрешить только изменяемые поля", "Проверить отказ для запрещённых полей"],
    vulnerableCode: "await db.user.update({ where: { id }, data: req.body });",
    fixedCode: "const { displayName } = schema.parse(req.body); await db.user.update({ where: { id }, data: { displayName } });",
    explanation: "Разрешайте только поля, которые пользователь вправе менять.", mitigation: "Разрешайте только поля, которые пользователь вправе менять."
  },
  {
    id: "rate-limiting", title: "Missing Rate Limiting", level: "Начальный",
    summary: "Endpoint входа принимает неограниченное число попыток.",
    objectives: ["Найти чувствительный endpoint без лимита", "Добавить rate limit", "Проверить поведение при серии запросов"],
    vulnerableCode: "app.post(\"/login\", loginHandler);",
    fixedCode: "app.post(\"/login\", rateLimit({ max: 5, timeWindow: \"1 minute\" }), loginHandler);",
    explanation: "Ограничивайте частоту чувствительных операций и дополняйте мониторингом.", mitigation: "Ограничивайте частоту чувствительных операций и дополняйте мониторингом."
  },
  {
    id: "business-logic", title: "Business Logic Flaw", level: "Средний",
    summary: "Клиент сам определяет цену заказа.",
    objectives: ["Найти доверие к цене из клиента", "Пересчитывать сумму на сервере", "Проверить, что подмена цены не влияет на итог"],
    vulnerableCode: "const total = Number(req.body.total);",
    fixedCode: "const total = await calculateCartTotalFromCatalog(req.user.id, req.body.items);",
    explanation: "Суммы, права и переходы состояний пересчитывайте на сервере.", mitigation: "Суммы, права и переходы состояний пересчитывайте на сервере."
  },
  {
    id: "prototype-pollution", title: "Prototype Pollution", level: "Продвинутый",
    summary: "Слияние недоверенного объекта может менять prototype.",
    objectives: ["Найти слияние недоверенного объекта", "Фильтровать ключи по allowlist", "Проверить блокировку опасных ключей"],
    vulnerableCode: "const config = Object.assign({}, defaults, JSON.parse(input));",
    fixedCode: "const config = pickAllowedKeys(JSON.parse(input), [\"theme\", \"locale\"]);",
    explanation: "Используйте allowlist ключей и безопасные структуры для недоверенных объектов.", mitigation: "Используйте allowlist ключей и безопасные структуры для недоверенных объектов."
  },
  {
    id: "nosql-injection", title: "NoSQL Injection", level: "Средний",
    summary: "Объект запроса напрямую становится фильтром MongoDB.",
    objectives: ["Найти объектный фильтр из пользовательского ввода", "Проверять типы и запретить операторы", "Проверить, что ввод не меняет структуру запроса"],
    vulnerableCode: "users.findOne({ email: req.body.email, password: req.body.password });",
    fixedCode: "users.findOne({ email: String(req.body.email), passwordHash: storedHash });",
    explanation: "Принимайте ожидаемые типы, не позволяйте клиенту задавать операторы запросов.", mitigation: "Принимайте ожидаемые типы, не позволяйте клиенту задавать операторы запросов."
  },
  {
    id: "ldap-injection", title: "LDAP Injection", level: "Продвинутый",
    summary: "Ввод пользователя встраивается в LDAP filter.",
    objectives: ["Найти LDAP-фильтр с конкатенацией", "Экранировать специальные LDAP-символы", "Проверить, что ввод остаётся значением"],
    vulnerableCode: "const filter = \"(uid=\" + username + \")\";",
    fixedCode: "const filter = \"(uid=\" + escapeLdapFilter(username) + \")\";",
    explanation: "Экранируйте специальные символы по правилам LDAP и используйте API библиотеки.", mitigation: "Экранируйте специальные символы по правилам LDAP и используйте API библиотеки."
  },
  {
    id: "insecure-deserialization", title: "Insecure Deserialization", level: "Продвинутый",
    summary: "Недоверенные данные восстанавливаются как исполняемый объект.",
    objectives: ["Найти десериализацию недоверенного объекта", "Использовать простой формат и проверку схемы", "Проверить отказ для данных неверной формы"],
    vulnerableCode: "const value = deserialize(req.body.payload);",
    fixedCode: "const value = JSON.parse(req.body.payload); validateSchema(value);",
    explanation: "Предпочитайте простой формат данных и проверяйте схему после разбора.", mitigation: "Предпочитайте простой формат данных и проверяйте схему после разбора."
  }
];

export function getLesson(id: string): Lesson | undefined {
  return lessons.find((lesson) => lesson.id === id);
}
