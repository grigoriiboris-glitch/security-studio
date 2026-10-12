export type Lesson = {
  id: "sql-injection";
  title: string;
  level: string;
  summary: string;
  objectives: string[];
  vulnerableCode: string;
  fixedCode: string;
  explanation: string;
};

export const lessons: Lesson[] = [{
  id: "sql-injection",
  title: "SQL Injection",
  level: "Начальный",
  summary: "Изучите, как конкатенация пользовательского ввода меняет SQL-запрос, и проверьте исправление параметризацией.",
  objectives: [
    "Найти передачу пользовательского ввода в SQL",
    "Отличить конкатенацию от параметризованного запроса",
    "Подтвердить исправление независимой проверкой"
  ],
  vulnerableCode: [
    "async function findUser(username, db) {",
    "  const query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";",
    "  return db.query(query);",
    "}"
  ].join("\n"),
  fixedCode: [
    "async function findUser(username, db) {",
    "  const query = \"SELECT * FROM users WHERE name = ?\";",
    "  return db.query(query, [username]);",
    "}"
  ].join("\n"),
  explanation: "При конкатенации ввод может стать частью SQL-синтаксиса. Параметризованный драйвер передаёт шаблон запроса и значение отдельно."
}];
