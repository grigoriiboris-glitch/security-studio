# Разработка и запуск

Требования: Node.js 22.12+, npm 10+, Docker Engine. Для AI нужен OpenCode Go API key.

    cp .env.example .env
    # Укажите OPENCODE_GO_API_KEY в .env
    npm install
    npm run dev

Frontend: http://127.0.0.1:5173  
API health: http://127.0.0.1:3001/api/healthz

В проекте зарегистрировано 30 уроков. Учебный код сохраняется раздельно по ID в `data/workspaces/<lesson-id>/solution.js`, отдельно от исходников OWASP-лабораторий. В UI можно выбрать урок, загрузить/сохранить решение, проверить его и сбросить активную лабораторию. Чтобы использовать другую локальную папку, задайте `SECURITY_STUDIO_WORKSPACE_DIR` для backend. Клиент может сохранить только фиксированный файл урока; передать произвольный путь через API нельзя.

Собрать образ учебной среды:

    docker build -f labs/Dockerfile -t security-labs:dev labs

Полная локальная проверка одним вызовом (lint, типизация, API/unit-тесты, production build и браузерные E2E):

    npx playwright install chromium
    npm run verify

Если браузер Chromium уже установлен, повторно запускать первую команду не нужно. Отдельные проверки доступны независимо: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`, `npm run test:e2e`.

Без Docker открывается UI и работают code-check/API health; запуск лаборатории вернёт понятную ошибку. Без API key AI отвечает конфигурационной ошибкой. Не запускайте Juice Shop и NodeGoat параллельно: backend держит не больше одного учебного контейнера.

Live AI Security evaluation отключён по умолчанию. Для явного включения задайте `AI_SECURITY_LIVE_TESTS_ENABLED=true`, `AI_SECURITY_LIVE_TESTS_TOKEN` (длинный случайный секрет) и `OPENCODE_GO_API_KEY`. Передавайте токен только заголовком `Authorization: Bearer …`; не публикуйте его в репозитории, frontend или логах. В `.env.example` секрет оставлен пустым. Проверки используют только фиксированные синтетические кейсы.
