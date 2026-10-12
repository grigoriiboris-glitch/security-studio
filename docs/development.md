# Разработка и запуск

Требования: Node.js 22.12+, npm 10+, Docker Engine. Для AI нужен OpenCode Go API key.

    cp .env.example .env
    # Укажите OPENCODE_GO_API_KEY в .env
    npm install
    npm run dev

Frontend: http://127.0.0.1:5173  
API health: http://127.0.0.1:3001/api/healthz

Собрать образ учебной среды:

    docker build -f labs/Dockerfile -t security-labs:dev labs

Проверки:

    npm run lint
    npm run typecheck
    npm test
    npm run build

Без Docker открывается UI и работают code-check/API health; запуск лаборатории вернёт понятную ошибку. Без API key AI отвечает конфигурационной ошибкой. Не запускайте Juice Shop и NodeGoat параллельно: backend держит не больше одного учебного контейнера.
