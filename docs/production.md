# Production runtime

Build the frontend and backend from the repository root:

    npm install
    npm run build
    NODE_ENV=production npm start

The API server serves the compiled frontend from `frontend/dist` and the API under `/api`. The production runtime smoke test in GitHub Actions checks the home page, an asset, SPA fallback, and an unknown API route.

The service currently stores learning progress and chat history in a shared local SQLite database and does not provide user accounts. Keep the API on loopback (the default). Production startup intentionally refuses a non-loopback API bind. If browser access from other devices is required, place an authenticated reverse proxy on the same host; do not expose port 3001 directly.

Before using this as a multi-user hosted service, add user authentication and scope progress, chat history, and lab sessions by user. The AI Security category labs are deterministic teaching fixtures; live model evaluation is a separate opt-in feature and does not replace adversarial evaluation of a real application.
