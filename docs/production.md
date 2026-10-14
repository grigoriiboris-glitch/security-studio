# Production runtime

Build the frontend and backend from the repository root:

    npm install
    npm run build
    NODE_ENV=production npm start

The API server serves the compiled frontend from `frontend/dist` and the API under `/api`. The production runtime smoke test in GitHub Actions checks the home page, an asset, SPA fallback, and an unknown API route.

This project is intended for one person on one local computer, not as a public hosted service. Learning progress and chat history are stored in a local SQLite database; user accounts and multi-user isolation are intentionally out of scope. Keep the API on loopback (the default) and do not expose port 3001 to the internet.

The AI Security category labs are deterministic teaching fixtures. Live model evaluation is a separate opt-in feature and does not replace adversarial evaluation of a real application.

For the full local check suite, install Chromium once with `npx playwright install chromium`, then run `npm run verify` from the repository root.
