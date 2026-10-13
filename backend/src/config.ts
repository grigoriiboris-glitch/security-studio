import "dotenv/config";

function envNumber(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) return fallback;
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : fallback;
}

export const config = {
  apiHost: process.env.API_HOST ?? "127.0.0.1",
  apiPort: envNumber("API_PORT", 3001),
  openCodeApiKey: process.env.OPENCODE_GO_API_KEY ?? "",
  openCodeBaseUrl: process.env.OPENCODE_GO_BASE_URL ?? "https://opencode.ai/zen/go/v1",
  model: process.env.OPENCODE_GO_MODEL ?? "mimo-v2.6-flash",
  labsImage: process.env.SECURITY_LABS_IMAGE ?? "security-labs:dev",
  allowedOrigins: new Set(
    (process.env.SECURITY_STUDIO_ALLOWED_ORIGINS ?? "http://127.0.0.1:5173,http://localhost:5173")
      .split(",").map((origin) => origin.trim()).filter(Boolean)
  )
};

export function assertSafeApiBind(host: string = config.apiHost, nodeEnv: string | undefined = process.env.NODE_ENV): void {
  if (nodeEnv === "production" && !["127.0.0.1", "::1", "localhost"].includes(host)) {
    throw new Error("Security Studio API must bind to loopback in production. Use a same-host reverse proxy for external access.");
  }
}
