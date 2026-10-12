import { buildApp } from "./app.js";
import { config } from "./config.js";

const app = buildApp();
try {
  await app.listen({ host: config.apiHost, port: config.apiPort });
  app.log.info("Security Studio API listening on " + config.apiHost + ":" + config.apiPort);
} catch (error) {
  app.log.error(error);
  process.exitCode = 1;
}
