import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { httpTargetLessonIds } from "../src/http-lab-targets.js";
import type { LessonId } from "../src/lessons.js";

type FixtureCase = {
  lessonId: LessonId;
  observe: (app: FastifyInstance, base: string) => Promise<boolean>;
};

const request = (app: FastifyInstance, url: string, method: "GET" | "POST" = "GET", payload?: Record<string, unknown>) =>
  app.inject({ method, url, ...(payload === undefined ? {} : { payload }) });

const cases: FixtureCase[] = [
  {
    lessonId: "xss-reflected",
    observe: async (app, base) => (await request(app, base + "?value=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")).body.includes("<img src=x onerror=alert(1)>")
  },
  {
    lessonId: "xss-stored",
    observe: async (app, base) => {
      await request(app, base, "POST", { comment: "<img src=x onerror=alert(1)>" });
      return (await request(app, base)).body.includes("<img src=x onerror=alert(1)>");
    }
  },
  {
    lessonId: "xss-dom",
    observe: async (app, base) => (await request(app, base)).body.includes(".innerHTML=value")
  },
  {
    lessonId: "idor",
    observe: async (app, base) => {
      const response = await request(app, base + "?id=bob-note");
      return response.statusCode === 200 && response.body.includes("BOB-PRIVATE-FIXTURE");
    }
  },
  {
    lessonId: "csrf",
    observe: async (app, base) => {
      const response = await request(app, base, "POST", {});
      return response.statusCode === 200 && response.body.includes('"changed":true');
    }
  },
  {
    lessonId: "path-traversal",
    observe: async (app, base) => (await request(app, base + "?path=..%2Fsecret.txt")).body.includes("LAB-ONLY-SECRET-FIXTURE")
  },
  {
    lessonId: "ssrf",
    observe: async (app, base) => (await request(app, base + "?url=http%3A%2F%2Fmetadata.lab%2Fidentity")).body.includes("LAB-METADATA-FIXTURE")
  },
  {
    lessonId: "broken-access-control",
    observe: async (app, base) => (await request(app, base + "?action=admin")).body.includes("LAB-ADMIN-FIXTURE")
  },
  {
    lessonId: "broken-authentication",
    observe: async (app, base) => (await request(app, base + "?password=wrong-lab-password")).body.includes("LAB-ONLY weak verifier accepts invalid password")
  },
  {
    lessonId: "session-fixation",
    observe: async (app, base) => (await request(app, base + "?sessionId=attacker-known-session")).body.includes('"before":"attacker-known-session","after":"attacker-known-session"')
  },
  {
    lessonId: "password-reset",
    observe: async (app, base) => {
      const response = await request(app, base + "?token=known-reset-token");
      return response.statusCode === 200 && response.body.includes('"resetAllowed":true');
    }
  },
  {
    lessonId: "file-upload",
    observe: async (app, base) => {
      const response = await request(app, base + "?filename=..%2Fpublic%2Flab.svg");
      return response.statusCode === 200 && response.body.includes('"accepted":true') && response.body.includes("LAB-UPLOAD-FIXTURE");
    }
  },
  {
    lessonId: "command-injection",
    observe: async (app, base) => (await request(app, base + "?input=hello%3Bmarker")).body.includes('"simulatedSecondCommand":true')
  },
  {
    lessonId: "xxe",
    observe: async (app, base) => (await request(app, base + "?entity=lab-file")).body.includes('"resolvedExternalEntity":true')
  },
  {
    lessonId: "ssti",
    observe: async (app, base) => {
      const response = await request(app, base + "?template=%7B%7B7%2A7%7D%7D");
      return response.body.includes('"evaluated":true') && response.body.includes('"rendered":"49"');
    }
  },
  {
    lessonId: "open-redirect",
    observe: async (app, base) => {
      const response = await request(app, base + "?next=https%3A%2F%2Fattacker.lab.example");
      return response.statusCode === 302 && response.headers.location === "https://attacker.lab.example";
    }
  },
  {
    lessonId: "cors",
    observe: async (app, base) => {
      const response = await request(app, base + "?origin=https%3A%2F%2Fattacker.lab.example");
      return response.headers["access-control-allow-origin"] === "https://attacker.lab.example" &&
        response.headers["access-control-allow-credentials"] === "true";
    }
  },
  {
    lessonId: "clickjacking",
    observe: async (app, base) => (await request(app, base)).body.includes('"framed":true')
  },
  {
    lessonId: "security-headers",
    observe: async (app, base) => (await request(app, base)).body.includes('"headersConfigured":false')
  },
  {
    lessonId: "secrets-exposure",
    observe: async (app, base) => (await request(app, base + "?field=apiKey")).body.includes("LAB-SYNTHETIC-SECRET-DO-NOT-USE")
  },
  {
    lessonId: "sensitive-data",
    observe: async (app, base) => {
      const body = (await request(app, base)).body;
      return body.includes("passwordHash") || body.includes("mfaRecovery");
    }
  },
  {
    lessonId: "jwt-validation",
    observe: async (app, base) => {
      const response = await request(app, base + "?token=invalid-lab-token");
      return response.statusCode === 200 && response.body.includes('"accepted":true');
    }
  },
  {
    lessonId: "mass-assignment",
    observe: async (app, base) => (await request(app, base + "?role=admin")).body.includes('"role":"admin"')
  },
  {
    lessonId: "rate-limiting",
    observe: async (app, base) => {
      const responses = await Promise.all(Array.from({ length: 5 }, () => request(app, base)));
      return responses.every((response) => response.statusCode === 200);
    }
  },
  {
    lessonId: "business-logic",
    observe: async (app, base) => (await request(app, base + "?total=1")).json().acceptedTotal === 1
  },
  {
    lessonId: "prototype-pollution",
    observe: async (app, base) => (await request(app, base + "?key=__proto__")).body.includes('"polluted":true')
  },
  {
    lessonId: "nosql-injection",
    observe: async (app, base) => (await request(app, base + "?username=%5Bobject%5D")).body.includes('"bypassed":true')
  },
  {
    lessonId: "ldap-injection",
    observe: async (app, base) => (await request(app, base + "?username=%2A%29%28uid%3D%2A%29")).body.includes('"broadenedSearch":true')
  },
  {
    lessonId: "insecure-deserialization",
    observe: async (app, base) => {
      const response = await request(app, base + "?type=admin");
      return response.statusCode === 200 && response.body.includes("LAB-DESERIALIZATION-FIXTURE");
    }
  }
];

describe("individual HTTP target behavior for every non-SQLi lesson", () => {
  const apps: FastifyInstance[] = [];
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

  it("covers all 29 controlled HTTP targets exactly once", () => {
    expect(cases.map(({ lessonId }) => lessonId).sort()).toEqual([...httpTargetLessonIds].sort());
  });

  it.each(cases)("$lessonId changes its HTTP response after the target is fixed", async ({ lessonId, observe }) => {
    const app = buildApp();
    await app.ready();
    apps.push(app);
    const runId = "http-coverage-" + lessonId;
    const base = "/api/labs/http-targets/" + lessonId + "/" + runId + "/fixture";

    const prepared = await request(app, "/api/labs/http-targets/" + lessonId + "/" + runId + "/prepare", "POST");
    expect(prepared.statusCode).toBe(200);

    expect(await observe(app, base), lessonId + " must expose its expected synthetic vulnerability before the fix").toBe(true);

    const fixed = await request(app, "/api/labs/http-targets/" + lessonId + "/" + runId + "/fix", "POST");
    expect(fixed.statusCode).toBe(200);
    expect(fixed.json()).toMatchObject({ fixed: true, target: "controlled-http-fixture" });

    expect(await observe(app, base), lessonId + " must block the same HTTP probe after the fix").toBe(false);
  });
});
