import { describe, expect, it } from "vitest";
import {
  createLabRun, fixLabRun, getLabRun, probeLabRun, recordLabProbeResult,
  recordLabRetestResult, retestLabRun
} from "../src/lab-runtime.js";

describe("runtime phase follows observed HTTP outcomes", () => {
  it("returns to ready when the baseline HTTP probe fails to reproduce a vulnerability", () => {
    const created = createLabRun("idor");
    expect(probeLabRun("idor", created.runId)?.phase).toBe("exploited");
    const recorded = recordLabProbeResult("idor", created.runId, false);
    expect(recorded).toMatchObject({ phase: "ready", fixed: false });
    expect(getLabRun("idor", created.runId)).toMatchObject({ phase: "ready", fixed: false });
  });

  it("does not keep phase passed when the independent HTTP retest still sees a vulnerability", () => {
    const created = createLabRun("idor");
    probeLabRun("idor", created.runId);
    expect(fixLabRun("idor", created.runId, "findUnique({ id: req.params.id, ownerId: req.user.id });")?.phase).toBe("fixed");
    expect(retestLabRun("idor", created.runId)?.phase).toBe("passed");
    const recorded = recordLabRetestResult("idor", created.runId, false);
    expect(recorded).toMatchObject({ phase: "fixed", fixed: true });
    expect(getLabRun("idor", created.runId)).toMatchObject({ phase: "fixed", fixed: true });
  });
});
