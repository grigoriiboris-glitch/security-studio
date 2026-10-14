import { describe, expect, it } from "vitest";
import { assertSafeApiBind } from "../src/config.js";

describe("production API bind policy", () => {
  it.each(["127.0.0.1", "::1", "localhost"])("allows loopback host %s in production", (host) => {
    expect(() => assertSafeApiBind(host, "production")).not.toThrow();
  });

  it.each(["0.0.0.0", "192.0.2.10", "::"])("rejects non-loopback host %s in production", (host) => {
    expect(() => assertSafeApiBind(host, "production")).toThrow(/must bind to loopback/);
  });

  it("keeps development binding configurable", () => {
    expect(() => assertSafeApiBind("0.0.0.0", "development")).not.toThrow();
  });
});
