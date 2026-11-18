import { describe, expect, it } from "vitest";
import { ENGINE_VERSION } from "../src/index.js";

// Toolchain smoke test (Step 2). The real suites arrive in Step 3.
describe("scaffold", () => {
  it("exports a version string", () => {
    expect(ENGINE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("can load each runtime dependency synchronously", async () => {
    const { RE2JS } = await import("re2js");
    expect(RE2JS.compile("a+b").matcher("xaab").find()).toBe(true);
    const { sha256 } = await import("@noble/hashes/sha2.js");
    expect(sha256(new Uint8Array()).length).toBe(32);
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    expect(typeof ed25519.verify).toBe("function");
    const v = await import("valibot");
    expect(v.safeParse(v.string(), "x").success).toBe(true);
  });
});
