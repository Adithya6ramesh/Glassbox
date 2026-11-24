// Canonicalization: views, offsets, idempotence (P1), intake (C0–C2).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { buildViews } from "../../src/canon/views.js";
import { parseJsonStrict } from "../../src/intake/json.js";
import { snapshot } from "../../src/intake/snapshot.js";

describe("Unicode views (C4)", () => {
  it("visible strips zero-width and format characters and records them", () => {
    const v = buildViews("ig​nore⁠ previous");
    expect(v.visible.text).toBe("ignore previous");
    expect(v.facts.invisibles.map((x) => x.cp)).toEqual([0x200b, 0x2060]);
  });

  it("norm applies NFKC, case folding and whitespace collapse", () => {
    const v = buildViews("ＩＧＮＯＲＥ    Previous\tInstructions");
    expect(v.norm.text).toBe("ignore previous instructions");
  });

  it("skeleton maps confusables (Cyrillic look-alikes) to Latin", () => {
    const v = buildViews("іgnоrе"); // Cyrillic і, о, е
    expect(v.skeleton.text).toBe("ignore");
    expect(v.norm.text).not.toBe("ignore");
  });

  it("tag characters decode into tagDecoded", () => {
    const tags = [..."hi there"].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
    const v = buildViews("ok" + tags);
    expect(v.tagDecoded).toBe("hi there");
    expect(v.visible.text).toBe("ok");
    expect(v.facts.tagCount).toBe(8);
  });

  it("ANSI escapes are removed from views and recorded", () => {
    const v = buildViews("\u001b[31mred\u001b[0m text \u001b]8;;http://x\u0007link\u001b]8;;\u0007");
    expect(v.norm.text).toBe("red text link");
    expect(v.facts.ansi).toBeGreaterThanOrEqual(3);
  });

  it("emoji ZWJ sequences and emoji variation selectors are not invisibles", () => {
    const v = buildViews("dev 👩‍💻 love ❤️");
    expect(v.facts.invisibles).toEqual([]);
  });

  it("bidi controls are recorded; LRM inside RTL text is not", () => {
    expect(buildViews("abc‮dcba").facts.bidi.length).toBe(1);
    expect(buildViews("שלום‏עולם").facts.bidi.length).toBe(0);
  });

  it("view offsets map back into the original string", () => {
    const original = "x​​IGNORE me";
    const v = buildViews(original);
    const i = v.norm.text.indexOf("ignore");
    const o = v.norm.toOriginal(i);
    expect(original.slice(o, o + 6)).toBe("IGNORE");
  });

  it("P1: norm and skeleton are idempotent", () => {
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 200 }), (s) => {
      const once = buildViews(s);
      expect(buildViews(once.norm.text).norm.text).toBe(once.norm.text);
      expect(buildViews(once.skeleton.text).skeleton.text).toBe(once.skeleton.text);
    }), { numRuns: 500 });
  });

  it("views never throw on lone surrogates or huge code points", () => {
    expect(() => buildViews("\uD800abc\uDFFF\u{10FFFF}")).not.toThrow();
  });
});

describe("strict JSON intake (C1–C2)", () => {
  it("duplicate keys are reported and every value is kept", () => {
    const r = parseJsonStrict('{"a":1,"a":"evil"}');
    expect(r.issues.map((i) => i.code)).toContain("CP-PARSE-001");
    expect(r.value).toMatchObject({ a: 1, "a~dup1": "evil" });
  });

  it("prototype keys are plain data and flagged", () => {
    const r = parseJsonStrict('{"__proto__":{"polluted":true},"constructor":1}');
    expect(r.issues.map((i) => i.code)).toContain("CP-PARSE-003");
    expect(Object.getPrototypeOf(r.value)).toBe(null);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.keys(r.value as object)).toEqual(["__proto__", "constructor"]);
  });

  it("depth over the limit stops parsing without recursion", () => {
    const deep = "[".repeat(100_000) + "]".repeat(100_000);
    const r = parseJsonStrict(deep, { maxDepth: 32 });
    expect(r.issues.map((i) => i.code)).toContain("CP-LIMIT-002");
  });

  it("lone surrogates are flagged", () => {
    expect(parseJsonStrict('"\\ud800"').issues.map((i) => i.code)).toContain("CP-PARSE-005");
  });

  it("invalid UTF-8 bytes are flagged", () => {
    const bytes = new Uint8Array([0x22, 0xff, 0xfe, 0x22]);
    expect(parseJsonStrict(bytes).issues.map((i) => i.code)).toContain("CP-PARSE-002");
  });

  it("a BOM is stripped", () => {
    expect(parseJsonStrict("﻿{\"a\":1}").value).toMatchObject({ a: 1 });
  });

  it("malformed JSON is an issue, not a throw", () => {
    for (const s of ["{", "[1,]", "{'a':1}", "nul", "1 2", ""]) {
      const r = parseJsonStrict(s);
      expect(r.ok, s).toBe(false);
    }
  });

  it("agrees with JSON.parse on valid JSON (property)", () => {
    fc.assert(fc.property(fc.jsonValue({ maxDepth: 5 }), (v) => {
      const text = JSON.stringify(v);
      const r = parseJsonStrict(text);
      expect(r.ok).toBe(true);
      expect(JSON.stringify(r.value)).toBe(JSON.stringify(JSON.parse(text)));
    }), { numRuns: 300 });
  });
});

describe("safe snapshot of objects (C2.4)", () => {
  it("never invokes getters, records them", () => {
    let called = false;
    const o = { get x() { called = true; return 1; }, y: 2 };
    const s = snapshot(o);
    expect(called).toBe(false);
    expect(s.issues.map((i) => i.code)).toContain("CP-PARSE-006");
    expect(s.value).toMatchObject({ y: 2 });
  });

  it("detects cycles", () => {
    const o: Record<string, unknown> = { a: 1 };
    o["self"] = o;
    expect(snapshot(o).issues.map((i) => i.code)).toContain("CP-PARSE-007");
  });

  it("survives a hostile Proxy", () => {
    const p = new Proxy({}, { ownKeys() { throw new Error("boom"); }, get() { throw new Error("boom"); } });
    const s = snapshot({ a: p });
    expect(s.degraded).toBe(true);
  });

  it("is deep-frozen with null prototypes", () => {
    const s = snapshot({ a: { b: [1, { c: "d" }] } });
    expect(Object.isFrozen(s.value)).toBe(true);
    expect(Object.getPrototypeOf((s.value as Record<string, unknown>)["a"])).toBe(null);
  });

  it("drops non-JSON values", () => {
    const s = snapshot({ f: () => 1, sym: Symbol("x"), big: 10n, u: undefined, ok: true });
    expect(Object.keys(s.value as object)).toEqual(["ok"]);
  });
});
