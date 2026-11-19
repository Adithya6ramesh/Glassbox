// Public repo: no credential-shaped literal may be committed, not even a fake one (secret
// scanners and push protection can't tell fakes from real ones). Test fakes are built from
// pieces at run time; rule test cases use {{fake:<type>}} placeholders.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectSecrets } from "../../src/secrets/detect.js";

const root = fileURLToPath(new URL("../../../../", import.meta.url));

describe("no committed secrets", () => {
  it("no tracked file contains a credential-shaped literal", () => {
    let files: string[];
    try {
      files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
    } catch {
      return; // not a git checkout (e.g. a packed tarball): nothing to check
    }
    expect(files.length).toBeGreaterThan(10);
    const hits: string[] = [];
    for (const f of files) {
      if (/\.(png|jpg|ico|woff2?)$/.test(f) || f === "pnpm-lock.yaml") continue;
      const text = readFileSync(join(root, f), "utf8");
      for (const s of detectSecrets(text)) {
        if (s.example || s.type === "generic-high-entropy") continue;
        hits.push(`${f}: ${s.type}`);
      }
    }
    expect(hits).toEqual([]);
  });

  it("docs/ is not tracked (kept out of the public repo)", () => {
    let files: string[];
    try {
      files = execFileSync("git", ["ls-files", "docs"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
    } catch {
      return;
    }
    expect(files).toEqual([]);
  });
});
