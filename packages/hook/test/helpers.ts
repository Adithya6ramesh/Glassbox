import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as v from "valibot";
import { SpoolEvent } from "@glassbox-ai/protocol";
import type { HookEnv } from "../src/index.js";

/** A fresh temporary user home with a project folder inside it. */
export function makeEnv(overrides: Partial<HookEnv> = {}): HookEnv & { root: string; project: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gbx-hook-test-"));
  const homeDir = path.join(root, "home");
  const project = path.join(homeDir, "proj");
  fs.mkdirSync(project, { recursive: true });
  return {
    root,
    project,
    homeDir,
    glassboxHome: path.join(homeDir, ".glassbox"),
    platform: process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux",
    ...overrides,
  };
}

let n = 0;
export const toolUseId = () => `toolu_TEST${String(++n).padStart(12, "0")}`;
export const SESSION = "00000000-0000-4000-8000-0000000000aa";

export function common(env: { project: string }, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    session_id: SESSION,
    transcript_path: "",
    cwd: env.project,
    prompt_id: "00000000-0000-4000-8000-0000000000bb",
    permission_mode: "default",
    effort: { level: "medium" },
    ...extra,
  };
}

export function pre(env: { project: string }, tool_name: string, tool_input: Record<string, unknown>, id = toolUseId(), extra: Record<string, unknown> = {}) {
  return { ...common(env), hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: id, ...extra };
}

export function post(env: { project: string }, tool_name: string, tool_input: Record<string, unknown>, id: string, tool_response: unknown, extra: Record<string, unknown> = {}) {
  return { ...common(env), hook_event_name: "PostToolUse", tool_name, tool_input, tool_response, tool_use_id: id, duration_ms: 5, ...extra };
}

/** All spooled events, validated against the protocol schema. */
export function spooled(env: HookEnv): v.InferOutput<typeof SpoolEvent>[] {
  const dir = path.join(env.glassboxHome, "spool");
  if (!fs.existsSync(dir)) return [];
  const out: v.InferOutput<typeof SpoolEvent>[] = [];
  for (const f of fs.readdirSync(dir).sort()) {
    if (!f.endsWith(".jsonl")) continue;
    for (const line of fs.readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (!line.trim()) continue;
      out.push(v.parse(SpoolEvent, JSON.parse(line)));
    }
  }
  return out;
}

/** Every file under a directory, as relative paths. */
export function allFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => path.relative(dir, path.join(e.parentPath, e.name)));
}

export const bash = (command: string) => ({ command, description: "test" });
