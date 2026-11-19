// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Node built-ins the engine must never import (engine-spec §2, §12).
// Beyond the spec's list: os, path, crypto, url, buffer, perf_hooks, so that the
// engine stays host-independent (portable to the browser grader) and
// path handling stays lexical and platform-independent (§7.6.3).
const BANNED_MODULES = [
  "fs", "fs/promises", "net", "http", "https", "http2", "child_process",
  "dgram", "dns", "tls", "worker_threads", "cluster", "vm", "module",
  "process", "os", "path", "crypto", "url", "buffer", "perf_hooks", "inspector",
];

const engineRestrictions = {
  // The engine detects and escapes control characters, so regexes name them on purpose.
  "no-control-regex": "off",
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-restricted-imports": ["error", {
    paths: BANNED_MODULES.flatMap((m) => [
      { name: m, message: "Banned in @glassbox/engine (engine-spec §2): no I/O or host APIs." },
      { name: `node:${m}`, message: "Banned in @glassbox/engine (engine-spec §2): no I/O or host APIs." },
    ]),
  }],
  "no-restricted-globals": ["error",
    ...["process", "require", "Buffer", "fetch", "XMLHttpRequest", "WebSocket",
        "setTimeout", "setInterval", "setImmediate", "queueMicrotask",
        "globalThis", "global", "window", "self"].map((name) => ({
      name, message: "Host globals are banned in @glassbox/engine (engine-spec §1, §2).",
    })),
  ],
  "no-restricted-syntax": ["error",
    { selector: "ImportExpression", message: "Dynamic import() is banned in the engine (engine-spec §2)." },
    { selector: "NewExpression[callee.name='Function'], CallExpression[callee.name='Function']", message: "Function constructor is banned (engine-spec §2)." },
    { selector: "NewExpression[callee.name='RegExp'], CallExpression[callee.name='RegExp']", message: "RegExp constructor is banned; rule regexes go through re2js (engine-spec §10.3)." },
    { selector: "MemberExpression[object.name='Math'][property.name='random']", message: "No randomness in the engine (engine-spec §1.1)." },
    { selector: "MemberExpression[object.name='Date'][property.name='now'], NewExpression[callee.name='Date']", message: "No wall clock in the engine; `now` is passed in by the caller (engine-spec §1.1, §10.2)." },
    { selector: "MemberExpression[object.name='Reflect'], MemberExpression[property.name='__proto__'], MemberExpression[property.value='__proto__']", message: "Reflection/prototype access is banned in the engine (engine-spec §5.2)." },
    // Red team RT-S2: `(() => {}).constructor("code")` reaches the Function
    // constructor without naming it. Nothing in the engine needs `.constructor`.
    { selector: "MemberExpression[property.name='constructor'], MemberExpression[property.value='constructor']", message: "`.constructor` access is banned in the engine (it reaches Function; engine-spec §2)." },
  ],
};

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "**/coverage/**"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["packages/engine/src/**/*.ts"],
    // Red team RT-S1: an inline `eslint-disable` comment would switch every
    // rule above off. Inline config is ignored for engine source.
    linterOptions: { noInlineConfig: true },
    rules: engineRestrictions,
  },
  {
    // Dev-time Node scripts (never part of the engine).
    files: ["packages/*/scripts/**/*.mjs", "scripts/**/*.mjs", "bench/**/*.mjs"],
    languageOptions: { globals: { process: "readonly", console: "readonly", URL: "readonly", Buffer: "readonly" } },
  },
  {
    // Tests feed hostile input on purpose (NBSP, control characters, the RFC 8785
    // sample numbers) and use non-null assertions on fixtures they just built.
    // shell-difftest is test-only code, never published.
    files: ["packages/*/test/**/*.ts", "packages/shell-difftest/src/**/*.ts"],
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "no-irregular-whitespace": "off",
      "no-control-regex": "off",
      "no-useless-escape": "off",
      "no-loss-of-precision": "off",
    },
  },
);
