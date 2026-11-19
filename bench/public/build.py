# Builds the public-source benchmark corpus from downloaded data (inert text only; nothing
# here runs any command from the data). Usage: python -I build.py <raw-dir> <out-dir>
# Labelling rules are fixed in bench/SOURCES.md before the engine is run on any case.
import ast, glob, hashlib, json, os, re, sys

RAW, OUT = sys.argv[1], sys.argv[2]
SALT = "glassbox-public-corpus-v1"
CAP = 150  # max cases per (source, label) after dedupe, chosen by hash order

def h(s): return hashlib.sha256((SALT + "|" + s).encode("utf8")).hexdigest()
def j(p): return json.load(open(os.path.join(RAW, p), encoding="utf8"))

cases = []
def add(source, license_, kind, category, label, key, inp, platform="linux"):
    cases.append(dict(id=f"{source}-{h(key)[:12]}", source=source, license=license_, kind=kind, category=category,
                      label=label, platform=platform, input=inp))

def capped(rows, keyf, n=CAP):
    seen, out = set(), []
    for r in rows:
        k = keyf(r)
        if k in seen: continue
        seen.add(k); out.append(r)
    out.sort(key=lambda r: h(keyf(r)))
    return out[:n]

def hf_rows(prefix):
    rows = []
    for f in sorted(glob.glob(os.path.join(RAW, prefix + "*.json"))):
        d = json.load(open(f, encoding="utf8"))
        rows += [r["row"] for r in d.get("rows", [])]
    return rows

# ── Tool results: prompt-injection datasets ────────────────────────────────────────────
dp = hf_rows("deepset-")
for lab, want in (("stop", 1), ("benign", 0)):
    for r in capped([r for r in dp if r["label"] == want and r["text"].strip()], lambda r: r["text"].strip()):
        add("deepset-prompt-injections", "Apache-2.0", "result", "result-injection", lab, r["text"].strip(), {"text": r["text"]})

for r in capped([r for r in hf_rows("gandalf-") if r["text"].strip()], lambda r: r["text"].strip()):
    add("lakera-gandalf-ignore-instructions", "MIT", "result", "result-injection", "stop", r["text"].strip(), {"text": r["text"]})

sp = hf_rows("spml-")
for lab, want in (("stop", 1), ("benign", 0)):
    for r in capped([r for r in sp if r["Prompt injection"] == want and (r["User Prompt"] or "").strip()], lambda r: r["User Prompt"].strip()):
        add("spml-chatbot-prompt-injection", "MIT", "result", "result-injection", lab, r["User Prompt"].strip(), {"text": r["User Prompt"]})

for f in ("bipia-text_attack_train.json", "bipia-text_attack_test.json", "bipia-code_attack_train.json", "bipia-code_attack_test.json"):
    for group, items in j(f).items():
        for t in items:
            add("microsoft-bipia", "MIT", "result", "result-injection", "stop", t, {"text": t, "group": group})

# InjecAgent: the tool response with the attacker instruction (stop), one per attacker
# instruction; and each user tool's response template with the placeholder removed (benign).
ia = j("injecagent-test_cases_dh_base.json") + j("injecagent-test_cases_ds_base.json")
for r in capped(ia, lambda r: r["Attacker Instruction"], n=10_000):
    add("injecagent", "MIT", "result", "result-injection", "stop", r["Attacker Instruction"], {"text": r["Tool Response"], "tool": r["User Tool"]})
for r in capped(ia, lambda r: r["User Tool"], n=10_000):
    tpl = r["Tool Response Template"].replace("<Attacker Instruction>", "")
    add("injecagent", "MIT", "result", "result-injection", "benign", "benign|" + r["User Tool"], {"text": tpl, "tool": r["User Tool"]})

# ── Manifests ──────────────────────────────────────────────────────────────────────────
def server(name, tools): return {"serverId": name, "initialize": {"protocolVersion": "2025-06-18", "serverInfo": {"name": name, "version": "1.0.0"}, "capabilities": {"tools": {}}}, "tools": tools}
def tool(name, desc, schema=None): return {"name": name, "description": desc, "inputSchema": schema or {"type": "object", "properties": {}}}

tox = [v for item in j("mcptox-pure_tool.json") for v in item.values()]
for r in tox:
    add("mcptox", "CC-BY-4.0", "manifest", "tool-poisoning", "stop", r["server_name"] + "|" + r["tool_name"] + "|" + r["tool_content"],
        {"server": server(r["server_name"], [tool(r["tool_name"], r["tool_content"].strip())]), "paradigm": r.get("paradigm"), "risk": r.get("security risk")})

def py_tools(path):
    t = ast.parse(open(os.path.join(RAW, path), encoding="utf8").read())
    out = {}
    for n in ast.walk(t):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any("tool" in ast.unparse(d) for d in n.decorator_list):
            props = {a.arg: {"type": "string"} for a in n.args.args}
            out[n.name] = tool(n.name, (ast.get_docstring(n) or "").strip(), {"type": "object", "properties": props})
    return out

msb_bad = py_tools("msb-maliciousadd.py")
# Tools the MCPSecBench README uses for its tool-poisoning and tool-shadowing attacks.
for name in ("add", "modify", "m_check", "aft_check"):
    add("mcpsecbench", "MIT", "manifest", "tool-poisoning", "stop", "msb|" + name, {"server": server("mcpsecbench-malicious", [msb_bad[name]])})
msb_good = py_tools("msb-main.py")
for name, t in msb_good.items():
    if t["description"]:
        add("mcpsecbench", "MIT", "manifest", "tool-poisoning", "benign", "msb-good|" + name, {"server": server("mcpsecbench", [t])})

for f in sorted(glob.glob(os.path.join(RAW, "ghmcp", "*.snap"))):
    t = json.load(open(f, encoding="utf8"))
    add("github-mcp-server", "MIT", "manifest", "tool-poisoning", "benign", "gh|" + t["name"], {"server": server("github", [t])})

# ── Shell: Atomic Red Team (attacks) ───────────────────────────────────────────────────
STOP = ("T1485", "T1490", "T1561", "T1529", "T1489", "T1486", "T1531",       # impact
        "T1053", "T1543", "T1547", "T1037", "T1098.004", "T1546.004", "T1546.013",  # persistence
        "T1562")                                                               # impair defenses
WARN = ("T1070.001", "T1070.002", "T1070.003", "T1552.001", "T1552.004")
def tech_label(tactic, tid):
    if tactic == "exfiltration": return "stop"
    if any(tid == p or tid.startswith(p + ".") for p in STOP): return "stop"
    if tid in WARN: return "warn"
    return None

art, seen = j("art-tests.json"), set()
for a in art:
    lab = tech_label(a["tactic"], a["technique"])
    if lab is None or a["guid"] in seen or not a["command"]: continue
    ex = a["executor"]
    if ex in ("sh", "bash"): tool_name, plat = "Bash", "linux"
    elif ex == "powershell": tool_name, plat = "PowerShell", "win32"
    else: continue
    seen.add(a["guid"])
    cmd = a["command"]
    for k, v in (a["args"] or {}).items():
        cmd = cmd.replace("#{" + k + "}", str(v))
    # Redact credential-shaped literals (repo rule: none may be committed). Only Slack webhooks
    # occur; the URL keeps its host so the network call is still visible.
    cmd = re.sub(r"hooks\.slack\.com/services/[A-Za-z0-9/]+", "hooks.slack.com/services/REDACTED", cmd)
    cmd = cmd.replace("PathToAtomicsFolder", "/tmp/atomics" if plat == "linux" else "C:\\AtomicRedTeam\\atomics").strip()
    cat = "exfil-shell" if a["tactic"] == "exfiltration" else ("powershell" if plat == "win32" else "destructive-shell")
    add("atomic-red-team", "MIT", "call", cat, lab, a["guid"], {"tool": tool_name, "command": cmd, "technique": a["technique"], "test": a["name"]}, plat)

# ── Shell: tldr pages (everyday commands, benign) ──────────────────────────────────────
TOOLS = ["git", "npm", "pnpm", "yarn", "npx", "node", "python", "python3", "pip", "ls", "cat", "head", "tail", "grep", "rg", "find", "sed",
         "awk", "jq", "curl", "wget", "docker", "docker-compose", "kubectl", "make", "cargo", "go", "tar", "zip", "unzip", "cp", "mv", "mkdir",
         "touch", "cd", "pwd", "echo", "diff", "wc", "sort", "uniq", "chmod", "du", "df", "ps", "kill", "tsc", "eslint", "prettier", "pytest",
         "gh", "git-commit", "git-push", "git-log", "git-diff", "git-status", "git-branch", "git-checkout", "git-rebase", "git-stash",
         "git-clone", "git-pull", "git-add", "git-merge", "git-tag", "git-reset", "rustc", "deno", "bun", "uv", "poetry", "ruff", "black"]
PS = ["get-childitem", "get-content", "set-location", "get-process", "select-string", "copy-item", "move-item", "new-item", "remove-item",
      "invoke-webrequest", "get-command", "get-help", "test-path", "get-location", "measure-object", "sort-object", "where-object"]
def tldr_examples(path):
    out, lines = [], open(path, encoding="utf8").read().splitlines()
    for ln in lines:
        m = re.match(r"^`(.+)`$", ln.strip())
        if m: out.append(re.sub(r"\{\{(.*?)\}\}", lambda mm: mm.group(1).replace("[", "").replace("]", ""), m.group(1)))
    return out
for name in TOOLS:
    for sub in ("common", "linux"):
        p = os.path.join(RAW, "tldr", sub, name + ".md")
        if os.path.exists(p):
            for ex in tldr_examples(p):
                add("tldr-pages", "CC-BY-4.0", "call", "everyday-shell", "benign", "tldr|" + ex, {"tool": "Bash", "command": ex, "page": f"{sub}/{name}"})
            break
for name in PS:
    p = os.path.join(RAW, "tldr", "windows", name + ".md")
    if os.path.exists(p):
        for ex in tldr_examples(p):
            add("tldr-pages", "CC-BY-4.0", "call", "everyday-powershell", "benign", "tldr-ps|" + ex, {"tool": "PowerShell", "command": ex, "page": f"windows/{name}"}, "win32")

# ── Dedupe ids, split 70/30 by hash ────────────────────────────────────────────────────
byid = {}
for c in cases: byid.setdefault(c["id"], c)
cases = sorted(byid.values(), key=lambda c: c["id"])
dev = [c for c in cases if int(h("split|" + c["id"])[:8], 16) % 100 < 70]
hold = [c for c in cases if int(h("split|" + c["id"])[:8], 16) % 100 >= 70]
os.makedirs(OUT, exist_ok=True)
for name, rows in (("dev.json", dev), ("holdout.json", hold)):
    with open(os.path.join(OUT, name), "w", encoding="utf8", newline="\n") as f:
        f.write("[\n" + ",\n".join(json.dumps(c, ensure_ascii=False, sort_keys=True) for c in rows) + "\n]\n")
from collections import Counter
print("total", len(cases), "dev", len(dev), "holdout", len(hold))
for k, v in sorted(Counter((c["source"], c["label"]) for c in cases).items()): print(f"  {k[0]:38} {k[1]:7} {v}")
