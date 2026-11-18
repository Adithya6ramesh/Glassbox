// Interpreter inline code (engine-spec §7.3 interpreter row, Q6 rev 4).
// A token heuristic: obfuscation markers → unanalyzable; dangerous tokens → high-risk;
// otherwise write-reversible. Bypassable by design (threat-model §7 #13).
import { test } from "../util/re.js";

export interface InlineVerdict {
  unanalyzable: string | null;
  dangerous: boolean;
}

const MARKERS: [string, string][] = [
  ["__import__", "__import__"],
  ["importlib", "importlib"],
  ["\\b(getattr|setattr|delattr)\\s*\\(", "getattr/setattr"],
  ["\\b(globals|locals|vars)\\s*\\(", "globals/locals/vars"],
  ["(^|[^.\\w])(exec|eval|compile)\\s*\\(", "exec/eval/compile"],
  ["\\bFunction\\s*\\(", "Function constructor"],
  ["\\brequire\\s*\\(\\s*[^'\"\\s)]", "require with a computed name"],
  ["\\bimport\\s*\\(\\s*[^'\"\\s)]", "dynamic import with a computed name"],
  ["\\b(base64|codecs|binascii|atob|btoa)\\b", "decoding"],
  ["Buffer\\.from\\s*\\([^)]*(base64|hex)", "decoding"],
  ["fromCharCode|\\bchr\\s*\\(|\\bord\\s*\\(", "character arithmetic"],
  ["\\\\x[0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}|\\\\[0-7]{3}", "escape sequences"],
  ["\\.decode\\s*\\(", ".decode()"],
  ["(['\"][^'\"\\n]{0,200}[/\\\\][^'\"\\n]{0,200}['\"]\\s*\\+)|(\\+\\s*['\"][^'\"\\n]{0,200}[/\\\\.][^'\"\\n]{0,200}['\"])", "string-built path"],
  ["\\b(os\\.path\\.join|path\\.join|path\\.resolve|Path\\s*\\()", "built path"],
  ["\\bf['\"][^'\"\\n]{0,200}\\{[^}]{0,100}\\}[^'\"\\n]{0,200}[/\\\\]", "f-string path"],
  ["`[^`\\n]{0,200}\\$\\{[^}]{0,100}\\}[^`\\n]{0,200}[/\\\\]", "template-literal path"],
  ["\\[\\s*::-1\\s*\\]|\\.reverse\\(\\)\\.join|\\bjoin\\s*\\(\\s*reversed", "reversed string"],
];

const DANGEROUS = [
  "\\b(rmtree|unlink|unlinkSync|rmdir|rmdirSync|rmSync|remove|removedirs|truncate)\\b", "\\bos\\.remove\\b", "\\bfs\\.(rm|unlink|rmdir|writeFile|appendFile)",
  "\\b(socket|http|https|urllib|urllib2|urllib3|requests|httpx|aiohttp|fetch|axios|XMLHttpRequest|WebSocket|net\\.connect|smtplib|ftplib|paramiko)\\b",
  "\\b(subprocess|child_process|spawn|spawnSync|execSync|execFile|execFileSync|popen|Popen|system|shell)\\b",
  "\\bexec[A-Z_]", "\\bshutil\\b", "\\bos\\.(system|popen|exec|kill|chmod|chown|rename|replace)",
  "open\\s*\\([^)]*,\\s*['\"](w|a|x|r\\+|wb|ab)", "\\bprocess\\.kill\\b", "\\bDeno\\.(run|remove|writeTextFile)",
];

export function analyzeInlineCode(code: string): InlineVerdict {
  if (code.length > 16 * 1024) return { unanalyzable: "inline code is too long to analyze", dangerous: true };
  for (const [pattern, label] of MARKERS) {
    if (test(pattern, code)) return { unanalyzable: `inline code uses an obfuscation marker (${label})`, dangerous: true };
  }
  return { unanalyzable: null, dangerous: DANGEROUS.some((p) => test(p, code)) };
}
