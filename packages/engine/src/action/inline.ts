// Interpreter inline code.
// A token heuristic: obfuscation markers → unanalyzable; dangerous tokens → high-risk;
// otherwise write-reversible. Bypassable by design.
import { test } from "../util/re.js";

export interface InlineVerdict {
  unanalyzable: string | null;
  dangerous: boolean;
  /** Deletes a whole directory tree (rmtree, rmSync recursive, rm_rf, File::Path). */
  destroysTree: boolean;
  /** Refers to the home directory or the filesystem root. */
  homeOrRoot: boolean;
  /** Uses the network. */
  network: boolean;
  /** Refers to credential files or reads the whole environment. */
  sensitive: boolean;
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

// Spec rev 6, Q3 item 3: what dangerous inline code is aimed at (re2 patterns, linear time).
const TREE_DELETE = "\\b(rmtree|removedirs|rm_rf|remove_dir_all|rmdir_p)\\b|\\b(rmSync|rm)\\s*\\(.{0,300}?recursive\\s*:\\s*true|File::Path";
const HOME_OR_ROOT = "expanduser\\s*\\(\\s*['\"]~|\\bhomedir\\s*\\(|Path\\.home\\s*\\(|\\$ENV\\{\\s*['\"]?HOME|ENV\\[\\s*['\"]HOME|environ\\[\\s*['\"]HOME|process\\.env\\.HOME|getenv\\(\\s*['\"](HOME|USERPROFILE)|['\"](~|/|~/\\*?|/\\*|[A-Za-z]:\\\\?)['\"]";
const NETWORK = "\\b(socket|urllib|urllib2|urllib3|requests|httpx|aiohttp|fetch|axios|XMLHttpRequest|WebSocket|smtplib|ftplib|paramiko|LWP|IO::Socket|open-uri)\\b|net\\.connect|HTTP::Tiny|Net::HTTP|https?\\.(request|get)\\b";
const SENSITIVE = "\\.ssh|id_rsa|id_ed25519|\\.aws|credentials|\\.netrc|\\.git-credentials|\\.kube|\\.config/gh|(^|[^.\\w])\\.env\\b|os\\.environ\\s*($|[^\\[.\\s]|\\.(items|copy)\\b)|dict\\(\\s*os\\.environ|process\\.env\\s*($|[^.\\[\\s])|JSON\\.stringify\\(\\s*process\\.env\\b|%ENV\\b|ENV\\.to_h";

export function analyzeInlineCode(code: string): InlineVerdict {
  const none = { destroysTree: false, homeOrRoot: false, network: false, sensitive: false };
  if (code.length > 16 * 1024) return { unanalyzable: "inline code is too long to analyze", dangerous: true, ...none };
  for (const [pattern, label] of MARKERS) {
    if (test(pattern, code)) return { unanalyzable: `inline code uses an obfuscation marker (${label})`, dangerous: true, ...none };
  }
  return {
    unanalyzable: null,
    dangerous: DANGEROUS.some((p) => test(p, code)),
    destroysTree: test(TREE_DELETE, code),
    homeOrRoot: test(HOME_OR_ROOT, code),
    network: test(NETWORK, code),
    sensitive: test(SENSITIVE, code),
  };
}
