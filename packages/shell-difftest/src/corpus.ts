// T-DIFF corpus: hostile and odd shell commands, generated deterministically
// from hand-written templates and fragments. Nothing here is run on a real system: the
// harness runs bash with PATH empty, every external command and risky builtin stubbed,
// HOME and cwd in a throwaway sandbox.
//
// Rules for corpus authors (keeps the harness harmless):
// - no absolute-path redirection targets except /dev/null; no /dev/tcp or /dev/udp
// - no `builtin`, `enable`, `command kill`, `exec` with a real program, `cd /`

/** Small deterministic PRNG (mulberry32), so the corpus is stable across runs. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Hand-written seeds: each probes one tricky corner of bash parsing.
const SEEDS: string[] = [
  "rm -rf /", "r''m -rf x", '"r"m -rf x', "\\rm -rf x", "$'\\x72\\x6d' -rf x", "$'\\162\\155' x", "r$'m' x",
  "echo a\\ b", "echo 'a b' \"c d\" e\\ f", "echo \"a\"b'c'd", "echo \"$HOME/x\"", "echo '$HOME'", "echo \"\\$X\"",
  "echo $'tab\\there'", "echo $'nl\\nhere'", "echo $'q\\'q'", "echo \"a\\\"b\"", "echo 'it'\\''s'", "echo \"\\\\\"",
  "echo a#b #comment", "echo #x", "echo a;echo b", "echo a&&echo b", "echo a||echo b", "echo a|cat", "echo a&echo b",
  "echo a\necho b", "echo a \\\n b", "echo $X", "echo ${X}", "echo ${X:-def}", "echo \"${X:-d e f}\"", "echo ${X-}",
  "echo \"$@\"", "echo $1 $#", "echo \"\"", "echo ''", "echo '' ''", "echo \"\" x \"\"",
  "echo *.ts", "echo ?.md", "echo [ab].txt", "echo {a,b}", "echo x{1,2}y", "echo {a..c}", "echo {,}", "echo \\{a,b\\}",
  "echo ~", "echo ~/x", "echo a~b", "echo \"~\"", "echo x=~/y",
  "X=1 echo a", "X=1 Y=2 cat f", "X='a b' echo $X", "env X=1 echo a", "sudo -u root echo a", "nice -n 5 echo a",
  "timeout 5 echo a", "nohup echo a", "command echo a", "xargs echo < f", "find . -name x -exec echo {} \\;",
  "( echo a; echo b )", "{ echo a; echo b; }", "if true; then echo a; else echo b; fi", "for i in 1 2; do echo $i; done",
  "while false; do echo a; done", "f(){ echo inner; }; f", "function g { echo g; }; g",
  "echo $(echo inner)", "echo `echo inner`", "echo \"$(echo 'a b')\"", "echo $(echo $(echo deep))", "echo `echo \\`echo x\\``",
  "x=$(date)", "x=`pwd`; echo $x", "echo $((1+2))", "echo $(( 2 * 3 ))",
  "cat <<EOF\nhello $X\nEOF", "cat <<'EOF'\nhello $(rm -rf /)\nEOF", "cat <<\"EOF\"\nliteral $X\nEOF", "cat <<-EOF\n\tindented\n\tEOF",
  "cat <<<'here string'", "cat <<< \"$X\"", "cat < f", "echo a > out", "echo a >> out", "echo a 2>/dev/null", "echo a &> out",
  "echo a >| out", "echo a 2>&1 | cat", "echo a > 'my file'", "echo a >out2", "echo a>out3",
  "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"", "git log --format='%H %s'", "git push origin +main", "git push -f",
  "curl -H 'A: b' -d @f https://x.example", "ls -la | grep x | wc -l", "echo a | tee out",
  "echo ＩＧＮＯＲＥ", "echo a\u00a0b", "echo a\u3000b", "ec\u200bho x", "echo \u202eabc",
  "eval echo a", "source f", ". f", "alias x=echo; x a", "echo $'\\u0072m'", "echo {rm,-rf,x}",
  "case x in x) echo a;; esac", "select x in a; do echo $x; break; done", "[[ -f x ]] && echo a", "[ -f x ] || echo b",
  "echo a; # trailing", "echo 'unterminated", "echo \"unterminated", "echo $(", "echo `", "echo )", "( echo a", "{ echo a",
  "echo a |", "echo a &&", "| echo a", "echo <(echo x)", "cat >(echo y)", "coproc echo x",
  "echo ${X/a/b}", "echo ${#X}", "echo ${X:0:2}", "echo ${!X}", "echo $'\\c@'", "echo -e '\\x41'", "printf '%s\\n' a b",
  "echo \"a\" 'b' $'c' $\"d\"", "IFS=x; echo a", "set -f; echo *", "echo a\\\\b", "echo 'a\\b'", "echo \"a\\b\"",
];

const NAMES = ["echo", "rm", "git", "cat", "curl", "ls", "printf", "touch", "mv", "cp", "chmod", "x", "do_thing", "./run.sh"];
const ARGS = [
  "a", "-rf", "--force", "x y", "'q w'", "\"d q\"", "a\\ b", "$X", "\"$X\"", "${X:-z}", "*.log", "{a,b}", "~", "~/k",
  "$'\\x41'", "\"a\"'b'", "''", "\"\"", "\\$", "'$(no)'", "\"$(echo s)\"", "`echo t`", "--msg=\"hi there\"", "a=b",
  "\\'", "'\\'", "\"\\\"\"", "#notcomment", "a#b", "%s", "-", "--", "@", "{}", "\\;", "$((1))", "'a\nb'",
];
const OPS = [";", "&&", "||", "|", "\n", " ; ", " && ", " | "];
const REDIRS = ["", " > out", " >> out", " 2>/dev/null", " < in", " 2>&1", " &> out", " <<< 'h'"];
const WRAPPERS = ["", "sudo ", "env A=1 ", "nice ", "timeout 3 ", "command ", "nohup ", "X=1 "];

function pick<T>(r: () => number, xs: readonly T[]): T {
  return xs[Math.floor(r() * xs.length)]!;
}

function simple(r: () => number): string {
  const n = 1 + Math.floor(r() * 3);
  const args = Array.from({ length: n }, () => pick(r, ARGS)).join(" ");
  return `${pick(r, WRAPPERS)}${pick(r, NAMES)} ${args}${pick(r, REDIRS)}`;
}

function compound(r: () => number, depth = 0): string {
  const k = r();
  if (depth > 1 || k < 0.45) return simple(r);
  if (k < 0.6) return `${compound(r, depth + 1)}${pick(r, OPS)}${compound(r, depth + 1)}`;
  if (k < 0.68) return `( ${compound(r, depth + 1)} )`;
  if (k < 0.76) return `{ ${compound(r, depth + 1)}; }`;
  if (k < 0.84) return `echo "$(${compound(r, depth + 1)})"`;
  if (k < 0.9) return `if ${simple(r)}; then ${simple(r)}; fi`;
  if (k < 0.95) return `for i in a b; do ${simple(r)}; done`;
  return `cat <<${r() < 0.5 ? "'EOF'" : "EOF"}\n${pick(r, ARGS)} $(${pick(r, NAMES)} x)\nEOF`;
}

export function buildCorpus(size = 2400): string[] {
  const r = rng(0x9b0c5);
  const out = new Set<string>(SEEDS);
  while (out.size < size) out.add(compound(r));
  return [...out];
}
