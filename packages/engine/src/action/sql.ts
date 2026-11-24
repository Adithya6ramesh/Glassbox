// SQL tokenizer and classifier. Linear, no regex on input.
import { Acc } from "./acc.js";

interface Tok { k: "word" | "str" | "num" | "punct"; v: string }

function tokenize(sql: string): Tok[][] | string {
  const stmts: Tok[][] = [[]];
  let i = 0;
  const n = sql.length;
  const cur = () => stmts[stmts.length - 1] as Tok[];
  while (i < n) {
    const c = sql[i] as string;
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f") { i++; continue; }
    if (c === "-" && sql[i + 1] === "-") { while (i < n && sql[i] !== "\n") i++; continue; }
    if (c === "#" ) { while (i < n && sql[i] !== "\n") i++; continue; }
    if (c === "/" && sql[i + 1] === "*") {
      const end = sql.indexOf("*/", i + 2);
      if (end < 0) return "unterminated comment";
      if (sql.slice(i + 2, end).includes("/*")) return "nested comment";
      i = end + 2;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      let v = "";
      for (;;) {
        if (j >= n) return "unterminated string";
        if (sql[j] === c) { if (sql[j + 1] === c) { v += c; j += 2; continue; } break; }
        if (sql[j] === "\\" && c === "'") { v += sql[j + 1] ?? ""; j += 2; continue; }
        v += sql[j];
        j++;
      }
      cur().push({ k: c === "'" ? "str" : "word", v: c === "'" ? v : v.toUpperCase() });
      i = j + 1;
      continue;
    }
    if (c === "$") {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(sql[j] as string)) j++;
      if (sql[j] === "$") {
        const tag = sql.slice(i, j + 1);
        const end = sql.indexOf(tag, j + 1);
        if (end < 0) return "unterminated dollar quote";
        cur().push({ k: "str", v: sql.slice(j + 1, end) });
        i = end + tag.length;
        continue;
      }
    }
    if (c === ";") { stmts.push([]); i++; continue; }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_$]/.test(sql[j] as string)) j++;
      cur().push({ k: "word", v: sql.slice(i, j).toUpperCase() });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      while (j < n && /[0-9.eE]/.test(sql[j] as string)) j++;
      cur().push({ k: "num", v: sql.slice(i, j) });
      i = j;
      continue;
    }
    cur().push({ k: "punct", v: c });
    i++;
  }
  return stmts.filter((s) => s.length > 0);
}

function tautology(where: Tok[]): boolean {
  if (where.length === 0) return true;
  const first = where[0];
  if (where.length === 1 && first && ((first.k === "word" && first.v === "TRUE") || (first.k === "num" && first.v !== "0"))) return true;
  for (let i = 0; i + 2 < where.length; i++) {
    const a = where[i] as Tok, op = where[i + 1] as Tok, b = where[i + 2] as Tok;
    if (op.k === "punct" && op.v === "=" && a.k === b.k && a.v === b.v && a.k !== "punct") {
      const prev = where[i - 1];
      const next = where[i + 3];
      const standalone = (!prev || prev.v === "OR" || prev.v === "WHERE" || prev.v === "(" || i === 0) && (!next || next.v === "OR" || next.v === ")" || next.v === "AND" && i === 0);
      if (standalone || where.length === 3) return true;
    }
    if (a.v === "OR" && (b.v === "TRUE" || (op.k === "num" && op.v === "1" && !b))) return true;
  }
  return where.some((t, k) => t.v === "OR" && (where[k + 1]?.v === "TRUE"));
}

export function analyzeSql(sql: string, maxBytes: number): Acc {
  const acc = new Acc();
  if (sql.length > maxBytes) { acc.unanalyzable("SQL longer than the analysis limit"); return acc; }
  const stmts = tokenize(sql);
  if (typeof stmts === "string") { acc.unanalyzable(`SQL ${stmts}`); return acc; }
  for (const s of stmts) {
    let k = 0;
    while (s[k]?.v === "(") k++;
    const first = s[k]?.v ?? "";
    const words = s.filter((t) => t.k === "word").map((t) => t.v);
    const whereIdx = s.findIndex((t) => t.k === "word" && t.v === "WHERE");
    const whereToks = whereIdx >= 0 ? s.slice(whereIdx + 1) : null;
    switch (first) {
      case "SELECT": case "SHOW": case "DESCRIBE": case "DESC": case "VALUES": case "TABLE":
        acc.tag("read", "db.read");
        break;
      case "EXPLAIN":
        if (words.includes("ANALYZE")) acc.tag("write-reversible", "db.write");
        else acc.tag("read", "db.read");
        break;
      case "WITH": {
        const w = ["DELETE", "UPDATE", "INSERT", "MERGE"].find((x) => words.includes(x));
        if (!w) { acc.tag("read", "db.read"); break; }
        if (w === "DELETE" || w === "UPDATE") {
          if (whereToks === null || tautology(whereToks)) { acc.tag("high-risk", "db.unscoped-write"); acc.find("CP-ACTION-020"); }
          else acc.tag(w === "DELETE" ? "high-risk" : "write-reversible", w === "DELETE" ? "db.delete" : "db.write");
        } else acc.tag("write-reversible", "db.write");
        break;
      }
      case "INSERT": case "UPSERT": case "REPLACE": case "MERGE":
        acc.tag("write-reversible", "db.write");
        break;
      case "COPY":
        if (words.includes("PROGRAM")) { acc.unanalyzable("COPY … PROGRAM runs a shell command"); break; }
        acc.tag(words.includes("FROM") ? "write-reversible" : "read", words.includes("FROM") ? "db.write" : "db.read");
        break;
      case "UPDATE":
        if (whereToks === null || tautology(whereToks)) { acc.tag("high-risk", "db.unscoped-write"); acc.find("CP-ACTION-020"); acc.reason("updates every row"); }
        else acc.tag("write-reversible", "db.write");
        break;
      case "DELETE":
        if (whereToks === null || tautology(whereToks)) { acc.tag("high-risk", "db.unscoped-write", "db.delete"); acc.find("CP-ACTION-020"); acc.reason("deletes every row"); }
        else acc.tag("high-risk", "db.delete");
        break;
      case "DROP": case "TRUNCATE":
        acc.tag("high-risk", "db.ddl");
        acc.find("CP-ACTION-021");
        acc.reason("drops or truncates a table");
        break;
      case "ALTER":
        if (s[k + 1]?.v === "ROLE" || s[k + 1]?.v === "USER") acc.tag("high-risk", "perm.change");
        else acc.tag("high-risk", "db.ddl");
        break;
      case "CREATE":
        if (s[k + 1]?.v === "ROLE" || s[k + 1]?.v === "USER") acc.tag("high-risk", "perm.change");
        else if (s[k + 1]?.v === "OR" && s[k + 2]?.v === "REPLACE") acc.tag("high-risk", "db.ddl");
        else if (words.includes("FUNCTION") || words.includes("PROCEDURE") || words.includes("TRIGGER")) acc.tag("high-risk", "db.ddl");
        else acc.tag("write-reversible", "db.write");
        break;
      case "RENAME":
        acc.tag("high-risk", "db.ddl");
        break;
      case "GRANT": case "REVOKE":
        acc.tag("high-risk", "perm.change");
        break;
      case "BEGIN": case "COMMIT": case "ROLLBACK": case "START": case "SAVEPOINT": case "RELEASE": case "USE": case "SET": case "END":
        break;
      case "ANALYZE": case "VACUUM": case "REINDEX": case "CLUSTER":
        acc.tag("write-reversible", "db.write");
        break;
      case "PRAGMA":
        if (s.some((t) => t.v === "=")) acc.unanalyzable("PRAGMA that writes settings");
        else acc.tag("read", "db.read");
        break;
      default:
        acc.unanalyzable(first ? `SQL statement ${first.slice(0, 20)} isn't analyzed` : "SQL statement couldn't be classified");
    }
  }
  return acc;
}
