// Command line: glassbox-hook <event> [--home <dir>]
//
// The state folder is chosen only by the hook's own command line (written by the installer,
// in a protected file) or os.homedir(). No GLASSBOX_* environment variable is read: a
// repository's settings can set environment variables for Claude Code and its hooks.
export function parseArgs(argv: readonly string[], _env: Readonly<Record<string, string | undefined>>, defaultHome: string): { event: string | null; homeDir: string } {
  void _env;
  let event: string | null = null;
  let homeDir = defaultHome;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === "--home") {
      const next = argv[i + 1];
      if (next !== undefined && next.length > 0 && !next.startsWith("--")) {
        homeDir = next;
        i++;
      }
    } else if (event === null && !a.startsWith("--")) {
      event = a;
    }
  }
  return { event, homeDir };
}
