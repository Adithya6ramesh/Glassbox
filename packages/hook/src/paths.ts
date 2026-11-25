// Fixed locations under the user's home folder.
import path from "node:path";

export const glassboxHomeOf = (homeDir: string): string => path.join(homeDir, ".glassbox");

