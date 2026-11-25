// Fixed locations under the user's home folder.
import path from "node:path";

export const glassboxHomeOf = (homeDir: string): string => path.join(homeDir, ".glassbox");

/** Node's compile cache for the hook: inside ~/.glassbox, so the engine protects it. */
export const compileCacheDir = (homeDir: string): string => path.join(glassboxHomeOf(homeDir), "cache", "node-compile");
