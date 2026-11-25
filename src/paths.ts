import { existsSync, readFileSync } from "fs";
import { basename, resolve, relative } from "path";
import { matchesPattern } from "./whitelist.js";

export function loadExcludedPaths(excludedPathsFile: string): string[] {
  if (!existsSync(excludedPathsFile)) return [];
  return readFileSync(excludedPathsFile, "utf8")
    .split("\n")
    .filter((line) => line.trim() && !line.startsWith("#"));
}

export function isExcluded(
  filePath: string,
  patterns: string[],
  repoRoot: string
): boolean {
  let rel: string;
  try {
    rel = relative(repoRoot, resolve(filePath));
  } catch {
    rel = filePath;
  }
  for (const pattern of patterns) {
    if (pattern.endsWith("/") && rel.startsWith(pattern)) return true;
    if (matchesPattern(rel, pattern)) return true;
    if (matchesPattern(basename(rel), pattern)) return true;
  }
  return false;
}

/**
 * True when `filePath` is one of the scanner's own config files (the
 * allowlist or excluded-paths file). These files hold allowed values by
 * design, so they must never be scanned. Paths are compared after resolving
 * them to absolute paths.
 */
export function isConfigFile(filePath: string, configFiles: string[]): boolean {
  const abs = resolve(filePath);
  return configFiles.some((f) => resolve(f) === abs);
}
