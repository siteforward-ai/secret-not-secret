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
 * Lockfiles skipped by default when scanning via `--all` / `--staged`.
 * Matched by basename in any directory. Files named explicitly on the
 * command line are still scanned.
 */
export const DEFAULT_LOCKFILES: readonly string[] = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "poetry.lock",
  "composer.lock",
  "go.sum",
];

export function isLockfile(filePath: string): boolean {
  return DEFAULT_LOCKFILES.includes(basename(filePath));
}
