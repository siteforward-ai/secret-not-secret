import { execFileSync, execSync } from "child_process";
import { resolve } from "path";

export function gitLsFiles(repoRoot: string): string[] {
  const out = execSync("git ls-files", { cwd: repoRoot }).toString();
  return out
    .split("\n")
    .filter(Boolean)
    .map((f) => resolve(repoRoot, f));
}

export function gitStagedFiles(repoRoot: string): string[] {
  // Files deleted in the index (D) have no staged content, so they are skipped.
  const out = execFileSync(
    "git",
    ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
    { cwd: repoRoot }
  ).toString();
  return out
    .split("\0")
    .filter(Boolean)
    .map((f) => resolve(repoRoot, f));
}

/** Read the staged (index) version of a file, given its path relative to the repo root. */
export function gitShowStaged(repoRoot: string, relPath: string): Buffer {
  return execFileSync("git", ["show", `:${relPath}`], {
    cwd: repoRoot,
    maxBuffer: 1024 * 1024 * 1024,
  });
}
