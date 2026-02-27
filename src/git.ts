import { execSync } from "child_process";
import { resolve } from "path";

export function gitLsFiles(repoRoot: string): string[] {
  const out = execSync("git ls-files", { cwd: repoRoot }).toString();
  return out
    .split("\n")
    .filter(Boolean)
    .map((f) => resolve(repoRoot, f));
}

export function gitStagedFiles(repoRoot: string): string[] {
  const out = execSync(
    "git diff --cached --name-only --diff-filter=ACM",
    { cwd: repoRoot }
  ).toString();
  return out
    .split("\n")
    .filter(Boolean)
    .map((f) => resolve(repoRoot, f));
}
