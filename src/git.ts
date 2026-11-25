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

const MAX_BUFFER = 1024 * 1024 * 1024;

/** Absolute path of the top-level directory of the repository containing `cwd`. */
export function gitTopLevel(cwd: string): string {
  return execFileSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();
}

export type CommitInfo = { sha: string; message: string };

/**
 * Commits reachable from `revs` (git rev-list syntax, e.g. ["--all"] or
 * ["main~10..main"]), oldest first (parents before children), with their
 * full messages. Throws if git rejects the revisions.
 */
export function gitLogCommits(repoRoot: string, revs: string[]): CommitInfo[] {
  // -z separates commits with NUL; commit messages cannot contain NUL.
  // The trailing "--" stops git from treating a revision as a path.
  const out = execFileSync(
    "git",
    ["log", "-z", "--reverse", "--topo-order", "--format=%H%n%B", ...revs, "--"],
    { cwd: repoRoot, maxBuffer: MAX_BUFFER, stdio: ["ignore", "pipe", "pipe"] }
  ).toString();
  return out
    .split("\0")
    .filter(Boolean)
    .map((rec) => {
      const nl = rec.indexOf("\n");
      return nl === -1
        ? { sha: rec.trim(), message: "" }
        : { sha: rec.slice(0, nl).trim(), message: rec.slice(nl + 1) };
    })
    .filter((c) => c.sha);
}

export type BlobChange = { commit: string; path: string; blob: string };

/**
 * Blobs added or modified by each commit (compared with each parent for
 * merges, and with the empty tree for root commits), in the order the
 * commits are given. Deletions and submodule (gitlink) entries are skipped.
 * Uses a single `git diff-tree --stdin` process.
 */
export function gitChangedBlobs(repoRoot: string, commits: string[]): BlobChange[] {
  if (commits.length === 0) return [];
  const out = execFileSync(
    "git",
    ["diff-tree", "--stdin", "-r", "-m", "--root", "--no-renames", "-z"],
    { cwd: repoRoot, input: commits.join("\n") + "\n", maxBuffer: MAX_BUFFER }
  ).toString();
  // Output is a NUL-separated token stream: a commit id, then for each
  // change a ":<modes> <shas> <status>" token followed by its path token.
  const tokens = out.split("\0");
  const changes: BlobChange[] = [];
  let commit = "";
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t) continue;
    if (t.startsWith(":")) {
      const path = tokens[++i];
      const [, newMode, , newSha, status] = t.slice(1).split(" ");
      if (!path || status === "D" || newMode === "160000") continue;
      if (!newSha || /^0+$/.test(newSha)) continue;
      changes.push({ commit, path, blob: newSha });
    } else {
      // A merge diffed with -m may print "<sha> (from <parent>)".
      commit = t.trim().split(/\s/)[0];
    }
  }
  return changes;
}

/**
 * Read many objects with `git cat-file --batch` (one process per chunk),
 * returning a map from object name to content. Objects git reports as
 * missing are absent from the result.
 */
export function gitReadBlobs(
  repoRoot: string,
  names: string[],
  chunkSize = 500
): Map<string, Buffer> {
  const result = new Map<string, Buffer>();
  for (let start = 0; start < names.length; start += chunkSize) {
    const chunk = names.slice(start, start + chunkSize);
    const out = execFileSync("git", ["cat-file", "--batch"], {
      cwd: repoRoot,
      input: chunk.join("\n") + "\n",
      maxBuffer: MAX_BUFFER,
    });
    let pos = 0;
    for (const name of chunk) {
      const nl = out.indexOf(0x0a, pos);
      if (nl === -1) break;
      // "<sha> <type> <size>", or "<name> missing" / "<name> ambiguous"
      const parts = out.subarray(pos, nl).toString().split(" ");
      pos = nl + 1;
      const size = Number(parts[parts.length - 1]);
      if (parts.length < 3 || !Number.isInteger(size)) continue;
      result.set(name, out.subarray(pos, pos + size));
      pos += size + 1; // content is followed by a newline
    }
  }
  return result;
}

/**
 * Map of repo-relative path -> blob sha for every file in HEAD's tree.
 * Returns an empty map when there is no HEAD commit.
 */
export function gitHeadTree(repoRoot: string): Map<string, string> {
  const tree = new Map<string, string>();
  let out: string;
  try {
    out = execFileSync("git", ["ls-tree", "-r", "-z", "HEAD"], {
      cwd: repoRoot,
      maxBuffer: MAX_BUFFER,
      stdio: ["ignore", "pipe", "ignore"],
    }).toString();
  } catch {
    return tree;
  }
  for (const rec of out.split("\0")) {
    // "<mode> <type> <sha>\t<path>"
    const tab = rec.indexOf("\t");
    if (tab === -1) continue;
    const [, type, sha] = rec.slice(0, tab).split(" ");
    if (type === "blob") tree.set(rec.slice(tab + 1), sha);
  }
  return tree;
}
