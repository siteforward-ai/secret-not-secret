/**
 * History scanning: scan every version of every file, and every commit
 * message, reachable from a set of revisions.
 */

import { resolve } from "path";
import { findSecretsInText, isBinaryContent } from "./scanner.js";
import type { Finding } from "./scanner.js";
import { isWhitelisted } from "./whitelist.js";
import type { WhitelistEntry } from "./whitelist.js";
import { isExcluded, isConfigFile, isLockfile } from "./paths.js";
import {
  gitLogCommits,
  gitChangedBlobs,
  gitReadBlobs,
  gitHeadTree,
} from "./git.js";

/** Pseudo-path under which secrets found in commit messages are reported. */
export const COMMIT_MESSAGE_PATH = "<commit-message>";

export type HistoryFinding = Finding & {
  /** Repo-relative path, or COMMIT_MESSAGE_PATH. */
  rel: string;
  /** Full sha of the oldest scanned commit in which the value appears at `rel`. */
  commit: string;
  /** Whether HEAD's version of `rel` still contains the value (always false for commit messages). */
  inHead: boolean;
};

export type HistoryResult = {
  findings: HistoryFinding[];
  /** "path@commit" descriptions of blobs that could not be read. */
  unreadable: string[];
};

export type HistoryOptions = {
  /** Repository top-level directory; paths from git are relative to it. */
  repoRoot: string;
  /** Revisions in git rev-list syntax, e.g. ["--all"] or ["main~10..main"]. */
  revs: string[];
  whitelist: WhitelistEntry[];
  excluded: string[];
  /** Absolute paths of the allowlist / excluded-paths files (never scanned). */
  configFiles: string[];
};

const CHUNK = 500;

export function scanHistory(opts: HistoryOptions): HistoryResult {
  const { repoRoot, revs, whitelist, excluded, configFiles } = opts;
  const commits = gitLogCommits(repoRoot, revs);

  const skipPath = new Map<string, boolean>();
  const skipped = (rel: string): boolean => {
    let v = skipPath.get(rel);
    if (v === undefined) {
      const abs = resolve(repoRoot, rel);
      v =
        isLockfile(rel) ||
        isConfigFile(abs, configFiles) ||
        isExcluded(abs, excluded, repoRoot);
      skipPath.set(rel, v);
    }
    return v;
  };

  // Added/modified blobs in commit order (oldest first), minus skipped paths.
  const changes = gitChangedBlobs(
    repoRoot,
    commits.map((c) => c.sha)
  ).filter((c) => !skipped(c.path));

  // Scan each unique blob once. Content is read in chunks and dropped after
  // scanning; only the findings are kept.
  const unique = [...new Set(changes.map((c) => c.blob))];
  const blobFindings = new Map<string, Finding[] | null>(); // null = unreadable
  for (let i = 0; i < unique.length; i += CHUNK) {
    const chunk = unique.slice(i, i + CHUNK);
    const contents = gitReadBlobs(repoRoot, chunk, CHUNK);
    for (const sha of chunk) {
      const buf = contents.get(sha);
      if (!buf) {
        blobFindings.set(sha, null);
      } else if (isBinaryContent(buf)) {
        blobFindings.set(sha, []);
      } else {
        blobFindings.set(sha, findSecretsInText(buf.toString("utf8")));
      }
    }
  }

  const findings: HistoryFinding[] = [];
  const seen = new Set<string>();
  const unreadable: string[] = [];
  const unreadableSeen = new Set<string>();
  const record = (rel: string, commit: string, f: Finding) => {
    const key = `${rel}\t${f.s}`;
    if (seen.has(key) || isWhitelisted(rel, f.s, whitelist)) return;
    seen.add(key);
    findings.push({ ...f, rel, commit, inHead: false });
  };

  // Walk commits oldest-first so the first record of a (path, value) pair is
  // the commit where it first appears.
  let ci = 0;
  for (const commit of commits) {
    for (const f of findSecretsInText(commit.message)) {
      record(COMMIT_MESSAGE_PATH, commit.sha, f);
    }
    while (ci < changes.length && changes[ci].commit === commit.sha) {
      const { path, blob } = changes[ci++];
      const fs = blobFindings.get(blob);
      if (fs === null || fs === undefined) {
        if (!unreadableSeen.has(blob)) {
          unreadableSeen.add(blob);
          unreadable.push(`${path}@${commit.sha.slice(0, 7)}`);
        }
        continue;
      }
      for (const f of fs) record(path, commit.sha, f);
    }
  }

  // Is each value still present in HEAD's version of its file?
  const head = gitHeadTree(repoRoot);
  const headShas = [
    ...new Set(
      findings
        .filter((f) => f.rel !== COMMIT_MESSAGE_PATH && head.has(f.rel))
        .map((f) => head.get(f.rel)!)
    ),
  ];
  const headContent = new Map<string, string>();
  for (let i = 0; i < headShas.length; i += CHUNK) {
    const chunk = headShas.slice(i, i + CHUNK);
    for (const [sha, buf] of gitReadBlobs(repoRoot, chunk, CHUNK)) {
      headContent.set(sha, buf.toString("utf8"));
    }
  }
  for (const f of findings) {
    const sha = f.rel === COMMIT_MESSAGE_PATH ? undefined : head.get(f.rel);
    const content = sha ? headContent.get(sha) : undefined;
    f.inHead = content !== undefined && content.includes(f.s);
  }

  return { findings, unreadable };
}
