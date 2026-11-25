#!/usr/bin/env node
/**
 * scan-secrets CLI — finds high-entropy strings in files that may be secrets.
 *
 * Usage:
 *   scan-secrets --all              # Scan all git-tracked files
 *   scan-secrets --staged           # Scan git-staged files (for pre-commit)
 *   scan-secrets file1 file2 ...    # Scan specific files
 *   scan-secrets --all --list       # Emit whitelist lines for review
 *   scan-secrets --history          # Scan every commit reachable from any ref
 *   scan-secrets --history main~10..main   # Scan only commits in a rev-range
 *
 * --history scans every version of every file (each unique blob once) and
 * every commit message. Each finding names the commit where it first appears
 * and whether the value is still in HEAD's version of the file ("still in
 * HEAD") or only in history ("removed"). Commit-message findings use the
 * pseudo-path <commit-message>. Paths are relative to the repository root.
 *
 * Options:
 *   --whitelist <path>       Path to whitelist file (default: not-secret-strings.txt)
 *   --excluded-paths <path>  Path to excluded-paths file (default: not-secret-paths.txt)
 *
 * Exit codes: 0 = clean, 1 = potential secrets found,
 *             2 = no secrets found, but some files could not be read (not scanned)
 *
 * Whitelist format (not-secret-strings.txt):
 *   Each non-comment line: filepath<whitespace>secret_string
 *   A filepath of '*' matches any file.
 */

import { readFileSync } from "fs";
import { resolve, relative, sep } from "path";
import { findSecretsInText, isBinaryContent } from "./scanner.js";
import { loadWhitelist, isWhitelisted } from "./whitelist.js";
import { loadExcludedPaths, isExcluded, isConfigFile, isLockfile } from "./paths.js";
import { gitLsFiles, gitStagedFiles, gitShowStaged, gitTopLevel } from "./git.js";
import { scanHistory, COMMIT_MESSAGE_PATH } from "./history.js";
import type { WhitelistEntry } from "./whitelist.js";

const REPO_ROOT = process.cwd();

const USAGE =
  "Usage: scan-secrets [--all|--staged|--history [<rev-range>]|file1 file2 ...] [--list]\n" +
  "                    [--whitelist <path>] [--excluded-paths <path>]\n";

type FileFinding = {
  rel: string;
  lineNo: number;
  s: string;
  entropy: number;
  kind: string;
};

function scanFile(
  filePath: string,
  whitelist: WhitelistEntry[],
  excluded: string[],
  staged = false
): FileFinding[] {
  if (isExcluded(filePath, excluded, REPO_ROOT)) return [];

  const rel = relative(REPO_ROOT, resolve(filePath));
  // Read once; throws if the content cannot be read (reported by the caller).
  // In staged mode scan the index version, not the working tree copy.
  const buf = staged
    ? gitShowStaged(REPO_ROOT, rel.split(sep).join("/"))
    : readFileSync(filePath);
  if (isBinaryContent(buf)) return [];
  const content = buf.toString("utf8");

  return findSecretsInText(content)
    .filter(({ s }) => !isWhitelisted(rel, s, whitelist))
    .map(({ lineNo, s, entropy, kind }) => ({ rel, lineNo, s, entropy, kind }));
}

function main(): number {
  const args = process.argv.slice(2);
  const listMode = args.includes("--list");

  // Extract --whitelist and --excluded-paths options
  let whitelistPath = resolve(REPO_ROOT, "not-secret-strings.txt");
  let excludedPathsPath = resolve(REPO_ROOT, "not-secret-paths.txt");

  const filteredArgs: string[] = [];
  let history = false;
  let revRange: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--history") {
      history = true;
      // An optional rev-range follows; anything starting with "-" is the
      // next option, never a revision passed to git.
      if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
        revRange = args[++i];
      }
    } else if (args[i].startsWith("--history=")) {
      history = true;
      revRange = args[i].slice("--history=".length);
      if (!revRange || revRange.startsWith("-")) {
        process.stderr.write(
          `Error: invalid rev-range for --history: '${revRange}'\n` + USAGE
        );
        return 1;
      }
    } else if (args[i] === "--whitelist" && i + 1 < args.length) {
      whitelistPath = resolve(args[++i]);
    } else if (args[i] === "--excluded-paths" && i + 1 < args.length) {
      excludedPathsPath = resolve(args[++i]);
    } else if (args[i] !== "--list") {
      filteredArgs.push(args[i]);
    }
  }

  if (history) {
    if (filteredArgs.length > 0) {
      process.stderr.write(
        "Error: --history cannot be combined with --all, --staged or file names\n" +
          USAGE
      );
      return 1;
    }
    return runHistory(revRange, whitelistPath, excludedPathsPath, listMode);
  }

  let files: string[];
  const staged =
    !filteredArgs.includes("--all") && filteredArgs.includes("--staged");
  if (filteredArgs.includes("--all")) {
    files = gitLsFiles(REPO_ROOT).filter((f) => !isLockfile(f));
  } else if (filteredArgs.includes("--staged")) {
    files = gitStagedFiles(REPO_ROOT).filter((f) => !isLockfile(f));
  } else if (filteredArgs.length > 0) {
    files = filteredArgs.map((f) => resolve(f));
  } else {
    process.stderr.write(USAGE);
    return 1;
  }

  const whitelist = loadWhitelist(whitelistPath);
  const excluded = loadExcludedPaths(excludedPathsPath);

  const allFindings: FileFinding[] = [];
  // Never scan the allowlist / excluded-paths files themselves: they hold
  // allowed values by design and would otherwise flag every entry.
  const configFiles = [whitelistPath, excludedPathsPath];
  const unreadable: string[] = [];
  for (const filePath of files) {
    if (isConfigFile(filePath, configFiles)) continue;
    try {
      allFindings.push(...scanFile(filePath, whitelist, excluded, staged));
    } catch (err) {
      unreadable.push(filePath);
      const reason = err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `Error: could not read ${relative(REPO_ROOT, resolve(filePath))}, not scanned: ${reason}\n`
      );
    }
  }

  // Exit codes: 0 = clean, 1 = potential secrets found,
  // 2 = no secrets found but one or more files could not be read/scanned.
  const unreadableExit = unreadable.length > 0 ? 2 : 0;
  if (unreadable.length > 0) {
    process.stderr.write(`${unreadable.length} file(s) could not be scanned.\n`);
  }

  if (allFindings.length === 0) return unreadableExit;

  if (listMode) {
    // Output unique (filepath, secret) pairs ready to paste into not-secret-strings.txt
    const seen = new Set<string>();
    for (const { rel, s } of allFindings) {
      const key = `${rel}\t${s}`;
      if (!seen.has(key)) {
        seen.add(key);
        process.stdout.write(`${rel}  ${s}\n`);
      }
    }
    return 1;
  }

  // Normal mode: print a diagnostic comment then the copy-pasteable whitelist line
  const seen = new Set<string>();
  for (const { rel, lineNo, s, entropy, kind } of allFindings) {
    const key = `${rel}\t${s}`;
    if (!seen.has(key)) {
      seen.add(key);
      process.stdout.write(
        `# ${rel}:${lineNo} [${kind}, entropy=${entropy.toFixed(2)}]\n` +
          `${rel}  ${s}\n`
      );
    }
  }

  process.stderr.write(
    `\nFound ${seen.size} potential secret(s). ` +
      "Add to not-secret-strings.txt if safe.\n"
  );
  return 1;
}

function runHistory(
  revRange: string | undefined,
  whitelistPath: string,
  excludedPathsPath: string,
  listMode: boolean
): number {
  let result;
  try {
    const repoRoot = gitTopLevel(REPO_ROOT);
    result = scanHistory({
      repoRoot,
      revs: revRange === undefined ? ["--all"] : [revRange],
      whitelist: loadWhitelist(whitelistPath),
      excluded: loadExcludedPaths(excludedPathsPath),
      configFiles: [whitelistPath, excludedPathsPath],
    });
  } catch (err) {
    const reason =
      err instanceof Error && "stderr" in err && String(err.stderr).trim()
        ? String(err.stderr).trim()
        : err instanceof Error
          ? err.message
          : String(err);
    process.stderr.write(`Error: could not scan git history: ${reason}\n`);
    return 2;
  }

  const { findings, unreadable } = result;
  for (const u of unreadable) {
    process.stderr.write(`Error: could not read ${u}, not scanned\n`);
  }
  if (unreadable.length > 0) {
    process.stderr.write(`${unreadable.length} blob(s) could not be scanned.\n`);
  }
  if (findings.length === 0) return unreadable.length > 0 ? 2 : 0;

  for (const { rel, lineNo, s, entropy, kind, commit, inHead } of findings) {
    if (!listMode) {
      const short = commit.slice(0, 7);
      const where =
        rel === COMMIT_MESSAGE_PATH
          ? `in commit ${short}`
          : `first seen in ${short}, ${inHead ? "still in HEAD" : "removed"}`;
      process.stdout.write(
        `# ${rel}:${lineNo} [${kind}, entropy=${entropy.toFixed(2)}] ${where}\n`
      );
    }
    process.stdout.write(`${rel}  ${s}\n`);
  }
  if (!listMode) {
    process.stderr.write(
      `\nFound ${findings.length} potential secret(s) in history. ` +
        "Add to not-secret-strings.txt if safe; values still in history " +
        "need rotating or a history rewrite before publishing.\n"
    );
  }
  return 1;
}

process.exit(main());
