#!/usr/bin/env node
/**
 * scan-secrets CLI — finds high-entropy strings in files that may be secrets.
 *
 * Usage:
 *   scan-secrets --all              # Scan all git-tracked files
 *   scan-secrets --staged           # Scan git-staged files (for pre-commit)
 *   scan-secrets file1 file2 ...    # Scan specific files
 *   scan-secrets --all --list       # Emit whitelist lines for review
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
import { resolve, relative } from "path";
import { findSecretsInText, isBinaryContent } from "./scanner.js";
import { loadWhitelist, isWhitelisted } from "./whitelist.js";
import { loadExcludedPaths, isExcluded } from "./paths.js";
import { gitLsFiles, gitStagedFiles } from "./git.js";
import type { WhitelistEntry } from "./whitelist.js";

const REPO_ROOT = process.cwd();

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
  excluded: string[]
): FileFinding[] {
  if (isExcluded(filePath, excluded, REPO_ROOT)) return [];

  // Read once; throws if the file cannot be read (reported by the caller).
  const buf = readFileSync(filePath);
  if (isBinaryContent(buf)) return [];
  const content = buf.toString("utf8");

  const rel = relative(REPO_ROOT, resolve(filePath));
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
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--whitelist" && i + 1 < args.length) {
      whitelistPath = resolve(args[++i]);
    } else if (args[i] === "--excluded-paths" && i + 1 < args.length) {
      excludedPathsPath = resolve(args[++i]);
    } else if (args[i] !== "--list") {
      filteredArgs.push(args[i]);
    }
  }

  let files: string[];
  if (filteredArgs.includes("--all")) {
    files = gitLsFiles(REPO_ROOT);
  } else if (filteredArgs.includes("--staged")) {
    files = gitStagedFiles(REPO_ROOT);
  } else if (filteredArgs.length > 0) {
    files = filteredArgs.map((f) => resolve(f));
  } else {
    process.stderr.write(
      "Usage: scan-secrets [--all|--staged|file1 file2 ...] [--list]\n" +
        "                   [--whitelist <path>] [--excluded-paths <path>]\n"
    );
    return 1;
  }

  const whitelist = loadWhitelist(whitelistPath);
  const excluded = loadExcludedPaths(excludedPathsPath);

  const allFindings: FileFinding[] = [];
  const unreadable: string[] = [];
  for (const filePath of files) {
    try {
      allFindings.push(...scanFile(filePath, whitelist, excluded));
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

process.exit(main());
