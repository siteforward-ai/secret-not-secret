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
 * Whitelist format (not-secret-strings.txt):
 *   Each non-comment line: filepath<whitespace>secret_string
 *   A filepath of '*' matches any file.
 */

import { readFileSync } from "fs";
import { resolve, relative } from "path";
import { findSecretsInText, isBinary } from "./scanner.js";
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
  if (isBinary(filePath)) return [];

  let content: string;
  try {
    content = readFileSync(filePath, "utf8");
  } catch (err) {
    process.stderr.write(`Warning: could not read ${filePath}: ${err}\n`);
    return [];
  }

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
  for (const filePath of files) {
    allFindings.push(...scanFile(filePath, whitelist, excluded));
  }

  if (allFindings.length === 0) return 0;

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
