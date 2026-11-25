import {
  BASE64_CHARS,
  URLSAFE_CHARS,
  HEX_CHARS,
  MIN_LENGTH,
  ENTROPY_THRESHOLD_B64,
  ENTROPY_THRESHOLD_HEX,
  shannonEntropy,
} from "./entropy.js";
import { openSync, readSync, closeSync } from "fs";

// ── Minimal safe-string patterns ──────────────────────────────────────────────
// Only patterns where a match is UNAMBIGUOUSLY not a secret.

const SAFE_PATTERNS: RegExp[] = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, // UUID
  /^[0-9a-f]{40}$/, // git SHA (lower)
  /^[0-9A-F]{40}$/, // git SHA (upper)
  /^[a-z]{20,}$/, // all lowercase
  /^[A-Z]{20,}$/, // all uppercase
  /^[A-Za-z_]{20,}$/, // letters + underscores only
  /^(https?|ftp|wss?):\/\//, // URLs
  /^--[a-z][a-z0-9-]+$/, // CSS custom properties
];

// File/module path: at least two slash-separated word segments
const PATH_LIKE = /^\/?[a-zA-Z][a-zA-Z0-9_.-]*\/[a-zA-Z][a-zA-Z0-9_./:-]*$/;

export function isSafe(s: string): boolean {
  if (SAFE_PATTERNS.some((p) => p.test(s))) return true;
  if (PATH_LIKE.test(s)) return true;
  return false;
}

// Subresource Integrity / lockfile integrity hashes, e.g. "sha512-<base64>".
// The extraction regexes below split on "-", so the base64 payload is matched
// on its own; we instead record the span of each SRI string in the line and
// skip any candidate that falls inside one.
const SRI_PATTERN = /\bsha(?:512|384|256|1)-[A-Za-z0-9+/]+={0,2}/g;

function sriSpans(line: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  for (const m of line.matchAll(SRI_PATTERN)) {
    spans.push([m.index!, m.index! + m[0].length]);
  }
  return spans;
}

export type Finding = { lineNo: number; s: string; entropy: number; kind: string };

export function findSecretsInText(content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  let spans: Array<[number, number]> = [];

  function add(
    lineNo: number,
    m: RegExpMatchArray,
    s: string,
    entropy: number,
    kind: string
  ) {
    const start = m.index!;
    const end = start + m[0].length;
    if (spans.some(([a, b]) => start >= a && end <= b)) return;
    if (!seen.has(s) && !isSafe(s)) {
      seen.add(s);
      findings.push({ lineNo, s, entropy, kind });
    }
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i];
    spans = sriSpans(line);

    // URL-safe base64 / JWT / API tokens (alphanumeric + hyphen + underscore)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9_\\-]{${MIN_LENGTH},}`, "g")
    )) {
      const s = m[0];
      const e = shannonEntropy(s, URLSAFE_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, m, s, e, "token");
    }

    // Standard base64 (includes + and /)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9+/]{${MIN_LENGTH},}={0,2}`, "g")
    )) {
      const s = m[0];
      const stripped = s.replace(/=+$/, "");
      if (stripped.includes("/") && PATH_LIKE.test(stripped)) continue;
      const e = shannonEntropy(stripped, BASE64_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, m, s, e, "base64");
    }

    // Hex strings (32+ chars)
    for (const m of line.matchAll(/[0-9a-fA-F]{32,}/g)) {
      const s = m[0];
      const e = shannonEntropy(s, HEX_CHARS);
      if (e >= ENTROPY_THRESHOLD_HEX) add(lineNo, m, s, e, "hex");
    }
  }

  return findings;
}

export function isBinary(filePath: string): boolean {
  try {
    const buf = Buffer.alloc(8192);
    const fd = openSync(filePath, "r");
    const bytesRead = readSync(fd, buf, 0, 8192, 0);
    closeSync(fd);
    return buf.subarray(0, bytesRead).includes(0);
  } catch {
    return true;
  }
}
