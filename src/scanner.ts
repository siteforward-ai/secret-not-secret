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

// ── Known secret prefixes (always reported, regardless of entropy) ────────────
// Each pattern requires a minimum body after the prefix so bare prefixes in
// docs (e.g. "keys start with sk_live_") are not flagged.

const NOT_IN_WORD = "(?<![A-Za-z0-9_])";

export const KNOWN_SECRET_PATTERNS: { kind: string; re: RegExp }[] = [
  { kind: "aws-key-id", re: new RegExp(`${NOT_IN_WORD}(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])`, "g") },
  { kind: "private-key", re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}(?:sk|rk)_live_[A-Za-z0-9]{10,}`, "g") },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}whsec_[A-Za-z0-9+/=]{16,}`, "g") },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}ghp_[A-Za-z0-9]{20,}`, "g") },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}github_pat_[A-Za-z0-9_]{20,}`, "g") },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}xox[bpa]-[A-Za-z0-9-]{10,}`, "g") },
  { kind: "known-prefix", re: new RegExp(`${NOT_IN_WORD}sk-ant-[A-Za-z0-9_-]{20,}`, "g") },
];

// ── Known public ID prefixes (never reported as entropy findings) ─────────────
// Stripe object IDs that are public by design: prices, products, webhook
// endpoints, billing portal configurations.

export const PUBLIC_ID_PREFIXES = ["price_", "prod_", "we_", "bpc_"];

const PUBLIC_ID_RE = new RegExp(
  `${NOT_IN_WORD}(?:${PUBLIC_ID_PREFIXES.join("|")})[A-Za-z0-9]+`,
  "g"
);

type Span = [number, number];

function overlaps(spans: Span[], start: number, end: number): boolean {
  return spans.some(([s, e]) => start < e && end > s);
}

export type Finding = { lineNo: number; s: string; entropy: number; kind: string };

export function findSecretsInText(content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  function add(lineNo: number, s: string, entropy: number, kind: string) {
    if (!seen.has(s) && !isSafe(s)) {
      seen.add(s);
      findings.push({ lineNo, s, entropy, kind });
    }
  }

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i];

    // Known secret prefixes: always reported (allowlist still applies later).
    // Their spans, plus public ID spans, are excluded from the entropy passes.
    const skip: Span[] = [];
    for (const { kind, re } of KNOWN_SECRET_PATTERNS) {
      for (const m of line.matchAll(re)) {
        const s = m[0];
        skip.push([m.index!, m.index! + s.length]);
        if (!seen.has(s)) {
          seen.add(s);
          findings.push({ lineNo, s, entropy: shannonEntropy(s, URLSAFE_CHARS), kind });
        }
      }
    }
    for (const m of line.matchAll(PUBLIC_ID_RE)) {
      skip.push([m.index!, m.index! + m[0].length]);
    }
    const skipped = (m: RegExpMatchArray) =>
      skip.length > 0 && overlaps(skip, m.index!, m.index! + m[0].length);

    // URL-safe base64 / JWT / API tokens (alphanumeric + hyphen + underscore)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9_\\-]{${MIN_LENGTH},}`, "g")
    )) {
      if (skipped(m)) continue;
      const s = m[0];
      const e = shannonEntropy(s, URLSAFE_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "token");
    }

    // Standard base64 (includes + and /)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9+/]{${MIN_LENGTH},}={0,2}`, "g")
    )) {
      if (skipped(m)) continue;
      const s = m[0];
      const stripped = s.replace(/=+$/, "");
      if (stripped.includes("/") && PATH_LIKE.test(stripped)) continue;
      const e = shannonEntropy(stripped, BASE64_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "base64");
    }

    // Hex strings (32+ chars)
    for (const m of line.matchAll(/[0-9a-fA-F]{32,}/g)) {
      if (skipped(m)) continue;
      const s = m[0];
      const e = shannonEntropy(s, HEX_CHARS);
      if (e >= ENTROPY_THRESHOLD_HEX) add(lineNo, s, e, "hex");
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
