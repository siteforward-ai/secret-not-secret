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

// URL host names (e.g. `abc123….lambda-url.us-east-1.on.aws`) often contain
// random-looking labels. Matches that fall entirely inside the host part of a
// URL are skipped. Userinfo (`user:pass@`), ports, paths and query strings are
// still scanned.
const URL_AUTHORITY = /\b(?:https?|ftp|wss?):(\/\/)([^\/?#\s"'`<>]*)/gi;

function urlHostSpans(line: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  for (const m of line.matchAll(URL_AUTHORITY)) {
    const slashStart = m.index! + m[0].length - m[2].length - 2;
    const authStart = slashStart + 2;
    const authority = m[2];
    const at = authority.lastIndexOf("@");
    const hostStart = authStart + at + 1;
    let host = authority.slice(at + 1);
    const port = host.startsWith("[") ? host.indexOf("]:") + 1 : host.indexOf(":");
    if (port > 0) host = host.slice(0, port);
    const hostEnd = hostStart + host.length;
    // With no userinfo, let the span cover the leading "//" too, since the
    // base64 pattern (which includes "/") picks it up as part of the match.
    spans.push([at === -1 ? slashStart : hostStart, hostEnd]);
  }
  return spans;
}

export type Finding = { lineNo: number; s: string; entropy: number; kind: string };

export function findSecretsInText(content: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i];
    // Spans to skip entirely: SRI integrity hashes and URL host names.
    const spans = [...sriSpans(line), ...urlHostSpans(line)];
    // Candidates on this line, with their positions, so that a match lying
    // inside a longer match (e.g. base64 inside a token) is reported once.
    const candidates: (Finding & { start: number; end: number })[] = [];

    const add = (s: string, entropy: number, kind: string, start = 0) => {
      const end = start + s.length;
      if (spans.some(([a, b]) => start >= a && end <= b)) return;
      if (!isSafe(s)) {
        candidates.push({ lineNo, s, entropy, kind, start, end });
      }
    };

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
      if (e >= ENTROPY_THRESHOLD_B64) add(s, e, "token", m.index);
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
      if (e >= ENTROPY_THRESHOLD_B64) add(s, e, "base64", m.index);
    }

    // Hex strings (32+ chars)
    for (const m of line.matchAll(/[0-9a-fA-F]{32,}/g)) {
      if (skipped(m)) continue;
      const s = m[0];
      const e = shannonEntropy(s, HEX_CHARS);
      if (e >= ENTROPY_THRESHOLD_HEX) add(s, e, "hex", m.index);
    }

    candidates.forEach((c, ci) => {
      const contained = candidates.some(
        (o, oi) =>
          oi !== ci &&
          o.start <= c.start &&
          o.end >= c.end &&
          // strictly longer, or an identical span reported by an earlier pattern
          (o.end - o.start > c.end - c.start || oi < ci)
      );
      if (contained || seen.has(c.s)) return;
      seen.add(c.s);
      findings.push({ lineNo: c.lineNo, s: c.s, entropy: c.entropy, kind: c.kind });
    });
  }

  return findings;
}

const BINARY_SNIFF_BYTES = 8192;

/**
 * Returns true if the given content looks binary, i.e. it contains a NUL
 * byte within its first 8192 bytes. Accepts a Buffer, Uint8Array or string.
 */
export function isBinaryContent(content: Buffer | Uint8Array | string): boolean {
  if (typeof content === "string") {
    return content.slice(0, BINARY_SNIFF_BYTES).includes("\0");
  }
  if (content instanceof Uint8Array) {
    return content.subarray(0, BINARY_SNIFF_BYTES).includes(0);
  }
  throw new TypeError(
    "isBinaryContent(content) expects a Buffer, Uint8Array or string"
  );
}

/**
 * Returns true if the file at `filePath` looks binary (NUL byte within its
 * first 8192 bytes). Throws if the file cannot be read, and throws a
 * TypeError if `filePath` is not a string; use `isBinaryContent` to check
 * content you already have in memory.
 */
export function isBinary(filePath: string): boolean {
  if (typeof filePath !== "string") {
    throw new TypeError(
      "isBinary(filePath) expects a file path string; " +
        "use isBinaryContent(content) to check a Buffer or string"
    );
  }
  const buf = Buffer.alloc(BINARY_SNIFF_BYTES);
  const fd = openSync(filePath, "r");
  try {
    const bytesRead = readSync(fd, buf, 0, BINARY_SNIFF_BYTES, 0);
    return isBinaryContent(buf.subarray(0, bytesRead));
  } finally {
    closeSync(fd);
  }
}
