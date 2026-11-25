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

// URL host names (e.g. `abc123….lambda-url.us-east-1.on.aws`) often contain
// random-looking labels. Matches that fall entirely inside the host part of a
// URL are skipped. Userinfo (`user:pass@`), ports, paths and query strings are
// still scanned.
const URL_AUTHORITY = /\b(?:https?|ftp|wss?):(\/\/)([^\/?#\s"'`<>]*)/gi;

type Span = { start: number; end: number };

function urlHostSpans(line: string): Span[] {
  const spans: Span[] = [];
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
    spans.push({ start: at === -1 ? slashStart : hostStart, end: hostEnd });
  }
  return spans;
}

function inSpans(spans: Span[], start: number, end: number): boolean {
  return spans.some((sp) => start >= sp.start && end <= sp.end);
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
    const hosts = urlHostSpans(line);
    const inHost = (m: RegExpMatchArray) =>
      inSpans(hosts, m.index!, m.index! + m[0].length);

    // URL-safe base64 / JWT / API tokens (alphanumeric + hyphen + underscore)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9_\\-]{${MIN_LENGTH},}`, "g")
    )) {
      if (inHost(m)) continue;
      const s = m[0];
      const e = shannonEntropy(s, URLSAFE_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "token");
    }

    // Standard base64 (includes + and /)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9+/]{${MIN_LENGTH},}={0,2}`, "g")
    )) {
      if (inHost(m)) continue;
      const s = m[0];
      const stripped = s.replace(/=+$/, "");
      if (stripped.includes("/") && PATH_LIKE.test(stripped)) continue;
      const e = shannonEntropy(stripped, BASE64_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "base64");
    }

    // Hex strings (32+ chars)
    for (const m of line.matchAll(/[0-9a-fA-F]{32,}/g)) {
      if (inHost(m)) continue;
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
