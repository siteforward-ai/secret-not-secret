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

    // URL-safe base64 / JWT / API tokens (alphanumeric + hyphen + underscore)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9_\\-]{${MIN_LENGTH},}`, "g")
    )) {
      const s = m[0];
      const e = shannonEntropy(s, URLSAFE_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "token");
    }

    // Standard base64 (includes + and /)
    for (const m of line.matchAll(
      new RegExp(`[A-Za-z0-9+/]{${MIN_LENGTH},}={0,2}`, "g")
    )) {
      const s = m[0];
      const stripped = s.replace(/=+$/, "");
      if (stripped.includes("/") && PATH_LIKE.test(stripped)) continue;
      const e = shannonEntropy(stripped, BASE64_CHARS);
      if (e >= ENTROPY_THRESHOLD_B64) add(lineNo, s, e, "base64");
    }

    // Hex strings (32+ chars)
    for (const m of line.matchAll(/[0-9a-fA-F]{32,}/g)) {
      const s = m[0];
      const e = shannonEntropy(s, HEX_CHARS);
      if (e >= ENTROPY_THRESHOLD_HEX) add(lineNo, s, e, "hex");
    }
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
