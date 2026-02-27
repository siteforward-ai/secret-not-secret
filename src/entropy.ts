// ── Character sets ────────────────────────────────────────────────────────────

export const BASE64_CHARS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
);
export const URLSAFE_CHARS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
);
export const HEX_CHARS = new Set("0123456789abcdefABCDEF");

export const MIN_LENGTH = 20;

// Entropy thresholds (bits per character).
//
// Character set theoretical maxima:
//   URL-safe base64 (64 chars): log2(64) = 6.0
//   Standard base64 (64 chars): log2(64) = 6.0
//   Hex (16 chars):              log2(16) = 4.0
//
// Securely-random API tokens/keys reach 4.5–5.9 bits/char.
// Human-readable identifiers (stack names, slugs, CSS vars) stay below 4.2.
// Threshold of 4.3 catches JWTs, DB passwords, GitHub tokens, etc.
export const ENTROPY_THRESHOLD_B64 = 4.3;
export const ENTROPY_THRESHOLD_HEX = 3.7;

export function shannonEntropy(s: string, charset: Set<string>): number {
  const chars = [...s].filter((c) => charset.has(c));
  if (chars.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of chars) freq.set(c, (freq.get(c) ?? 0) + 1);
  const total = chars.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
