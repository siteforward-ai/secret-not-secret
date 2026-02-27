import { existsSync, readFileSync } from "fs";
import { minimatch } from "minimatch";

export type WhitelistEntry = { pathPattern: string; secret: string };

export function matchesPattern(str: string, pattern: string): boolean {
  if (pattern === str) return true;
  return minimatch(str, pattern, { dot: true });
}

export function loadWhitelist(whitelistPath: string): WhitelistEntry[] {
  if (!existsSync(whitelistPath)) return [];
  return readFileSync(whitelistPath, "utf8")
    .split("\n")
    .filter((line) => line.trim() && !line.startsWith("#"))
    .flatMap((line) => {
      const parts = line.trim().split(/\s+/, 2);
      return parts.length === 2
        ? [{ pathPattern: parts[0], secret: parts[1] }]
        : [];
    });
}

export function isWhitelisted(
  relPath: string,
  secret: string,
  whitelist: WhitelistEntry[]
): boolean {
  for (const { pathPattern, secret: wlSecret } of whitelist) {
    if (wlSecret !== secret) continue;
    if (pathPattern === "*") return true;
    if (matchesPattern(relPath, pathPattern)) return true;
  }
  return false;
}
