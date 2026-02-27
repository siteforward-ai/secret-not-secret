import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  shannonEntropy,
  URLSAFE_CHARS,
  HEX_CHARS,
  ENTROPY_THRESHOLD_B64,
  ENTROPY_THRESHOLD_HEX,
} from "../src/entropy.js";
import { isSafe } from "../src/scanner.js";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    assert.equal(shannonEntropy("", URLSAFE_CHARS), 0);
  });

  it("returns 0 for string with no chars in charset", () => {
    assert.equal(shannonEntropy("!!!", URLSAFE_CHARS), 0);
  });

  it("returns 0 for single repeated character", () => {
    assert.equal(shannonEntropy("aaaa", URLSAFE_CHARS), 0);
  });

  it("returns positive entropy for mixed string", () => {
    const e = shannonEntropy("abcdef", URLSAFE_CHARS);
    assert.ok(e > 0);
  });

  it("flags a real GitHub PAT as high entropy", () => {
    // Realistic high-entropy token
    const token = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const e = shannonEntropy(token, URLSAFE_CHARS);
    assert.ok(e >= ENTROPY_THRESHOLD_B64, `Expected >= ${ENTROPY_THRESHOLD_B64}, got ${e}`);
  });

  it("flags a hex string as high entropy", () => {
    // Randomly distributed hex string with high entropy
    const hex = "f3a9b72c1e05d468af91b34c72e68d5a";
    const e = shannonEntropy(hex, HEX_CHARS);
    assert.ok(e >= ENTROPY_THRESHOLD_HEX, `Expected >= ${ENTROPY_THRESHOLD_HEX}, got ${e}`);
  });
});

describe("isSafe", () => {
  it("recognizes UUIDs as safe", () => {
    assert.ok(isSafe("550e8400-e29b-41d4-a716-446655440000"));
  });

  it("recognizes git SHAs as safe", () => {
    assert.ok(isSafe("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"));
  });

  it("recognizes all-lowercase as safe", () => {
    assert.ok(isSafe("abcdefghijklmnopqrstuvwxyz"));
  });

  it("recognizes all-uppercase as safe", () => {
    assert.ok(isSafe("ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"));
  });

  it("recognizes URLs as safe", () => {
    assert.ok(isSafe("https://example.com/some/path"));
  });

  it("recognizes CSS custom properties as safe", () => {
    assert.ok(isSafe("--primary-background-color"));
  });

  it("recognizes path-like strings as safe", () => {
    assert.ok(isSafe("src/components/Button.tsx"));
  });

  it("does not mark real secrets as safe", () => {
    assert.ok(!isSafe("ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x"));
  });
});
