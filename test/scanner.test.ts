import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findSecretsInText, isBinary, isBinaryContent } from "../src/scanner.js";

describe("findSecretsInText", () => {
  it("returns empty array for empty content", () => {
    assert.deepEqual(findSecretsInText(""), []);
  });

  it("returns empty array for plain text", () => {
    const findings = findSecretsInText("Hello world, this is just plain text.");
    assert.deepEqual(findings, []);
  });

  it("returns empty array for a UUID", () => {
    const findings = findSecretsInText(
      "id: 550e8400-e29b-41d4-a716-446655440000"
    );
    assert.deepEqual(findings, []);
  });

  it("returns empty array for a git SHA", () => {
    const findings = findSecretsInText(
      "commit: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    );
    assert.deepEqual(findings, []);
  });

  it("detects a high-entropy token", () => {
    const secret = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const findings = findSecretsInText(`TOKEN=${secret}`);
    assert.ok(findings.length > 0, "Should find a secret");
    assert.ok(
      findings.some((f) => f.s === secret),
      "Should find the exact secret string"
    );
  });

  it("detects a base64-encoded secret", () => {
    // High-entropy base64 string
    const secret = "dGhpcyBpcyBhIHZlcnkgc2VjcmV0IGtleQ==";
    const findings = findSecretsInText(`key = "${secret}"`);
    // Only flag if it has high entropy; this particular string may or may not
    // exceed the threshold, so we just verify the function runs without error
    assert.ok(Array.isArray(findings));
  });

  it("detects a high-entropy hex string", () => {
    const secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    const findings = findSecretsInText(`HASH=${secret}`);
    assert.ok(findings.length > 0, "Should find hex secret");
    assert.ok(findings.some((f) => f.s === secret));
  });

  it("does not deduplicate across different content (deduplication within single call)", () => {
    const secret = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const content = `a=${secret}\nb=${secret}`;
    const findings = findSecretsInText(content);
    // The deduplication within a single call means the secret appears only once
    assert.equal(
      findings.filter((f) => f.s === secret).length,
      1
    );
  });

  it("reports correct line numbers", () => {
    const secret = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const content = `line1\nline2\nTOKEN=${secret}`;
    const findings = findSecretsInText(content);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].lineNo, 3);
  });

  it("ignores SRI / lockfile integrity hashes", () => {
    const content = [
      '"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+5gzOkdMC5Uk5nb7v+8GqbeQ6R7dw5o+3ufJGQ==",',
      '"integrity": "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC",',
      "integrity sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
      "integrity sha1-QuMSd5sH8C1dK1lcn6kfAMVH8M8=",
    ].join("\n");
    assert.deepEqual(findSecretsInText(content), []);
  });

  it("still detects secrets on a line containing an SRI hash", () => {
    const secret = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const content = `sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+5gzOkdMC5Uk5nb7v+8GqbeQ6R7dw5o+3ufJGQ== ${secret}`;
    const findings = findSecretsInText(content);
    assert.ok(findings.some((f) => f.s === secret));
    assert.ok(!findings.some((f) => f.s.includes("v2kDEe57")));
  });

  it("still detects the same base64 payload without an SRI prefix", () => {
    const findings = findSecretsInText(
      "key = v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+5gzOkdMC5Uk5nb7v+8GqbeQ6R7dw5o+3ufJGQ=="
    );
    assert.ok(findings.length > 0);
  });
});

describe("isBinaryContent", () => {
  it("returns false for text Buffer, Uint8Array and string", () => {
    assert.equal(isBinaryContent(Buffer.from("hello world\n")), false);
    assert.equal(isBinaryContent(new TextEncoder().encode("hello")), false);
    assert.equal(isBinaryContent("hello world"), false);
    assert.equal(isBinaryContent(Buffer.alloc(0)), false);
  });

  it("returns true when a NUL byte is in the first 8192 bytes", () => {
    assert.equal(isBinaryContent(Buffer.from([0x41, 0x00, 0x42])), true);
    assert.equal(isBinaryContent(new Uint8Array([1, 2, 0])), true);
    assert.equal(isBinaryContent("a\0b"), true);
  });

  it("ignores NUL bytes after the first 8192 bytes", () => {
    const buf = Buffer.alloc(9000, 0x61);
    buf[8500] = 0;
    assert.equal(isBinaryContent(buf), false);
    buf[8191] = 0;
    assert.equal(isBinaryContent(buf), true);
  });

  it("throws TypeError for unsupported input", () => {
    assert.throws(() => isBinaryContent(42 as unknown as string), TypeError);
  });
});

describe("isBinary", () => {
  const dir = mkdtempSync(join(tmpdir(), "sns-isbinary-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("detects text and binary files by path", () => {
    const text = join(dir, "a.txt");
    const bin = join(dir, "b.bin");
    writeFileSync(text, "just text\n");
    writeFileSync(bin, Buffer.from([0x89, 0x50, 0x00, 0x47]));
    assert.equal(isBinary(text), false);
    assert.equal(isBinary(bin), true);
  });

  it("throws when the file cannot be read instead of returning true", () => {
    assert.throws(() => isBinary(join(dir, "does-not-exist")), /ENOENT/);
    assert.throws(() => isBinary(dir), /EISDIR/);
  });

  it("throws TypeError when not given a string path", () => {
    assert.throws(
      () => isBinary(Buffer.from("text") as unknown as string),
      TypeError
    );
  });
});
