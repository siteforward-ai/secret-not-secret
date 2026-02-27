import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  matchesPattern,
  loadWhitelist,
  isWhitelisted,
} from "../src/whitelist.js";

describe("matchesPattern", () => {
  it("exact match returns true", () => {
    assert.ok(matchesPattern("foo/bar.ts", "foo/bar.ts"));
  });

  it("glob match returns true", () => {
    assert.ok(matchesPattern("src/foo.ts", "src/*.ts"));
  });

  it("glob no match returns false", () => {
    assert.ok(!matchesPattern("src/foo.js", "src/*.ts"));
  });

  it("wildcard * matches any", () => {
    assert.ok(matchesPattern("anything", "*"));
  });

  it("dot files matched with dot:true", () => {
    assert.ok(matchesPattern(".env", ".*"));
  });
});

describe("loadWhitelist", () => {
  let tmpFile: string;

  before(() => {
    tmpFile = join(tmpdir(), `whitelist-test-${process.pid}.txt`);
    writeFileSync(
      tmpFile,
      [
        "# comment line",
        "src/config.ts  mySecretToken123",
        "*  globallyWhitelistedSecret456",
        "",
        "  ",
      ].join("\n")
    );
  });

  after(() => {
    unlinkSync(tmpFile);
  });

  it("loads entries from file", () => {
    const entries = loadWhitelist(tmpFile);
    assert.equal(entries.length, 2);
  });

  it("skips comments", () => {
    const entries = loadWhitelist(tmpFile);
    assert.ok(entries.every((e) => !e.pathPattern.startsWith("#")));
  });

  it("parses pathPattern and secret correctly", () => {
    const entries = loadWhitelist(tmpFile);
    assert.equal(entries[0].pathPattern, "src/config.ts");
    assert.equal(entries[0].secret, "mySecretToken123");
  });

  it("returns empty array for non-existent file", () => {
    const entries = loadWhitelist("/non/existent/path.txt");
    assert.deepEqual(entries, []);
  });
});

describe("isWhitelisted", () => {
  const whitelist = [
    { pathPattern: "src/config.ts", secret: "secretABC" },
    { pathPattern: "*", secret: "globalSecret" },
    { pathPattern: "test/**", secret: "testOnlySecret" },
  ];

  it("returns true for exact path match", () => {
    assert.ok(isWhitelisted("src/config.ts", "secretABC", whitelist));
  });

  it("returns false for wrong path", () => {
    assert.ok(!isWhitelisted("src/other.ts", "secretABC", whitelist));
  });

  it("returns true for wildcard * entry", () => {
    assert.ok(isWhitelisted("any/path/file.ts", "globalSecret", whitelist));
  });

  it("returns true for glob pattern match", () => {
    assert.ok(
      isWhitelisted("test/fixtures/data.ts", "testOnlySecret", whitelist)
    );
  });

  it("returns false for wrong secret", () => {
    assert.ok(!isWhitelisted("src/config.ts", "wrongSecret", whitelist));
  });

  it("returns false for empty whitelist", () => {
    assert.ok(!isWhitelisted("src/config.ts", "anySecret", []));
  });
});
