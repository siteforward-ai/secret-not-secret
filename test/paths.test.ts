import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, relative } from "path";
import { isConfigFile } from "../src/paths.js";

describe("isConfigFile", () => {
  const cwd = process.cwd();
  const whitelist = join(cwd, "not-secret-strings.txt");
  const excluded = join(cwd, "not-secret-paths.txt");

  it("matches the allowlist file by absolute path", () => {
    assert.ok(isConfigFile(whitelist, [whitelist, excluded]));
  });

  it("matches the excluded-paths file by absolute path", () => {
    assert.ok(isConfigFile(excluded, [whitelist, excluded]));
  });

  it("matches relative or unnormalized paths", () => {
    assert.ok(isConfigFile("not-secret-strings.txt", [whitelist]));
    assert.ok(isConfigFile("./src/../not-secret-paths.txt", [excluded]));
    assert.ok(isConfigFile(whitelist, [relative(cwd, whitelist)]));
  });

  it("matches a custom --whitelist location instead of the default", () => {
    const custom = join(cwd, "config", "allow.txt");
    assert.ok(isConfigFile(custom, [custom, excluded]));
    assert.ok(!isConfigFile(whitelist, [custom, excluded]));
  });

  it("does not match a same-named file in another directory", () => {
    assert.ok(
      !isConfigFile(join(cwd, "sub", "not-secret-strings.txt"), [whitelist, excluded])
    );
  });

  it("does not match unrelated files", () => {
    assert.ok(!isConfigFile(join(cwd, "src", "cli.ts"), [whitelist, excluded]));
  });
});
