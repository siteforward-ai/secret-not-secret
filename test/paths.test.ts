import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, relative } from "path";
import { isConfigFile, isLockfile, DEFAULT_LOCKFILES } from "../src/paths.js";

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

describe("isLockfile", () => {
  it("matches every default lockfile by basename at the root", () => {
    for (const name of DEFAULT_LOCKFILES) {
      assert.equal(isLockfile(name), true, name);
    }
  });

  it("matches lockfiles in nested directories", () => {
    assert.equal(isLockfile("packages/app/package-lock.json"), true);
    assert.equal(isLockfile("/abs/path/to/yarn.lock"), true);
    assert.equal(isLockfile("crates/foo/Cargo.lock"), true);
    assert.equal(isLockfile("svc/go.sum"), true);
  });

  it("does not match other files", () => {
    assert.equal(isLockfile("package.json"), false);
    assert.equal(isLockfile("src/yarn.lock.ts"), false);
    assert.equal(isLockfile("my-package-lock.json"), false);
    assert.equal(isLockfile("go.mod"), false);
    assert.equal(isLockfile("cargo.lock"), false);
  });
});
