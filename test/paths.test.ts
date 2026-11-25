import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isLockfile, DEFAULT_LOCKFILES } from "../src/paths.js";

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
