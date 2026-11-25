import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const TSX = import.meta.resolve("tsx/esm");

function run(cwd: string, args: string[]) {
  return spawnSync(process.execPath, ["--import", TSX, CLI, ...args], {
    cwd,
    encoding: "utf8",
  });
}

describe("scan-secrets CLI: unreadable files", () => {
  let dir: string;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), "sns-cli-"));
    writeFileSync(join(dir, "clean.txt"), "nothing to see here\n");
    writeFileSync(join(dir, "bin.dat"), Buffer.from([0x00, 0x01, 0x02]));
    writeFileSync(
      join(dir, "secret.txt"),
      "token = ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x\n"
    );
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("exits 0 for clean text and binary files", () => {
    const r = run(dir, ["clean.txt", "bin.dat"]);
    assert.equal(r.status, 0, r.stderr);
  });

  it("reports an unreadable file as not scanned and exits 2", () => {
    const r = run(dir, ["clean.txt", "missing.txt"]);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /missing\.txt.*not scanned/);
  });

  it("still exits 1 when secrets are found alongside unreadable files", () => {
    const r = run(dir, ["secret.txt", "missing.txt"]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /missing\.txt.*not scanned/);
    assert.match(r.stdout, /secret\.txt/);
  });
});
