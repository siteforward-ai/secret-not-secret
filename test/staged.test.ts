import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { fileURLToPath } from "url";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..");
const CLI = join(ROOT, "src", "cli.ts");
const TSX = join(ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const SECRET = "ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";

function git(cwd: string, ...args: string[]): void {
  execFileSync("git", args, { cwd, stdio: "ignore" });
}

function scanStaged(cwd: string) {
  return spawnSync(process.execPath, ["--import", TSX, CLI, "--staged"], {
    cwd,
    encoding: "utf8",
  });
}

describe("--staged", () => {
  let repo: string;

  before(() => {
    repo = mkdtempSync(join(tmpdir(), "sns-staged-"));
    git(repo, "init", "-q");
    git(repo, "config", "user.email", "test@example.com");
    git(repo, "config", "user.name", "test");
  });

  after(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("flags a secret that is staged but removed from the working tree", () => {
    const file = join(repo, "config.env");
    writeFileSync(file, `TOKEN=${SECRET}\n`);
    git(repo, "add", "config.env");
    writeFileSync(file, "TOKEN=placeholder\n");

    const res = scanStaged(repo);
    assert.equal(res.status, 1, res.stderr);
    assert.ok(res.stdout.includes(SECRET), res.stdout);
  });

  it("flags a staged secret whose file was deleted from disk", () => {
    unlinkSync(join(repo, "config.env"));
    const res = scanStaged(repo);
    assert.equal(res.status, 1, res.stderr);
    assert.ok(res.stdout.includes(SECRET), res.stdout);
  });

  it("ignores a secret that exists only in the working tree", () => {
    writeFileSync(join(repo, "config.env"), "TOKEN=placeholder\n");
    git(repo, "add", "config.env");
    git(repo, "commit", "-q", "-m", "init");
    writeFileSync(join(repo, "config.env"), `TOKEN=${SECRET}\n`);
    writeFileSync(join(repo, "other.txt"), "hello\n");
    git(repo, "add", "other.txt");

    const res = scanStaged(repo);
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });

  it("skips files deleted in the index", () => {
    git(repo, "commit", "-q", "-m", "other");
    git(repo, "rm", "-q", "--cached", "config.env");

    const res = scanStaged(repo);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.equal(res.stderr, "");
  });
});
