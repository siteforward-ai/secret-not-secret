import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const TSX = import.meta.resolve("tsx/esm");

// Built from pieces so the test source holds no realistic-looking secret.
const REMOVED = ["gh", "p_", "aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x"].join("");
const KEPT = ["gh", "p_", "Zq8Wm2Xk5Lp9Rt3Vn7Bc1Hd4Jf6Gs0Ya2Ue"].join("");
const IN_MESSAGE = ["gh", "p_", "Mn4Bv7Cx1Zl9Kj3Hg6Fd2Sa5Qw8Er0Ty4Ui"].join("");
const ALLOWED = ["gh", "p_", "Pl0Ok9Ij8Uh7Yg6Tf5Rd4Es3Wa2Qz1Xc0Vb"].join("");
const IN_LOCKFILE = ["gh", "p_", "Lk3Jh5Gf7Ds9Aq1Wz2Xs4Ce6Vr8Bt0Ny2Mu"].join("");
const IN_EXCLUDED = ["gh", "p_", "Ex7Cl9Ud2Ed4Pa6Th8Sv1Al3Ue5Hi7Dd9En"].join("");
const LATE = ["gh", "p_", "La4Te7Co2Mm9It5Se3Cr8Et1Va6Lu0Eh3Er"].join("");

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

function commit(cwd: string, message: string): string {
  git(cwd, "add", "-A");
  git(cwd, "commit", "-q", "-m", message);
  return git(cwd, "rev-parse", "HEAD");
}

function run(cwd: string, args: string[]) {
  return spawnSync(process.execPath, ["--import", TSX, CLI, ...args], {
    cwd,
    encoding: "utf8",
  });
}

describe("--history", () => {
  let repo: string;
  let addCommit: string;
  let msgCommit: string;
  let lateBase: string;

  before(() => {
    repo = mkdtempSync(join(tmpdir(), "sns-history-"));
    git(repo, "init", "-q");
    git(repo, "config", "user.email", "test@example.com");
    git(repo, "config", "user.name", "test");
    git(repo, "config", "commit.gpgsign", "false");

    writeFileSync(join(repo, "README.md"), "hello\n");
    writeFileSync(join(repo, "not-secret-strings.txt"), `*  ${ALLOWED}\n`);
    writeFileSync(join(repo, "not-secret-paths.txt"), "vendor/\n");
    commit(repo, "initial");

    // Secret added, then removed in a later commit.
    writeFileSync(join(repo, "config.env"), `A=1\nTOKEN=${REMOVED}\n`);
    writeFileSync(join(repo, "kept.env"), `KEY=${KEPT}\n`);
    writeFileSync(join(repo, "allowed.txt"), `value ${ALLOWED}\n`);
    writeFileSync(join(repo, "package-lock.json"), `"${IN_LOCKFILE}"\n`);
    mkdirSync(join(repo, "vendor"));
    writeFileSync(join(repo, "vendor", "lib.js"), `x = "${IN_EXCLUDED}"\n`);
    addCommit = commit(repo, "add config");

    writeFileSync(join(repo, "config.env"), "A=1\nTOKEN=placeholder\n");
    commit(repo, "remove token");

    writeFileSync(join(repo, "README.md"), "hello again\n");
    msgCommit = commit(repo, `oops\n\nused token ${IN_MESSAGE} while testing`);
    lateBase = msgCommit;

    writeFileSync(join(repo, "late.txt"), `${LATE}\n`);
    commit(repo, "late");
  });

  after(() => rmSync(repo, { recursive: true, force: true }));

  it("finds a removed secret, with the commit where it first appeared", () => {
    const r = run(repo, ["--history"]);
    assert.equal(r.status, 1, r.stderr);
    const short = addCommit.slice(0, 7);
    assert.match(
      r.stdout,
      new RegExp(
        `# config\\.env:2 \\[known-prefix, entropy=[0-9.]+\\] first seen in ${short}, removed\\n` +
          `config\\.env  ${REMOVED}\\n`
      )
    );
  });

  it("marks a secret that is still in HEAD", () => {
    const r = run(repo, ["--history"]);
    assert.match(
      r.stdout,
      new RegExp(`# kept\\.env:1 .* first seen in ${addCommit.slice(0, 7)}, still in HEAD\\n`)
    );
  });

  it("finds a secret in a commit message", () => {
    const r = run(repo, ["--history"]);
    assert.match(
      r.stdout,
      new RegExp(
        `# <commit-message>:3 .* in commit ${msgCommit.slice(0, 7)}\\n` +
          `<commit-message>  ${IN_MESSAGE}\\n`
      )
    );
  });

  it("applies the allowlist, excluded paths and lockfile skipping", () => {
    const r = run(repo, ["--history"]);
    assert.ok(!r.stdout.includes(ALLOWED), r.stdout);
    assert.ok(!r.stdout.includes(IN_LOCKFILE), r.stdout);
    assert.ok(!r.stdout.includes(IN_EXCLUDED), r.stdout);
  });

  it("limits the scan to a rev-range", () => {
    const r = run(repo, ["--history", `${lateBase}..HEAD`]);
    assert.equal(r.status, 1, r.stderr);
    assert.ok(r.stdout.includes(LATE), r.stdout);
    assert.ok(!r.stdout.includes(REMOVED), r.stdout);
    assert.ok(!r.stdout.includes(IN_MESSAGE), r.stdout);
    assert.ok(!r.stdout.includes(KEPT), r.stdout);
  });

  it("exits 0 for a clean rev-range", () => {
    const r = run(repo, ["--history=HEAD~1..HEAD~1"]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, "");
  });

  it("emits only whitelist lines with --list", () => {
    const r = run(repo, ["--history", "--list"]);
    assert.equal(r.status, 1, r.stderr);
    const lines = r.stdout.trim().split("\n");
    assert.ok(lines.every((l) => !l.startsWith("#")), r.stdout);
    assert.ok(lines.includes(`config.env  ${REMOVED}`), r.stdout);
    assert.ok(lines.includes(`<commit-message>  ${IN_MESSAGE}`), r.stdout);
  });

  it("rejects a rev-range that looks like an option", () => {
    const r = run(repo, ["--history=--output=x"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /invalid rev-range/);
  });

  it("exits 2 when git cannot resolve the rev-range", () => {
    const r = run(repo, ["--history", "no-such-branch..HEAD"]);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /could not scan git history/);
  });

  it("scans content introduced by a merge commit", () => {
    const m = mkdtempSync(join(tmpdir(), "sns-history-merge-"));
    try {
      git(m, "init", "-q", "-b", "main");
      git(m, "config", "user.email", "test@example.com");
      git(m, "config", "user.name", "test");
      git(m, "config", "commit.gpgsign", "false");
      writeFileSync(join(m, "a.txt"), "a\n");
      commit(m, "root");
      git(m, "checkout", "-q", "-b", "side");
      writeFileSync(join(m, "side.txt"), "side\n");
      commit(m, "side");
      git(m, "checkout", "-q", "main");
      writeFileSync(join(m, "main.txt"), "main\n");
      commit(m, "main");
      git(m, "merge", "-q", "--no-commit", "--no-ff", "side");
      writeFileSync(join(m, "merged.txt"), `${LATE}\n`);
      const merge = commit(m, "merge side");
      const r = run(m, ["--history"]);
      assert.equal(r.status, 1, r.stderr);
      assert.match(
        r.stdout,
        new RegExp(`# merged\\.txt:1 .* first seen in ${merge.slice(0, 7)}, still in HEAD\\n`)
      );
    } finally {
      rmSync(m, { recursive: true, force: true });
    }
  });

  it("cannot be combined with other scan modes", () => {
    const r = run(repo, ["--history", "--all"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /cannot be combined/);
  });
});
