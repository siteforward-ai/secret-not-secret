import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { findSecretsInText } from "../src/scanner.js";
import { isWhitelisted } from "../src/whitelist.js";

function kinds(text: string) {
  return findSecretsInText(text).map((f) => [f.kind, f.s]);
}

describe("known secret prefixes", () => {
  it("reports AWS access key IDs (AKIA/ASIA) regardless of entropy", () => {
    assert.deepEqual(kinds("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"), [
      ["aws-key-id", "AKIAIOSFODNN7EXAMPLE"],
    ]);
    assert.deepEqual(kinds('"ASIAAAAAAAAAAAAAAAAA"'), [
      ["aws-key-id", "ASIAAAAAAAAAAAAAAAAA"],
    ]);
  });

  it("does not report AKIA embedded in a longer word or too short", () => {
    assert.deepEqual(kinds("XAKIAIOSFODNN7EXAMPLE"), []);
    assert.deepEqual(kinds("AKIAIOSFODNN7EX"), []);
  });

  it("reports PEM private key headers", () => {
    for (const h of [
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ]) {
      assert.deepEqual(kinds(h), [["private-key", h]], h);
    }
    assert.deepEqual(kinds("-----BEGIN PUBLIC KEY-----"), []);
  });

  it("reports low-entropy keys after known prefixes", () => {
    // Prefix and body joined at runtime so no key-shaped literal is committed.
    const samples = [
      ["sk_live_", "a".repeat(16)],
      ["rk_live_", "a".repeat(16)],
      ["whsec_", "a".repeat(20)],
      ["ghp_", "a".repeat(24)],
      ["github_pat_", "a".repeat(22)],
      ["xoxb-", "1111111111-aaaaaaaa"],
      ["xoxp-", "1111111111-aaaaaaaa"],
      ["xoxa-", "1111111111-aaaaaaaa"],
      ["sk-ant-", "a".repeat(24)],
    ].map(([p, b]) => p + b);
    for (const s of samples) {
      assert.deepEqual(kinds(`KEY=${s}`), [["known-prefix", s]], s);
    }
  });

  it("does not report bare prefixes mentioned in docs", () => {
    const doc =
      "Live keys start with sk_live_ or rk_live_, webhooks use whsec_, " +
      "GitHub tokens ghp_ / github_pat_, Slack xoxb-, Anthropic sk-ant-.";
    assert.deepEqual(findSecretsInText(doc), []);
  });

  it("does not duplicate a high-entropy known-prefix key as token/base64", () => {
    // Built at runtime so the fixture doesn't trip GitHub push protection.
    const s = ["sk", "live", "51HxQ9aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x"].join("_");
    assert.deepEqual(kinds(`STRIPE=${s}`), [["known-prefix", s]]);
  });

  it("known-prefix findings can still be allowlisted", () => {
    const [f] = findSecretsInText("AKIAIOSFODNN7EXAMPLE");
    assert.ok(
      isWhitelisted("docs/aws.md", f.s, [
        { pathPattern: "docs/**", secret: "AKIAIOSFODNN7EXAMPLE" },
      ])
    );
  });
});

describe("public ID prefixes", () => {
  it("skips Stripe public IDs even when high-entropy", () => {
    for (const s of [
      "price_1OqXyZ2eZvKYlo2CkL9mN3pQ",
      "prod_Pq7XyZ2eZvKYlo2CkL9mN3pQ",
      "we_1OqXyZ2eZvKYlo2CkL9mN3pQrS",
      "bpc_1OqXyZ2eZvKYlo2CkL9mN3pQrS",
    ]) {
      assert.deepEqual(findSecretsInText(`id: ${s}`), [], s);
    }
  });

  it("still flags other high-entropy strings on the same line", () => {
    const secret = "aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x";
    const findings = findSecretsInText(
      `price_1OqXyZ2eZvKYlo2CkL9mN3pQ ${secret}`
    );
    assert.ok(findings.some((f) => f.s === secret));
    assert.ok(findings.every((f) => !f.s.includes("1OqXyZ")));
  });
});
