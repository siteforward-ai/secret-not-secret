# @siteforward/secret-not-secret

> Entropy-based secrets scanner for Git repos — detects high-entropy strings in staged or tracked files before they accidentally reach version control.

[![npm](https://img.shields.io/npm/v/@siteforward/secret-not-secret)](https://www.npmjs.com/package/@siteforward/secret-not-secret)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

<p align="center">
  <img src="secret-not-secret.png" alt="Secret / Not Secret" width="400" />
</p>

## How It Works

`secret-not-secret` uses [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) to identify strings that are statistically likely to be secrets — API keys, tokens, passwords, and cryptographic material — without relying on pattern matching or keyword lists.

Strings are scored against three character sets:

| Kind | Alphabet | Entropy Threshold | Min Length |
|------|----------|-------------------|------------|
| `token` | URL-safe base64 (`A-Z a-z 0-9 - _`) | 4.3 bits/char | 20 chars |
| `base64` | Standard base64 (+ `/`) | 4.3 bits/char | 20 chars |
| `hex` | Hex (`0-9 a-f`) | 3.7 bits/char | 32 chars |

Legitimate high-entropy values like UUIDs, git SHAs, URLs, and CSS custom properties are filtered out via a built-in safe-pattern list.

When a finding is a known-safe value in your codebase, add it to **`not-secret-strings.txt`** — an allowlist file that maps file path patterns to strings that should never be flagged. Entries use [minimatch](https://github.com/isaacs/minimatch) glob syntax so a single entry can cover an entire directory or file type.

Some files should never be scanned at all (generated bundles, lockfiles, test fixtures, etc.). List those path patterns in **`not-secret-paths.txt`** and `scan-secrets` will skip them entirely. Git-ignored files are also skipped automatically.

---

## Installation

```bash
npm install --save-dev @siteforward/secret-not-secret
```

---

## CLI Usage

```
scan-secrets [--all | --staged | file1 file2 ...] [--list]
             [--whitelist <path>] [--excluded-paths <path>]
```

### Scan modes

| Flag | Description |
|------|-------------|
| `--staged` | Scan only staged files — ideal for a pre-commit hook |
| `--all` | Scan all git-tracked files |
| `file1 file2 ...` | Scan specific files |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--whitelist <path>` | `not-secret-strings.txt` | Path to allowlist file |
| `--excluded-paths <path>` | `not-secret-paths.txt` | Path to path-exclusion file |
| `--list` | — | Output findings in whitelist-ready format |

Exits with code `1` if potential secrets are found, `0` if clean.

### Example output

```
# src/config.ts:15 [token, entropy=4.85]
src/config.ts	ghp_aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW7x

Found 1 potential secret(s). Add to not-secret-strings.txt if safe.
```

---

## Pre-commit Hook

The most common use case is scanning staged files before every commit. Add this to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
npx scan-secrets --staged
```

Or with [husky](https://typicode.github.io/husky/):

```bash
npx husky add .husky/pre-commit "npx scan-secrets --staged"
```

---

## Allowlisting False Positives

When `scan-secrets` flags something that isn't actually a secret, add it to `not-secret-strings.txt`:

```
# Format: <filepath-pattern>  <secret-string>
# Lines starting with # are ignored

# Exact file match
src/config.ts  myPublicConfigValue

# Glob pattern — matches any .ts file in src/
src/*.ts  anotherHighEntropyButSafeValue

# Wildcard — matches any file
*  knownPublicIdentifier

# Test fixtures
test/**  testFixtureToken
```

Filepath patterns use [minimatch](https://github.com/isaacs/minimatch) glob syntax.

---

## Excluding Paths

To skip entire directories or file patterns, add them to `not-secret-paths.txt` (not that git-ignored files are already ignored):

```
# Directories (trailing slash)
tests/

# File patterns
*.min.js
*.lock
*.map
```

---

## Programmatic API

```typescript
import {
  findSecretsInText,
  isSafe,
  isBinary,
  loadWhitelist,
  isWhitelisted,
  loadExcludedPaths,
  isExcluded,
  gitStagedFiles,
  gitLsFiles,
  ENTROPY_THRESHOLD_B64,
  ENTROPY_THRESHOLD_HEX,
  MIN_LENGTH,
} from '@siteforward/secret-not-secret';

// Scan text content
const findings = findSecretsInText(fileContent);
// findings: Array<{ lineNo: number; s: string; entropy: number; kind: string }>

// Check a single string
if (!isSafe(someString)) {
  console.log('Potentially sensitive');
}

// Load and apply a whitelist
const whitelist = loadWhitelist('not-secret-strings.txt');
const safe = isWhitelisted('src/config.ts', 'myValue', whitelist);
```

---

## Supported Node.js Versions

Node.js 18, 20, and 22 (tested in CI).

---

## License

MIT — [SiteForward AI](https://github.com/siteforward-ai)
