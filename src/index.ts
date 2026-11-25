export { shannonEntropy, ENTROPY_THRESHOLD_B64, ENTROPY_THRESHOLD_HEX, MIN_LENGTH } from "./entropy.js";
export {
  findSecretsInText,
  isSafe,
  isBinary,
  isBinaryContent,
  KNOWN_SECRET_PATTERNS,
  PUBLIC_ID_PREFIXES,
} from "./scanner.js";
export type { Finding } from "./scanner.js";
export { loadWhitelist, isWhitelisted, matchesPattern } from "./whitelist.js";
export type { WhitelistEntry } from "./whitelist.js";
export {
  loadExcludedPaths,
  isExcluded,
  isConfigFile,
  isLockfile,
  DEFAULT_LOCKFILES,
} from "./paths.js";
export { gitLsFiles, gitStagedFiles } from "./git.js";
export { scanHistory, COMMIT_MESSAGE_PATH } from "./history.js";
export type { HistoryFinding, HistoryResult, HistoryOptions } from "./history.js";
