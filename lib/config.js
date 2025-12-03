'use strict';

/**
 * Configuration constants for Worm Buster scanner
 *
 * IOCs sourced from:
 * - Wiz Security Research: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
 * - Datadog Security Labs: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
 * - Check Point Research: https://blog.checkpoint.com/research/shai-hulud-2-0-inside-the-second-coming
 */

// Known malicious artifact files (Indicators of Compromise)
const MALICIOUS_ARTIFACTS = [
  // GitHub Actions malicious workflow
  '.github/workflows/discussion.yaml',
  '.github/workflows/discussion.yml',
  // Exfiltrated data files (double base64 encoded)
  'cloud.json',
  'contents.json',
  'environment.json',
  'truffleSecrets.json',
  'actionsSecrets.json',
  // Malware payload files
  'setup_bun.js',
  'bun_environment.js',
];

// Known SHA256 hashes of malware files
const MALWARE_HASHES = {
  'bun_environment.js': [
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0',
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068',
    'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd',
  ],
  'setup_bun.js': [
    'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a',
  ],
};

// Pattern for suspicious workflow files (formatter_*.yml)
const SUSPICIOUS_WORKFLOW_PATTERN = /formatter_\d+\.ya?ml$/;

// Suspicious process patterns to detect running malware
const SUSPICIOUS_PROCESS_PATTERNS = [
  /bun.*environment/i,
  /bun_environment/i,
  /setup_bun/i,
  /bun.*detach/i,
];

// GitHub-based IOC markers
const GITHUB_IOC_MARKERS = {
  repoDescriptions: [
    'Sha1-Hulud: The Second Coming',
    'Shai-Hulud Migration',
  ],
  runnerName: 'SHA1HULUD',
  migrationSuffix: '-migration',
};

// Credential files that may have been exfiltrated
const CREDENTIAL_FILES = [
  '.aws/credentials',
  '.azure/credentials',
  '.config/gcloud/credentials.db',
  '.npmrc',
  '.netrc',
  '.git-credentials',
];

// Common project directory names to scan with --all flag
const COMMON_PROJECT_DIRS = [
  'code',
  'projects',
  'workspace',
  'workspaces',
  'dev',
  'development',
  'repos',
  'github',
  'Documents/code',
  'Documents/projects',
];

// Dependency types to check in package.json
const DEPENDENCY_TYPES = [
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
];

// Suspicious install script names
const SUSPICIOUS_SCRIPTS = ['preinstall', 'postinstall', 'prepare'];

// Patterns in scripts that indicate possible malware
const SUSPICIOUS_SCRIPT_PATTERNS = ['bun', 'setup_', 'curl', 'wget', 'eval'];

module.exports = {
  MALICIOUS_ARTIFACTS,
  MALWARE_HASHES,
  SUSPICIOUS_WORKFLOW_PATTERN,
  SUSPICIOUS_PROCESS_PATTERNS,
  GITHUB_IOC_MARKERS,
  CREDENTIAL_FILES,
  COMMON_PROJECT_DIRS,
  DEPENDENCY_TYPES,
  SUSPICIOUS_SCRIPTS,
  SUSPICIOUS_SCRIPT_PATTERNS,
};
