'use strict';

/**
 * Output formatting functions for Worm Buster
 */

/**
 * Print the banner header
 */
function printBanner() {
  console.log('\n' + '='.repeat(65));
  console.log('  WORM BUSTER - Shai-Hulud 2 Malware Scanner');
  console.log('  Supply Chain Attack Detection Tool');
  console.log('='.repeat(65) + '\n');
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Worm Buster - Shai-Hulud 2 Malware Scanner

Usage: worm-buster [options] [directories...]

Options:
  -h, --help        Show this help message
  -v, --verbose     Show verbose output including warnings
  --json            Output results in JSON format only
  --all             Scan all common project directories
  --processes       Check for suspicious running processes
  --credentials     Check for credential files that may have been compromised
  --full            Enable all checks (--processes + --credentials)

Examples:
  worm-buster                      # Scan current directory
  worm-buster --all                # Scan all common directories
  worm-buster --full .             # Full scan of current directory
  worm-buster /path/to/project     # Scan specific directory
  worm-buster . ../other --json    # Scan multiple directories, JSON output
`);
}

/**
 * Print scan results to console
 *
 * @param {Object} findings - Object with critical, warning, info arrays
 * @param {Object} options - Display options
 */
function printResults(findings, options = {}) {
  console.log('\n' + '='.repeat(65));
  console.log('  SCAN RESULTS');
  console.log('='.repeat(65) + '\n');

  // Separate known targets from other warnings
  const knownTargets = findings.warning.filter(f => f.type === 'KNOWN_TARGET');
  const otherWarnings = findings.warning.filter(f => f.type !== 'KNOWN_TARGET');

  if (findings.critical.length === 0 && otherWarnings.length === 0) {
    if (knownTargets.length > 0) {
      console.log('  [OK] No infected packages found.\n');
    } else {
      console.log('  [OK] No infected packages or malicious artifacts found.\n');
      console.log('  Your scanned directories appear clean of Shai-Hulud 2 indicators.\n');
    }
  }

  // Print critical findings
  if (findings.critical.length > 0) {
    console.log('  [CRITICAL] ' + findings.critical.length + ' INFECTED package(s) found:\n');
    console.log('-'.repeat(65));
    for (const finding of findings.critical) {
      printFinding(finding);
    }
    console.log('');
  }

  // Print other warnings (suspicious scripts, etc.)
  if (otherWarnings.length > 0) {
    console.log('  [WARNING] ' + otherWarnings.length + ' warning(s):\n');
    console.log('-'.repeat(65));
    for (const finding of otherWarnings) {
      printFinding(finding);
    }
    console.log('');
  }

  // Print known targets (packages that were compromised but user has different version)
  if (knownTargets.length > 0) {
    console.log('  [CAUTION] ' + knownTargets.length + ' package(s) were targeted in the attack:\n');
    console.log('  You have SAFE versions, but be careful when updating these packages.\n');
    console.log('-'.repeat(65));
    for (const finding of knownTargets) {
      printFinding(finding);
    }
    console.log('');
  }

  // Print summary
  console.log('-'.repeat(65));
  console.log(
    `  Summary: ${findings.critical.length} infected, ` +
    `${otherWarnings.length} warnings, ${knownTargets.length} targeted packages`
  );

  // Print recommended actions if critical issues found
  if (findings.critical.length > 0) {
    printRecommendedActions();
  }
}

/**
 * Print a single finding
 */
function printFinding(finding) {
  console.log(`\n  Type: ${finding.type}`);

  if (finding.package) {
    console.log(`  Package: ${finding.package}@${finding.version}`);
    if (finding.infectedVersions) {
      console.log(`  Known infected versions: ${finding.infectedVersions.join(', ')}`);
    }
  }

  if (finding.file) {
    console.log(`  File: ${finding.file}`);
  }

  if (finding.path && !finding.file) {
    console.log(`  Path: ${finding.path}`);
  }

  if (finding.artifact) {
    console.log(`  Artifact: ${finding.artifact}`);
  }

  if (finding.process) {
    console.log(`  Process: ${finding.process}`);
  }

  if (finding.script) {
    console.log(`  Script: ${finding.script}`);
    console.log(`  Content: ${finding.content}`);
  }

  if (finding.note) {
    console.log(`  Note: ${finding.note}`);
  }
}

/**
 * Print recommended actions for remediation
 */
function printRecommendedActions() {
  console.log('\n  RECOMMENDED ACTIONS:');
  console.log('  1. DO NOT run npm install in affected projects');
  console.log('  2. Remove infected packages from package.json');
  console.log('  3. Delete node_modules and package-lock.json');
  console.log('  4. Check .github/workflows for suspicious files');
  console.log('  5. Rotate ALL credentials (AWS, GCP, Azure, GitHub, npm)');
  console.log('  6. Review GitHub Actions for unauthorized workflows');
  console.log('  7. Check for Bun runtime: which bun');
}

/**
 * Format findings as JSON string
 *
 * @param {Object} findings - Findings object
 * @param {boolean} pretty - Pretty print JSON
 * @returns {string} JSON string
 */
function formatJson(findings, pretty = true) {
  return JSON.stringify(findings, null, pretty ? 2 : 0);
}

module.exports = {
  printBanner,
  printHelp,
  printResults,
  printRecommendedActions,
  formatJson,
};
