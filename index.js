#!/usr/bin/env node
/**
 * Worm Buster - Shai-Hulud 2 Malware Scanner
 *
 * A security tool for detecting the Shai-Hulud 2 supply chain attack
 * that compromised npm packages in November 2025.
 *
 * @license MIT
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

// Import modules
const { loadInfectedPackages, getPackageStats } = require('./lib/loader');
const { findPackageFiles, findMaliciousArtifacts } = require('./lib/scanner');
const { checkPackageJson, checkPackageLock, checkNodeModules } = require('./lib/analyzer');
const { checkRunningProcesses, checkCredentialFiles } = require('./lib/system');
const { printBanner, printHelp, printResults } = require('./lib/output');
const { createReport, saveReports, generateMarkdown, generateHtml } = require('./lib/reporter');
const { COMMON_PROJECT_DIRS } = require('./lib/config');

// ============================================================================
// CLI ARGUMENT PARSING
// ============================================================================

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    help: false,
    verbose: false,
    json: false,
    scanAll: false,
    checkProcesses: false,
    checkCredentials: false,
    reportFormats: { json: true, markdown: true, html: true },
    outputDir: process.cwd(),
    directories: [],
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '-v':
      case '--verbose':
        options.verbose = true;
        break;
      case '--json':
        options.json = true;
        break;
      case '--all':
        options.scanAll = true;
        break;
      case '--processes':
        options.checkProcesses = true;
        break;
      case '--credentials':
        options.checkCredentials = true;
        break;
      case '--full':
        options.checkProcesses = true;
        options.checkCredentials = true;
        break;
      case '--report':
      case '-r':
        // Enable all report formats
        options.reportFormats.markdown = true;
        options.reportFormats.html = true;
        break;
      case '--markdown':
      case '--md':
        options.reportFormats.markdown = true;
        break;
      case '--html':
        options.reportFormats.html = true;
        break;
      case '--output':
      case '-o':
        if (args[i + 1] && !args[i + 1].startsWith('-')) {
          options.outputDir = path.resolve(args[++i]);
        }
        break;
      default:
        if (!arg.startsWith('-')) {
          options.directories.push(path.resolve(arg));
        }
    }
  }

  return options;
}

function printExtendedHelp() {
  console.log(`
Worm Buster - Shai-Hulud 2 Malware Scanner
==========================================

Usage: worm-buster [options] [directory1] [directory2] ...

  If no directories are specified, scans the current directory.
  You can specify one or more directories to scan.

Scan Options:
  -h, --help        Show this help message
  -v, --verbose     Show verbose output including warnings
  --all             Scan all common project directories (~/{code,projects,dev,...})
  --processes       Check for suspicious running processes
  --credentials     Check for credential files that may have been compromised
  --full            Enable all checks (--processes + --credentials)

Output Options:
  --json            Output results in JSON format only (to stdout)
  -r, --report      Generate reports in all formats (JSON, Markdown, HTML)
  --markdown, --md  Generate Markdown report
  --html            Generate HTML report
  -o, --output DIR  Output directory for reports (default: current directory)

Examples:
  worm-buster                              # Scan current directory
  worm-buster .                            # Scan current directory (explicit)
  worm-buster /path/to/project             # Scan one specific directory
  worm-buster ~/code/app1 ~/code/app2      # Scan multiple directories
  worm-buster --all                        # Scan all common project directories
  worm-buster --full ~/projects            # Full scan with process/credential checks
  worm-buster ~/code --report              # Scan and generate JSON/MD/HTML reports
  worm-buster . --html -o ./reports        # Generate HTML report to ./reports/

Exit Codes:
  0 - No critical issues found
  1 - Critical issues detected
  2 - Fatal error occurred

More Info:
  IOCs based on research from Wiz, Datadog, and Check Point security teams.
  See: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
`);
}

// ============================================================================
// DIRECTORY RESOLUTION
// ============================================================================

function getDirectoriesToScan(options) {
  if (options.directories.length > 0) {
    return options.directories;
  }

  if (options.scanAll) {
    const homeDir = os.homedir();
    const directories = [];

    for (const dir of COMMON_PROJECT_DIRS) {
      const fullPath = path.join(homeDir, dir);
      if (fs.existsSync(fullPath)) {
        directories.push(fullPath);
      }
    }

    return directories.length > 0 ? directories : [homeDir];
  }

  return [process.cwd()];
}

// ============================================================================
// MAIN SCANNER
// ============================================================================

async function scan(options) {
  if (!options.json) {
    printBanner();
  }

  // Load infected packages database
  const wormFile = path.join(__dirname, 'worm.md');

  if (!fs.existsSync(wormFile)) {
    const error = `Error: Cannot find worm.md database at ${wormFile}`;
    if (options.json) {
      console.log(JSON.stringify({ error }));
    } else {
      console.error(error);
      console.error('Please ensure worm.md is in the same directory as this script.');
    }
    process.exit(1);
  }

  const infectedPackages = loadInfectedPackages(wormFile);
  const stats = getPackageStats(infectedPackages);

  if (!options.json) {
    console.log(`[*] Loaded ${stats.uniquePackages} infected packages (${stats.totalVersions} versions)\n`);
  }

  const findings = {
    critical: [],
    warning: [],
    info: [],
  };

  const errorHandler = options.verbose
    ? (filePath, err) => console.error(`  [!] Error scanning ${filePath}: ${err.message}`)
    : null;

  // Get directories to scan
  const directories = getDirectoriesToScan(options);

  if (!options.json) {
    console.log(`[*] Scanning ${directories.length} director${directories.length === 1 ? 'y' : 'ies'}...`);
  }

  // Scan each directory
  for (const dir of directories) {
    if (!fs.existsSync(dir)) {
      if (!options.json) {
        console.log(`[!] Directory not found: ${dir}`);
      }
      continue;
    }

    if (!options.json) {
      console.log(`\n[*] Scanning: ${dir}`);
    }

    // Find package files
    const packageFiles = findPackageFiles(dir, options, errorHandler);
    const packageJsonFiles = packageFiles.filter(f => f.type === 'package.json');
    const lockFiles = packageFiles.filter(f => f.type === 'package-lock.json');
    const nodeModulesDirs = packageFiles.filter(f => f.type === 'node_modules');

    if (options.verbose && !options.json) {
      console.log(`    Found ${packageJsonFiles.length} package.json, ${lockFiles.length} lock files, ${nodeModulesDirs.length} node_modules`);
    }

    // Check package.json files
    for (const { path: filePath } of packageJsonFiles) {
      const pkgFindings = checkPackageJson(filePath, infectedPackages, options);
      for (const finding of pkgFindings) {
        if (finding.severity === 'CRITICAL') {
          findings.critical.push(finding);
        } else if (finding.severity === 'WARNING') {
          findings.warning.push(finding);
        } else {
          findings.info.push(finding);
        }
      }
    }

    // Check package-lock.json files
    for (const { path: filePath } of lockFiles) {
      const lockFindings = checkPackageLock(filePath, infectedPackages, options);
      for (const finding of lockFindings) {
        if (finding.severity === 'CRITICAL') {
          findings.critical.push(finding);
        } else if (finding.severity === 'WARNING') {
          findings.warning.push(finding);
        } else {
          findings.info.push(finding);
        }
      }
    }

    // Check node_modules
    for (const { path: nmPath } of nodeModulesDirs) {
      const nmFindings = checkNodeModules(nmPath, infectedPackages, options);
      for (const finding of nmFindings) {
        if (finding.severity === 'CRITICAL') {
          findings.critical.push(finding);
        } else if (finding.severity === 'WARNING') {
          findings.warning.push(finding);
        } else {
          findings.info.push(finding);
        }
      }
    }

    // Check for malicious artifacts
    const artifacts = findMaliciousArtifacts(dir, errorHandler);
    for (const artifact of artifacts) {
      findings.critical.push({
        type: 'MALICIOUS_ARTIFACT',
        severity: 'CRITICAL',
        ...artifact,
      });
    }
  }

  // Optional system checks
  if (options.checkProcesses) {
    if (!options.json) {
      console.log('\n[*] Checking for suspicious processes...');
    }
    const processFindings = checkRunningProcesses();
    findings.critical.push(...processFindings);
  }

  if (options.checkCredentials) {
    if (!options.json) {
      console.log('[*] Checking credential files...');
    }
    const credFindings = checkCredentialFiles();
    findings.info.push(...credFindings);
  }

  // Output results
  if (options.json) {
    console.log(JSON.stringify(findings, null, 2));
  } else {
    printResults(findings, options);

    // Generate reports
    const report = createReport(findings, options, directories);
    const basePath = path.join(options.outputDir, 'worm-buster-report');

    // Ensure output directory exists
    if (!fs.existsSync(options.outputDir)) {
      fs.mkdirSync(options.outputDir, { recursive: true });
    }

    const generated = saveReports(report, basePath, options.reportFormats);

    console.log('\n[+] Reports generated:');
    for (const [format, filePath] of Object.entries(generated)) {
      console.log(`    ${format.toUpperCase()}: ${filePath}`);
    }
  }

  return findings;
}

// ============================================================================
// EXPORTS (for programmatic use and testing)
// ============================================================================

module.exports = {
  scan,
  parseArgs,
  // Re-export from modules for convenience
  loadInfectedPackages,
  findPackageFiles,
  findMaliciousArtifacts,
  checkPackageJson,
  checkPackageLock,
  checkNodeModules,
  checkRunningProcesses,
  checkCredentialFiles,
  createReport,
  generateMarkdown,
  generateHtml,
};

// ============================================================================
// CLI ENTRY POINT
// ============================================================================

if (require.main === module) {
  const options = parseArgs(process.argv);

  if (options.help) {
    printExtendedHelp();
    process.exit(0);
  }

  scan(options)
    .then(findings => {
      process.exit(findings.critical.length > 0 ? 1 : 0);
    })
    .catch(err => {
      console.error('Fatal error:', err.message);
      if (process.env.DEBUG) {
        console.error(err.stack);
      }
      process.exit(2);
    });
}
