#!/usr/bin/env node
/**
 * Worm Buster - Shai-Hulud 2 Malware Scanner
 * Enhanced version with CLI arguments and automatic path detection
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

// Parse command line arguments
const args = process.argv.slice(2);
const showHelp = args.includes('--help') || args.includes('-h');
const verbose = args.includes('--verbose') || args.includes('-v');
const outputJson = args.includes('--json');
const scanAll = args.includes('--all');

// Show help
if (showHelp) {
  console.log(`
Worm Buster - Shai-Hulud 2 Malware Scanner

Usage: node worm-buster.js [options] [directories...]

Options:
  -h, --help      Show this help message
  -v, --verbose   Show verbose output
  --json          Output results in JSON format
  --all           Scan all common project directories
  --current       Scan current directory only (default if no paths specified)

Examples:
  node worm-buster.js                    # Scan current directory
  node worm-buster.js --all              # Scan all common directories
  node worm-buster.js /path/to/project   # Scan specific directory
  node worm-buster.js . ../other-project # Scan multiple directories
  `);
  process.exit(0);
}

// Load infected packages from worm.md
function loadInfectedPackages(wormFile) {
  const content = fs.readFileSync(wormFile, 'utf8');
  const packages = new Map();

  // Handle markdown table format
  const lines = content.split('\n');
  let inTable = false;
  
  for (const line of lines) {
    // Skip table headers and separators
    if (line.includes('| Package') || line.includes('|---')) {
      inTable = true;
      continue;
    }
    
    if (inTable && line.startsWith('|')) {
      // Parse markdown table row: | package | version | status | ... |
      const parts = line.split('|').map(p => p.trim()).filter(p => p);
      if (parts.length >= 2) {
        const name = parts[0];
        const version = parts[1];
        if (name && version && !name.includes('Package')) {
          if (!packages.has(name)) {
            packages.set(name, new Set());
          }
          packages.get(name).add(version);
        }
      }
    } else if (line.includes('\t')) {
      // Fallback to tab-separated format
      const parts = line.trim().split('\t');
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const version = parts[1].trim();
        if (name && version) {
          if (!packages.has(name)) {
            packages.set(name, new Set());
          }
          packages.get(name).add(version);
        }
      }
    }
  }

  return packages;
}

// Malicious artifact files to look for
const MALICIOUS_ARTIFACTS = [
  '.github/workflows/discussion.yaml',
  '.github/workflows/discussion.yml',
  'cloud.json',
  'contents.json',
  'environment.json',
  'truffleSecrets.json',
  'actionsSecrets.json',
  'setup_bun.js',
  'bun_environment.js',
];

const SUSPICIOUS_WORKFLOW_PATTERN = /formatter_\d+\.ya?ml$/;

// Find all package.json files recursively
function findPackageJsonFiles(dir, results = []) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.name === 'node_modules') {
        const nodeModulesPath = fullPath;
        if (fs.existsSync(nodeModulesPath)) {
          results.push({ type: 'node_modules', path: nodeModulesPath });
        }
        continue;
      }

      if (entry.name.startsWith('.') && entry.name !== '.github') {
        continue;
      }

      if (entry.isDirectory()) {
        findPackageJsonFiles(fullPath, results);
      } else if (entry.name === 'package.json') {
        results.push({ type: 'package.json', path: fullPath });
      } else if (entry.name === 'package-lock.json') {
        results.push({ type: 'package-lock.json', path: fullPath });
      }
    }
  } catch (err) {
    if (verbose) {
      console.error(`Error scanning ${dir}: ${err.message}`);
    }
  }

  return results;
}

// Check for malicious artifact files
function findMaliciousArtifacts(dir, results = []) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.name === 'node_modules') continue;

      if (entry.isDirectory()) {
        findMaliciousArtifacts(fullPath, results);
      } else {
        const relativePath = entry.name;
        for (const artifact of MALICIOUS_ARTIFACTS) {
          if (fullPath.endsWith(artifact) || entry.name === path.basename(artifact)) {
            results.push({ artifact, path: fullPath });
          }
        }

        if (fullPath.includes('.github/workflows/') && SUSPICIOUS_WORKFLOW_PATTERN.test(entry.name)) {
          results.push({ artifact: 'suspicious_workflow', path: fullPath });
        }
      }
    }
  } catch (err) {
    if (verbose) {
      console.error(`Error scanning artifacts in ${dir}: ${err.message}`);
    }
  }

  return results;
}

// Check package.json for infected dependencies
function checkPackageJson(filePath, infectedPackages) {
  const findings = [];

  try {
    const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const depTypes = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

    for (const depType of depTypes) {
      if (content[depType]) {
        for (const [pkg, versionSpec] of Object.entries(content[depType])) {
          if (infectedPackages.has(pkg)) {
            const version = versionSpec.replace(/^[\^~>=<]+/, '').split(' ')[0];
            const infectedVersions = infectedPackages.get(pkg);

            if (infectedVersions.has(version)) {
              findings.push({
                type: 'INFECTED_PACKAGE',
                severity: 'CRITICAL',
                package: pkg,
                version: version,
                declaredVersion: versionSpec,
                depType,
                file: filePath
              });
            } else if (verbose) {
              findings.push({
                type: 'SUSPICIOUS_PACKAGE',
                severity: 'WARNING',
                package: pkg,
                version: version,
                declaredVersion: versionSpec,
                infectedVersions: Array.from(infectedVersions),
                depType,
                file: filePath
              });
            }
          }
        }
      }
    }

    // Check for suspicious scripts
    if (content.scripts) {
      const suspiciousScripts = ['preinstall', 'postinstall', 'prepare'];
      for (const script of suspiciousScripts) {
        if (content.scripts[script]) {
          const scriptContent = content.scripts[script];
          if (scriptContent.includes('bun') ||
              scriptContent.includes('setup_') ||
              scriptContent.includes('curl') ||
              scriptContent.includes('wget') ||
              scriptContent.includes('eval')) {
            findings.push({
              type: 'SUSPICIOUS_SCRIPT',
              severity: 'WARNING',
              script,
              content: scriptContent,
              file: filePath
            });
          }
        }
      }
    }
  } catch (err) {
    if (verbose) {
      console.error(`Error checking ${filePath}: ${err.message}`);
    }
  }

  return findings;
}

// Check node_modules for installed infected packages
function checkNodeModules(nodeModulesPath, infectedPackages) {
  const findings = [];

  try {
    const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      if (entry.name.startsWith('@')) {
        const scopePath = path.join(nodeModulesPath, entry.name);
        const scopedEntries = fs.readdirSync(scopePath, { withFileTypes: true });

        for (const scopedEntry of scopedEntries) {
          if (!scopedEntry.isDirectory()) continue;
          const pkgName = `${entry.name}/${scopedEntry.name}`;
          const pkgJsonPath = path.join(scopePath, scopedEntry.name, 'package.json');

          if (infectedPackages.has(pkgName) && fs.existsSync(pkgJsonPath)) {
            try {
              const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
              const infectedVersions = infectedPackages.get(pkgName);
              if (infectedVersions.has(pkgJson.version)) {
                findings.push({
                  type: 'INSTALLED_INFECTED_PACKAGE',
                  severity: 'CRITICAL',
                  package: pkgName,
                  version: pkgJson.version,
                  path: path.join(scopePath, scopedEntry.name)
                });
              }
            } catch (e) {}
          }
        }
      } else {
        const pkgName = entry.name;
        const pkgJsonPath = path.join(nodeModulesPath, pkgName, 'package.json');

        if (infectedPackages.has(pkgName) && fs.existsSync(pkgJsonPath)) {
          try {
            const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
            const infectedVersions = infectedPackages.get(pkgName);
            if (infectedVersions.has(pkgJson.version)) {
              findings.push({
                type: 'INSTALLED_INFECTED_PACKAGE',
                severity: 'CRITICAL',
                package: pkgName,
                version: pkgJson.version,
                path: path.join(nodeModulesPath, pkgName)
              });
            }
          } catch (e) {}
        }
      }
    }
  } catch (err) {
    if (verbose) {
      console.error(`Error checking node_modules: ${err.message}`);
    }
  }

  return findings;
}

// Get directories to scan
function getDirectoriesToScan() {
  const directories = [];
  
  // Get non-flag arguments as directories
  const pathArgs = args.filter(arg => !arg.startsWith('-'));
  
  if (pathArgs.length > 0) {
    // Use specified directories
    directories.push(...pathArgs.map(p => path.resolve(p)));
  } else if (scanAll) {
    // Scan all common directories
    const homeDir = os.homedir();
    const commonDirs = [
      path.join(homeDir, 'code'),
      path.join(homeDir, 'projects'),
      path.join(homeDir, 'workspace'),
      path.join(homeDir, 'workspaces'),
      path.join(homeDir, 'dev'),
      path.join(homeDir, 'development'),
      path.join(homeDir, 'repos'),
      path.join(homeDir, 'github'),
      path.join(homeDir, 'Documents', 'code'),
      path.join(homeDir, 'Documents', 'projects'),
    ];
    
    // Add existing directories
    for (const dir of commonDirs) {
      if (fs.existsSync(dir)) {
        directories.push(dir);
      }
    }
    
    if (directories.length === 0) {
      // Fallback to home directory
      directories.push(homeDir);
    }
  } else {
    // Default to current directory
    directories.push(process.cwd());
  }
  
  return directories;
}

// Main scanning function
async function scan() {
  if (!outputJson) {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║              WORM BUSTER - MALWARE SCANNER                     ║');
    console.log('║         Detecting Shai-Hulud 2 Supply Chain Attack             ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');
  }

  // Load infected packages
  const wormFile = path.join(__dirname, 'worm.md');
  
  if (!fs.existsSync(wormFile)) {
    console.error(`Error: Cannot find worm.md database at ${wormFile}`);
    console.error('Please ensure worm.md is in the same directory as this script.');
    process.exit(1);
  }
  
  if (!outputJson && verbose) {
    console.log(`[*] Loading infected packages from ${wormFile}...`);
  }
  
  const infectedPackages = loadInfectedPackages(wormFile);
  
  if (!outputJson) {
    console.log(`[+] Loaded ${infectedPackages.size} infected packages\n`);
  }

  const allFindings = {
    critical: [],
    warning: [],
    info: []
  };

  // Get directories to scan
  const directories = getDirectoriesToScan();
  
  if (!outputJson) {
    console.log(`[*] Scanning ${directories.length} director${directories.length === 1 ? 'y' : 'ies'}...`);
  }

  // Scan each directory
  for (const dir of directories) {
    if (!fs.existsSync(dir)) {
      if (!outputJson) {
        console.log(`[!] Directory not found: ${dir}`);
      }
      continue;
    }

    if (!outputJson) {
      console.log(`\n[*] Scanning: ${dir}`);
      console.log('─'.repeat(60));
    }

    // Find package files
    const packageFiles = findPackageJsonFiles(dir);
    const packageJsonFiles = packageFiles.filter(f => f.type === 'package.json');
    const nodeModulesDirs = packageFiles.filter(f => f.type === 'node_modules');

    if (verbose && !outputJson) {
      console.log(`    Found ${packageJsonFiles.length} package.json files`);
      console.log(`    Found ${nodeModulesDirs.length} node_modules directories`);
    }

    // Check package.json files
    for (const { path: filePath } of packageJsonFiles) {
      const findings = checkPackageJson(filePath, infectedPackages);
      for (const finding of findings) {
        if (finding.severity === 'CRITICAL') {
          allFindings.critical.push(finding);
        } else if (finding.severity === 'WARNING') {
          allFindings.warning.push(finding);
        }
      }
    }

    // Check node_modules
    for (const { path: nmPath } of nodeModulesDirs) {
      const findings = checkNodeModules(nmPath, infectedPackages);
      allFindings.critical.push(...findings);
    }

    // Check for malicious artifacts
    const artifacts = findMaliciousArtifacts(dir);
    for (const artifact of artifacts) {
      allFindings.critical.push({
        type: 'MALICIOUS_ARTIFACT',
        severity: 'CRITICAL',
        ...artifact
      });
    }
  }

  // Output results
  if (outputJson) {
    console.log(JSON.stringify(allFindings, null, 2));
  } else {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║                        SCAN RESULTS                            ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    if (allFindings.critical.length === 0 && allFindings.warning.length === 0) {
      console.log('✅ NO INFECTED PACKAGES OR MALICIOUS ARTIFACTS FOUND\n');
    } else {
      if (allFindings.critical.length > 0) {
        console.log('🚨 CRITICAL FINDINGS:');
        console.log('─'.repeat(60));
        for (const finding of allFindings.critical) {
          console.log(`\n  Type: ${finding.type}`);
          if (finding.package) {
            console.log(`  Package: ${finding.package}@${finding.version}`);
          }
          if (finding.file) {
            console.log(`  File: ${finding.file}`);
          }
          if (finding.path) {
            console.log(`  Path: ${finding.path}`);
          }
          if (finding.artifact) {
            console.log(`  Artifact: ${finding.artifact}`);
          }
        }
        console.log('\n');
      }

      if (allFindings.warning.length > 0 && verbose) {
        console.log('⚠️  WARNINGS:');
        console.log('─'.repeat(60));
        for (const finding of allFindings.warning) {
          console.log(`\n  Type: ${finding.type}`);
          if (finding.package) {
            console.log(`  Package: ${finding.package}`);
          }
          if (finding.file) {
            console.log(`  File: ${finding.file}`);
          }
        }
        console.log('\n');
      }
    }

    // Summary
    console.log('─'.repeat(60));
    console.log(`  Critical: ${allFindings.critical.length} | Warnings: ${allFindings.warning.length}`);
    
    if (allFindings.critical.length > 0) {
      console.log('\n⚠️  IMMEDIATE ACTIONS REQUIRED:');
      console.log('  1. Remove infected packages from package.json');
      console.log('  2. Delete node_modules and package-lock.json');
      console.log('  3. Check and remove malicious files');
      console.log('  4. Rotate ALL credentials immediately');
      console.log('  5. Review GitHub Actions for unauthorized workflows');
    }

    // Save report
    const reportPath = path.join(process.cwd(), 'worm-buster-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(allFindings, null, 2));
    console.log(`\n[+] Report saved to: ${reportPath}`);
  }

  return allFindings;
}

// Run the scanner
scan().catch(console.error);