#!/usr/bin/env node
/**
 * Shai-Hulud 2 Malware Scanner
 * Scans for infected npm packages and indicators of compromise
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Load infected packages from worm.md
function loadInfectedPackages(wormFile) {
  const content = fs.readFileSync(wormFile, 'utf8');
  const packages = new Map(); // name -> Set of versions

  content.split('\n').forEach(line => {
    // Parse format: "package-name\tversion\tstatus..."
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
  });

  return packages;
}

// Malicious artifact files to look for (IoCs)
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

// Patterns for suspicious workflow files
const SUSPICIOUS_WORKFLOW_PATTERN = /formatter_\d+\.ya?ml$/;

// Find all package.json files recursively
function findPackageJsonFiles(dir, results = []) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Skip node_modules deep dives but check first level
      if (entry.name === 'node_modules') {
        // Check node_modules for installed infected packages
        const nodeModulesPath = fullPath;
        if (fs.existsSync(nodeModulesPath)) {
          results.push({ type: 'node_modules', path: nodeModulesPath });
        }
        continue;
      }

      // Skip hidden directories except .github
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
    // Permission denied or other errors
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
        // Check against known malicious artifacts
        const relativePath = entry.name;
        for (const artifact of MALICIOUS_ARTIFACTS) {
          if (fullPath.endsWith(artifact) || entry.name === path.basename(artifact)) {
            results.push({ artifact, path: fullPath });
          }
        }

        // Check for suspicious workflow files
        if (fullPath.includes('.github/workflows/') && SUSPICIOUS_WORKFLOW_PATTERN.test(entry.name)) {
          results.push({ artifact: 'suspicious_workflow', path: fullPath });
        }
      }
    }
  } catch (err) {
    // Permission denied or other errors
  }

  return results;
}

// Check package.json for infected dependencies
function checkPackageJson(filePath, infectedPackages) {
  const findings = [];

  try {
    const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const projectName = content.name || path.dirname(filePath);

    // Check dependencies, devDependencies, peerDependencies, optionalDependencies
    const depTypes = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

    for (const depType of depTypes) {
      if (content[depType]) {
        for (const [pkg, versionSpec] of Object.entries(content[depType])) {
          if (infectedPackages.has(pkg)) {
            // Extract version from spec (remove ^, ~, etc.)
            const version = versionSpec.replace(/^[\^~>=<]+/, '').split(' ')[0];
            const infectedVersions = infectedPackages.get(pkg);

            // Check if the version matches any infected version
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
            } else {
              // Package is on the list but version might differ
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

    // Check for suspicious preinstall scripts
    if (content.scripts) {
      const suspiciousScripts = ['preinstall', 'postinstall', 'prepare'];
      for (const script of suspiciousScripts) {
        if (content.scripts[script]) {
          const scriptContent = content.scripts[script];
          // Look for suspicious patterns
          if (scriptContent.includes('bun') ||
              scriptContent.includes('setup_') ||
              scriptContent.includes('curl') ||
              scriptContent.includes('wget') ||
              scriptContent.includes('eval') ||
              /node\s+.*\.js/.test(scriptContent)) {
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
    // Invalid JSON or read error
  }

  return findings;
}

// Check package-lock.json for infected packages
function checkPackageLock(filePath, infectedPackages) {
  const findings = [];

  try {
    const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    // Handle both lockfile v1, v2, and v3 formats
    const packages = content.packages || {};
    const dependencies = content.dependencies || {};

    // Check packages (v2/v3 format)
    for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
      if (!pkgPath || pkgPath === '') continue;

      // Extract package name from path like "node_modules/@scope/package"
      const parts = pkgPath.replace('node_modules/', '').split('node_modules/');
      const pkgName = parts[parts.length - 1];

      if (infectedPackages.has(pkgName) && pkgInfo.version) {
        const infectedVersions = infectedPackages.get(pkgName);
        if (infectedVersions.has(pkgInfo.version)) {
          findings.push({
            type: 'INFECTED_LOCKED_PACKAGE',
            severity: 'CRITICAL',
            package: pkgName,
            version: pkgInfo.version,
            file: filePath,
            installed: true
          });
        }
      }
    }

    // Check dependencies (v1 format)
    function checkDeps(deps, parentPath = '') {
      for (const [name, info] of Object.entries(deps)) {
        if (infectedPackages.has(name) && info.version) {
          const infectedVersions = infectedPackages.get(name);
          if (infectedVersions.has(info.version)) {
            findings.push({
              type: 'INFECTED_LOCKED_PACKAGE',
              severity: 'CRITICAL',
              package: name,
              version: info.version,
              file: filePath,
              installed: true
            });
          }
        }
        // Check nested dependencies
        if (info.dependencies) {
          checkDeps(info.dependencies, `${parentPath}/${name}`);
        }
      }
    }

    checkDeps(dependencies);

  } catch (err) {
    // Invalid JSON or read error
  }

  return findings;
}

// Check node_modules for actually installed infected packages
function checkNodeModules(nodeModulesPath, infectedPackages) {
  const findings = [];

  try {
    const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      // Handle scoped packages (@scope/package)
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
    // Permission denied or other errors
  }

  return findings;
}

// Check for suspicious running processes
function checkRunningProcesses() {
  const findings = [];

  try {
    // Check for Bun processes that might be malicious
    const psOutput = execSync('ps aux 2>/dev/null || tasklist 2>/dev/null', { encoding: 'utf8' });

    const suspiciousPatterns = [
      /bun.*environment/i,
      /bun_environment/i,
      /setup_bun/i,
      /bun.*detach/i,
    ];

    const lines = psOutput.split('\n');
    for (const line of lines) {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(line)) {
          findings.push({
            type: 'SUSPICIOUS_PROCESS',
            severity: 'CRITICAL',
            process: line.trim()
          });
        }
      }
    }
  } catch (err) {
    // Process check failed
  }

  return findings;
}

// Check for credential files that might have been exfiltrated
function checkCredentialFiles() {
  const findings = [];
  const homeDir = process.env.HOME || process.env.USERPROFILE;

  const credentialFiles = [
    '.aws/credentials',
    '.azure/credentials',
    '.config/gcloud/credentials.db',
    '.npmrc',
    '.netrc',
    '.git-credentials',
  ];

  // These files existing is normal, but we note them for awareness
  for (const file of credentialFiles) {
    const fullPath = path.join(homeDir, file);
    if (fs.existsSync(fullPath)) {
      findings.push({
        type: 'CREDENTIAL_FILE_EXISTS',
        severity: 'INFO',
        file: fullPath,
        note: 'Verify this file has not been tampered with'
      });
    }
  }

  return findings;
}

// Main scanning function
async function scan(directories) {
  console.log('\n╔════════════════════════════════════════════════════════════════╗');
  console.log('║         SHAI-HULUD 2 MALWARE SCANNER                          ║');
  console.log('║         Supply Chain Attack Detection Tool                     ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  // Load infected packages
  const wormFile = path.join(__dirname, 'worm.md');
  console.log(`[*] Loading infected packages list from ${wormFile}...`);
  const infectedPackages = loadInfectedPackages(wormFile);
  console.log(`[+] Loaded ${infectedPackages.size} unique infected package names\n`);

  const allFindings = {
    critical: [],
    warning: [],
    info: []
  };

  // Scan each directory
  for (const dir of directories) {
    if (!fs.existsSync(dir)) {
      console.log(`[!] Directory not found: ${dir}`);
      continue;
    }

    console.log(`\n[*] Scanning: ${dir}`);
    console.log('─'.repeat(60));

    // Find package files
    console.log('[*] Finding package.json and package-lock.json files...');
    const packageFiles = findPackageJsonFiles(dir);
    const packageJsonFiles = packageFiles.filter(f => f.type === 'package.json');
    const lockFiles = packageFiles.filter(f => f.type === 'package-lock.json');
    const nodeModulesDirs = packageFiles.filter(f => f.type === 'node_modules');

    console.log(`    Found ${packageJsonFiles.length} package.json files`);
    console.log(`    Found ${lockFiles.length} package-lock.json files`);
    console.log(`    Found ${nodeModulesDirs.length} node_modules directories`);

    // Check package.json files
    console.log('[*] Checking package.json files for infected dependencies...');
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

    // Check package-lock.json files
    console.log('[*] Checking package-lock.json files...');
    for (const { path: filePath } of lockFiles) {
      const findings = checkPackageLock(filePath, infectedPackages);
      for (const finding of findings) {
        if (finding.severity === 'CRITICAL') {
          allFindings.critical.push(finding);
        }
      }
    }

    // Check node_modules
    console.log('[*] Checking installed packages in node_modules...');
    for (const { path: nmPath } of nodeModulesDirs) {
      const findings = checkNodeModules(nmPath, infectedPackages);
      for (const finding of findings) {
        allFindings.critical.push(finding);
      }
    }

    // Check for malicious artifacts
    console.log('[*] Scanning for malicious artifact files (IoCs)...');
    const artifacts = findMaliciousArtifacts(dir);
    for (const artifact of artifacts) {
      allFindings.critical.push({
        type: 'MALICIOUS_ARTIFACT',
        severity: 'CRITICAL',
        ...artifact
      });
    }
  }

  // Check running processes
  console.log('\n[*] Checking for suspicious running processes...');
  const processFindings = checkRunningProcesses();
  allFindings.critical.push(...processFindings);

  // Check credential files
  console.log('[*] Checking credential files...');
  const credFindings = checkCredentialFiles();
  allFindings.info.push(...credFindings);

  // Print results
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║                        SCAN RESULTS                            ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');

  if (allFindings.critical.length === 0 && allFindings.warning.length === 0) {
    console.log('✅ NO INFECTED PACKAGES OR MALICIOUS ARTIFACTS FOUND\n');
    console.log('Your scanned directories appear clean of Shai-Hulud 2 indicators.\n');
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
        if (finding.process) {
          console.log(`  Process: ${finding.process}`);
        }
      }
      console.log('\n');
    }

    if (allFindings.warning.length > 0) {
      console.log('⚠️  WARNINGS:');
      console.log('─'.repeat(60));
      for (const finding of allFindings.warning) {
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
        if (finding.script) {
          console.log(`  Script: ${finding.script}`);
          console.log(`  Content: ${finding.content}`);
        }
      }
      console.log('\n');
    }
  }

  // Summary
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║                         SUMMARY                                ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');
  console.log(`  Critical Findings: ${allFindings.critical.length}`);
  console.log(`  Warnings:          ${allFindings.warning.length}`);
  console.log(`  Info:              ${allFindings.info.length}`);

  if (allFindings.critical.length > 0) {
    console.log('\n📋 RECOMMENDED ACTIONS:');
    console.log('─'.repeat(60));
    console.log('  1. DO NOT run npm install in affected projects');
    console.log('  2. Remove infected packages from package.json');
    console.log('  3. Delete node_modules and package-lock.json');
    console.log('  4. Check .github/workflows for suspicious files');
    console.log('  5. Rotate ALL credentials (AWS, GCP, Azure, GitHub, npm)');
    console.log('  6. Check for unauthorized GitHub Actions workflows');
    console.log('  7. Review recent commits for unauthorized changes');
    console.log('  8. Check for Bun runtime installation: which bun');
  }

  // Write detailed report
  const reportPath = path.join(__dirname, 'scan-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(allFindings, null, 2));
  console.log(`\n[+] Detailed report saved to: ${reportPath}`);

  return allFindings;
}

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Shai-Hulud 2 Malware Scanner
============================

Usage: node scan-shai-hulud.js <directory> [directory2] [directory3] ...

Examples:
  node scan-shai-hulud.js .
  node scan-shai-hulud.js ~/projects ~/code
  node scan-shai-hulud.js /path/to/your/apps

Options:
  -h, --help    Show this help message
`);
  process.exit(0);
}

// Resolve paths to absolute
const directories = args.map(dir => path.resolve(dir));

scan(directories).catch(console.error);
