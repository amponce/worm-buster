'use strict';

const fs = require('fs');
const path = require('path');
const {
  DEPENDENCY_TYPES,
  SUSPICIOUS_SCRIPTS,
  SUSPICIOUS_SCRIPT_PATTERNS,
} = require('./config');

/**
 * Check package.json for infected dependencies and suspicious scripts
 *
 * @param {string} filePath - Path to package.json
 * @param {Map<string, Set<string>>} infectedPackages - Map of infected packages
 * @param {Object} options - Scan options
 * @param {boolean} options.verbose - Include warnings for suspicious packages
 * @returns {Array} Array of findings
 */
function checkPackageJson(filePath, infectedPackages, options = {}) {
  const findings = [];
  let content;

  try {
    content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    if (options.verbose) {
      findings.push({
        type: 'PARSE_ERROR',
        severity: 'INFO',
        file: filePath,
        message: `Failed to parse: ${err.message}`,
      });
    }
    return findings;
  }

  // Check all dependency types
  for (const depType of DEPENDENCY_TYPES) {
    if (!content[depType]) continue;

    for (const [pkg, versionSpec] of Object.entries(content[depType])) {
      if (!infectedPackages.has(pkg)) continue;

      // Extract version from spec (remove ^, ~, >=, etc.)
      const version = extractVersion(versionSpec);
      const infectedVersions = infectedPackages.get(pkg);

      if (infectedVersions.has(version)) {
        findings.push({
          type: 'INFECTED_PACKAGE',
          severity: 'CRITICAL',
          package: pkg,
          version,
          declaredVersion: versionSpec,
          depType,
          file: filePath,
        });
      } else {
        // Package was targeted in the attack but user has a different version
        findings.push({
          type: 'KNOWN_TARGET',
          severity: 'WARNING',
          package: pkg,
          version,
          declaredVersion: versionSpec,
          infectedVersions: Array.from(infectedVersions),
          depType,
          file: filePath,
          note: 'This package was compromised in the Shai-Hulud 2 attack but you have a different version. Do NOT upgrade to: ' + Array.from(infectedVersions).join(', '),
        });
      }
    }
  }

  // Check for suspicious install scripts
  if (content.scripts) {
    for (const script of SUSPICIOUS_SCRIPTS) {
      if (!content.scripts[script]) continue;

      const scriptContent = content.scripts[script];
      const isSuspicious = SUSPICIOUS_SCRIPT_PATTERNS.some(pattern =>
        scriptContent.includes(pattern)
      );

      if (isSuspicious) {
        findings.push({
          type: 'SUSPICIOUS_SCRIPT',
          severity: 'WARNING',
          script,
          content: scriptContent,
          file: filePath,
        });
      }
    }
  }

  return findings;
}

/**
 * Check package-lock.json for infected packages
 *
 * @param {string} filePath - Path to package-lock.json
 * @param {Map<string, Set<string>>} infectedPackages - Map of infected packages
 * @param {Object} options - Scan options
 * @returns {Array} Array of findings
 */
function checkPackageLock(filePath, infectedPackages, options = {}) {
  const findings = [];
  let content;

  try {
    content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    if (options.verbose) {
      findings.push({
        type: 'PARSE_ERROR',
        severity: 'INFO',
        file: filePath,
        message: `Failed to parse: ${err.message}`,
      });
    }
    return findings;
  }

  // Handle lockfile v2/v3 format (packages object)
  const packages = content.packages || {};
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
          installed: true,
        });
      }
    }
  }

  // Handle lockfile v1 format (dependencies object)
  if (content.dependencies) {
    checkDependenciesV1(content.dependencies, filePath, infectedPackages, findings);
  }

  return findings;
}

/**
 * Recursively check v1 lockfile dependencies
 */
function checkDependenciesV1(deps, filePath, infectedPackages, findings) {
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
          installed: true,
        });
      }
    }
    // Check nested dependencies
    if (info.dependencies) {
      checkDependenciesV1(info.dependencies, filePath, infectedPackages, findings);
    }
  }
}

/**
 * Check node_modules for installed infected packages
 *
 * @param {string} nodeModulesPath - Path to node_modules directory
 * @param {Map<string, Set<string>>} infectedPackages - Map of infected packages
 * @param {Object} options - Scan options
 * @returns {Array} Array of findings
 */
function checkNodeModules(nodeModulesPath, infectedPackages, options = {}) {
  const findings = [];
  let entries;

  try {
    entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
  } catch (err) {
    if (options.verbose) {
      findings.push({
        type: 'READ_ERROR',
        severity: 'INFO',
        path: nodeModulesPath,
        message: `Failed to read: ${err.message}`,
      });
    }
    return findings;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    // Handle scoped packages (@scope/package)
    if (entry.name.startsWith('@')) {
      const scopePath = path.join(nodeModulesPath, entry.name);
      let scopedEntries;
      try {
        scopedEntries = fs.readdirSync(scopePath, { withFileTypes: true });
      } catch (err) {
        continue;
      }

      for (const scopedEntry of scopedEntries) {
        if (!scopedEntry.isDirectory()) continue;
        const pkgName = `${entry.name}/${scopedEntry.name}`;
        const pkgPath = path.join(scopePath, scopedEntry.name);
        checkInstalledPackage(pkgName, pkgPath, infectedPackages, findings, options);
      }
    } else {
      const pkgPath = path.join(nodeModulesPath, entry.name);
      checkInstalledPackage(entry.name, pkgPath, infectedPackages, findings, options);
    }
  }

  return findings;
}

/**
 * Check a single installed package for infection
 */
function checkInstalledPackage(pkgName, pkgPath, infectedPackages, findings, options) {
  if (!infectedPackages.has(pkgName)) return;

  const pkgJsonPath = path.join(pkgPath, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) return;

  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  } catch (err) {
    if (options.verbose) {
      findings.push({
        type: 'PARSE_ERROR',
        severity: 'INFO',
        path: pkgJsonPath,
        message: `Failed to parse: ${err.message}`,
      });
    }
    return;
  }

  const infectedVersions = infectedPackages.get(pkgName);
  if (infectedVersions.has(pkgJson.version)) {
    findings.push({
      type: 'INSTALLED_INFECTED_PACKAGE',
      severity: 'CRITICAL',
      package: pkgName,
      version: pkgJson.version,
      path: pkgPath,
    });
  }
}

/**
 * Extract clean version from version specifier
 * @param {string} versionSpec - Version specifier (e.g., "^1.2.3", ">=2.0.0")
 * @returns {string} Clean version number
 */
function extractVersion(versionSpec) {
  return versionSpec.replace(/^[\^~>=<]+/, '').split(' ')[0];
}

module.exports = {
  checkPackageJson,
  checkPackageLock,
  checkNodeModules,
  extractVersion,
};
