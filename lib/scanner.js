'use strict';

const fs = require('fs');
const path = require('path');
const { MALICIOUS_ARTIFACTS, SUSPICIOUS_WORKFLOW_PATTERN } = require('./config');

/**
 * Find package.json, package-lock.json, and node_modules directories
 *
 * @param {string} dir - Directory to scan
 * @param {Object} options - Scan options
 * @param {boolean} options.verbose - Enable verbose error output
 * @param {Function} onError - Optional error callback (path, error)
 * @returns {Array<{type: string, path: string}>} Found items
 */
function findPackageFiles(dir, options = {}, onError = null) {
  const results = [];

  function scan(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      if (onError) onError(currentDir, err);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      // Handle node_modules specially - record but don't recurse into it
      if (entry.name === 'node_modules') {
        if (fs.existsSync(fullPath)) {
          results.push({ type: 'node_modules', path: fullPath });
        }
        continue;
      }

      // Skip hidden directories except .github
      if (entry.name.startsWith('.') && entry.name !== '.github') {
        continue;
      }

      if (entry.isDirectory()) {
        scan(fullPath);
      } else if (entry.name === 'package.json') {
        results.push({ type: 'package.json', path: fullPath });
      } else if (entry.name === 'package-lock.json') {
        results.push({ type: 'package-lock.json', path: fullPath });
      }
    }
  }

  scan(dir);
  return results;
}

/**
 * Find malicious artifact files (Indicators of Compromise)
 *
 * @param {string} dir - Directory to scan
 * @param {Function} onError - Optional error callback (path, error)
 * @returns {Array<{artifact: string, path: string}>} Found artifacts
 */
function findMaliciousArtifacts(dir, onError = null) {
  const results = [];

  function scan(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      if (onError) onError(currentDir, err);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      // Skip node_modules
      if (entry.name === 'node_modules') continue;

      if (entry.isDirectory()) {
        scan(fullPath);
      } else {
        // Check against known malicious artifacts
        for (const artifact of MALICIOUS_ARTIFACTS) {
          // For path-based artifacts (contain /), check if path ends with artifact
          // For simple filenames, require exact name match to avoid false positives
          // (e.g., "environment.json" shouldn't match "foo.postman_environment.json")
          const isPathArtifact = artifact.includes('/');
          const matches = isPathArtifact
            ? fullPath.endsWith(artifact)
            : entry.name === artifact;
          if (matches) {
            results.push({ artifact, path: fullPath });
          }
        }

        // Check for suspicious workflow files (formatter_*.yml pattern)
        if (
          fullPath.includes('.github/workflows/') &&
          SUSPICIOUS_WORKFLOW_PATTERN.test(entry.name)
        ) {
          results.push({ artifact: 'suspicious_workflow', path: fullPath });
        }
      }
    }
  }

  scan(dir);
  return results;
}

module.exports = {
  findPackageFiles,
  findMaliciousArtifacts,
};
