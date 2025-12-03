'use strict';

const fs = require('fs');

/**
 * Load infected packages database from worm.md
 *
 * Supports two formats:
 * 1. Markdown table: | package | version | status | ... |
 * 2. Tab-separated: package\tversion\tstatus...
 *
 * @param {string} wormFile - Path to worm.md file
 * @returns {Map<string, Set<string>>} Map of package name to Set of infected versions
 * @throws {Error} If file cannot be read
 */
function loadInfectedPackages(wormFile) {
  const content = fs.readFileSync(wormFile, 'utf8');
  const packages = new Map();
  const lines = content.split('\n');
  let inTable = false;

  for (const line of lines) {
    // Detect markdown table header
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
          addPackage(packages, name, version);
        }
      }
    } else if (line.includes('\t')) {
      // Fallback: tab-separated format
      const parts = line.trim().split('\t');
      if (parts.length >= 2) {
        const name = parts[0].trim();
        const version = parts[1].trim();
        if (name && version) {
          addPackage(packages, name, version);
        }
      }
    }
  }

  return packages;
}

/**
 * Helper to add a package to the map
 */
function addPackage(packages, name, version) {
  if (!packages.has(name)) {
    packages.set(name, new Set());
  }
  packages.get(name).add(version);
}

/**
 * Get count statistics from loaded packages
 * @param {Map} packages - Loaded packages map
 * @returns {Object} Statistics object
 */
function getPackageStats(packages) {
  let totalVersions = 0;
  for (const versions of packages.values()) {
    totalVersions += versions.size;
  }

  return {
    uniquePackages: packages.size,
    totalVersions,
  };
}

module.exports = {
  loadInfectedPackages,
  getPackageStats,
};
