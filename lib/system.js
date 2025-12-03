'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');
const { SUSPICIOUS_PROCESS_PATTERNS, CREDENTIAL_FILES } = require('./config');

/**
 * Check for suspicious running processes that may indicate active malware
 *
 * @returns {Array} Array of findings for suspicious processes
 */
function checkRunningProcesses() {
  const findings = [];

  try {
    // Use ps on Unix, tasklist on Windows
    const psOutput = execSync('ps aux 2>/dev/null || tasklist 2>/dev/null', {
      encoding: 'utf8',
      timeout: 10000,
    });

    const lines = psOutput.split('\n');
    for (const line of lines) {
      for (const pattern of SUSPICIOUS_PROCESS_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            type: 'SUSPICIOUS_PROCESS',
            severity: 'CRITICAL',
            process: line.trim(),
          });
        }
      }
    }
  } catch (err) {
    // Process check failed - not critical, silently skip
    // This can happen on restricted systems or containers
  }

  return findings;
}

/**
 * Check for credential files that may have been compromised
 *
 * These files existing is normal, but if malware was active,
 * they may have been exfiltrated.
 *
 * @returns {Array} Array of info findings for existing credential files
 */
function checkCredentialFiles() {
  const findings = [];
  const homeDir = os.homedir();

  for (const file of CREDENTIAL_FILES) {
    const fullPath = path.join(homeDir, file);
    if (fs.existsSync(fullPath)) {
      findings.push({
        type: 'CREDENTIAL_FILE_EXISTS',
        severity: 'INFO',
        file: fullPath,
        note: 'If malware was active, rotate these credentials',
      });
    }
  }

  return findings;
}

/**
 * Get system information for reporting
 *
 * @returns {Object} System info object
 */
function getSystemInfo() {
  return {
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,
    homeDir: os.homedir(),
    cwd: process.cwd(),
  };
}

module.exports = {
  checkRunningProcesses,
  checkCredentialFiles,
  getSystemInfo,
};
