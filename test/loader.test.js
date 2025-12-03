'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { loadInfectedPackages, getPackageStats } = require('../lib/loader');

describe('loader', () => {
  let tempDir;
  let tempFile;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'worm-buster-test-'));
  });

  afterEach(() => {
    if (tempFile && fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmdirSync(tempDir, { recursive: true });
    }
  });

  describe('loadInfectedPackages', () => {
    it('should parse markdown table format', () => {
      tempFile = path.join(tempDir, 'worm.md');
      fs.writeFileSync(tempFile, `
| Package | Version | Status |
|---------|---------|--------|
| bad-package | 1.0.0 | offline |
| @scope/pkg | 2.0.0 | offline |
`);

      const packages = loadInfectedPackages(tempFile);

      assert.strictEqual(packages.size, 2);
      assert.ok(packages.has('bad-package'));
      assert.ok(packages.has('@scope/pkg'));
      assert.ok(packages.get('bad-package').has('1.0.0'));
      assert.ok(packages.get('@scope/pkg').has('2.0.0'));
    });

    it('should parse tab-separated format', () => {
      tempFile = path.join(tempDir, 'worm.md');
      fs.writeFileSync(tempFile, `
bad-package\t1.0.0\toffline
another-pkg\t3.0.0\toffline
`);

      const packages = loadInfectedPackages(tempFile);

      assert.strictEqual(packages.size, 2);
      assert.ok(packages.has('bad-package'));
      assert.ok(packages.has('another-pkg'));
    });

    it('should handle multiple versions of same package', () => {
      tempFile = path.join(tempDir, 'worm.md');
      fs.writeFileSync(tempFile, `
| Package | Version | Status |
|---------|---------|--------|
| bad-package | 1.0.0 | offline |
| bad-package | 1.0.1 | offline |
| bad-package | 2.0.0 | offline |
`);

      const packages = loadInfectedPackages(tempFile);

      assert.strictEqual(packages.size, 1);
      const versions = packages.get('bad-package');
      assert.strictEqual(versions.size, 3);
      assert.ok(versions.has('1.0.0'));
      assert.ok(versions.has('1.0.1'));
      assert.ok(versions.has('2.0.0'));
    });

    it('should skip header rows', () => {
      tempFile = path.join(tempDir, 'worm.md');
      fs.writeFileSync(tempFile, `
| Package | Version | Status |
|---------|---------|--------|
| real-package | 1.0.0 | offline |
`);

      const packages = loadInfectedPackages(tempFile);

      assert.strictEqual(packages.size, 1);
      assert.ok(!packages.has('Package'));
      assert.ok(packages.has('real-package'));
    });

    it('should handle empty file', () => {
      tempFile = path.join(tempDir, 'worm.md');
      fs.writeFileSync(tempFile, '');

      const packages = loadInfectedPackages(tempFile);

      assert.strictEqual(packages.size, 0);
    });
  });

  describe('getPackageStats', () => {
    it('should return correct statistics', () => {
      const packages = new Map();
      packages.set('pkg1', new Set(['1.0.0', '1.0.1']));
      packages.set('pkg2', new Set(['2.0.0']));

      const stats = getPackageStats(packages);

      assert.strictEqual(stats.uniquePackages, 2);
      assert.strictEqual(stats.totalVersions, 3);
    });

    it('should handle empty map', () => {
      const packages = new Map();
      const stats = getPackageStats(packages);

      assert.strictEqual(stats.uniquePackages, 0);
      assert.strictEqual(stats.totalVersions, 0);
    });
  });
});
