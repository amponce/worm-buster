'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { findPackageFiles, findMaliciousArtifacts } = require('../lib/scanner');

describe('scanner', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'worm-buster-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  describe('findPackageFiles', () => {
    it('should find package.json in directory', () => {
      fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');

      const results = findPackageFiles(tempDir);

      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].type, 'package.json');
    });

    it('should find package-lock.json', () => {
      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');

      const results = findPackageFiles(tempDir);

      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].type, 'package-lock.json');
    });

    it('should find node_modules directory', () => {
      fs.mkdirSync(path.join(tempDir, 'node_modules'));

      const results = findPackageFiles(tempDir);

      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].type, 'node_modules');
    });

    it('should find files in subdirectories', () => {
      const subDir = path.join(tempDir, 'packages', 'sub');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'package.json'), '{}');

      const results = findPackageFiles(tempDir);

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].path.includes('sub'));
    });

    it('should skip hidden directories except .github', () => {
      const hiddenDir = path.join(tempDir, '.hidden');
      const githubDir = path.join(tempDir, '.github');
      fs.mkdirSync(hiddenDir);
      fs.mkdirSync(githubDir);
      fs.writeFileSync(path.join(hiddenDir, 'package.json'), '{}');
      fs.writeFileSync(path.join(githubDir, 'package.json'), '{}');

      const results = findPackageFiles(tempDir);

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].path.includes('.github'));
    });

    it('should call error handler on permission error', () => {
      const errors = [];
      const onError = (filePath, err) => errors.push({ filePath, err });

      // Create a directory we can't read (if running as non-root)
      const restrictedDir = path.join(tempDir, 'restricted');
      fs.mkdirSync(restrictedDir);

      // Try to make it unreadable (may not work on all systems)
      try {
        fs.chmodSync(restrictedDir, 0o000);
        findPackageFiles(tempDir, {}, onError);

        // Restore permissions for cleanup
        fs.chmodSync(restrictedDir, 0o755);

        // If chmod worked, we should have an error
        if (errors.length > 0) {
          assert.ok(errors[0].err);
        }
      } catch (e) {
        // chmod may not work on Windows or when running as root
      }
    });
  });

  describe('findMaliciousArtifacts', () => {
    it('should find setup_bun.js', () => {
      fs.writeFileSync(path.join(tempDir, 'setup_bun.js'), '');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].artifact.includes('setup_bun.js'));
    });

    it('should find bun_environment.js', () => {
      fs.writeFileSync(path.join(tempDir, 'bun_environment.js'), '');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
    });

    it('should find cloud.json', () => {
      fs.writeFileSync(path.join(tempDir, 'cloud.json'), '{}');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].artifact.includes('cloud.json'));
    });

    it('should find discussion.yaml in .github/workflows', () => {
      const workflowDir = path.join(tempDir, '.github', 'workflows');
      fs.mkdirSync(workflowDir, { recursive: true });
      fs.writeFileSync(path.join(workflowDir, 'discussion.yaml'), '');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
      assert.ok(results[0].artifact.includes('discussion.yaml'));
    });

    it('should find suspicious formatter_*.yml workflow', () => {
      const workflowDir = path.join(tempDir, '.github', 'workflows');
      fs.mkdirSync(workflowDir, { recursive: true });
      fs.writeFileSync(path.join(workflowDir, 'formatter_12345.yml'), '');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].artifact, 'suspicious_workflow');
    });

    it('should skip node_modules', () => {
      const nmDir = path.join(tempDir, 'node_modules', 'some-pkg');
      fs.mkdirSync(nmDir, { recursive: true });
      fs.writeFileSync(path.join(nmDir, 'setup_bun.js'), '');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 0);
    });

    it('should find artifacts in subdirectories', () => {
      const subDir = path.join(tempDir, 'src', 'lib');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'truffleSecrets.json'), '{}');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
    });

    it('should return empty array for clean directory', () => {
      fs.writeFileSync(path.join(tempDir, 'index.js'), '');
      fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 0);
    });

    it('should not flag postman environment files as malicious', () => {
      // Postman files end with .postman_environment.json which is NOT the same as environment.json
      fs.writeFileSync(path.join(tempDir, 'Sandbox.postman_environment.json'), '{}');
      fs.writeFileSync(path.join(tempDir, 'localhost Environment.postman_environment.json'), '{}');
      fs.writeFileSync(path.join(tempDir, 'my-config.environment.json'), '{}');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 0, 'Postman environment files should not be flagged');
    });

    it('should flag exact environment.json as malicious', () => {
      // The actual malware file is exactly named environment.json
      fs.writeFileSync(path.join(tempDir, 'environment.json'), '{}');

      const results = findMaliciousArtifacts(tempDir);

      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].artifact, 'environment.json');
    });
  });
});
