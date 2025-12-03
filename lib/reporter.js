'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Generate scan reports in various formats (JSON, Markdown, HTML)
 */

/**
 * Generate a complete report object with metadata
 *
 * @param {Object} findings - Scan findings
 * @param {Object} options - Scan options used
 * @param {Array<string>} directories - Directories that were scanned
 * @returns {Object} Complete report object
 */
function createReport(findings, options = {}, directories = []) {
  return {
    meta: {
      tool: 'Worm Buster',
      version: '1.0.0',
      description: 'Shai-Hulud 2 Malware Scanner',
      scanDate: new Date().toISOString(),
      hostname: os.hostname(),
      platform: os.platform(),
      nodeVersion: process.version,
    },
    scan: {
      directories,
      options: {
        verbose: options.verbose || false,
        checkProcesses: options.checkProcesses || false,
        checkCredentials: options.checkCredentials || false,
      },
    },
    summary: {
      critical: findings.critical.length,
      warning: findings.warning.length,
      info: findings.info.length,
      status: findings.critical.length > 0 ? 'INFECTED' : 'CLEAN',
    },
    findings,
  };
}

/**
 * Save report as JSON
 *
 * @param {Object} report - Report object
 * @param {string} outputPath - Output file path
 */
function saveJson(report, outputPath) {
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
}

/**
 * Generate Markdown report content
 *
 * @param {Object} report - Report object
 * @returns {string} Markdown content
 */
function generateMarkdown(report) {
  const lines = [];

  // Header
  lines.push('# Worm Buster Scan Report');
  lines.push('## Shai-Hulud 2 Malware Detection Results');
  lines.push('');
  lines.push('---');
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`**Status:** ${report.summary.status}`);
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| Critical | ${report.summary.critical} |`);
  lines.push(`| Warning | ${report.summary.warning} |`);
  lines.push(`| Info | ${report.summary.info} |`);
  lines.push('');

  // Scan Details
  lines.push('## Scan Details');
  lines.push('');
  lines.push(`- **Date:** ${report.meta.scanDate}`);
  lines.push(`- **Hostname:** ${report.meta.hostname}`);
  lines.push(`- **Platform:** ${report.meta.platform}`);
  lines.push(`- **Node Version:** ${report.meta.nodeVersion}`);
  lines.push('');
  lines.push('### Scanned Directories');
  lines.push('');
  for (const dir of report.scan.directories) {
    lines.push(`- \`${dir}\``);
  }
  lines.push('');

  // Critical Findings
  if (report.findings.critical.length > 0) {
    lines.push('## Critical Findings');
    lines.push('');
    lines.push('> **IMMEDIATE ACTION REQUIRED**');
    lines.push('');

    for (let i = 0; i < report.findings.critical.length; i++) {
      const finding = report.findings.critical[i];
      lines.push(`### ${i + 1}. ${finding.type}`);
      lines.push('');

      if (finding.package) {
        lines.push(`- **Package:** \`${finding.package}@${finding.version}\``);
        if (finding.depType) {
          lines.push(`- **Dependency Type:** ${finding.depType}`);
        }
      }

      if (finding.file) {
        lines.push(`- **File:** \`${finding.file}\``);
      }

      if (finding.path && !finding.file) {
        lines.push(`- **Path:** \`${finding.path}\``);
      }

      if (finding.artifact) {
        lines.push(`- **Artifact:** \`${finding.artifact}\``);
      }

      if (finding.process) {
        lines.push(`- **Process:** \`${finding.process}\``);
      }

      lines.push('');
    }
  }

  // Warnings
  if (report.findings.warning.length > 0) {
    lines.push('## Warnings');
    lines.push('');

    for (const finding of report.findings.warning) {
      lines.push(`### ${finding.type}`);
      lines.push('');

      if (finding.package) {
        lines.push(`- **Package:** \`${finding.package}@${finding.version}\``);
        if (finding.infectedVersions) {
          lines.push(`- **Known infected versions:** ${finding.infectedVersions.join(', ')}`);
        }
      }

      if (finding.script) {
        lines.push(`- **Script:** \`${finding.script}\``);
        lines.push(`- **Content:** \`${finding.content}\``);
      }

      if (finding.file) {
        lines.push(`- **File:** \`${finding.file}\``);
      }

      lines.push('');
    }
  }

  // Info (credential files)
  if (report.findings.info.length > 0) {
    lines.push('## Informational');
    lines.push('');
    lines.push('These items are not necessarily compromised but should be reviewed if malware was detected.');
    lines.push('');

    for (const finding of report.findings.info) {
      if (finding.type === 'CREDENTIAL_FILE_EXISTS') {
        lines.push(`- \`${finding.file}\` - ${finding.note}`);
      }
    }
    lines.push('');
  }

  // Recommended Actions
  if (report.summary.critical > 0) {
    lines.push('## Recommended Actions');
    lines.push('');
    lines.push('1. **DO NOT** run `npm install` in affected projects');
    lines.push('2. Remove infected packages from `package.json`');
    lines.push('3. Delete `node_modules` and `package-lock.json`');
    lines.push('4. Check `.github/workflows` for suspicious files (especially `discussion.yaml`)');
    lines.push('5. **Rotate ALL credentials immediately:**');
    lines.push('   - AWS credentials');
    lines.push('   - Azure credentials');
    lines.push('   - Google Cloud credentials');
    lines.push('   - GitHub tokens');
    lines.push('   - npm tokens');
    lines.push('6. Review GitHub Actions for unauthorized workflows and self-hosted runners named `SHA1HULUD`');
    lines.push('7. Check for Bun runtime: `which bun`');
    lines.push('8. Review GitHub for repositories with suspicious descriptions containing "Shai-Hulud"');
    lines.push('');
  }

  // References
  lines.push('## References');
  lines.push('');
  lines.push('- [Wiz Security - Shai-Hulud 2.0 Analysis](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)');
  lines.push('- [Datadog Security Labs - npm Worm Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)');
  lines.push('- [Check Point Research - Technical Deep Dive](https://blog.checkpoint.com/research/shai-hulud-2-0-inside-the-second-coming)');
  lines.push('');

  // Footer
  lines.push('---');
  lines.push(`*Generated by Worm Buster v${report.meta.version}*`);

  return lines.join('\n');
}

/**
 * Generate HTML report content
 *
 * @param {Object} report - Report object
 * @returns {string} HTML content
 */
function generateHtml(report) {
  const statusClass = report.summary.status === 'CLEAN' ? 'clean' : 'infected';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Worm Buster Scan Report</title>
  <style>
    :root {
      --critical: #dc2626;
      --warning: #f59e0b;
      --info: #3b82f6;
      --clean: #16a34a;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #1e293b;
      --border: #e2e8f0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    h1 { font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { font-size: 1.5rem; margin: 2rem 0 1rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }
    h3 { font-size: 1.1rem; margin: 1rem 0 0.5rem; }
    .subtitle { color: #64748b; margin-bottom: 2rem; }
    .card {
      background: var(--card-bg);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .status { display: inline-block; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; font-size: 1.2rem; }
    .status.clean { background: #dcfce7; color: var(--clean); }
    .status.infected { background: #fee2e2; color: var(--critical); }
    .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 1rem 0; }
    .summary-item { text-align: center; padding: 1rem; background: var(--bg); border-radius: 6px; }
    .summary-item .count { font-size: 2rem; font-weight: 700; }
    .summary-item.critical .count { color: var(--critical); }
    .summary-item.warning .count { color: var(--warning); }
    .summary-item.info .count { color: var(--info); }
    .finding { border-left: 4px solid var(--critical); padding: 1rem; margin: 0.5rem 0; background: #fef2f2; border-radius: 0 6px 6px 0; }
    .finding.warning { border-left-color: var(--warning); background: #fffbeb; }
    .finding.info { border-left-color: var(--info); background: #eff6ff; }
    .finding-type { font-weight: 600; color: var(--critical); margin-bottom: 0.5rem; }
    .finding.warning .finding-type { color: var(--warning); }
    .finding.info .finding-type { color: var(--info); }
    .finding-detail { font-size: 0.9rem; margin: 0.25rem 0; }
    code { background: #e2e8f0; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
    .meta { font-size: 0.85rem; color: #64748b; }
    .meta-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; }
    ul { padding-left: 1.5rem; margin: 0.5rem 0; }
    .actions { background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }
    .actions h3 { color: #92400e; margin-top: 0; }
    .actions ol { padding-left: 1.5rem; }
    .actions li { margin: 0.5rem 0; }
    .footer { text-align: center; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #64748b; font-size: 0.85rem; }
    a { color: var(--info); }
  </style>
</head>
<body>
  <div class="container">
    <h1>Worm Buster Scan Report</h1>
    <p class="subtitle">Shai-Hulud 2 Malware Detection Results</p>

    <div class="card">
      <span class="status ${statusClass}">${report.summary.status}</span>
      <div class="summary-grid">
        <div class="summary-item critical">
          <div class="count">${report.summary.critical}</div>
          <div>Critical</div>
        </div>
        <div class="summary-item warning">
          <div class="count">${report.summary.warning}</div>
          <div>Warnings</div>
        </div>
        <div class="summary-item info">
          <div class="count">${report.summary.info}</div>
          <div>Info</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Scan Details</h3>
      <div class="meta-grid meta">
        <div><strong>Date:</strong> ${new Date(report.meta.scanDate).toLocaleString()}</div>
        <div><strong>Hostname:</strong> ${report.meta.hostname}</div>
        <div><strong>Platform:</strong> ${report.meta.platform}</div>
        <div><strong>Node:</strong> ${report.meta.nodeVersion}</div>
      </div>
      <h4 style="margin-top: 1rem;">Scanned Directories</h4>
      <ul>
        ${report.scan.directories.map(d => `<li><code>${escapeHtml(d)}</code></li>`).join('\n        ')}
      </ul>
    </div>

    ${report.findings.critical.length > 0 ? `
    <h2>Critical Findings</h2>
    ${report.findings.critical.map(f => renderFinding(f, 'critical')).join('\n    ')}
    ` : ''}

    ${report.findings.warning.length > 0 ? `
    <h2>Warnings</h2>
    ${report.findings.warning.map(f => renderFinding(f, 'warning')).join('\n    ')}
    ` : ''}

    ${report.findings.info.length > 0 ? `
    <h2>Informational</h2>
    <p>These items are not necessarily compromised but should be reviewed if malware was detected.</p>
    ${report.findings.info.map(f => renderFinding(f, 'info')).join('\n    ')}
    ` : ''}

    ${report.summary.critical > 0 ? `
    <div class="actions">
      <h3>Recommended Actions</h3>
      <ol>
        <li><strong>DO NOT</strong> run <code>npm install</code> in affected projects</li>
        <li>Remove infected packages from <code>package.json</code></li>
        <li>Delete <code>node_modules</code> and <code>package-lock.json</code></li>
        <li>Check <code>.github/workflows</code> for suspicious files</li>
        <li><strong>Rotate ALL credentials immediately</strong> (AWS, Azure, GCP, GitHub, npm)</li>
        <li>Review GitHub Actions for unauthorized workflows and runners named <code>SHA1HULUD</code></li>
        <li>Check for Bun runtime: <code>which bun</code></li>
        <li>Review GitHub for repositories with "Shai-Hulud" in description</li>
      </ol>
    </div>
    ` : ''}

    <h2>References</h2>
    <ul>
      <li><a href="https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack" target="_blank">Wiz Security - Shai-Hulud 2.0 Analysis</a></li>
      <li><a href="https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/" target="_blank">Datadog Security Labs - npm Worm Analysis</a></li>
      <li><a href="https://blog.checkpoint.com/research/shai-hulud-2-0-inside-the-second-coming" target="_blank">Check Point Research - Technical Deep Dive</a></li>
    </ul>

    <div class="footer">
      Generated by Worm Buster v${report.meta.version}
    </div>
  </div>
</body>
</html>`;
}

function renderFinding(finding, severity) {
  let details = '';

  if (finding.package) {
    details += `<div class="finding-detail"><strong>Package:</strong> <code>${escapeHtml(finding.package)}@${escapeHtml(finding.version)}</code></div>`;
    if (finding.depType) {
      details += `<div class="finding-detail"><strong>Dependency Type:</strong> ${escapeHtml(finding.depType)}</div>`;
    }
    if (finding.infectedVersions) {
      details += `<div class="finding-detail"><strong>Known infected:</strong> ${finding.infectedVersions.join(', ')}</div>`;
    }
  }

  if (finding.file) {
    details += `<div class="finding-detail"><strong>File:</strong> <code>${escapeHtml(finding.file)}</code></div>`;
  }

  if (finding.path && !finding.file) {
    details += `<div class="finding-detail"><strong>Path:</strong> <code>${escapeHtml(finding.path)}</code></div>`;
  }

  if (finding.artifact) {
    details += `<div class="finding-detail"><strong>Artifact:</strong> <code>${escapeHtml(finding.artifact)}</code></div>`;
  }

  if (finding.process) {
    details += `<div class="finding-detail"><strong>Process:</strong> <code>${escapeHtml(finding.process)}</code></div>`;
  }

  if (finding.script) {
    details += `<div class="finding-detail"><strong>Script:</strong> <code>${escapeHtml(finding.script)}</code></div>`;
    details += `<div class="finding-detail"><strong>Content:</strong> <code>${escapeHtml(finding.content)}</code></div>`;
  }

  if (finding.note) {
    details += `<div class="finding-detail"><em>${escapeHtml(finding.note)}</em></div>`;
  }

  return `<div class="finding ${severity}">
      <div class="finding-type">${escapeHtml(finding.type)}</div>
      ${details}
    </div>`;
}

function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Save report in multiple formats
 *
 * @param {Object} report - Report object
 * @param {string} basePath - Base path for output files (without extension)
 * @param {Object} formats - Which formats to generate { json, markdown, html }
 * @returns {Object} Paths to generated files
 */
function saveReports(report, basePath, formats = { json: true, markdown: true, html: true }) {
  const generated = {};

  if (formats.json) {
    const jsonPath = basePath + '.json';
    saveJson(report, jsonPath);
    generated.json = jsonPath;
  }

  if (formats.markdown) {
    const mdPath = basePath + '.md';
    fs.writeFileSync(mdPath, generateMarkdown(report));
    generated.markdown = mdPath;
  }

  if (formats.html) {
    const htmlPath = basePath + '.html';
    fs.writeFileSync(htmlPath, generateHtml(report));
    generated.html = htmlPath;
  }

  return generated;
}

module.exports = {
  createReport,
  saveJson,
  generateMarkdown,
  generateHtml,
  saveReports,
};
