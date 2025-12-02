# Worm Buster - Shai-Hulud 2 Malware Scanner

## Overview

Worm Buster is a security scanner designed to detect and remove the **Shai-Hulud 2** supply chain attack that infected numerous npm packages in November 2025. This malware campaign compromised over 1000 npm packages with malicious code designed to steal credentials and sensitive information.

## Features

- 🔍 **Package Scanning**: Detects infected npm packages in your projects
- 📦 **Dependency Analysis**: Checks package.json and package-lock.json files
- 🚨 **Artifact Detection**: Identifies malicious files left by the malware
- 🔐 **Credential Protection**: Alerts about potentially compromised credential files
- 📊 **Comprehensive Reporting**: Generates detailed JSON reports of findings

## Files in This Repository

- `scan-shai-hulud.js` - Main scanner script
- `worm.md` - Database of infected packages (1000+ entries)
- `SCAN-REPORT.md` - Human-readable scan report
- `scan-report.json` - Detailed JSON report of scan findings

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Linux/macOS/Windows with WSL

### Setup

1. Clone or download this repository:
```bash
git clone https://github.com/yourusername/worm-buster.git
cd worm-buster
```

2. Ensure the scanner script has execute permissions:
```bash
chmod +x scan-shai-hulud.js
```

## Usage

### Quick Scan (Default Directories)

Run the scanner with default settings to scan common project directories:

```bash
node scan-shai-hulud.js
```

By default, it scans:
- `/home/[user]/code`
- `/home/[user]`
- `/home/[user]/workspaces`

### Custom Directory Scan

To scan specific directories, modify the `directories` array at the bottom of `scan-shai-hulud.js`:

```javascript
const directories = [
  '/path/to/your/project',
  '/another/project/path'
];
```

Then run:
```bash
node scan-shai-hulud.js
```

### Single Project Scan

For a quick single project scan:
```bash
cd /path/to/your/project
node /path/to/worm-buster/scan-shai-hulud.js .
```

## What the Scanner Detects

### 1. Infected Packages
The scanner checks for over 1000 known infected npm packages listed in `worm.md`, including:
- Direct dependencies in `package.json`
- Locked versions in `package-lock.json`
- Actually installed packages in `node_modules`

### 2. Malicious Artifacts
Known malicious files created by the malware:
- `.github/workflows/discussion.yaml`
- `cloud.json`
- `environment.json`
- `truffleSecrets.json`
- `actionsSecrets.json`
- `setup_bun.js`
- `bun_environment.js`
- Suspicious workflow files matching pattern `formatter_*.yml`

### 3. Suspicious Scripts
Detects potentially malicious npm scripts:
- `preinstall`, `postinstall`, `prepare` scripts
- Scripts containing suspicious commands (curl, wget, eval, bun)

### 4. Running Processes
Checks for suspicious Bun runtime processes that might be active

### 5. Credential Files
Identifies credential files that may have been targeted:
- `.aws/credentials`
- `.azure/credentials`
- `.config/gcloud/credentials.db`
- `.npmrc`
- `.netrc`
- `.git-credentials`

## Understanding the Results

### Severity Levels

- **🚨 CRITICAL**: Infected packages or malicious artifacts found - immediate action required
- **⚠️ WARNING**: Suspicious packages or scripts detected - review recommended
- **ℹ️ INFO**: Informational findings - no immediate action required

### Report Files

After scanning, two report files are generated:

1. **scan-report.json**: Detailed JSON report with all findings
2. **Console Output**: Human-readable summary with recommended actions

## Recommended Actions if Infected

If the scanner detects infections:

1. **DO NOT** run `npm install` in affected projects
2. Remove infected packages from `package.json`
3. Delete `node_modules` and `package-lock.json`
4. Check `.github/workflows` for unauthorized workflow files
5. **Rotate ALL credentials immediately**:
   - AWS access keys
   - Azure credentials
   - Google Cloud credentials
   - GitHub tokens
   - npm tokens
   - Any API keys in environment variables
6. Check for unauthorized GitHub Actions workflows in your repositories
7. Review recent commits for unauthorized changes
8. Check if Bun runtime was installed: `which bun`
9. Remove Bun if found and not intentionally installed

## Cleaning Infected Systems

### Step 1: Remove Infected Packages
```bash
# Remove node_modules and lock file
rm -rf node_modules package-lock.json

# Edit package.json to remove infected packages
# Then reinstall clean versions
npm install
```

### Step 2: Remove Malicious Artifacts
```bash
# Remove known malicious files
rm -f .github/workflows/discussion.yaml
rm -f cloud.json environment.json truffleSecrets.json
rm -f actionsSecrets.json setup_bun.js bun_environment.js

# Check for suspicious workflow files
ls -la .github/workflows/formatter_*.yml
```

### Step 3: Clean Bun Installation (if present)
```bash
# Check if Bun is installed
which bun

# If found and not intentionally installed:
npm uninstall -g bun
rm -rf ~/.bun
```

## Prevention Tips

1. **Use npm audit regularly**: `npm audit`
2. **Enable 2FA** on npm and GitHub accounts
3. **Review dependencies** before installing
4. **Use lock files** and commit them to version control
5. **Monitor GitHub Actions** for unauthorized workflows
6. **Use tools like Snyk** or **Socket.dev** for continuous monitoring

## Contributing

If you discover new infected packages or malicious indicators not in our database, please:

1. Create an issue with package details
2. Submit a pull request updating `worm.md`
3. Include version information and IoCs (Indicators of Compromise)

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided as-is for security scanning purposes. Always verify findings and take appropriate security measures. The authors are not responsible for any damages arising from the use of this tool.

## Resources

- [npm Security Advisories](https://www.npmjs.com/advisories)
- [GitHub Security Advisories](https://github.com/advisories)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## Support

For issues or questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the malware analysis in SCAN-REPORT.md

---
**Stay Safe!** 🛡️ Remember to always keep your dependencies updated and credentials secure.