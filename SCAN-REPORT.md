# Shai-Hulud 2 Malware Scan Report - Example

This is an example scan report. When you run the scanner, it will generate a `scan-report.json` with findings specific to your system.

---

## What the Scanner Checks

### Malicious Indicators of Compromise (IoCs)

| IoC Type | Description |
|----------|-------------|
| `cloud.json` | Exfiltrated cloud credentials |
| `truffleSecrets.json` | Stolen secrets |
| `actionsSecrets.json` | GitHub Actions secrets |
| `.github/workflows/discussion.yaml` | Backdoor workflow |
| `formatter_*.yml` workflows | Randomly-named malicious workflows |
| `setup_bun.js` | Dropper script |
| `bun_environment.js` | Main payload (obfuscated) |

### Package Analysis

The scanner checks:
- All `package.json` files for infected dependencies
- All `package-lock.json` files for locked infected versions
- All `node_modules` directories for installed infected packages

### Process Checks

- Scans for suspicious Bun processes running in background
- Checks if Bun runtime is installed and when

---

## Understanding Results

### CRITICAL Findings
These require immediate action - infected packages or malicious files found.

### WARNING Findings
These need review - packages on the infected list but with different versions, or suspicious scripts.

### INFO Findings
Informational - credential files that exist (normal, but verify integrity).

---

## False Positives

The scanner may flag legitimate files that match IoC patterns:

- **pnpm/npm cache metadata** - Registry metadata files, not malicious
- **Postman environment files** - Test configuration files
- **IDE extension configs** - Editor settings
- **Test fixtures** - Library test data

These are typically in cache directories or deeply nested paths, not at project roots where actual IoCs would appear.

---

## Recommended Actions if Infected

1. **DO NOT** run `npm install` in affected projects
2. Remove infected packages from `package.json`
3. Delete `node_modules` and `package-lock.json`
4. Check `.github/workflows` for suspicious files
5. **Rotate ALL credentials**:
   - GitHub PATs and tokens
   - AWS access keys
   - GCP service accounts
   - Azure credentials
   - npm publish tokens
6. Review recent commits for unauthorized changes
7. Check for Bun runtime: `which bun`

---

## About Shai-Hulud 2

The Shai-Hulud 2 campaign is a sophisticated supply chain attack that:

- **Targets**: GitHub tokens, AWS/GCP/Azure credentials, npm tokens
- **Propagates**: Via stolen npm tokens to publish infected package versions
- **Backdoors**: Creates GitHub Actions workflows for remote code execution
- **Destroys**: Can wipe home directories using `shred` (Linux) or `cipher /W` (Windows)

The attack uses Bun runtime for stealth execution and self-replicates through the npm supply chain.

---

*Report template - Shai-Hulud Scanner v1.0*
