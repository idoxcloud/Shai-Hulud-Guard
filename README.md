# Shai-Hulud Scanner & Guard

🛡️ Supply chain malware detection and protection system for npm packages.

[![Release](https://img.shields.io/github/v/release/idoxcloud/Shai-Hulud-Scanner?include_prereleases)](https://github.com/idoxcloud/Shai-Hulud-Scanner/releases)
[![License](https://img.shields.io/github/license/idoxcloud/Shai-Hulud-Scanner)](LICENSE)

> 📋 **Internal Documentation**: This tool is based on the [Idox Shai-Hulud Response Plan](https://idoxsoftware.sharepoint.com/:w:/s/dev/IQAby2aS9UHOSbIQazIgPgEVAQs97jfjvsycnXiIV6KpQWM?e=8m8cpM) (requires Idox SharePoint access)

## Features

- **🔍 Shai-Hulud Scanner**: Detect compromised npm packages with quick and full scan modes
- **🛡️ Shai-Hulud Guard**: Install/uninstall npm registry protection system
- **📊 Comprehensive Reports**: Generate security reports combining scan results with protection status
- **☁️ S3 Scanning**: Scan S3 buckets for compromised packages
- **💻 Cross-platform**: Linux, macOS (Intel & ARM), Windows support
- **🔒 Backup Protection**: Never overwrites original hosts file
- **🎯 Enhanced UX**: Native Go flags, intuitive command syntax
- **⚡ Performance**: Bash 3.2+ and Bash 4+ compatibility
- **📁 Clean Reports**: Scan reports written to dedicated directory with timestamps

## Quick Start

### One-Shot Installer (Recommended)

#### macOS / Linux

Run a security report without installation:

```bash
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | bash
```

Or install permanently:

```bash
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | sudo bash -s install
```

Available one-shot commands:

```bash
# Run security report (default)
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | bash

# Run scan only
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | bash -s scan

# Check protection status
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | bash -s status

# Install binary to /usr/local/bin
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | sudo bash -s install

# Install guard protection (blocks npm registry, requires sudo)
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | sudo bash -s -- guard-install

# Uninstall guard protection (restore npm access, requires sudo)
curl -fsSL https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.sh | sudo bash -s -- guard-uninstall
```

#### Windows (PowerShell)

Run a security report without installation:

```powershell
irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1 | iex
```

Or install permanently (requires Administrator):

```powershell
# Run PowerShell as Administrator, then:
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action install
```

Available one-shot commands:

```powershell
# Run security report (default)
irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1 | iex

# Run scan only
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action scan

# Check protection status
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action status

# Install binary to Program Files (run PowerShell as Administrator)
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action install

# Install guard protection (blocks npm registry, run as Administrator)
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action guard-install

# Uninstall guard protection (restore npm access, run as Administrator)
& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1))) -Action guard-uninstall
```

### Manual Installation

Download the binary for your platform:

```bash
# macOS (Apple Silicon)
curl -L https://github.com/idoxcloud/Shai-Hulud-Guard/releases/download/v0.1-alpha.4/shai-hulud-guard-darwin-arm64 -o shai-hulud-guard
chmod +x shai-hulud-guard
sudo mv shai-hulud-guard /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/idoxcloud/Shai-Hulud-Guard/releases/download/v0.1-alpha.4/shai-hulud-guard-darwin-amd64 -o shai-hulud-guard
chmod +x shai-hulud-guard
sudo mv shai-hulud-guard /usr/local/bin/

# Linux (AMD64)
curl -L https://github.com/idoxcloud/Shai-Hulud-Guard/releases/download/v0.1-alpha.4/shai-hulud-guard-linux-amd64 -o shai-hulud-guard
chmod +x shai-hulud-guard
sudo mv shai-hulud-guard /usr/local/bin/

# Linux (ARM64)
curl -L https://github.com/idoxcloud/Shai-Hulud-Guard/releases/download/v0.1-alpha.4/shai-hulud-guard-linux-arm64 -o shai-hulud-guard
chmod +x shai-hulud-guard
sudo mv shai-hulud-guard /usr/local/bin/
```

### Usage

```bash
# Generate comprehensive security report (recommended for support)
shai-hulud-guard -report

# Scan your system (quick scan)
shai-hulud-guard -scan

# Full comprehensive scan
shai-hulud-guard -scan -mode full

# Scan specific directory
shai-hulud-guard -scan -root /path/to/dir -mode full

# Install protection
sudo shai-hulud-guard -install

# Check status
shai-hulud-guard -status

# Show help
shai-hulud-guard -h
```

> **💡 Tip**: Use `shai-hulud-guard -report` to generate a comprehensive security report that combines scan results with system protection status. Perfect for sharing with support teams or security audits.

## Documentation

- **[Guard Documentation](docs/README-GUARD.md)** - Detailed guide for Shai-Hulud Guard protection system
- **[Certificate Setup](docs/CERTIFICATE_SETUP.md)** - Instructions for certificate management

---

## Technical Details

### Background

Shai-Hulud is a sophisticated supply chain attack targeting npm packages that was first discovered in September 2025, with a more advanced variant (Shai-Hulud 2.0) appearing in November 2025. The malware compromises npm packages to:

- Harvest credentials and environment variables
- Exfiltrate secrets via webhook endpoints
- Install malicious GitHub Actions self-hosted runners
- Clone and manipulate private repositories

This scanner detects indicators of compromise (IOCs) from both variants.

### Scan Modes

**Quick Mode** (~10-30 seconds)
- Scans top-level `node_modules` only (depth-limited to 5 levels)
- Checks root `package.json` for suspicious hooks
- Hash-scans only files with suspicious names
- Skips npm cache, self-hosted runners, env patterns

**Full Mode** (~5-30+ minutes depending on codebase size)
- Recursive scan of all `node_modules` directories (unrestricted depth)
- Complete npm cache analysis
- Full hash scan of all JS/TS files
- Deep postinstall hook analysis
- Self-hosted runner detection
- Environment variable exfiltration pattern detection

### Scanner Checks

The scanner performs the following security checks:

| Check | Quick Mode | Full Mode | Description |
|-------|------------|-----------|-------------|
| Compromised npm packages | Yes | Yes | Fetches live IOC feeds and scans `node_modules` |
| npm cache scan | No | Yes | Scans npm cache for compromised packages |
| Malicious file artifacts | Yes | Yes | Detects known Shai-Hulud files (`shai-hulud.js`, `setup_bun.js`, etc.) |
| Git branch/remote analysis | Yes | Yes | Checks for suspicious branches and remotes |
| GitHub Actions workflows | Yes | Yes | Scans for malicious workflow patterns |
| Cloud credential exposure | Partial | Yes | Detects AWS/Azure/npm credential files |
| Self-hosted runner detection | No | Yes | Finds GitHub Actions runner installations |
| Postinstall hook analysis | Root only | Yes | Scans `package.json` for suspicious scripts |
| Hash-based detection | Targeted | Yes | SHA256/SHA1 matching against known malware |
| Migration suffix detection | No | Yes | Identifies `-migration` repo attack pattern |
| TruffleHog detection | PATH only | Yes | Detects credential harvesting tool |
| Env+exfil pattern scan | No | Yes | Finds code combining env access with exfiltration |

### Detected IOCs

#### Malicious Files
- `shai-hulud.js`, `shai_hulud.js`
- `setup_bun.js`, `bun_environment.js`
- `discussion.yaml`
- `truffleSecrets.json`, `actionsSecrets.json`

#### Workflow Patterns
- `formatter_*.yml` (Shai-Hulud 2.0 pattern)
- `self-hosted` runner configurations
- `SHA1HULUD` references
- `webhook.site` endpoints

#### Git Indicators
- Branches containing `shai-hulud` or `SHA1HULUD`
- Remotes with `-migration` suffix
- Repositories named `*-migration`

#### Known Malicious Hashes

**SHA256:**
- `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09` - bundle.js payload
- `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`

**SHA1 (Shai-Hulud 2.0):**
- `d1829b4708126dcc7bea7437c04d1f10eacd4a16` - setup_bun.js
- `d60ec97eea19fffb4809bc35b91033b52490ca11` - bun_environment.js
- `3d7570d14d34b0ba137d502f042b27b0f37a59fa` - bun_environment.js variant

### Output and Reporting

The scanner generates:

1. **Console output** - Real-time progress and findings displayed during scan
2. **Report file** - Detailed findings written to `/var/log/shai-hulud/` (or temp directory fallback)
3. **Status information** - Protection status and overall security assessment

#### Example Output

```
[OK] No indicators of Shai-Hulud compromise were found in the scanned locations.
```

Or if issues are found:

```
[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: 3 item(s)

Type              Package/Indicator                    Location
----              -----------------                    --------
node_modules      @example/malicious-pkg               C:\Projects\app\node_modules\...
workflow-content  Workflow contains: self-hosted       C:\Projects\app\.github\workflows\ci.yml
malware-hash      SHA256 match: Shai-Hulud bundle.js   C:\Projects\app\dist\bundle.js
```

### Offline Support

The scanner supports offline operation:

1. On first successful run, the compromised packages list is cached to the system temp directory (valid for 24 hours)
   - **Unix/Linux/macOS**: `${TMPDIR:-/tmp}/shai-hulud-scanner-cache/`
   - **Windows**: `%TEMP%\shai-hulud-scanner-cache\`
2. Cache is automatically refreshed every 24 hours when scanner runs
3. If the IOC feed is unreachable, the scanner falls back to cached data with a warning
4. File-based IOC checks (hashes, filenames, patterns) work without network access

## References

- [Wiz: Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Wiz: Shai-Hulud 2.0 Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Unit 42: npm Supply Chain Attack Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Sngular: Shai-Hulud Integrity Scanner](https://github.com/sngular/shai-hulud-integrity-scanner)

## License

MIT

