# MCPSec - MCP Security Analysis Tool


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**MCPSec is a comprehensive security analysis tool built for Model Context Protocol (MCP) servers. It automates security validation, detects vulnerabilities, and checks compliance to safeguard streaming assets and intellectual property.**

---

## Table of Contents

* [Purpose & Key Features](#purpose--key-features)
* [Installation](#installation)

  * [Global](#global-installation)
  * [Project Local](#project-installation)
  * [From Source](#from-source)
* [Quick Start](#quick-start)
* [Configuration](#configuration)
* [Security Rules](#security-rules)
* [Output Formats](#output-formats)
* [CLI Commands](#cli-commands)
* [CI/CD Integration](#cicd-integration)
* [MCP Project Best Practices](#project-structure-best-practices)
* [Common Violations & Fixes](#common-violations-and-fixes)
* [Troubleshooting](#troubleshooting)
* [Testing](#testing)
* [Custom Rules](#custom-rules)
* [Contributing](#contributing)
* [License](#license)
* [Support](#reporting-issues--support)
* [Version History](#version-history)
* [Roadmap](#roadmap)
* [Acknowledgements](#acknowledgements)

---

## Purpose & Key Features

MCPSec addresses key security concerns for MCP server development:

* Prompt injection prevention
* Input validation and sanitization
* Authentication & authorization checks
* Audit logging for compliance
* Streaming asset protection
* Rate limiting enforcement
* Sensitive data protection
* Automated vulnerability scanning
* Policy & standards compliance checking

---

## Installation

### Global Installation

```bash
npm install -g mcpsec
```

### Project Installation

```bash
npm install --save-dev mcpsec
```

### From Source

```bash
git clone https://github.com/arterberry/mcpsec.git
cd mcpsec
npm install
npm run build
npm link
```

---

## Quick Start

### Initialize Configuration

```bash
mcpsec init
mcpsec init --template strict
mcpsec init --template basic
```

### Analyze MCP Server

```bash
mcpsec analyze .
mcpsec analyze ./my-mcp-server
mcpsec analyze ./my-mcp-server --format json --output security-report.json
```

---

## Configuration

Create a `.mcpsec.json` to configure rules and settings:

```json
{
  "rules": {
    "auth-required": { "enabled": true, "severity": "error" },
    "input-sanitization": { "enabled": true, "severity": "error" },
    "fox-streaming-protection": { "enabled": true, "severity": "error" },
    "audit-logging": { "enabled": true, "severity": "error" }
  }
  "ignorePatterns": [
    "node_modules/**",
    "dist/**",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
```

---

## Security Rules

### Mandatory Rules

* **auth-required**: Enforce authentication presence and strength.
* **input-sanitization**: Ensure user input is sanitized.
* **injection-detection**: Scan for injection patterns.
* **audit-logging**: Validate audit log coverage.

### Optional Rules

* **rate-limit-enforcement**
* **permission-checks**
* **har-security**

Use `mcpsec rules` to list all rules.

---

## Output Formats

* **Text (default)**
* **JSON**: `--format json`
* **JUnit XML**: `--format junit`
* **SARIF**: `--format sarif`

---

## CLI Commands

* `mcpsec analyze <path>`
* `mcpsec rules [--category <cat>] [--mandatory-only]`
* `mcpsec validate-config <config_path>`

---

## CI/CD Integration

### GitHub Actions

Example workflow using SARIF for GitHub Security:

```yaml
- name: Run MCPSec
  run: mcpsec analyze . --format sarif --output results.sarif --fail-on error
```


### Pre-commit Hook

```bash
mcpsec analyze . --fail-on error || exit 1
```

---

## Project Structure Best Practices

```
my-mcp-server/
├── src/
├── tests/
├── .mcpsec.json
└── package.json
```

Ensure modular auth, validation, and logging structure.

---

## Common Violations and Fixes

### Authentication

**Bad:** Missing auth context

```ts
export function myTool(params: any) {
  return doWork(params);
}
```

**Good:** Enforce context

```ts
export function myTool(params: any, context: AuthContext) {
  if (!context.user) throw new Error('Unauthorized');
  return doWork(params);
}
```

### Input Validation

Use sanitizers and validators. Avoid raw interpolation.

### Logging

Log user actions with metadata.

---

## Troubleshooting

* Check `.mcpsec.json` with: `mcpsec validate-config`
* Use `ignorePatterns` to skip large/unnecessary files
* Ensure `.ts` sources are in included paths

---

## Testing

```bash
npm test
npm run test:coverage
npm run test:watch
```

---

## Custom Rules

Implement `MCPSecurityRule` interface in `src/rules/custom/`:

```ts
export const myRule: MCPSecurityRule = {
  id: 'my-rule',
  async check(ctx) {
    // AST analysis
    return [];
  }
}
```

---

## Contributing

* Fork, clone, install deps
* Use `npm run lint`
* Add rules and tests
* Submit a PR

---

## License

MIT License

---

## Reporting Issues & Support

* GitHub Issues for bugs/requests


---

## Version History

* **v1.4.0**: SARIF + CI/CD
* **v1.3.0**: HAR validation
* **v1.2.0**: Conviva security
* **v1.1.0**: Streaming rules
* **v1.0.0**: Initial release

---

## Roadmap

* v2.0.0: Runtime monitoring
* v2.1.0: ML-assisted detection
* v2.2.0: Internal security integration
* v2.3.0: Real-time dashboards

---

## Acknowledgements

Built by John Eric Arterberry : https://github.com/arterberry

Looking At ways to improve to MCP server security.
