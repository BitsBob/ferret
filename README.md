# Ferret

**Ferret out secrets and vulnerabilities in your API collections.**

Ferret is a local-first, offline CLI tool that scans API collections for hardcoded secrets, leaked credentials, and common API security misconfigurations. It supports Bruno, Postman, and Insomnia collections and runs entirely offline with no accounts, no cloud, no telemetry.

Built for small development teams (2–20 people) who don't have a dedicated security engineer but still want to catch secrets before they reach production.

## Features

- **Secret Detection** - 15 regex-based rules covering AWS keys, GitHub tokens, Stripe keys, Slack tokens, JWTs, private keys, Google/SendGrid/Twilio credentials, hardcoded passwords, and more
- **Entropy Analysis** - flags high-entropy strings that look like secrets, with false positive suppression for template variables and placeholders
- **OWASP API Top 10** - 9 heuristic rules checking for missing auth, HTTP endpoints, mass assignment risk, missing pagination, security misconfigurations, and unversioned APIs
- **Multi-Format Support** - parses Bruno directories, Postman v2.0/v2.1 exports, and Insomnia v4 exports with automatic format detection
- **CI/CD Ready** - `--fail-on` flag returns exit code 1 when findings meet a severity threshold, perfect for pipeline gates
- **Multiple Output Formats** - terminal (colored), JSON (machine-readable), and self-contained HTML reports
- **Offline & Private** — everything runs locally, no network calls, no data leaves your machine

## Installation

Now avaliable on the AUR!

```bash
yay -S ferret-scanner
paru -S ferret-scanner
```

### From source

```bash
git clone https://github.com/youruser/ferret.git
cd ferret
cargo build --release
# Binary is at target/release/ferret
```

## Usage

```bash
# Scan a Bruno collection directory
ferret scan ~/projects/my-api

# Scan a Postman export file
ferret scan ./collection.json

# Scan an Insomnia export file
ferret scan ./insomnia-export.json

# Scan current directory (auto-detects collection type)
ferret scan .

# Output as JSON
ferret scan . --format json

# Generate an HTML report
ferret scan . --format html --output report.html

# Fail if any high or critical findings (useful for CI)
ferret scan . --fail-on high

# Fail on medium and above
ferret scan . --fail-on medium
```

## Example Output

```
ferret v0.1.0 — API Security Scanner

Scanning: ~/projects/my-api (Bruno collection)
Found 47 requests

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 FINDINGS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Critical  2
 High      3
 Medium    7
 Low       4
 Info      1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] SEC003 — GitHub Token Detected
  File:     requests/users/get-users.bru
  Field:    header: Authorization
  Evidence: ghp_••••••••••••••••••••
  Fix:      Replace the hardcoded token with an environment variable: {{github_token}}

[HIGH] SEC004 — Stripe Live Secret Key
  File:     requests/payments/charge.bru
  Field:    header: X-Stripe-Key
  Evidence: sk_l••••••••••••••••••••
  Fix:      Use an environment variable. Never commit live keys to collections.
```

Secrets are always redacted in output — Ferret shows just enough to identify the finding without exposing the full value.

## Scanner Rules

### Secret Detection

| Rule | Name | Severity |
|------|------|----------|
| SEC001 | AWS Access Key | Critical |
| SEC002 | AWS Secret Key | Critical |
| SEC003 | GitHub Token | Critical |
| SEC004 | Stripe Secret Key | High |
| SEC005 | Stripe Publishable Key | Medium |
| SEC006 | Slack Token | High |
| SEC007 | Generic JWT | Medium |
| SEC008 | Private Key Block | Critical |
| SEC009 | Google API Key | High |
| SEC010 | SendGrid API Key | High |
| SEC011 | Twilio Account SID | High |
| SEC012 | Bearer Token (Hardcoded) | High |
| SEC013 | Basic Auth (Hardcoded) | High |
| SEC014 | Password in URL | High |
| SEC015 | Hardcoded Password Field | High |
| SEC099 | High Entropy String | Medium |

### OWASP API Top 10

| Rule | Category | What It Checks |
|------|----------|----------------|
| OWA001 | API1 — Broken Object Level Auth | Requests with IDs in URL but no auth header |
| OWA002 | API2 — Broken Auth | Auth endpoints not using HTTPS |
| OWA003 | API2 — Broken Auth | Auth headers sent over HTTP |
| OWA004 | API3 — Broken Object Property Level Auth | Large PUT/PATCH bodies (mass assignment risk) |
| OWA005 | API4 — Unrestricted Resource Consumption | Missing pagination on collection endpoints |
| OWA006 | API8 — Security Misconfiguration | Missing Content-Type on POST/PUT/PATCH |
| OWA007 | API8 — Security Misconfiguration | X-Powered-By header present |
| OWA008 | API9 — Improper Inventory Management | Non-versioned API paths |
| OWA009 | API10 — Unsafe API Consumption | HTTP (non-TLS) endpoints |

### False Positive Suppression

Ferret is designed for a low false positive rate. It will **not** flag:

- Template variables: `{{token}}`, `${API_KEY}`, `<placeholder>`
- Common placeholders: `your_api_key_here`, `xxx`, `example`, `test`, `dummy`
- Obviously non-secret values: content types, booleans, numbers
- Localhost URLs for HTTP rules

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan API collections for secrets
  run: ferret scan ./collections --fail-on high --format json --output ferret-report.json

- name: Upload security report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: ferret-security-report
    path: ferret-report.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no findings at or above `--fail-on` threshold |
| 1 | Findings at or above `--fail-on` severity level |
| 2 | Error (file not found, parse failure, etc.) |

## Collection Auto-Detection

Ferret automatically detects the collection format:

- **Directory with `.bru` files or `bruno.json`** → Bruno collection
- **JSON file with `info._postman_id`** → Postman collection
- **JSON file with `"_type": "export"`** → Insomnia export

## Supported Formats

| Format | Input | What's Scanned |
|--------|-------|----------------|
| Bruno | Directory of `.bru` files | Requests, headers, bodies, auth, `.env` files |
| Postman | Collection JSON (v2.0/v2.1) | Requests, headers, bodies, auth, pre-request & test scripts |
| Insomnia | Export JSON (v4) | Requests, headers, bodies, auth, environment variables |

## Development

```bash
# Run tests
cargo test

# Build debug
cargo build

# Build release
cargo build --release

# Run directly
cargo run -- scan ./path/to/collection
```

## License

MIT
