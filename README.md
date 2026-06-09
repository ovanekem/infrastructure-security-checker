# infrastructure-security-checker

<p align="center">
  <img src="infrastructure-security-checker.png" alt="infrastructure-security-checker logo" width="320" />
</p>

A command-line tool that audits the TLS/SSL posture, HTTP security headers, port exposure, and known vulnerability surface of a web application — all from a single command.

Think of it as a lightweight, self-hosted alternative to tools like [SSL Labs](https://www.ssllabs.com/ssltest/) or [testssl.sh](https://testssl.sh/), built in TypeScript and designed to be easy to integrate into CI pipelines or use on demand.

---

## What it checks

### TLS / SSL protocols
Probes each protocol version for support and flags anything that deviates from the configured policy (`protocols-list.json`):

| Protocol | Default policy |
|----------|----------------|
| SSLv2    | Deprecated     |
| SSLv3    | Deprecated     |
| TLS 1.0  | Deprecated     |
| TLS 1.1  | Deprecated     |
| TLS 1.2  | Validated      |
| TLS 1.3  | Validated      |

### Cipher suites
Probes a curated set of cipher suites derived from the [IANA TLS parameters registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xml) and flags deprecated or weak ciphers (RC4, 3DES, NULL ciphers, EXPORT suites, etc.).

### Known TLS vulnerabilities
Runs individual exploit-detection probes for each of the following CVEs:

| Vulnerability | CVE |
|---------------|-----|
| BEAST | CVE-2011-3389 |
| CRIME / TLS compression | CVE-2012-4929 |
| POODLE (SSLv3) | CVE-2014-3566 |
| POODLE (TLS) | CVE-2014-8730 |
| Heartbleed | CVE-2014-0160 |
| OpenSSL CCS injection | CVE-2014-0224 |
| LUCKY13 | CVE-2013-0169 |
| FREAK | CVE-2015-0204 |
| LOGJAM | CVE-2015-4000 |
| DROWN | CVE-2016-0800 / CVE-2016-0703 |
| Ticketbleed | CVE-2016-9244 |
| SWEET32 | CVE-2016-2183 / CVE-2016-6329 |
| ROBOT | CVE-2017-13099 |
| Winshock | CVE-2014-6321 |
| Downgrade / TLS_FALLBACK_SCSV | CVE-2014-3566 |
| Opossum | CVE-2025-49812 |

### Client simulations
Simulates a TLS handshake from a range of real-world clients to show which protocol and cipher each client would negotiate:

Android 7–13 · Safari / iOS 9–17 · Chrome 70–120 · Firefox 66–121 · IE 11 · Edge 18 / 120 · Java 8u161–17 · OpenSSL 1.1.1 / 3.x · curl 7.88

### HTTP security headers
Checks for the presence and correctness of:
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `X-Frame-Options`
- `Content-Security-Policy`
- HTTP → HTTPS redirect

### Server banner disclosure
Detects the `Server` response header and compares the reported version against a baseline of known minimum-secure versions for popular web servers (nginx, Apache, IIS, …). Discloses outdated versions as `FAIL`, name-only disclosure as `WARN`, suppressed banner as `PASS`.

### Sensitive path and file exposure
Probes a list of well-known dangerous paths and checks whether they are publicly reachable:

- Spring Boot Actuator (`/actuator`, `/actuator/env`, `/actuator/heapdump`)
- Swagger / OpenAPI UI (`/swagger-ui`, `/v3/api-docs`)
- Admin and console interfaces (`/admin`, `/console`)
- Backup archives and database dumps (`.zip`, `.sql`, `.tar.gz`)
- Leftover source files (`.bak`, `.old`)
- Environment and config files (`.env`, `config.yml`, `application.properties`, …)
- Version-control metadata (`.git/config`, `.git/HEAD`, `.svn/entries`)

### Port scan
Checks 68 ports (TCP and UDP) across common services — web, mail, database, infrastructure, cloud-native tools — against a configurable policy (`ports-list.json`). Ports that are expected to be closed but found open are flagged as `FAIL`.

Includes protocol-aware probes for HTTP, HTTPS, SSH, SMTP, IMAP, POP3, and banner grabbing for other services.

### ICMP
Reports whether the host responds to ping. ICMP on public-facing servers is flagged as `WARN`.

---

## Prerequisites

- **Node.js** ≥ 20
- **OpenSSL** CLI available in `$PATH` (used for cipher probing, SSLv3 detection, and compression checks)

---

## Installation

```bash
git clone https://github.com/your-org/infrastructure-security-checker.git
cd infrastructure-security-checker
npm install
npm run build
```

The first time you run it, you also need to fetch the IANA cipher list:

```bash
node dist/cli/main.js --update-ciphers-list
```

This downloads the current IANA TLS parameters registry and writes `ciphers-list.json` to the project root. Re-run this periodically to stay up to date with new cipher assignments.

---

## Usage

```
node dist/cli/main.js [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--url <https://target>` | Target URL to analyze. Must be a valid absolute URL with `http://` or `https://` scheme. |
| `--update-ciphers-list` | Download the IANA TLS parameters registry and regenerate `ciphers-list.json`. Can be combined with `--url` to refresh ciphers and run the scan in one go. |
| `--help`, `-h` | Show usage information. |

### Examples

**Fetch the latest IANA cipher list (run once, then periodically):**
```bash
node dist/cli/main.js --update-ciphers-list
```

**Scan a target:**
```bash
node dist/cli/main.js --url https://example.com
```

**Refresh ciphers and scan in one command:**
```bash
node dist/cli/main.js --update-ciphers-list --url https://example.com
```

**Using an HTTPS target on a non-standard port:**
```bash
node dist/cli/main.js --url https://myapp.internal:8443
```

---

## Output

Each run produces two outputs:

### 1. Console report (real-time, colored)

```
Overall status: ❌ FAIL
Target: https://example.com/
Duration: 238879ms

General information
-------------------
- Web server: nginx/1.24.0
- Negotiated protocol: TLSv1.3 (validated)
- Negotiated cipher: TLS_AES_256_GCM_SHA384 (Y)
- Certificate valid from: May 31 21:39:12 2026 GMT
- Certificate valid to:   Aug 29 21:41:26 2026 GMT

Infrastructure checks
---------------------
- ✅ Certificate expiration window: Certificate is valid for 81 more days.
- ✅ HTTP to HTTPS redirect: Primary target already uses HTTPS.
- ⚠️ HSTS header presence: HSTS header not present.
- ❌ X-Content-Type-Options header: Header not present.
- ❌ Content-Security-Policy header: Header not present.
...

Protocol checks
---------------
- ✅ SSLv2 [deprecated] => not supported; success=true
- ✅ TLSv1_3 [validated] => supported; success=true
...

Vulnerability tests
-------------------
- ✅ Heartbleed (CVE-2014-0160): Server did not complete handshake — Heartbeat extension not supported.
- ✅ DROWN (CVE-2016-0800): Server does not accept SSLv2 — DROWN preconditions not met.
...

Client simulations
------------------
  Client                                Protocol    Forward Secrecy  Cipher
----------------------------------------------------------------------------------------------------
✅ Android 13                           TLSv1.3     Yes              TLS_AES_256_GCM_SHA384
✅ Chrome 120 / Win 11                  TLSv1.3     Yes              TLS_AES_256_GCM_SHA384
❌ IE 11 / Win 10                       No connection -               -
...
```

### 2. Markdown report (written to disk)

A Markdown file is saved to the project root at the end of each scan, named after the date and target:

```
20260609-example.com-security-report.md
```

It contains the full analysis results in a structured, human-readable format suitable for sharing or archiving.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (`PASS`) |
| `1` | At least one `WARN` and no `FAIL` |
| `2` | At least one `FAIL`, or an error occurred (bad URL, missing config file, network failure) |

This makes it straightforward to integrate into CI pipelines — a failing gate exits non-zero.

---

## Configuration files

The tool ships with three JSON policy files that you can customize:

| File | Purpose |
|------|---------|
| `protocols-list.json` | Which TLS/SSL protocol versions are `validated` or `deprecated` |
| `ports-list.json` | Which ports are scanned and their expected state (`open` or `closed`) |
| `web-servers-list.json` | Known web servers with their minimum-secure version thresholds |
| `ciphers-list.json` | Generated by `--update-ciphers-list` from the IANA registry; do not edit manually |

---

## Running the tests

```bash
npm test
```

This builds the project and runs the test suite with Node's built-in test runner.

---

## Contributing

Contributions are welcome — whether that's a new vulnerability probe, an updated client simulation profile, a missing port in the policy list, or a bug fix.

1. Fork the repository and create a branch from `main`.
2. Make your changes and add tests where applicable.
3. Open a pull request with a clear description of what changed and why.

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for your commit messages (e.g. `feat(vulns): add TLS renegotiation check`, `fix(ports): handle ECONNRESET on UDP probes`).

---

## License

[MIT](LICENSE)
