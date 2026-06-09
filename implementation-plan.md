# Infrastructure Security Checker — Requirements & Implementation Plan

## 1. Objective

Build a command-line tool (TypeScript + shell launcher) that can:

1. Analyze a target website infrastructure from a provided URL.
2. Validate SSL/TLS properties (certificate, protocol/cipher posture, and related checks).
3. Maintain a local `ciphers-list.json` built from IANA TLS parameters XML (`tls-parameters-4` registry).
4. Use a manually managed `protocols-list.json` to classify protocol versions as `validated` or `deprecated` during URL analysis.
5. Support updating the cipher list via `--update-ciphers-list` and, when a URL is also provided, run both update + analysis in the same execution.
6. Generate a Markdown security report file for each URL analysis run using the format `<YYYYMMDD>-<URL>-security-report.md`.
7. Execute targeted TLS vulnerability and downgrade-resilience tests (BEAST, POODLE, Heartbleed, Ticketbleed, LUCKY13, LOGJAM, FREAK, SWEET32, DROWN, Opossum, Winshock, ROBOT and related checks) with actionable implementation-oriented results.
8. Scan common TCP and UDP ports based on a local `ports-list.json`, run lightweight protocol-aware checks on open TCP ports, and include open-port findings in the report.
9. Detect the target web server product and version (when exposed) and include this in the report general information.

---

## 2. Functional Requirements

## 2.1 CLI Interface

- The tool must support:
  - `--url <https://target>`: target website to analyze.
  - `--update-ciphers-list`: fetch IANA XML and regenerate/update `ciphers-list.json`.
  - `protocols-list.json` is a required local input for protocol posture checks and is managed manually (not fetched from IANA).
  - `ports-list.json` is a required local input for TCP/UDP port scanning/protocol checks and is managed manually.
  - Optional combinations:
    - Only `--update-ciphers-list` → update list only.
    - Only `--url` → analyze using existing `ciphers-list.json`.
    - `--update-ciphers-list --url ...` → update list first, then analyze in same run.
- The CLI must return non-zero exit code when:
  - URL format is invalid.
  - IANA fetch/parsing fails while update flag is requested.
  - `protocols-list.json` is missing or invalid when URL analysis is requested.
  - `ports-list.json` is missing or invalid when URL analysis is requested.
  - Analysis cannot be performed due to unrecoverable network/TLS errors.

## 2.2 Cipher List Update from IANA

- Data source: `https://www.iana.org/assignments/tls-parameters/tls-parameters.xml`.
- The tool must parse registry with `id="tls-parameters-4"`.
- For each registry `record`, extract at minimum:
  - `description` (cipher suite name)
  - `rec` (recommended status: `Y`, `N`, `D`)
  - Optional traceability fields (value code point and references) if present.
- Output file: `ciphers-list.json` in `infrastructure-security-checker` directory.
- Regeneration rules:
  - Recreate file atomically (write temp + replace) to avoid partial output.
  - Preserve deterministic ordering (e.g., by cipher name or code point).
  - Exclude malformed/empty records.

## 2.3 Website Analysis

- URL normalization and validation (scheme + host required).
- Resolve hostname and attempt TLS handshake.
- Test protocol support matrix against entries from `protocols-list.json` (not only the negotiated protocol).
- Test cipher support matrix against entries from `ciphers-list.json` (not only the negotiated cipher).
- Collect and report at least:
  - Certificate validity window (not-before/not-after).
  - Certificate trust/chain validation result.
  - Hostname/SAN match result.
  - Negotiated protocol version.
  - Protocol status from `protocols-list.json` (`validated`, `deprecated`, or `UNKNOWN`).
  - Negotiated cipher suite.
  - Recommendation status of negotiated cipher based on `ciphers-list.json` (`Y`, `D`, `N`, or `UNKNOWN`).
  - Detected web server and version (e.g., via HTTP response headers/TLS fingerprints) or `UNKNOWN` when not disclosed.
- Additional infrastructure checks (minimum set for MVP):
  - TLS expiration warning threshold (e.g., <= 30 days).
  - Redirect from HTTP to HTTPS.
  - Presence of HSTS header.
  - Flag the endpoint when negotiated protocol is marked `deprecated` in `protocols-list.json`.
  - Sensitive path exposure probes (e.g., Spring Boot Actuator, admin consoles): default severity is `FAIL` when exposed. Swagger / OpenAPI documentation paths (`/swagger-ui`, `/v3/api-docs`) are treated as `WARN` (informational exposure, not a direct vulnerability).
  - ICMP echo (ping) reachability check: if the host responds to ICMP echo requests, report as `WARN` (ICMP should ideally be disabled on public-facing servers but is not a critical vulnerability). No reply → `PASS`.

## 2.4 Protocol List (Manual Input)

- Input file: `protocols-list.json` in `infrastructure-security-checker` directory.
- Ownership: maintained manually by project maintainers.
- Expected statuses:
  - `validated`
  - `deprecated`
- `--update-ciphers-list` must not modify `protocols-list.json`.

## 2.5 Output & Reporting

- Console output must include:
  - High-level status summary (`PASS/WARN/FAIL`).
  - Per-check result with short remediation hints.
  - Port-scan summary (total tested, open, closed/filtered, inconclusive) plus per-port protocol-check outcomes where applicable.
  - Per-vulnerability-test result with clear evidence (`vulnerable`, `not vulnerable`, or `inconclusive`) and next action.
  - Final exit code reflecting worst severity.
- Recommended optional output format flag for automation (future-ready): `--format json`.

## 2.6 Markdown Security Report File

- For each run with `--url`, generate a Markdown report file in the format:
  - `<YYYYMMDD>-<URL>-security-report.md`
- `<YYYYMMDD>` must be the local execution date.
- `<URL>` should be normalized/sanitized for safe file naming (e.g., remove scheme and replace unsafe filename characters).
- The report must include:
  - **General information**:
    - URL used for testing
    - Date and time of the test
    - Test duration
    - Detected web server and version (or `UNKNOWN` when not reliably detected)
  - **List of all TCP and UDP ports tested** with transport type, state (`open`, `closed`, `filtered`, `inconclusive`) and detected/validated protocol behavior when a probe is available.
  - **Open ports summary** highlighting every port found open.
  - **List of all protocols tested** with policy-driven colors:
    - green for success (`validated` + supported, `deprecated` + not supported),
    - orange when a `validated` entry is not supported,
    - red when a `deprecated` entry is supported.
  - **List of all ciphers tested** with the same policy-driven colors (green/orange/red).
  - **Vulnerability test results** for all checks listed in section 2.7, including status and concise evidence.
- Success rule for both protocols and ciphers:
  - a `validated` item is supported by the target;
  - a `deprecated` item is not supported by the target.

## 2.7 Additional Security/Vulnerability Tests

The tool must execute and report the following tests during URL analysis. Each item includes an implementation summary to guide development:

- **BEAST attack (CVE-2011-3389)**
  - Summary for implementation: detect whether TLS 1.0 is supported with CBC cipher suites; mark risk when both conditions are true (client-side exploit preconditions still present). CVE-2011-3389 is reported as a separate line item sharing the same precondition result.
- **POODLE (SSLv3) (CVE-2014-3566)**
  - Summary for implementation: test SSLv3 negotiation support; if SSLv3 + CBC is accepted, flag as vulnerable exposure.
- **POODLE (TLS) (CVE-2014-8730)**
  - Summary for implementation: send a TLS 1.2 ClientHello with only CBC suites; if the server accepts it, send a malformed application-data record with bad CBC padding and classify the alert response (bad_record_mac/decrypt_error → WARN; handshake_failure → PASS; no CBC negotiation → PASS).
- **Downgrade attack prevention (CVE-2014-3566 / TLS_FALLBACK_SCSV)**
  - Summary for implementation: send a TLS 1.1 ClientHello that includes the TLS_FALLBACK_SCSV pseudo-cipher-suite (0x5600). A correctly configured server must respond with an `inappropriate_fallback` alert (0x56). A ServerHello in response indicates missing fallback protection (FAIL); any other alert means the server rejected the downgrade (PASS).
- **SSL/TLS compression / CRIME (CVE-2012-4929)**
  - Summary for implementation: inspect negotiated compression method during handshake via `openssl s_client -brief`; retry with `-state -msg` if the compression field is absent. Any non-null compression must be flagged (CRIME-style risk).
- **RC4 (CVE-2013-2566 / CVE-2015-2808)**
  - Summary for implementation: scan offered/accepted cipher suites for RC4 variants and mark support as failure.
- **Heartbleed (CVE-2014-0160)**
  - Summary for implementation: send a TLS ClientHello with the heartbeat extension; if the server completes the handshake, send a malformed heartbeat request with an over-length payload field and detect over-read indicators in the response.
- **Ticketbleed (CVE-2016-9244)**
  - Summary for implementation: send a TLS ClientHello with a 1-byte session ID and an empty session-ticket extension; inspect the session ID length echoed in the ServerHello — a length greater than 1 indicates memory leakage.
- **LUCKY13 (CVE-2013-0169)**
  - Summary for implementation: check whether the server negotiates any CBC cipher suite (necessary precondition). If CBC is accepted, send two application-data records with maximally different padding byte values (0x00 vs 0x0f) immediately after the ServerHello and measure the latency delta between alert responses. A timing delta > 5ms on a single probe is flagged as a noticeable anomaly (WARN); CBC present but delta ≤ 5ms is still WARN (insufficient for statistical confirmation). No CBC → PASS. A definitive result requires hundreds of timed probes on a controlled network path; single-shot probing can only confirm the precondition and report a rough timing signal.
- **LOGJAM (CVE-2015-4000)**
  - Summary for implementation: send two TLS 1.2 ClientHellos in parallel — one advertising only DHE_EXPORT cipher suites (512-bit DH) and one advertising standard DHE suites. For each that produces a ServerKeyExchange (handshake type `0x0c`), parse the DH prime length from the first `dh_p` length field (RFC 5246 §7.4.3). Classify: prime ≤ 512 bits → `FAIL` (export-grade, trivially breakable); 513–1023 bits → `FAIL` (weak); 1024–2047 bits → `WARN` (marginal, < 2048-bit minimum); ≥ 2048 bits → `PASS`. No DHE negotiation → `PASS`.
- **DROWN (CVE-2016-0800 / CVE-2016-0703)**
  - Summary for implementation: three-step probe. (1) Send a raw SSLv2 ClientHello (2-byte record header, MSG-CLIENT-HELLO 0x01, version 0x00/0x02, one export cipher spec). If the server responds with an SSLv2 ServerHello (MSG-SERVER-HELLO 0x04) → Direct DROWN confirmed (`FAIL`, CVE-2016-0800). (2) If SSLv2 is accepted, send a ClientMasterKey with zero-length `clear_key` for the export cipher — if the server responds with MSG-SERVER-VERIFY (0x06) or MSG-CLIENT-FINISHED (0x02) instead of an error, Special DROWN (CVE-2016-0703) is signalled (`FAIL`). (3) If SSLv2 is not detected, send a TLS 1.2 ClientHello offering only RSA key-exchange cipher suites; if accepted, report `WARN` (General DROWN precondition — same RSA key may be shared with an SSLv2-capable service elsewhere). No SSLv2 and no RSA key exchange → `PASS`.
- **FREAK (CVE-2015-0204)**
  - Summary for implementation: send a TLS 1.2 ClientHello listing only RSA_EXPORT cipher suites (512-bit RSA key exchange: `TLS_RSA_EXPORT_WITH_RC4_40_MD5`, `TLS_RSA_EXPORT_WITH_DES40_CBC_SHA`, and related). If the server responds with a ServerHello → `FAIL` (export-grade RSA accepted, session key factorable in hours). No ServerHello → `PASS`. Extract the negotiated cipher code from the ServerHello for evidence.
- **SWEET32 (CVE-2016-2183 / CVE-2016-6329)**
  - Summary for implementation: send a TLS 1.2 ClientHello listing only 64-bit block cipher suites (3DES_EDE family: `TLS_RSA_WITH_3DES_EDE_CBC_SHA` and variants; DES; IDEA). If the server returns a ServerHello → `FAIL` (64-bit block cipher accepted; birthday attacks feasible after ~32 GB of traffic). Extract the negotiated cipher for evidence and distinguish 3DES from DES/IDEA in the message. No ServerHello → `PASS`.
- **Opossum (CVE-2025-49812)**
  - Summary for implementation: send a TLS 1.3 ClientHello that simultaneously includes a non-empty `session_ticket` extension (type `0x0023`) and an `early_data` extension (type `0x002a`), along with `supported_versions` (TLS 1.3 only) and a `key_share` extension. Scan the server's response for handshake messages of type `0x04` (NewSessionTicket) or `0x05` (EndOfEarlyData) appearing before a ServerHello is observed — this indicates a state-machine confusion. A normal ServerHello or TLS alert → `PASS`; state-confusion message detected → `FAIL`; no response / inconclusive → `WARN`/`PASS`.
- **Winshock (CVE-2014-6321 / MS14-066)**
  - Summary for implementation: uses negative fingerprinting aligned with testssl.sh `run_winshock()`. (1) Check whether the server accepts the 4 MS14-066 rollup GCM ciphers (`0x009C–0x009F`) — if accepted, the patch is applied → `PASS`. (2) Check for post-2012 ciphers (ECDHE-RSA-AES-GCM `0xC02F/0xC030`, CHACHA, CCM, ARIA, CAMELLIA) — if accepted, the server is Windows Server 2016+ or non-Windows → `PASS`. (3) Retrieve the HTTP `Server:` header — only `Microsoft-IIS/8.0` (Server 2012) and `Microsoft-IIS/8.5` (Server 2012 R2) WITHOUT the rollup ciphers are flagged `FAIL`. `Microsoft-HTTPAPI/2.0` without rollup → `WARN`. Any other IIS version or non-IIS → `PASS`.
- **OpenSSL CCS vuln. (CVE-2014-0224)**
  - Summary for implementation: attempt out-of-order/early `ChangeCipherSpec` injection during handshake and flag endpoints that accept unsafe state transition.
- **ROBOT (CVE-2017-13099)**
  - Summary for implementation: test RSA key-exchange endpoints with Bleichenbacher-style oracle probe sets and classify oracle strength (`strong/weak/inconclusive`).

Result semantics for these tests:

- `PASS`: not vulnerable / control is effective.
- `FAIL`: vulnerable behavior detected.
- `WARN`: inconclusive, not testable, or insufficient signal.

## 2.8 TCP & UDP Port Scanning & Protocol Checks

- Input file: `ports-list.json` in `infrastructure-security-checker` directory.
- Ownership: maintained manually by project maintainers.
- Each entry includes a `transport` field (`tcp` or `udp`) to distinguish the layer-4 protocol.
- Duplicate detection is keyed on `transport:port` (the same port number may appear once for TCP and once for UDP).
- For each configured TCP port, the tool must:
  - attempt a TCP connection with configurable timeout;
  - classify the port state (`open`, `closed`, `filtered`, or `inconclusive`);
  - when `open`, run a lightweight protocol-aware probe according to configured expectations (e.g., HTTP/HTTPS response, SSH banner, SMTP greeting, database handshake indicator where feasible).
- For each configured UDP port, the tool must:
  - send an empty UDP datagram probe to the target port;
  - classify the port state based on the response:
    - no response within timeout → `open` (open|filtered — standard UDP behavior);
    - ICMP port unreachable received → `closed`;
    - UDP response received → `open`;
    - other error → `inconclusive`.
  - Note: UDP scanning is inherently less reliable than TCP scanning due to the connectionless nature of UDP. The absence of a response typically means the port is open or filtered, but cannot be definitively determined without protocol-specific probes.
- The scan scope is driven only by entries in `ports-list.json` (no unrestricted full-range scans in MVP).
- Open ports must be explicitly listed in both console output and Markdown report, with transport type clearly indicated.

---

## 3. Non-Functional Requirements

- Implemented in TypeScript (Node.js runtime).
- Cross-platform execution via shell launcher (`check-infrastructure-security.sh`).
- Deterministic results for same target/context.
- Clear, actionable error messages.
- Reasonable timeout defaults for network operations.

---

## 4. Proposed Project Structure

```text
infrastructure-security-checker/
  ├── src/
  │   ├── cli/
  │   ├── iana/
  │   ├── tls/
  │   ├── checks/
  │   ├── reporting/
  │   └── types/
  ├── ciphers-list.json
  ├── protocols-list.json
  ├── ports-list.json
  ├── check-infrastructure-security.sh
  ├── package.json
  ├── tsconfig.json
  └── implementation-plan.md
```

---

## 5. Data Models

## 5.1 `ciphers-list.json`

Recommended JSON shape:

- `metadata`
  - source URL
  - fetched timestamp
  - registry id (`tls-parameters-4`)
- `ciphers` (array)
  - `name` (from `description`)
  - `recommended` (`Y` | `D` | `N`)
  - `value` (optional code point)
  - `references` (optional list)

Normalization rules:

- Trim whitespace.
- Keep canonical TLS naming from IANA.
- Ignore records that are not concrete cipher suites (e.g., explicit unassigned placeholders) based on validation rules.

## 5.2 `protocols-list.json`

Recommended JSON shape:

- `protocols` (array)
  - `name` (e.g., `TLSv1_2`)
  - `status` (`validated` | `deprecated`)

Rules:

- File is manually maintained.
- Names must match protocol identifiers emitted by TLS probing logic (or be normalized before comparison).
- Unknown negotiated protocols must be reported as `UNKNOWN` without failing parsing.

## 5.3 `ports-list.json`

Recommended JSON shape:

- `ports` (array)
  - `port` (port number, 1–65535)
  - `transport` (`tcp` | `udp` — layer-4 protocol for scanning)
  - `service` (human-friendly service label, e.g., `HTTPS`, `SSH`, `DNS (UDP)`)
  - `protocol` (expected application protocol for lightweight probe routing, e.g., `https`, `ssh`, `http`, `dns`)
  - `policy` (optional: `open` | `closed` — expected state)
  - `notes` (optional short context, e.g., `public web entrypoint`)

Rules:

- File is manually maintained.
- Duplicate entries are keyed on `transport:port` — the same port number may appear once for TCP and once for UDP.
- Unknown protocol values should not fail the whole run; mark the probe as `WARN`/`inconclusive` while still reporting port state.
- If `transport` is omitted during validation, it defaults to `tcp` for backward compatibility.

---

## 6. Implementation Plan (Phased)

## Phase 1 — CLI Skeleton & Configuration

1. Initialize TypeScript project and CLI argument parsing.
2. Define options contract (`--url`, `--update-ciphers-list`, future `--format`).
3. Implement input validation and process exit code strategy.

## Phase 2 — IANA Fetch & Parser

1. Implement XML download with timeout/retry policy.
2. Parse XML and locate registry `tls-parameters-4`.
3. Transform records into normalized internal model.
4. Write `ciphers-list.json` atomically with metadata.

## Phase 3 — TLS & Infrastructure Checks

1. Implement URL normalization and DNS/TLS connection flow.
2. Collect certificate details and validation outcomes.
3. Detect negotiated protocol/cipher and map:
   - protocol to status from `protocols-list.json`,
   - cipher to recommendation status from `ciphers-list.json`.
4. Add protocol/cipher support matrix probing to evaluate each configured entry against `validated`/`deprecated` policy.
5. Add MVP checks: cert expiry threshold, HTTPS redirect, HSTS presence, deprecated protocol flag.
6. Add web server fingerprinting logic (prioritize explicit server banners/headers, augment with lightweight heuristics where possible) and normalize to `product + version` or `UNKNOWN`.
7. Implement vulnerability/downgrade probes listed in section 2.7 (BEAST, POODLE SSLv3/TLS, downgrade prevention, CRIME compression, RC4, Heartbleed, Ticketbleed, LUCKY13, LOGJAM, FREAK, SWEET32, DROWN, Opossum, Winshock, OpenSSL CCS, ROBOT) with explicit evidence capture and inconclusive handling.
8. Implement TCP and UDP port scanning over `ports-list.json` with per-port state classification and protocol-aware probes for open TCP ports. UDP scanning uses `dgram` to send empty probe datagrams and classifies state based on ICMP responses or timeouts.

## Phase 4 — Reporting

1. Build unified check result model (severity, message, evidence, remediation).
2. Render human-readable console report.
3. Render Markdown report file named `<YYYYMMDD>-<URL>-security-report.md` with general information + full protocol/cipher tested lists.
4. Add TCP ports section with tested ports, states, protocol-probe outcomes, and explicit open-port summary.
5. Apply policy-driven colors in Markdown protocol/cipher lists: green for success, orange for `validated` but not supported, red for `deprecated` but supported.
6. Add a dedicated vulnerability section to console + Markdown outputs, including test name, status, evidence, and remediation hint.
7. Compute global status + exit code policy.

## Phase 5 — Orchestration Logic

1. Implement execution order:
   - If update flag present: run IANA refresh first.
   - If URL present: run analysis after update (if requested).
2. Ensure partial-failure behavior is explicit (e.g., update failed => analysis skipped unless fallback policy is defined).

## Phase 6 — Testing & Validation

1. Unit tests:
  - XML parsing and registry filtering.
  - Cipher recommendation mapping logic.
  - Protocol status mapping logic from `protocols-list.json`.
  - Port-list parsing and validation logic from `ports-list.json`.
  - Port state classification mapping (`open/closed/filtered/inconclusive`).
  - URL and CLI argument validation.
2. Integration tests:
  - `--update-ciphers-list` regenerates valid JSON.
  - `--url` analysis against controlled targets.
  - Combined mode (`--update-ciphers-list --url`).
  - Deprecated protocol detection based on manual `protocols-list.json`.
  - TCP port scanning against controlled endpoints with known open/closed ports.
  - Protocol-aware probe behavior on open ports (e.g., HTTP/SSH sample targets).
  - Report file generation with expected naming pattern and required sections.
  - Web server/version detection in report general information (including `UNKNOWN` fallback behavior).
  - Report contains open-port list and per-port state.
  - Success criteria rendering in protocol/cipher lists (`validated` supported, `deprecated` unsupported).
  - Coverage for each section 2.7 security test (BEAST/CVE-2011-3389, POODLE SSLv3/CVE-2014-3566, POODLE TLS/CVE-2014-8730, downgrade prevention/TLS_FALLBACK_SCSV, CRIME compression/CVE-2012-4929, RC4/CVE-2013-2566/CVE-2015-2808, Heartbleed/CVE-2014-0160, Ticketbleed/CVE-2016-9244, LUCKY13/CVE-2013-0169, LOGJAM/CVE-2015-4000, FREAK/CVE-2015-0204, SWEET32/CVE-2016-2183/CVE-2016-6329, DROWN/CVE-2016-0800/CVE-2016-0703, Opossum/CVE-2025-49812, Winshock/CVE-2014-6321, OpenSSL CCS/CVE-2014-0224, ROBOT/CVE-2017-13099).
3. Robustness tests:
   - Network timeout/unreachable host.
   - Invalid or changed XML schema handling.
- **Inconclusive-vs-fail classification for ambiguous probe responses (e.g., POODLE TLS alert types, Winshock on non-Windows hosts).**
- **Timing-based probe accuracy** → LUCKY13 single-shot probes are dominated by network jitter over public paths; results are always WARN (CBC present) or PASS (no CBC). Definitive classification requires controlled multi-sample timing analysis outside the scope of this tool.

## Phase 7 — Packaging & Launch Script

1. Add `check-infrastructure-security.sh` wrapper:
   - validates Node availability,
   - forwards all args to compiled TypeScript CLI.
2. Document usage examples and operational notes.

---

## 7. Acceptance Criteria

- Running with `--update-ciphers-list` produces a valid, non-empty `ciphers-list.json` based on IANA `tls-parameters-4` records.
- Running with `--url <target>` outputs certificate + negotiated cipher/protocol analysis and recommendation status from local cipher list.
- Running with `--url <target>` also classifies negotiated protocol using `protocols-list.json` and warns/fails on deprecated protocols per policy.
- Running with `--url <target>` scans all ports from `ports-list.json`, classifies port state, and performs protocol-aware checks on open ports when supported.
- Running with `--url <target>` generates `<YYYYMMDD>-<URL>-security-report.md` including general info, test duration, and full protocol/cipher tested lists.
- Running with `--url <target>` includes detected web server and version in general information (or `UNKNOWN` if hidden/unavailable).
- The generated report includes a dedicated ports section and explicitly lists open ports.
- Report marks protocol/cipher checks with policy-driven colors: green for success (`validated` supported, `deprecated` unsupported), orange for `validated` unsupported, red for `deprecated` supported.
- Running with `--url <target>` executes all section 2.7 security tests and reports each with `PASS/WARN/FAIL`, concise evidence, and remediation guidance. Current tests: BEAST/CVE-2011-3389, POODLE SSLv3/CVE-2014-3566, POODLE TLS/CVE-2014-8730, Downgrade prevention/TLS_FALLBACK_SCSV, CRIME compression/CVE-2012-4929, RC4/CVE-2013-2566/CVE-2015-2808, Heartbleed/CVE-2014-0160, Ticketbleed/CVE-2016-9244, LUCKY13/CVE-2013-0169, LOGJAM/CVE-2015-4000, FREAK/CVE-2015-0204, SWEET32/CVE-2016-2183/CVE-2016-6329, DROWN/CVE-2016-0800/CVE-2016-0703, Opossum/CVE-2025-49812, Winshock/CVE-2014-6321, OpenSSL CCS/CVE-2014-0224, ROBOT/CVE-2017-13099.
- Running with both flags updates cipher list and analyzes the URL in one command.
- Exit codes and severity reporting are consistent and script-friendly.
- Shell launcher successfully executes the TypeScript CLI.

---

## 8. Risks & Mitigations

- **IANA XML schema drift** → isolate parser with defensive checks + parser tests.
- **Platform-specific TLS behavior** → centralize TLS probing logic and test across representative environments.
- **Port scan false positives/negatives due filtering/firewalls** → use explicit timeout classes, classify as `filtered/inconclusive` when uncertain, and capture probe evidence.
- **Web server/version fingerprint ambiguity or masked banners** → prioritize explicit evidence (headers/banners), report confidence, and default to `UNKNOWN` instead of guessing.
- **False positives in infrastructure checks** → mark checks with confidence/evidence and explicit thresholds.
- **Network instability** → retries + clear timeout messaging.

---

## 9. Future Enhancements

- OCSP stapling and revocation checks.
- Full cipher suite scan (supported vs negotiated only).
- Output export for CI pipelines (`json`, `sarif`).
- Policy profiles (strict, baseline, legacy-compatible).