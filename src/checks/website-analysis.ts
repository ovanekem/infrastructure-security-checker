import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import type {
  AnalysisResult,
  CipherListFile,
  InfrastructureCheck,
  PolicyCheckResult,
  PortPolicyEntry,
  ProtocolPolicyEntry,
  Severity,
  WebServerEntry,
  WebServersFile,
} from '../types/index.js';
import { checkIcmp, scanPorts } from './ports.js';
import { runClientSimulations } from './client-simulations.js';
import {
  cipherStatusFromPolicy,
  evaluateCipherMatrix,
  evaluateProtocolMatrix,
  getTlsSessionInfo,
  protocolStatusFromPolicy,
} from './tls.js';
import { evaluateVulnerabilityChecks } from './vulnerabilities.js';

function severityRank(severity: Severity): number {
  if (severity === 'FAIL') return 3;
  if (severity === 'WARN') return 2;
  return 1;
}

function maxSeverity(values: Severity[]): Severity {
  return values.sort((a, b) => severityRank(b) - severityRank(a))[0] || 'PASS';
}

export function policyCheckSeverity(item: PolicyCheckResult): Severity {
  if (item.success) return 'PASS';
  if (item.policy === 'validated' && item.supported === false) return 'WARN';
  if (item.policy === 'deprecated' && item.supported === true) return 'FAIL';
  return 'WARN';
}

function checkCertificateExpiration(validTo?: string): InfrastructureCheck {
  if (!validTo) {
    return {
      name: 'Certificate expiration window',
      status: 'WARN',
      evidence: 'Certificate valid-to date unavailable.',
      remediation: 'Ensure server presents a complete certificate chain.',
    };
  }

  const expiryDate = new Date(validTo);
  if (Number.isNaN(expiryDate.getTime())) {
    return {
      name: 'Certificate expiration window',
      status: 'WARN',
      evidence: `Unable to parse certificate valid-to date: ${validTo}`,
      remediation: 'Validate certificate formatting and parsing logic.',
    };
  }

  const daysRemaining = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  if (daysRemaining <= 0) {
    return {
      name: 'Certificate expiration window',
      status: 'FAIL',
      evidence: `Certificate appears expired (${daysRemaining} days remaining).`,
      remediation: 'Renew and deploy a valid TLS certificate immediately.',
    };
  }
  if (daysRemaining <= 30) {
    return {
      name: 'Certificate expiration window',
      status: 'WARN',
      evidence: `Certificate expires soon (${daysRemaining} days remaining).`,
      remediation: 'Plan certificate renewal before expiration.',
    };
  }

  return {
    name: 'Certificate expiration window',
    status: 'PASS',
    evidence: `Certificate is valid for ${daysRemaining} more days.`,
    remediation: 'No action required.',
  };
}

export interface SensitivePathEntry {
  path: string;
  label: string;
  /** Override the default severity when the path is found exposed. Defaults to 'FAIL'. */
  severity?: Severity;
}

export const SENSITIVE_PATHS: SensitivePathEntry[] = [
  // Spring Boot Actuator
  { path: '/actuator', label: 'Spring Boot Actuator (/actuator)' },
  { path: '/actuator/env', label: 'Spring Boot Actuator (/actuator/env)' },
  { path: '/actuator/heapdump', label: 'Spring Boot Actuator (/actuator/heapdump)' },
  // Swagger / OpenAPI UI — WARN only (informational exposure, not a direct vulnerability)
  { path: '/swagger-ui', label: 'Swagger UI (/swagger-ui)', severity: 'WARN' },
  { path: '/v3/api-docs', label: 'OpenAPI docs (/v3/api-docs)', severity: 'WARN' },
  // General sensitive paths
  { path: '/admin', label: 'Admin interface (/admin)' },
  { path: '/console', label: 'Console interface (/console)' },
];

export interface ExposedFileEntry {
  path: string;
  label: string;
}

export const EXPOSED_FILE_PATHS: ExposedFileEntry[] = [
  // Backup / archive files
  { path: '/backup.zip', label: 'Backup archive (/backup.zip)' },
  { path: '/backup.sql', label: 'Database dump (/backup.sql)' },
  { path: '/db.sql', label: 'Database dump (/db.sql)' },
  { path: '/dump.sql', label: 'Database dump (/dump.sql)' },
  { path: '/backup.tar.gz', label: 'Backup archive (/backup.tar.gz)' },
  // Leftover / renamed source files
  { path: '/index.php.bak', label: 'Backup file (/index.php.bak)' },
  { path: '/config.php.bak', label: 'Backup file (/config.php.bak)' },
  { path: '/web.config.bak', label: 'Backup file (/web.config.bak)' },
  { path: '/index.php.old', label: 'Old file (/index.php.old)' },
  { path: '/config.php.old', label: 'Old file (/config.php.old)' },
  // Environment / config files
  { path: '/.env', label: 'Environment file (/.env)' },
  { path: '/.env.local', label: 'Environment file (/.env.local)' },
  { path: '/.env.production', label: 'Environment file (/.env.production)' },
  { path: '/config.yml', label: 'Config file (/config.yml)' },
  { path: '/config.yaml', label: 'Config file (/config.yaml)' },
  { path: '/config.json', label: 'Config file (/config.json)' },
  { path: '/application.properties', label: 'Config file (/application.properties)' },
  { path: '/application.yml', label: 'Config file (/application.yml)' },
  // Version control metadata
  { path: '/.git/config', label: 'Git repository config (/.git/config)' },
  { path: '/.git/HEAD', label: 'Git repository HEAD (/.git/HEAD)' },
  { path: '/.svn/entries', label: 'SVN repository metadata (/.svn/entries)' },
];

/**
 * Pure helper – builds an InfrastructureCheck for an exposed-file probe result.
 * Exported for unit testing.
 */
export function buildExposedFileCheck(
  entry: ExposedFileEntry,
  statusCode: number | null,
  errorMessage?: string,
): InfrastructureCheck {
  if (errorMessage !== undefined || statusCode === null) {
    return {
      name: `Exposed backup/config file: ${entry.label}`,
      status: 'PASS',
      evidence: `Probe failed (likely not reachable): ${errorMessage ?? 'unknown error'}`,
      remediation: 'No action required.',
    };
  }

  const notFound = statusCode === 404 || statusCode === 410;
  return {
    name: `Exposed backup/config file: ${entry.label}`,
    status: notFound ? 'PASS' : 'FAIL',
    evidence: notFound
      ? `Path returned HTTP ${statusCode} — file not exposed.`
      : `Path returned HTTP ${statusCode} — file potentially exposed.`,
    remediation: notFound
      ? 'No action required.'
      : `Remove or deny access to \`${entry.path}\` via web server rules. Backup and config files must never be publicly accessible.`,
  };
}

/**
 * Pure helper – builds an InfrastructureCheck for a sensitive-path probe result.
 * Exported for unit testing.
 */
export function buildSensitivePathCheck(
  entry: SensitivePathEntry,
  statusCode: number | null,
  errorMessage?: string,
): InfrastructureCheck {
  if (errorMessage !== undefined || statusCode === null) {
    return {
      name: `Sensitive path exposure: ${entry.label}`,
      status: 'PASS',
      evidence: `Probe failed (likely not reachable): ${errorMessage ?? 'unknown error'}`,
      remediation: 'No action required.',
    };
  }

  const notFound = statusCode === 404 || statusCode === 410;
  const exposedSeverity = entry.severity ?? 'FAIL';
  return {
    name: `Sensitive path exposure: ${entry.label}`,
    status: notFound ? 'PASS' : exposedSeverity,
    evidence: notFound
      ? `Path returned HTTP ${statusCode} — not exposed.`
      : `Path returned HTTP ${statusCode} — potentially exposed.`,
    remediation: notFound
      ? 'No action required.'
      : `Restrict or disable access to \`${entry.path}\` at the web server / reverse-proxy level. Do not expose internal endpoints publicly.`,
  };
}

async function fetchHttpGet(url: URL, timeoutMs: number): Promise<http.IncomingMessage> {
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(
      {
        method: 'GET',
        protocol: url.protocol,
        host: url.hostname,
        port: url.port ? Number(url.port) : undefined,
        path: url.pathname || '/',
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (response) => {
        // Consume body to free the socket
        response.resume();
        resolve(response);
      },
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('HTTP probe timed out'));
    });
    request.on('error', reject);
    request.end();
  });
}

/**
 * Probe a set of sensitive paths on the HTTPS endpoint.
 * A path that returns any status code other than 404 or 410 is considered exposed and results in FAIL.
 */
async function checkSensitivePaths(url: URL): Promise<InfrastructureCheck[]> {
  const baseUrl = new URL(url.toString());
  baseUrl.protocol = 'https:';
  // Strip any existing path — we always probe from root
  baseUrl.pathname = '/';
  baseUrl.search = '';
  baseUrl.hash = '';

  const results: InfrastructureCheck[] = [];

  for (const entry of SENSITIVE_PATHS) {
    const probeUrl = new URL(baseUrl.toString());
    probeUrl.pathname = entry.path;

    try {
      const response = await fetchHttpGet(probeUrl, 6_000);
      const status = response.statusCode ?? 0;
      results.push(buildSensitivePathCheck(entry, status));
    } catch (error) {
      results.push(buildSensitivePathCheck(entry, null, (error as Error).message));
    }
  }

  for (const entry of EXPOSED_FILE_PATHS) {
    const probeUrl = new URL(baseUrl.toString());
    probeUrl.pathname = entry.path;

    try {
      const response = await fetchHttpGet(probeUrl, 6_000);
      const status = response.statusCode ?? 0;
      results.push(buildExposedFileCheck(entry, status));
    } catch (error) {
      results.push(buildExposedFileCheck(entry, null, (error as Error).message));
    }
  }

  return results;
}

async function fetchHttpHead(url: URL, timeoutMs: number): Promise<http.IncomingMessage> {
  const client = url.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request(
      {
        method: 'HEAD',
        protocol: url.protocol,
        host: url.hostname,
        port: url.port ? Number(url.port) : undefined,
        path: url.pathname || '/',
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (response) => {
        resolve(response);
      },
    );

    request.on('timeout', () => {
      request.destroy();
      reject(new Error('HTTP probe timed out'));
    });
    request.on('error', reject);
    request.end();
  });
}

async function checkRedirectToHttps(url: URL): Promise<InfrastructureCheck> {
  if (url.protocol === 'https:') {
    return {
      name: 'HTTP to HTTPS redirect',
      status: 'PASS',
      evidence: 'Primary target already uses HTTPS.',
      remediation: 'No action required.',
    };
  }

  const probeUrl = new URL(url.toString());
  probeUrl.protocol = 'http:';

  try {
    const response = await fetchHttpHead(probeUrl, 6_000);
    const location = response.headers.location || '';
    const redirectOk = [301, 302, 307, 308].includes(response.statusCode || 0)
      && location.toString().startsWith('https://');

    return {
      name: 'HTTP to HTTPS redirect',
      status: redirectOk ? 'PASS' : 'WARN',
      evidence: `HTTP status ${response.statusCode}; location=${location || 'n/a'}`,
      remediation: 'Enforce redirect from HTTP to HTTPS at the edge.',
    };
  } catch (error) {
    return {
      name: 'HTTP to HTTPS redirect',
      status: 'WARN',
      evidence: `Redirect probe failed: ${(error as Error).message}`,
      remediation: 'Validate public HTTP reachability and redirection rules.',
    };
  }
}

async function checkHsts(url: URL): Promise<InfrastructureCheck> {
  const httpsUrl = new URL(url.toString());
  httpsUrl.protocol = 'https:';

  try {
    const response = await fetchHttpHead(httpsUrl, 6_000);
    const hsts = response.headers['strict-transport-security'];

    return {
      name: 'HSTS header presence',
      status: hsts ? 'PASS' : 'WARN',
      evidence: hsts ? `strict-transport-security: ${hsts}` : 'HSTS header not present.',
      remediation: 'Add `Strict-Transport-Security` with an adequate max-age.',
    };
  } catch (error) {
    return {
      name: 'HSTS header presence',
      status: 'WARN',
      evidence: `HTTPS header probe failed: ${(error as Error).message}`,
      remediation: 'Validate HTTPS endpoint availability and response headers.',
    };
  }
}

async function fetchHttpsHeaders(url: URL): Promise<http.IncomingHttpHeaders | null> {
  const httpsUrl = new URL(url.toString());
  httpsUrl.protocol = 'https:';
  try {
    const response = await fetchHttpHead(httpsUrl, 6_000);
    return response.headers;
  } catch {
    return null;
  }
}

function detectWebServerFromHeaders(headers: http.IncomingHttpHeaders | null): string {
  if (!headers) return 'UNKNOWN';
  const server = headers.server;
  if (typeof server === 'string' && server.trim()) {
    return server.trim();
  }
  return 'UNKNOWN';
}

/**
 * Compare two dot-separated version strings.
 * Returns -1 if a < b, 0 if equal, 1 if a > b.
 * Exported for unit testing.
 */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const aN = aParts[i] ?? 0;
    const bN = bParts[i] ?? 0;
    if (aN < bN) return -1;
    if (aN > bN) return 1;
  }
  return 0;
}

/**
 * Pure helper — evaluates the `Server` response header value against the list
 * of known web servers to detect banner disclosure and check version currency.
 *
 * Rules:
 *   - No Server header → PASS (banner suppressed)
 *   - Server header present, no version token → WARN (name disclosed, version hidden)
 *   - Version present, matches known server, version >= minimumSecureVersion → WARN
 *   - Version present, matches known server, version < minimumSecureVersion → FAIL
 *   - Version present, unrecognised server → WARN
 *
 * Exported for unit testing.
 */
export function buildServerBannerCheck(
  serverHeader: string | null | undefined,
  webServers: WebServerEntry[],
): InfrastructureCheck {
  if (!serverHeader || !serverHeader.trim()) {
    return {
      name: 'Server banner disclosure',
      status: 'PASS',
      evidence: 'No Server header present — banner suppressed.',
      remediation: 'No action required.',
    };
  }

  const banner = serverHeader.trim();

  for (const entry of webServers) {
    const regex = new RegExp(entry.pattern, 'i');
    const match = regex.exec(banner);
    if (!match) continue;

    const detectedVersion = match[1] ?? null;

    if (!detectedVersion) {
      return {
        name: 'Server banner disclosure',
        status: 'WARN',
        evidence: `Server header discloses software name but no version: "${banner}".`,
        remediation: 'Remove the Server header entirely, or configure the server to suppress it (e.g. ServerTokens Prod for Apache, server_tokens off for nginx).',
      };
    }

    const outdated = compareVersions(detectedVersion, entry.minimumSecureVersion) < 0;
    if (outdated) {
      return {
        name: 'Server banner disclosure',
        status: 'FAIL',
        evidence: `Server header discloses "${banner}". Detected version ${detectedVersion} is below the minimum secure version ${entry.minimumSecureVersion} for ${entry.name}.`,
        remediation: `Update ${entry.name} to at least version ${entry.minimumSecureVersion} and suppress the Server header. ${entry.notes ?? ''}`.trim(),
      };
    }

    return {
      name: 'Server banner disclosure',
      status: 'WARN',
      evidence: `Server header discloses "${banner}". Version ${detectedVersion} meets the minimum secure threshold (${entry.minimumSecureVersion}) but version information should not be exposed.`,
      remediation: 'Suppress the Server header to avoid disclosing software versions to potential attackers.',
    };
  }

  // Unrecognised server — still a disclosure
  return {
    name: 'Server banner disclosure',
    status: 'WARN',
    evidence: `Server header discloses "${banner}". No known-version baseline available for this software.`,
    remediation: 'Suppress or anonymise the Server header to avoid disclosing server software identity.',
  };
}

function checkXContentTypeOptions(headers: http.IncomingHttpHeaders | null): InfrastructureCheck {
  if (!headers) {
    return {
      name: 'X-Content-Type-Options header',
      status: 'WARN',
      evidence: 'HTTPS header probe failed — unable to check header.',
      remediation: 'Add `X-Content-Type-Options: nosniff` response header.',
    };
  }
  const value = headers['x-content-type-options'];
  if (typeof value === 'string' && value.trim().toLowerCase() === 'nosniff') {
    return {
      name: 'X-Content-Type-Options header',
      status: 'PASS',
      evidence: `x-content-type-options: ${value.trim()}`,
      remediation: 'No action required.',
    };
  }
  return {
    name: 'X-Content-Type-Options header',
    status: 'FAIL',
    evidence: value ? `Unexpected value: ${value}` : 'Header not present.',
    remediation: 'Add `X-Content-Type-Options: nosniff` response header to prevent MIME-type sniffing.',
  };
}

function checkXXssProtection(headers: http.IncomingHttpHeaders | null): InfrastructureCheck {
  if (!headers) {
    return {
      name: 'X-XSS-Protection header',
      status: 'WARN',
      evidence: 'HTTPS header probe failed — unable to check header.',
      remediation: 'Add `X-XSS-Protection: 1; mode=block` response header.',
    };
  }
  const value = headers['x-xss-protection'];
  if (typeof value === 'string' && /^\s*1\s*;\s*mode\s*=\s*block\s*$/i.test(value)) {
    return {
      name: 'X-XSS-Protection header',
      status: 'PASS',
      evidence: `x-xss-protection: ${value.trim()}`,
      remediation: 'No action required.',
    };
  }
  return {
    name: 'X-XSS-Protection header',
    status: 'FAIL',
    evidence: value ? `Unexpected value: ${value}` : 'Header not present.',
    remediation: 'Add `X-XSS-Protection: 1; mode=block` response header to enable browser XSS filtering.',
  };
}

function checkXFrameOptions(headers: http.IncomingHttpHeaders | null): InfrastructureCheck {
  if (!headers) {
    return {
      name: 'X-Frame-Options header',
      status: 'WARN',
      evidence: 'HTTPS header probe failed — unable to check header.',
      remediation: 'Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` response header.',
    };
  }
  const value = headers['x-frame-options'];
  if (typeof value === 'string') {
    const normalized = value.trim().toUpperCase();
    if (normalized === 'DENY' || normalized === 'SAMEORIGIN') {
      return {
        name: 'X-Frame-Options header',
        status: 'PASS',
        evidence: `x-frame-options: ${value.trim()}`,
        remediation: 'No action required.',
      };
    }
    return {
      name: 'X-Frame-Options header',
      status: 'WARN',
      evidence: `Unexpected value: ${value.trim()}`,
      remediation: 'Set `X-Frame-Options` to `DENY` or `SAMEORIGIN` to prevent clickjacking.',
    };
  }
  return {
    name: 'X-Frame-Options header',
    status: 'FAIL',
    evidence: 'Header not present.',
    remediation: 'Add `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN` response header to prevent clickjacking.',
  };
}

/**
 * Evaluate Content-Security-Policy header.
 *
 * Scoring algorithm:
 *   - Header absent → FAIL
 *   - Header present but contains any `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`,
 *     data: URI sources, or wildcard (*) sources → WARN (policy weakened but present)
 *   - Header present with no unsafe directives → PASS
 */
function checkContentSecurityPolicy(headers: http.IncomingHttpHeaders | null): InfrastructureCheck {
  if (!headers) {
    return {
      name: 'Content-Security-Policy header',
      status: 'WARN',
      evidence: 'HTTPS header probe failed — unable to check header.',
      remediation: 'Add a Content-Security-Policy header to mitigate XSS and data-injection attacks.',
    };
  }

  const value = headers['content-security-policy'];
  if (!value) {
    return {
      name: 'Content-Security-Policy header',
      status: 'FAIL',
      evidence: 'Header not present.',
      remediation: 'Add a Content-Security-Policy header. Start with a report-only policy and tighten iteratively.',
    };
  }

  const csp = typeof value === 'string' ? value : (Array.isArray(value) ? value.join(', ') : String(value));

  // Detect weakening patterns
  const unsafePatterns: { pattern: RegExp; label: string }[] = [
    { pattern: /'unsafe-inline'/i, label: "'unsafe-inline'" },
    { pattern: /'unsafe-eval'/i, label: "'unsafe-eval'" },
    { pattern: /'unsafe-hashes'/i, label: "'unsafe-hashes'" },
    { pattern: /\bdata:/i, label: 'data: URI source' },
    { pattern: /(?:^|[\s;])\s*(?:default-src|script-src|style-src|img-src|connect-src|font-src|object-src|media-src|frame-src|child-src|worker-src)\s[^;]*(?:^|\s)\*(?:\s|;|$)/i, label: 'wildcard (*) source' },
  ];

  const findings: string[] = [];
  for (const { pattern, label } of unsafePatterns) {
    if (pattern.test(csp)) {
      findings.push(label);
    }
  }

  if (findings.length > 0) {
    return {
      name: 'Content-Security-Policy header',
      status: 'WARN',
      evidence: `CSP present but contains weakening directives: ${findings.join(', ')}. Policy: ${csp.length > 200 ? `${csp.slice(0, 200)}…` : csp}`,
      remediation: `Remove or replace unsafe directives (${findings.join(', ')}) with nonce/hash-based alternatives where possible.`,
    };
  }

  return {
    name: 'Content-Security-Policy header',
    status: 'PASS',
    evidence: `content-security-policy: ${csp.length > 200 ? `${csp.slice(0, 200)}…` : csp}`,
    remediation: 'No action required.',
  };
}

/**
 * HTTP methods that are considered dangerous when enabled on a public endpoint.
 * TRACE enables cross-site tracing (XST). PUT/DELETE/PATCH allow content modification.
 * WebDAV methods (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK) extend the
 * attack surface significantly.
 * Exported for unit testing.
 */
export const DANGEROUS_HTTP_METHODS = [
  'TRACE',
  'PUT',
  'DELETE',
  'PATCH',
  'PROPFIND',
  'PROPPATCH',
  'MKCOL',
  'COPY',
  'MOVE',
  'LOCK',
  'UNLOCK',
] as const;

/**
 * Pure helper — builds an InfrastructureCheck from the set of allowed methods
 * advertised by a server (typically parsed from the `Allow` response header of
 * an OPTIONS request).
 * Exported for unit testing.
 *
 * @param allowedMethods  List of HTTP method tokens the server advertises, or
 *                        `null` when the OPTIONS probe failed / no Allow header.
 * @param errorMessage    Set when the probe threw a network-level error.
 */
export function buildHttpMethodCheck(
  allowedMethods: string[] | null,
  errorMessage?: string,
): InfrastructureCheck {
  if (errorMessage !== undefined || allowedMethods === null) {
    return {
      name: 'Dangerous HTTP methods',
      status: 'PASS',
      evidence: errorMessage
        ? `OPTIONS probe failed (likely not reachable): ${errorMessage}`
        : 'No Allow header returned by server — methods undiscoverable via OPTIONS.',
      remediation: 'No action required.',
    };
  }

  const normalised = allowedMethods.map((m) => m.trim().toUpperCase());
  const found = DANGEROUS_HTTP_METHODS.filter((m) => normalised.includes(m));

  if (found.length === 0) {
    return {
      name: 'Dangerous HTTP methods',
      status: 'PASS',
      evidence: `No dangerous methods found. Allowed: ${normalised.join(', ') || '(none advertised)'}`,
      remediation: 'No action required.',
    };
  }

  return {
    name: 'Dangerous HTTP methods',
    status: 'WARN',
    evidence: `Dangerous method(s) enabled: ${found.join(', ')}. Full Allow header: ${normalised.join(', ')}`,
    remediation: `Disable dangerous HTTP methods (${found.join(', ')}) in your web server / reverse-proxy configuration unless explicitly required.`,
  };
}

async function probeHttpMethods(url: URL, timeoutMs: number): Promise<string[] | null> {
  const httpsUrl = new URL(url.toString());
  httpsUrl.protocol = 'https:';
  httpsUrl.pathname = '/';
  httpsUrl.search = '';
  httpsUrl.hash = '';

  const client = https;

  return new Promise((resolve) => {
    const request = client.request(
      {
        method: 'OPTIONS',
        protocol: httpsUrl.protocol,
        host: httpsUrl.hostname,
        port: httpsUrl.port ? Number(httpsUrl.port) : undefined,
        path: httpsUrl.pathname,
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (response) => {
        response.resume();
        const allow = response.headers['allow'] ?? response.headers['public'];
        if (!allow) {
          resolve(null);
          return;
        }
        const raw = Array.isArray(allow) ? allow.join(', ') : allow;
        resolve(raw.split(',').map((m) => m.trim()).filter(Boolean));
      },
    );

    request.on('timeout', () => { request.destroy(); resolve(null); });
    request.on('error', () => { resolve(null); });
    request.end();
  });
}

async function checkHttpMethods(url: URL): Promise<InfrastructureCheck> {
  try {
    const methods = await probeHttpMethods(url, 6_000);
    return buildHttpMethodCheck(methods);
  } catch (error) {
    return buildHttpMethodCheck(null, (error as Error).message);
  }
}

function buildCertificateChecks(authorizationError: string | undefined, hostnameMatches: boolean): InfrastructureCheck[] {
  const checks: InfrastructureCheck[] = [];
  checks.push({
    name: 'Certificate trust/chain validation',
    status: authorizationError ? 'WARN' : 'PASS',
    evidence: authorizationError ? `authorizationError=${authorizationError}` : 'Certificate chain accepted by runtime trust store.',
    remediation: 'Install a trusted certificate chain from a recognized CA.',
  });

  checks.push({
    name: 'Hostname / SAN match',
    status: hostnameMatches ? 'PASS' : 'FAIL',
    evidence: hostnameMatches ? 'Certificate subject/SAN matches target hostname.' : 'Target hostname does not match certificate subject/SAN.',
    remediation: 'Use a certificate that includes the exact requested hostname.',
  });

  return checks;
}

export function computeGlobalStatus(severities: Severity[]): { globalStatus: Severity; exitCode: number; } {
  const globalStatus = maxSeverity(severities);
  const exitCode = globalStatus === 'PASS' ? 0 : globalStatus === 'WARN' ? 1 : 2;
  return { globalStatus, exitCode };
}

export async function analyzeWebsite(
  targetUrl: URL,
  protocols: ProtocolPolicyEntry[],
  ciphersFile: CipherListFile,
  ports: PortPolicyEntry[],
  webServers: WebServersFile,
): Promise<AnalysisResult> {
  const startedAt = new Date();
  const host = targetUrl.hostname;

  const dnsResult = await dns.lookup(host);
  if (!dnsResult.address) {
    throw new Error(`Unable to resolve hostname: ${host}`);
  }

  const tlsPort = targetUrl.port ? Number(targetUrl.port) : 443;
  const tlsInfo = await getTlsSessionInfo(host, tlsPort, host);

  const protocolResults = await evaluateProtocolMatrix(host, tlsPort, host, protocols);
  const cipherResults = await evaluateCipherMatrix(host, tlsPort, host, ciphersFile.ciphers, tlsInfo.negotiatedCipher);
  const vulnerabilityResults = await evaluateVulnerabilityChecks(host, tlsPort, host, protocolResults, cipherResults);

  const infraChecks: InfrastructureCheck[] = [
    checkCertificateExpiration(tlsInfo.certificate.validTo),
    ...buildCertificateChecks(tlsInfo.certificate.authorizationError, tlsInfo.certificate.hostnameMatches),
    await checkRedirectToHttps(targetUrl),
    await checkHsts(targetUrl),
  ];

  // Fetch HTTPS response headers once for all header-based checks
  const httpsHeaders = await fetchHttpsHeaders(targetUrl);
  const webServer = detectWebServerFromHeaders(httpsHeaders);
  const serverHeaderValue = httpsHeaders?.server;
  const serverHeader = Array.isArray(serverHeaderValue) ? serverHeaderValue[0] : (serverHeaderValue ?? null);
  infraChecks.push(
    checkXContentTypeOptions(httpsHeaders),
    checkXXssProtection(httpsHeaders),
    checkXFrameOptions(httpsHeaders),
    checkContentSecurityPolicy(httpsHeaders),
    buildServerBannerCheck(serverHeader, webServers.webServers),
  );

  // Sensitive-path exposure checks
  const sensitivePathChecks = await checkSensitivePaths(targetUrl);
  infraChecks.push(...sensitivePathChecks);

  // Dangerous HTTP methods check
  infraChecks.push(await checkHttpMethods(targetUrl));

  const negotiatedProtocolStatus = protocolStatusFromPolicy(tlsInfo.negotiatedProtocol, protocols);
  if (negotiatedProtocolStatus === 'deprecated') {
    infraChecks.push({
      name: 'Deprecated negotiated protocol',
      status: 'FAIL',
      evidence: `Negotiated protocol ${tlsInfo.negotiatedProtocol} is marked deprecated in policy.`,
      remediation: 'Disable deprecated protocols on the server.',
    });
  }

  const portResults = await scanPorts(host, ports);
  const icmpCheck = await checkIcmp(host);
  const clientSimulations = await runClientSimulations(host, tlsPort, host);

  const finishedAt = new Date();
  const durationMs = finishedAt.getTime() - startedAt.getTime();

  const allSeverities: Severity[] = [
    ...infraChecks.map((item) => item.status),
    ...vulnerabilityResults.map((item) => item.status),
    ...portResults.map((item) => item.probe?.status || 'WARN'),
    ...protocolResults.map(policyCheckSeverity),
    ...cipherResults.map(policyCheckSeverity),
  ];

  const { globalStatus, exitCode } = computeGlobalStatus(allSeverities);

  return {
    targetUrl: targetUrl.toString(),
    startedAt,
    finishedAt,
    durationMs,
    webServer,
    certificate: tlsInfo.certificate,
    negotiatedProtocol: tlsInfo.negotiatedProtocol,
    negotiatedProtocolStatus,
    negotiatedCipher: tlsInfo.negotiatedCipher,
    negotiatedCipherStatus: cipherStatusFromPolicy(tlsInfo.negotiatedCipher, ciphersFile.ciphers),
    protocolResults,
    cipherResults,
    infrastructureChecks: infraChecks,
    portResults,
    icmpCheck,
    vulnerabilityResults,
    clientSimulations,
    globalStatus,
    exitCode,
  };
}
