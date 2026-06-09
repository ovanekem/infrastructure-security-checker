import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSensitivePathCheck,
  SENSITIVE_PATHS,
  buildExposedFileCheck,
  EXPOSED_FILE_PATHS,
  buildHttpMethodCheck,
  DANGEROUS_HTTP_METHODS,
  buildServerBannerCheck,
  compareVersions,
} from '../dist/checks/website-analysis.js';

// ---------------------------------------------------------------------------
// SENSITIVE_PATHS list integrity
// ---------------------------------------------------------------------------

test('SENSITIVE_PATHS contains all expected Spring Boot Actuator paths', () => {
  const paths = SENSITIVE_PATHS.map((e) => e.path);
  assert.ok(paths.includes('/actuator'), 'Missing /actuator');
  assert.ok(paths.includes('/actuator/env'), 'Missing /actuator/env');
  assert.ok(paths.includes('/actuator/heapdump'), 'Missing /actuator/heapdump');
});

test('SENSITIVE_PATHS contains all expected Swagger / OpenAPI paths', () => {
  const paths = SENSITIVE_PATHS.map((e) => e.path);
  assert.ok(paths.includes('/swagger-ui'), 'Missing /swagger-ui');
  assert.ok(paths.includes('/v3/api-docs'), 'Missing /v3/api-docs');
});

test('SENSITIVE_PATHS contains all expected general sensitive paths', () => {
  const paths = SENSITIVE_PATHS.map((e) => e.path);
  assert.ok(paths.includes('/admin'), 'Missing /admin');
  assert.ok(paths.includes('/console'), 'Missing /console');
});

// ---------------------------------------------------------------------------
// buildSensitivePathCheck — PASS cases (not exposed)
// ---------------------------------------------------------------------------

const actuatorEntry = { path: '/actuator', label: 'Spring Boot Actuator (/actuator)' };

test('returns PASS when path returns HTTP 404', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 404);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /404/);
  assert.match(result.evidence, /not exposed/);
  assert.equal(result.remediation, 'No action required.');
});

test('returns PASS when path returns HTTP 410', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 410);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /410/);
});

test('returns PASS when probe throws a network error', () => {
  const result = buildSensitivePathCheck(actuatorEntry, null, 'Connection refused');
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /Connection refused/);
  assert.equal(result.remediation, 'No action required.');
});

// ---------------------------------------------------------------------------
// buildSensitivePathCheck — FAIL cases (exposed)
// ---------------------------------------------------------------------------

test('returns FAIL when path returns HTTP 200', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 200);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /200/);
  assert.match(result.evidence, /potentially exposed/);
  assert.match(result.remediation, /\/actuator/);
});

test('returns FAIL when path returns HTTP 401 (auth wall — still reachable)', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 401);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /401/);
  assert.match(result.evidence, /potentially exposed/);
});

test('returns FAIL when path returns HTTP 403', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 403);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /403/);
});

test('returns FAIL when path returns HTTP 302 (redirect — path exists)', () => {
  const result = buildSensitivePathCheck(actuatorEntry, 302);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /302/);
});

// ---------------------------------------------------------------------------
// buildSensitivePathCheck — check name includes path label
// ---------------------------------------------------------------------------

test('check name includes the entry label', () => {
  const entry = { path: '/swagger-ui', label: 'Swagger UI (/swagger-ui)' };
  const result = buildSensitivePathCheck(entry, 200);
  assert.match(result.name, /Swagger UI/);
  assert.match(result.name, /\/swagger-ui/);
});

// ---------------------------------------------------------------------------
// Per-path smoke test: every known sensitive path emits FAIL or WARN on HTTP 200
// ---------------------------------------------------------------------------

for (const entry of SENSITIVE_PATHS) {
  const expected = entry.severity ?? 'FAIL';
  test(`${expected} on HTTP 200 for sensitive path ${entry.path}`, () => {
    const result = buildSensitivePathCheck(entry, 200);
    assert.equal(result.status, expected, `Expected ${expected} for ${entry.path}`);
  });
}

// ---------------------------------------------------------------------------
// EXPOSED_FILE_PATHS list integrity
// ---------------------------------------------------------------------------

test('EXPOSED_FILE_PATHS contains backup archive files (.zip, .sql, .tar.gz)', () => {
  const paths = EXPOSED_FILE_PATHS.map((e) => e.path);
  assert.ok(paths.some((p) => p.endsWith('.zip')), 'Missing .zip entry');
  assert.ok(paths.some((p) => p.endsWith('.sql')), 'Missing .sql entry');
  assert.ok(paths.some((p) => p.endsWith('.tar.gz')), 'Missing .tar.gz entry');
});

test('EXPOSED_FILE_PATHS contains backup/old renamed source files (.bak, .old)', () => {
  const paths = EXPOSED_FILE_PATHS.map((e) => e.path);
  assert.ok(paths.some((p) => p.endsWith('.bak')), 'Missing .bak entry');
  assert.ok(paths.some((p) => p.endsWith('.old')), 'Missing .old entry');
});

test('EXPOSED_FILE_PATHS contains environment / config files', () => {
  const paths = EXPOSED_FILE_PATHS.map((e) => e.path);
  assert.ok(paths.includes('/.env'), 'Missing /.env');
  assert.ok(paths.includes('/.env.local'), 'Missing /.env.local');
  assert.ok(paths.includes('/.env.production'), 'Missing /.env.production');
  assert.ok(paths.some((p) => p.includes('config')), 'Missing a config file entry');
  assert.ok(paths.includes('/application.properties'), 'Missing /application.properties');
  assert.ok(paths.includes('/application.yml'), 'Missing /application.yml');
});

test('EXPOSED_FILE_PATHS contains version-control metadata paths (.git, .svn)', () => {
  const paths = EXPOSED_FILE_PATHS.map((e) => e.path);
  assert.ok(paths.some((p) => p.startsWith('/.git/')), 'Missing /.git/ entry');
  assert.ok(paths.some((p) => p.startsWith('/.svn/')), 'Missing /.svn/ entry');
});

// ---------------------------------------------------------------------------
// buildExposedFileCheck — PASS cases (not exposed)
// ---------------------------------------------------------------------------

const envEntry = { path: '/.env', label: 'Environment file (/.env)' };

test('buildExposedFileCheck returns PASS when file returns HTTP 404', () => {
  const result = buildExposedFileCheck(envEntry, 404);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /404/);
  assert.match(result.evidence, /not exposed/);
  assert.equal(result.remediation, 'No action required.');
});

test('buildExposedFileCheck returns PASS when file returns HTTP 410', () => {
  const result = buildExposedFileCheck(envEntry, 410);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /410/);
});

test('buildExposedFileCheck returns PASS when probe throws a network error', () => {
  const result = buildExposedFileCheck(envEntry, null, 'Connection refused');
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /Connection refused/);
  assert.equal(result.remediation, 'No action required.');
});

// ---------------------------------------------------------------------------
// buildExposedFileCheck — FAIL cases (exposed)
// ---------------------------------------------------------------------------

test('buildExposedFileCheck returns FAIL when file returns HTTP 200', () => {
  const result = buildExposedFileCheck(envEntry, 200);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /200/);
  assert.match(result.evidence, /potentially exposed/);
  assert.match(result.remediation, /\/.env/);
});

test('buildExposedFileCheck returns FAIL when file returns HTTP 403 (blocked but exists)', () => {
  const result = buildExposedFileCheck(envEntry, 403);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /403/);
});

test('buildExposedFileCheck returns FAIL when file returns HTTP 401', () => {
  const result = buildExposedFileCheck(envEntry, 401);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /401/);
});

test('buildExposedFileCheck returns FAIL when file returns HTTP 302', () => {
  const result = buildExposedFileCheck(envEntry, 302);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /302/);
});

// ---------------------------------------------------------------------------
// buildExposedFileCheck — check name includes file label
// ---------------------------------------------------------------------------

test('buildExposedFileCheck name includes the entry label', () => {
  const entry = { path: '/.git/config', label: 'Git repository config (/.git/config)' };
  const result = buildExposedFileCheck(entry, 200);
  assert.match(result.name, /Git repository config/);
  assert.match(result.name, /\/.git\/config/);
});

test('buildExposedFileCheck name is prefixed with "Exposed backup/config file"', () => {
  const result = buildExposedFileCheck(envEntry, 200);
  assert.match(result.name, /^Exposed backup\/config file:/);
});

// ---------------------------------------------------------------------------
// Per-file smoke test: every known exposed-file path emits FAIL on HTTP 200
// ---------------------------------------------------------------------------

for (const entry of EXPOSED_FILE_PATHS) {
  test(`FAIL on HTTP 200 for exposed file path ${entry.path}`, () => {
    const result = buildExposedFileCheck(entry, 200);
    assert.equal(result.status, 'FAIL', `Expected FAIL for ${entry.path}`);
  });
}

// ---------------------------------------------------------------------------
// DANGEROUS_HTTP_METHODS list integrity
// ---------------------------------------------------------------------------

test('DANGEROUS_HTTP_METHODS contains TRACE (cross-site tracing)', () => {
  assert.ok(DANGEROUS_HTTP_METHODS.includes('TRACE'), 'Missing TRACE');
});

test('DANGEROUS_HTTP_METHODS contains content-modifying methods PUT, DELETE, PATCH', () => {
  assert.ok(DANGEROUS_HTTP_METHODS.includes('PUT'), 'Missing PUT');
  assert.ok(DANGEROUS_HTTP_METHODS.includes('DELETE'), 'Missing DELETE');
  assert.ok(DANGEROUS_HTTP_METHODS.includes('PATCH'), 'Missing PATCH');
});

test('DANGEROUS_HTTP_METHODS contains WebDAV methods', () => {
  const webdav = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];
  for (const m of webdav) {
    assert.ok(DANGEROUS_HTTP_METHODS.includes(m), `Missing WebDAV method ${m}`);
  }
});

// ---------------------------------------------------------------------------
// buildHttpMethodCheck — PASS cases (safe / unreachable)
// ---------------------------------------------------------------------------

test('buildHttpMethodCheck returns PASS when only safe methods are advertised', () => {
  const result = buildHttpMethodCheck(['GET', 'HEAD', 'POST', 'OPTIONS']);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /No dangerous methods found/);
  assert.equal(result.remediation, 'No action required.');
});

test('buildHttpMethodCheck returns PASS when allowed methods list is empty', () => {
  const result = buildHttpMethodCheck([]);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /No dangerous methods found/);
});

test('buildHttpMethodCheck returns PASS when allowedMethods is null (no Allow header)', () => {
  const result = buildHttpMethodCheck(null);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /No Allow header/);
  assert.equal(result.remediation, 'No action required.');
});

test('buildHttpMethodCheck returns PASS when probe throws a network error', () => {
  const result = buildHttpMethodCheck(null, 'Connection refused');
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /Connection refused/);
  assert.equal(result.remediation, 'No action required.');
});

// ---------------------------------------------------------------------------
// buildHttpMethodCheck — WARN cases (dangerous methods present)
// ---------------------------------------------------------------------------

test('buildHttpMethodCheck returns WARN when TRACE is in allowed methods', () => {
  const result = buildHttpMethodCheck(['GET', 'POST', 'TRACE', 'OPTIONS']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /TRACE/);
  assert.match(result.remediation, /TRACE/);
});

test('buildHttpMethodCheck returns WARN when PUT is in allowed methods', () => {
  const result = buildHttpMethodCheck(['GET', 'PUT', 'OPTIONS']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /PUT/);
});

test('buildHttpMethodCheck returns WARN when DELETE is in allowed methods', () => {
  const result = buildHttpMethodCheck(['GET', 'DELETE']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /DELETE/);
});

test('buildHttpMethodCheck returns WARN when PATCH is in allowed methods', () => {
  const result = buildHttpMethodCheck(['GET', 'POST', 'PATCH']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /PATCH/);
});

test('buildHttpMethodCheck returns WARN when WebDAV methods are present', () => {
  const result = buildHttpMethodCheck(['GET', 'HEAD', 'PROPFIND', 'MKCOL', 'LOCK']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /PROPFIND/);
  assert.match(result.evidence, /MKCOL/);
  assert.match(result.evidence, /LOCK/);
});

test('buildHttpMethodCheck evidence lists all found dangerous methods', () => {
  const result = buildHttpMethodCheck(['GET', 'PUT', 'DELETE', 'TRACE']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /PUT/);
  assert.match(result.evidence, /DELETE/);
  assert.match(result.evidence, /TRACE/);
});

test('buildHttpMethodCheck remediation mentions all found dangerous methods', () => {
  const result = buildHttpMethodCheck(['TRACE', 'PUT']);
  assert.match(result.remediation, /TRACE/);
  assert.match(result.remediation, /PUT/);
});

// ---------------------------------------------------------------------------
// buildHttpMethodCheck — method matching is case-insensitive
// ---------------------------------------------------------------------------

test('buildHttpMethodCheck matches dangerous methods case-insensitively', () => {
  const result = buildHttpMethodCheck(['get', 'trace', 'put']);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /TRACE/);
  assert.match(result.evidence, /PUT/);
});

// ---------------------------------------------------------------------------
// Per-method smoke test: every dangerous method triggers WARN when present alone
// ---------------------------------------------------------------------------

for (const method of DANGEROUS_HTTP_METHODS) {
  test(`WARN when ${method} is the only advertised dangerous method`, () => {
    const result = buildHttpMethodCheck(['GET', 'HEAD', method]);
    assert.equal(result.status, 'WARN', `Expected WARN for method ${method}`);
    assert.match(result.evidence, new RegExp(method));
  });
}

// ---------------------------------------------------------------------------
// compareVersions utility
// ---------------------------------------------------------------------------

test('compareVersions returns 0 for equal versions', () => {
  assert.equal(compareVersions('2.4.62', '2.4.62'), 0);
});

test('compareVersions returns -1 when first version is lower', () => {
  assert.equal(compareVersions('2.4.61', '2.4.62'), -1);
  assert.equal(compareVersions('1.26.1', '1.26.2'), -1);
  assert.equal(compareVersions('9.0', '10.0'), -1);
});

test('compareVersions returns 1 when first version is higher', () => {
  assert.equal(compareVersions('2.4.63', '2.4.62'), 1);
  assert.equal(compareVersions('2.5.0', '2.4.62'), 1);
});

test('compareVersions handles missing patch segment (treats as 0)', () => {
  assert.equal(compareVersions('2.4', '2.4.0'), 0);
  assert.equal(compareVersions('10', '10.0'), 0);
  assert.equal(compareVersions('9', '10.0'), -1);
});

// ---------------------------------------------------------------------------
// Shared web server list fixture used across banner tests
// ---------------------------------------------------------------------------

const webServers = [
  {
    name: 'Apache',
    pattern: '^Apache(?:\\/(\\d+(?:\\.\\d+)*))?( .*)?$',
    minimumSecureVersion: '2.4.62',
    notes: 'Update Apache.',
  },
  {
    name: 'nginx',
    pattern: '^nginx(?:\\/(\\d+(?:\\.\\d+)*))?$',
    minimumSecureVersion: '1.26.2',
    notes: 'Update nginx.',
  },
  {
    name: 'Microsoft-IIS',
    pattern: '^Microsoft-IIS(?:\\/(\\d+(?:\\.\\d+)*))?$',
    minimumSecureVersion: '10.0',
    notes: 'Update IIS.',
  },
];

// ---------------------------------------------------------------------------
// buildServerBannerCheck — PASS (no Server header)
// ---------------------------------------------------------------------------

test('buildServerBannerCheck returns PASS when Server header is absent (null)', () => {
  const result = buildServerBannerCheck(null, webServers);
  assert.equal(result.status, 'PASS');
  assert.match(result.evidence, /No Server header/);
  assert.equal(result.remediation, 'No action required.');
});

test('buildServerBannerCheck returns PASS when Server header is empty string', () => {
  const result = buildServerBannerCheck('', webServers);
  assert.equal(result.status, 'PASS');
});

test('buildServerBannerCheck returns PASS when Server header is whitespace only', () => {
  const result = buildServerBannerCheck('   ', webServers);
  assert.equal(result.status, 'PASS');
});

// ---------------------------------------------------------------------------
// buildServerBannerCheck — WARN (name only, no version)
// ---------------------------------------------------------------------------

test('buildServerBannerCheck returns WARN when Apache banner has no version', () => {
  const result = buildServerBannerCheck('Apache', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /Apache/);
  assert.match(result.evidence, /no version/);
});

test('buildServerBannerCheck returns WARN when nginx banner has no version', () => {
  const result = buildServerBannerCheck('nginx', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /nginx/);
});

test('buildServerBannerCheck returns WARN when Microsoft-IIS banner has no version', () => {
  const result = buildServerBannerCheck('Microsoft-IIS', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /Microsoft-IIS/);
});

test('buildServerBannerCheck returns WARN for unrecognised server software', () => {
  const result = buildServerBannerCheck('Caddy/2.8.4', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /Caddy/);
  assert.match(result.evidence, /No known-version baseline/);
});

// ---------------------------------------------------------------------------
// buildServerBannerCheck — WARN (version present and meets minimum)
// ---------------------------------------------------------------------------

test('buildServerBannerCheck returns WARN when Apache version equals minimum secure version', () => {
  const result = buildServerBannerCheck('Apache/2.4.62', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /2\.4\.62/);
  assert.match(result.evidence, /meets the minimum secure threshold/);
});

test('buildServerBannerCheck returns WARN when Apache version exceeds minimum secure version', () => {
  const result = buildServerBannerCheck('Apache/2.4.63', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /2\.4\.63/);
  assert.match(result.evidence, /meets the minimum secure threshold/);
});

test('buildServerBannerCheck returns WARN when nginx version meets minimum', () => {
  const result = buildServerBannerCheck('nginx/1.26.2', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /meets the minimum secure threshold/);
});

test('buildServerBannerCheck returns WARN when IIS version meets minimum (10.0)', () => {
  const result = buildServerBannerCheck('Microsoft-IIS/10.0', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /meets the minimum secure threshold/);
});

// ---------------------------------------------------------------------------
// buildServerBannerCheck — FAIL (version present and below minimum)
// ---------------------------------------------------------------------------

test('buildServerBannerCheck returns FAIL when Apache version is below minimum', () => {
  const result = buildServerBannerCheck('Apache/2.4.61', webServers);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /2\.4\.61/);
  assert.match(result.evidence, /below the minimum secure version/);
  assert.match(result.evidence, /2\.4\.62/);
  assert.match(result.remediation, /Apache/);
  assert.match(result.remediation, /2\.4\.62/);
});

test('buildServerBannerCheck returns FAIL when nginx version is below minimum', () => {
  const result = buildServerBannerCheck('nginx/1.26.1', webServers);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /1\.26\.1/);
  assert.match(result.evidence, /below the minimum secure version/);
  assert.match(result.remediation, /1\.26\.2/);
});

test('buildServerBannerCheck returns FAIL when IIS version is below minimum (8.5)', () => {
  const result = buildServerBannerCheck('Microsoft-IIS/8.5', webServers);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /8\.5/);
  assert.match(result.evidence, /below the minimum secure version/);
  assert.match(result.evidence, /10\.0/);
});

test('buildServerBannerCheck FAIL remediation includes notes from web server entry', () => {
  const result = buildServerBannerCheck('Apache/2.4.1', webServers);
  assert.equal(result.status, 'FAIL');
  assert.match(result.remediation, /Update Apache/);
});

// ---------------------------------------------------------------------------
// buildServerBannerCheck — matching is case-insensitive
// ---------------------------------------------------------------------------

test('buildServerBannerCheck matches Apache banner case-insensitively', () => {
  const result = buildServerBannerCheck('apache/2.4.61', webServers);
  assert.equal(result.status, 'FAIL');
});

test('buildServerBannerCheck matches nginx banner case-insensitively', () => {
  const result = buildServerBannerCheck('NGINX/1.26.1', webServers);
  assert.equal(result.status, 'FAIL');
});

// ---------------------------------------------------------------------------
// buildServerBannerCheck — Apache with extra tokens (e.g. OS, modules)
// ---------------------------------------------------------------------------

test('buildServerBannerCheck handles Apache banner with extra OS suffix', () => {
  // e.g. "Apache/2.4.61 (Ubuntu)" — version still below minimum → FAIL
  const result = buildServerBannerCheck('Apache/2.4.61 (Ubuntu)', webServers);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /2\.4\.61/);
});

test('buildServerBannerCheck handles Apache banner with version at minimum + OS suffix', () => {
  const result = buildServerBannerCheck('Apache/2.4.62 (Debian)', webServers);
  assert.equal(result.status, 'WARN');
  assert.match(result.evidence, /meets the minimum secure threshold/);
});
