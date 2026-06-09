import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMarkdownReport } from '../dist/reporting/markdown.js';

function buildBaseResult() {
  const now = new Date('2026-03-12T09:00:00.000Z');
  return {
    targetUrl: 'https://example.com',
    startedAt: now,
    finishedAt: new Date(now.getTime() + 5000),
    durationMs: 5000,
    webServer: 'Unknown',
    certificate: {
      trustValid: true,
      hostnameMatches: true,
    },
    negotiatedProtocol: 'TLSv1_2',
    negotiatedProtocolStatus: 'validated',
    negotiatedCipher: 'TLS_AES_128_GCM_SHA256',
    negotiatedCipherStatus: 'Y',
    protocolResults: [],
    cipherResults: [],
    infrastructureChecks: [],
    portResults: [],
    vulnerabilityResults: [],
    clientSimulations: [],
    icmpCheck: { reachable: false, status: 'PASS', evidence: 'No ICMP response' },
    globalStatus: 'PASS',
    exitCode: 0,
  };
}

test('buildMarkdownReport colors validated but unsupported items in orange', () => {
  const result = buildBaseResult();
  result.protocolResults = [
    {
      name: 'TLSv1_3',
      policy: 'validated',
      supported: false,
      success: false,
      evidence: 'Handshake rejected',
    },
  ];

  const report = buildMarkdownReport(result);
  assert.match(report, /<span style="color: orange;">TLSv1_3 \[validated\] → not supported \(Handshake rejected\)<\/span>/);
});

test('buildMarkdownReport colors deprecated but supported items in red', () => {
  const result = buildBaseResult();
  result.cipherResults = [
    {
      name: 'TLS_RSA_WITH_RC4_128_SHA',
      policy: 'deprecated',
      supported: true,
      success: false,
      evidence: 'Handshake accepted',
    },
  ];

  const report = buildMarkdownReport(result);
  assert.match(report, /<span style="color: red;">TLS_RSA_WITH_RC4_128_SHA \[deprecated\] → supported \(Handshake accepted\)<\/span>/);
});

test('buildMarkdownReport keeps successful policy checks in green', () => {
  const result = buildBaseResult();
  result.protocolResults = [
    {
      name: 'TLSv1_2',
      policy: 'validated',
      supported: true,
      success: true,
      evidence: 'Handshake accepted',
    },
  ];

  const report = buildMarkdownReport(result);
  assert.match(report, /- <span style="color: green;">TLSv1_2 \[validated\] → supported \(Handshake accepted\)<\/span>/);
});
