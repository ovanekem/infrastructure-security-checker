import test from 'node:test';
import assert from 'node:assert/strict';
import { printConsoleReport } from '../dist/reporting/console.js';

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

function captureConsoleOutput(run) {
  const lines = [];
  const originalLog = console.log;
  console.log = (...args) => {
    lines.push(args.join(' '));
  };

  try {
    run();
  } finally {
    console.log = originalLog;
  }

  return lines.join('\n');
}

test('printConsoleReport renders policy colors and signs for protocol/cipher mismatches', () => {
  const result = buildBaseResult();
  result.protocolResults = [
    {
      name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      policy: 'validated',
      supported: false,
      success: false,
      evidence: 'Handshake rejected',
    },
  ];
  result.cipherResults = [
    {
      name: 'TLS_RSA_WITH_RC4_128_SHA',
      policy: 'deprecated',
      supported: true,
      success: false,
      evidence: 'Handshake accepted',
    },
    {
      name: 'TLSv1_2',
      policy: 'validated',
      supported: true,
      success: true,
      evidence: 'Handshake accepted',
    },
  ];

  const output = captureConsoleOutput(() => printConsoleReport(result));

  assert.match(output, /- \u001b\[38;5;208m⚠️ TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 \[validated\] => not supported; success=false\u001b\[0m/);
  assert.match(output, /- \u001b\[31m❌ TLS_RSA_WITH_RC4_128_SHA \[deprecated\] => supported; success=false\u001b\[0m/);
  assert.match(output, /- \u001b\[32m✅ TLSv1_2 \[validated\] => supported; success=true\u001b\[0m/);
});