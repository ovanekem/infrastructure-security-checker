import test from 'node:test';
import assert from 'node:assert/strict';
import { computeGlobalStatus, policyCheckSeverity } from '../dist/checks/website-analysis.js';

test('global status is WARN when only warning-level policy mismatches exist', () => {
  const warningPolicySeverity = policyCheckSeverity({
    name: 'TLSv1_3',
    policy: 'validated',
    supported: false,
    success: false,
    evidence: 'Handshake rejected',
  });

  const result = computeGlobalStatus(['PASS', warningPolicySeverity, 'PASS']);

  assert.equal(result.globalStatus, 'WARN');
  assert.equal(result.exitCode, 1);
});

test('global status is FAIL when at least one fail-level policy mismatch exists', () => {
  const failPolicySeverity = policyCheckSeverity({
    name: 'SSLv3',
    policy: 'deprecated',
    supported: true,
    success: false,
    evidence: 'Handshake accepted',
  });

  const result = computeGlobalStatus(['WARN', failPolicySeverity, 'PASS']);

  assert.equal(result.globalStatus, 'FAIL');
  assert.equal(result.exitCode, 2);
});