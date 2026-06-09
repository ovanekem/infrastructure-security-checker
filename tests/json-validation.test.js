import test from 'node:test';
import assert from 'node:assert/strict';
import { validatePortsFile, validateProtocolsFile } from '../dist/utils/json.js';

test('validateProtocolsFile accepts expected statuses', () => {
  const parsed = validateProtocolsFile({
    protocols: [
      { name: 'TLSv1_2', status: 'validated' },
      { name: 'TLSv1_1', status: 'deprecated' },
    ],
  });
  assert.equal(parsed.protocols.length, 2);
});

test('validatePortsFile rejects duplicate ports', () => {
  assert.throws(() => validatePortsFile({
    ports: [
      { port: 443, service: 'HTTPS', protocol: 'https' },
      { port: 443, service: 'HTTPS-alt', protocol: 'https' },
    ],
  }));
});
