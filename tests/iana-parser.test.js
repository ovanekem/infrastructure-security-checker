import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCipherRegistryXml } from '../dist/iana/update-ciphers-list.js';

test('parseCipherRegistryXml extracts tls-parameters-4 records and filters invalid ones', () => {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<registry id="root">
  <registry id="tls-parameters-4">
    <record>
      <value>0x00,0x2F</value>
      <description>TLS_RSA_WITH_AES_128_CBC_SHA</description>
      <rec>D</rec>
    </record>
    <record>
      <value>0x13,0x01</value>
      <description>TLS_AES_128_GCM_SHA256</description>
      <rec>Y</rec>
    </record>
    <record>
      <value>0x00,0x00</value>
      <description>Unassigned</description>
      <rec>Y</rec>
    </record>
    <record>
      <value>0x00,0x01</value>
      <description>TLS_FAKE_WITH_NO_REC</description>
    </record>
  </registry>
</registry>`;

  const parsed = parseCipherRegistryXml(xml);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].name, 'TLS_RSA_WITH_AES_128_CBC_SHA');
  assert.equal(parsed[1].recommended, 'Y');
});
