import * as net from 'node:net';
import * as tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import type { PolicyCheckResult, VulnerabilityResult } from '../types/index.js';
import { runOpenSsl } from './openssl.js';

function hasSupported(results: PolicyCheckResult[], matcher: (name: string) => boolean): boolean {
  return results.some((r) => r.supported === true && matcher(r.name));
}

function getProtocolSupport(results: PolicyCheckResult[], protocolName: string): boolean {
  return results.some((r) => r.name === protocolName && r.supported === true);
}

// ---------------------------------------------------------------------------
// Low-level TCP helpers
// ---------------------------------------------------------------------------

function connectTcp(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => { sock.setTimeout(0); resolve(sock); });
    sock.once('timeout', () => { sock.destroy(); reject(new Error('TCP connect timeout')); });
    sock.once('error', reject);
  });
}

function readBytes(sock: net.Socket, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      sock.off('data', onData);
      sock.off('error', onError);
      resolve(Buffer.concat(chunks));
    }, timeoutMs);
    function onData(chunk: Buffer) {
      chunks.push(chunk);
      clearTimeout(timer);
      setTimeout(() => {
        sock.off('data', onData);
        sock.off('error', onError);
        resolve(Buffer.concat(chunks));
      }, 200);
    }
    function onError(err: Error) {
      clearTimeout(timer);
      sock.off('data', onData);
      reject(err);
    }
    sock.on('data', onData);
    sock.once('error', onError);
  });
}

// ---------------------------------------------------------------------------
// TLS record / handshake building blocks
// ---------------------------------------------------------------------------

/** Build a TLS ClientHello record selecting a specific protocol version and cipher list. */
function buildClientHello(recordVersion: [number, number], helloVersion: [number, number], ciphers: number[]): Buffer {
  // Random: 32 bytes (4 bytes gmt_unix_time + 28 random)
  const random = Buffer.alloc(32, 0xab);
  random.writeUInt32BE(Math.floor(Date.now() / 1000), 0);

  const cipherSuitesLen = ciphers.length * 2;
  const cipherBuf = Buffer.alloc(cipherSuitesLen);
  ciphers.forEach((c, i) => cipherBuf.writeUInt16BE(c, i * 2));

  // Extensions: SNI not included to keep it minimal, just renegotiation_info
  const riExt = Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]); // renegotiation_info empty

  // SessionID length = 0, compression = [1 byte: 0x00 (null)]
  const body = Buffer.concat([
    Buffer.from([helloVersion[0], helloVersion[1]]),
    random,
    Buffer.from([0x00]),                     // session id length = 0
    Buffer.from([(cipherSuitesLen >> 8) & 0xff, cipherSuitesLen & 0xff]),
    cipherBuf,
    Buffer.from([0x01, 0x00]),               // compression methods length=1, null
    Buffer.from([(riExt.length >> 8) & 0xff, riExt.length & 0xff]),
    riExt,
  ]);

  const handshake = Buffer.concat([
    Buffer.from([0x01]),                     // HandshakeType: client_hello
    Buffer.from([0x00, (body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);

  const record = Buffer.concat([
    Buffer.from([0x16, recordVersion[0], recordVersion[1]]),
    Buffer.from([(handshake.length >> 8) & 0xff, handshake.length & 0xff]),
    handshake,
  ]);

  return record;
}

/** Build a TLS ClientHello that includes TLS_FALLBACK_SCSV (0x5600) in the cipher list. */
function buildClientHelloWithFallbackScsv(
  recordVersion: [number, number],
  helloVersion: [number, number],
  ciphers: number[],
): Buffer {
  return buildClientHello(recordVersion, helloVersion, [...ciphers, 0x5600]);
}

/** Parse the first TLS alert from a buffer and return the alert description byte (or null). */
function parseTlsAlert(buf: Buffer): { level: number; description: number } | null {
  if (buf.length < 7) return null;
  if (buf[0] !== 0x15) return null; // alert record type
  return { level: buf[5], description: buf[6] };
}

/** Returns true if the buffer contains a TLS ServerHello (handshake type 0x02). */
function hasServerHello(buf: Buffer): boolean {
  if (buf.length < 6) return false;
  return buf[0] === 0x16 && buf[5] === 0x02;
}

// ---------------------------------------------------------------------------
// Individual probe functions
// ---------------------------------------------------------------------------

/** POODLE (TLS): Send a TLS record with bad CBC padding; if server responds with a decryption alert
 *  rather than a generic handshake_failure it may indicate a CBC padding oracle. */
async function probePoodleTls(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'POODLE (TLS) (CVE-2014-8730)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // Minimal TLS 1.2 ClientHello with only CBC suites
    const cbcCiphers = [
      0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
      0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
      0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
      0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
    ];
    const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], cbcCiphers);
    sock.write(hello);
    const response = await readBytes(sock, 4_000);

    if (hasServerHello(response)) {
      // Server accepted CBC ClientHello — now send a malformed finished record.
      // A 1-byte application_data record with bad padding is the POODLE TLS canary.
      // Record: type=0x17 (app data), version=3,3, length=1, payload=0x00 (invalid CBC padding)
      const badPad = Buffer.from([0x17, 0x03, 0x03, 0x00, 0x01, 0x00]);
      sock.write(badPad);
      const alertBuf = await readBytes(sock, 3_000);
      const alert = parseTlsAlert(alertBuf);
      // Alert 0x14 = bad_record_mac, 0x28 = handshake_failure, 0x32 = decrypt_error
      if (alert) {
        if (alert.description === 0x14 || alert.description === 0x32) {
          return {
            name, status: 'WARN',
            evidence: `Server sent TLS alert ${alert.description} on malformed CBC record — inconclusive oracle signal; dedicated tooling required.`,
            remediation: 'Run a dedicated exploit-grade scanner (testssl.sh) to confirm POODLE (TLS) oracle behavior.',
          };
        }
        return {
          name, status: 'PASS',
          evidence: `Server rejected malformed CBC padding with alert ${alert.description} (handshake_failure class).`,
          remediation: 'No action required.',
        };
      }
      return {
        name, status: 'WARN',
        evidence: 'Server accepted CBC ClientHello but no alert received after malformed padding — inconclusive.',
        remediation: 'Run a dedicated exploit-grade scanner to confirm this finding.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'Server rejected CBC-only ClientHello — no CBC negotiation possible.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm this finding.',
    };
  } finally {
    sock?.destroy();
  }
}


/** Downgrade attack prevention: attempt a TLS 1.1 ClientHello with TLS_FALLBACK_SCSV.
 *  A properly configured server must respond with an inappropriate_fallback alert (0x56). */
async function probeDowngrade(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'Downgrade attack prevention (CVE-2014-3566/TLS_FALLBACK_SCSV)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);
    // TLS 1.1 hello + FALLBACK_SCSV — server supporting >= 1.2 must reject with alert 86 (0x56)
    const hello = buildClientHelloWithFallbackScsv(
      [0x03, 0x02], [0x03, 0x02],
      [0x002f, 0x0035, 0x000a],
    );
    sock.write(hello);
    const response = await readBytes(sock, 4_000);
    const alert = parseTlsAlert(response);

    if (alert && alert.description === 0x56) {
      return {
        name, status: 'PASS',
        evidence: 'Server sent inappropriate_fallback alert (0x56) — TLS_FALLBACK_SCSV is enforced.',
        remediation: 'No action required.',
      };
    }
    if (hasServerHello(response)) {
      return {
        name, status: 'FAIL',
        evidence: 'Server accepted a downgraded TLS 1.1 ClientHello with TLS_FALLBACK_SCSV — fallback signaling is not enforced.',
        remediation: 'Enable TLS_FALLBACK_SCSV signaling and configure TLS 1.3 downgrade sentinels on the server.',
      };
    }
    if (alert) {
      // Any other alert (e.g. handshake_failure=40) still means server rejected — treat as PASS
      return {
        name, status: 'PASS',
        evidence: `Server rejected downgraded ClientHello with alert description ${alert.description}.`,
        remediation: 'No action required.',
      };
    }
    return {
      name, status: 'WARN',
      evidence: 'Could not fully assert fallback signaling (TLS_FALLBACK_SCSV) — no clear alert or ServerHello received.',
      remediation: 'Ensure TLS_FALLBACK_SCSV and TLS 1.3 downgrade sentinels are enabled.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Probe could not complete due to a network/connection error.',
      remediation: 'Ensure TLS_FALLBACK_SCSV and TLS 1.3 downgrade sentinels are enabled.',
    };
  } finally {
    sock?.destroy();
  }
}

/** SSL/TLS compression: use openssl s_client and inspect the Compression field. */
async function evaluateCompression(host: string, port: number, servername: string): Promise<VulnerabilityResult> {
  const result = await runOpenSsl(['s_client', '-connect', `${host}:${port}`, '-servername', servername, '-brief'], 6_000);
  if (!result.ok) {
    return {
      name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
      status: 'WARN',
      evidence: `Unable to determine compression method: ${result.error || 'OpenSSL probe failed'}`,
      remediation: 'Retry from a stable network path and validate with an external TLS scanner.',
    };
  }

  if (/compression\s*:\s*none/i.test(result.output)) {
    return {
      name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
      status: 'PASS',
      evidence: 'Compression is disabled (Compression: NONE).',
      remediation: 'No action required.',
    };
  }

  if (/compression\s*:\s*(?!none)\S/i.test(result.output)) {
    return {
      name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
      status: 'FAIL',
      evidence: 'Compression appears enabled in TLS handshake output.',
      remediation: 'Disable TLS-level compression to mitigate CRIME-style risks.',
    };
  }

  // OpenSSL -brief may suppress the Compression line; retry with -state for confirmation
  const detailed = await runOpenSsl(
    ['s_client', '-connect', `${host}:${port}`, '-servername', servername, '-state', '-msg'],
    8_000,
  );
  if (detailed.ok) {
    if (/Compression: NONE/i.test(detailed.output)) {
      return {
        name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
        status: 'PASS',
        evidence: 'Compression is disabled (confirmed via -state output).',
        remediation: 'No action required.',
      };
    }
    if (/Compression:/i.test(detailed.output)) {
      const match = detailed.output.match(/Compression:\s*(\S+)/i);
      return {
        name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
        status: 'FAIL',
        evidence: `Compression method detected: ${match?.[1] ?? 'non-null'}.`,
        remediation: 'Disable TLS-level compression to mitigate CRIME-style risks.',
      };
    }
  }

  return {
    name: 'SSL/TLS compression / CRIME (CVE-2012-4929)',
    status: 'WARN',
    evidence: 'Compression method was not explicitly reported by OpenSSL output.',
    remediation: 'Verify compression status with a dedicated scanner that exposes this handshake field.',
  };
}

/** Heartbleed: send a TLS 1.2 ClientHello followed by a malformed Heartbeat request (RFC 6520).
 *  A vulnerable server echoes back more bytes than requested. */
async function probeHeartbleed(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'Heartbleed (CVE-2014-0160)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // ClientHello with heartbeat extension (type 0x000f) and all common ciphers
    const hbExt = Buffer.from([
      0x00, 0x0f, // extension type: heartbeat
      0x00, 0x01, // length 1
      0x01,       // peer_allowed_to_send
    ]);
    const ciphers = [0x002f, 0x0035, 0xc013, 0xc014, 0x000a];
    const cipherSuitesLen = ciphers.length * 2;
    const cipherBuf = Buffer.alloc(cipherSuitesLen);
    ciphers.forEach((c, i) => cipherBuf.writeUInt16BE(c, i * 2));
    const random = Buffer.alloc(32, 0xab);
    random.writeUInt32BE(Math.floor(Date.now() / 1000), 0);

    const extLen = hbExt.length;
    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      random,
      Buffer.from([0x00]),
      Buffer.from([(cipherSuitesLen >> 8) & 0xff, cipherSuitesLen & 0xff]),
      cipherBuf,
      Buffer.from([0x01, 0x00]),
      Buffer.from([(extLen >> 8) & 0xff, extLen & 0xff]),
      hbExt,
    ]);

    const handshake = Buffer.concat([
      Buffer.from([0x01, 0x00, (body.length >> 8) & 0xff, body.length & 0xff]),
      body,
    ]);
    const record = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x03]),
      Buffer.from([(handshake.length >> 8) & 0xff, handshake.length & 0xff]),
      handshake,
    ]);

    sock.write(record);
    const serverResponse = await readBytes(sock, 4_000);

    // Check if server sent ServerHello (accepted handshake)
    if (!hasServerHello(serverResponse)) {
      return {
        name, status: 'PASS',
        evidence: 'Server did not complete handshake — Heartbeat extension not supported or rejected.',
        remediation: 'No action required.',
      };
    }

    // Send malformed heartbeat: request_length (0xffff) >> actual_payload (1 byte "A")
    // type=0x18 (heartbeat), version=3,3, record_length=8:
    //   [heartbeat_type=1 (request), payload_length=0x4000, payload=0x41, padding=3 bytes]
    const hbRequest = Buffer.from([
      0x18, 0x03, 0x03, 0x00, 0x08,  // TLS record header
      0x01,                            // heartbeat type: request
      0x40, 0x00,                      // payload_length = 16384 (far more than actual)
      0x41,                            // single byte payload
      0x00, 0x00, 0x00,               // padding (minimum 16 bytes in spec but this tests lax impl)
    ]);
    sock.write(hbRequest);
    const hbResponse = await readBytes(sock, 4_000);

    // type 0x18 = heartbeat, type 0x15 = alert
    if (hbResponse.length > 0 && hbResponse[0] === 0x18) {
      // Received a heartbeat response — check if length is larger than we sent
      if (hbResponse.length > 10) {
        return {
          name, status: 'FAIL',
          evidence: `Server returned a heartbeat response (${hbResponse.length} bytes) to an over-length heartbeat request — Heartbleed exposure detected.`,
          remediation: 'Upgrade OpenSSL to 1.0.1g or later and patch immediately.',
        };
      }
      return {
        name, status: 'WARN',
        evidence: 'Server returned a heartbeat response but payload size was not conclusive.',
        remediation: 'Run a dedicated exploit-grade scanner (testssl.sh --heartbleed) to confirm.',
      };
    }
    if (hbResponse.length > 0 && hbResponse[0] === 0x15) {
      return {
        name, status: 'PASS',
        evidence: 'Server sent an alert in response to malformed heartbeat — not vulnerable.',
        remediation: 'No action required.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'No heartbeat response received — heartbeat extension not active or rejected.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Heartbleed probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm this finding.',
    };
  } finally {
    sock?.destroy();
  }
}

/** Ticketbleed: issue a TLS ClientHello with a non-zero SessionID and a session ticket extension.
 *  A vulnerable F5 server copies beyond the session ID boundary, leaking memory bytes.
 *
 *  Detection logic (aligned with testssl.sh):
 *  1. Send a ClientHello with a 1-byte session ID (canary byte 0x42) and an empty session_ticket extension.
 *  2. Parse the ServerHello at the correct fixed offset to extract the echoed session_id_length and session_id.
 *  3. A non-vulnerable server either:
 *     a. generates its own unrelated 32-byte session ID (first byte != 0x42), OR
 *     b. echoes back exactly a 1-byte session ID matching our canary, OR
 *     c. returns an empty (0-byte) session ID.
 *  4. A vulnerable F5 server echoes a session ID where:
 *     - the first byte matches our canary (0x42), AND
 *     - the length is > 1 (typically 32 bytes, padded with leaked memory).
 *  Only condition (4) is flagged as FAIL.
 */
async function probeTicketbleed(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'Ticketbleed (CVE-2016-9244)';
  const CANARY = 0x42;
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // Session ticket extension (empty)
    const ticketExt = Buffer.from([0x00, 0x23, 0x00, 0x00]);
    const ciphers = [0xc02b, 0xc02c, 0x002f, 0x0035];
    const cipherSuitesLen = ciphers.length * 2;
    const cipherBuf = Buffer.alloc(cipherSuitesLen);
    ciphers.forEach((c, i) => cipherBuf.writeUInt16BE(c, i * 2));
    const random = Buffer.alloc(32, 0xcd);
    // Use a 1-byte session ID with canary value
    const sessionId = Buffer.from([0x01, CANARY]);

    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),   // TLS 1.2
      random,
      sessionId,
      Buffer.from([(cipherSuitesLen >> 8) & 0xff, cipherSuitesLen & 0xff]),
      cipherBuf,
      Buffer.from([0x01, 0x00]),   // compression: null
      Buffer.from([0x00, ticketExt.length]),
      ticketExt,
    ]);

    const handshake = Buffer.concat([
      Buffer.from([0x01, 0x00, (body.length >> 8) & 0xff, body.length & 0xff]),
      body,
    ]);
    const record = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01]),
      Buffer.from([(handshake.length >> 8) & 0xff, handshake.length & 0xff]),
      handshake,
    ]);

    sock.write(record);
    const response = await readBytes(sock, 4_000);

    if (!hasServerHello(response)) {
      return {
        name, status: 'PASS',
        evidence: 'Server did not complete handshake — session ticket extension not supported or rejected.',
        remediation: 'No action required.',
      };
    }

    // Parse ServerHello at fixed offsets:
    // [0..4]   TLS record header (5 bytes: type, version_major, version_minor, length_hi, length_lo)
    // [5]      Handshake type (should be 0x02 = ServerHello)
    // [6..8]   Handshake length (3 bytes)
    // [9..10]  Server version (2 bytes)
    // [11..42] Server random (32 bytes)
    // [43]     session_id_length
    // [44..]   session_id bytes
    if (response.length < 44 || response[5] !== 0x02) {
      return {
        name, status: 'WARN',
        evidence: 'Could not parse ServerHello at expected offset — response may be fragmented.',
        remediation: 'Run testssl.sh --ticketbleed to confirm.',
      };
    }

    const sessionIdLen = response[43];
    if (sessionIdLen === 0) {
      return {
        name, status: 'PASS',
        evidence: 'Server returned an empty session ID — Ticketbleed not applicable.',
        remediation: 'No action required.',
      };
    }

    if (sessionIdLen <= 1) {
      return {
        name, status: 'PASS',
        evidence: `Server echoed a ${sessionIdLen}-byte session ID — matches request length, not vulnerable.`,
        remediation: 'No action required.',
      };
    }

    // Session ID is > 1 byte. Check if the first byte matches our canary.
    // A normal server generates its own session ID unrelated to the client's.
    // A vulnerable F5 copies the client's 1-byte ID and pads it with leaked memory.
    if (response.length > 44 && response[44] === CANARY) {
      return {
        name, status: 'FAIL',
        evidence: `Server echoed a ${sessionIdLen}-byte session ID starting with our 1-byte canary (0x${CANARY.toString(16)}) — Ticketbleed memory leak confirmed (CVE-2016-9244).`,
        remediation: 'Apply vendor patch for CVE-2016-9244 (F5 BIG-IP). Disable session tickets if patching is not immediately possible.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: `Server returned a ${sessionIdLen}-byte session ID but first byte (0x${response[44]?.toString(16) ?? '??'}) does not match canary (0x${CANARY.toString(16)}) — server generated its own session ID, not vulnerable.`,
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Ticketbleed probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm this finding.',
    };
  } finally {
    sock?.destroy();
  }
}

/** OpenSSL CCS injection (CVE-2014-0224): send an out-of-order ChangeCipherSpec before the
 *  handshake is complete and check whether the server accepts the invalid state transition. */
async function probeCcsInjection(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'OpenSSL CCS vuln. (CVE-2014-0224)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], [0x002f, 0x0035, 0xc013, 0x000a]);
    sock.write(hello);
    const serverResponse = await readBytes(sock, 4_000);

    if (!hasServerHello(serverResponse)) {
      return {
        name, status: 'PASS',
        evidence: 'Server did not complete ClientHello exchange — CCS injection precondition not met.',
        remediation: 'No action required.',
      };
    }

    // Send a premature ChangeCipherSpec record (type 0x14) before Finished
    const ccs = Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    sock.write(ccs);
    const response = await readBytes(sock, 3_000);
    const alert = parseTlsAlert(response);

    if (alert) {
      // Any alert means server rejected the premature CCS
      return {
        name, status: 'PASS',
        evidence: `Server rejected premature ChangeCipherSpec with alert description ${alert.description}.`,
        remediation: 'No action required.',
      };
    }

    if (response.length === 0) {
      return {
        name, status: 'WARN',
        evidence: 'Server closed connection silently after premature CCS — inconclusive without full multi-message oracle.',
        remediation: 'Run a dedicated exploit-grade scanner (testssl.sh --ccs) to confirm CVE-2014-0224.',
      };
    }

    return {
      name, status: 'FAIL',
      evidence: 'Server responded to premature ChangeCipherSpec without sending an alert — possible CCS injection acceptance.',
      remediation: 'Upgrade OpenSSL to 1.0.1h / 1.0.0m / 0.9.8za or later to fix CVE-2014-0224.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'CCS injection probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm CVE-2014-0224.',
    };
  } finally {
    sock?.destroy();
  }
}

/** ROBOT (CVE-2017-13099 et al.): perform two RSA-PKCS#1 v1.5 key-exchange probes with plaintext
 *  substitution and compare alert responses.  A strong oracle produces different alerts for
 *  structurally-valid vs structurally-invalid PKCS#1 messages. */
async function probeRobot(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'ROBOT (CVE-2017-13099)';

  async function sendRsaHello(alterPayload: boolean): Promise<{ alert: { level: number; description: number } | null; serverHello: boolean }> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);
      // ClientHello offering only RSA key exchange ciphers
      const rsaCiphers = [0x0035, 0x002f, 0x000a];
      const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], rsaCiphers);
      sock.write(hello);
      const serverResponse = await readBytes(sock, 4_000);
      if (!hasServerHello(serverResponse)) return { alert: null, serverHello: false };

      // Send a ClientKeyExchange with a syntactically invalid (if alterPayload) pre-master secret.
      // The pre-master secret here is just zeroed — for alterPayload we flip the version bytes.
      // 2-byte handshake prefix + 2-byte encrypted_premaster_secret length (256 for RSA-2048)
      const pmsLen = 256;
      const pms = Buffer.alloc(pmsLen + 4);
      pms.writeUInt8(0x10, 0);                         // HandshakeType: client_key_exchange
      pms.writeUInt16BE(0x0000, 1);                   // 3-byte length (hi 0, lo below)
      pms.writeUInt8((pmsLen + 2) & 0xff, 3);
      pms.writeUInt16BE(pmsLen, 4);                   // encrypted_premaster_secret length
      if (!alterPayload) {
        // "valid" structure: 0x00 0x02 ... 0x00 <version> (all zeros here, not truly valid but same structure)
        pms[6] = 0x00; pms[7] = 0x02;
        pms[pmsLen + 3] = 0x03; pms[pmsLen + 4] = 0x03;
      } else {
        // "invalid" structure: starts with 0x00 0x01 (wrong block type)
        pms[6] = 0x00; pms[7] = 0x01;
      }

      const record = Buffer.concat([
        Buffer.from([0x16, 0x03, 0x03]),
        Buffer.from([(pms.length >> 8) & 0xff, pms.length & 0xff]),
        pms,
      ]);
      sock.write(record);
      const alertBuf = await readBytes(sock, 3_000);
      return { alert: parseTlsAlert(alertBuf), serverHello: true };
    } catch {
      return { alert: null, serverHello: false };
    } finally {
      sock?.destroy();
    }
  }

  try {
    const [r1, r2] = await Promise.all([sendRsaHello(false), sendRsaHello(true)]);

    if (!r1.serverHello && !r2.serverHello) {
      return {
        name, status: 'PASS',
        evidence: 'Server does not support RSA key exchange ciphers — ROBOT precondition not met.',
        remediation: 'No action required.',
      };
    }

    const desc1 = r1.alert?.description ?? -1;
    const desc2 = r2.alert?.description ?? -1;

    if (desc1 !== desc2) {
      return {
        name, status: 'WARN',
        evidence: `Differential alert responses detected (probe1 alert=${desc1}, probe2 alert=${desc2}) — possible weak Bleichenbacher oracle. Dedicated RSA oracle tooling required to confirm.`,
        remediation: 'Disable RSA key exchange ciphers and switch to ECDHE. Run a dedicated ROBOT scanner to confirm.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: `Both RSA key exchange probes returned the same alert response (desc=${desc1}) — no strong oracle signal detected.`,
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'ROBOT probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm this finding.',
    };
  }
}

/** Winshock (CVE-2014-6321 / MS14-066): heap overflow in Windows Schannel ECDHE code path.
 *
 *  Detection strategy aligned with testssl.sh run_winshock():
 *
 *  Uses negative fingerprinting to rule out patched or non-Windows servers by checking
 *  for indicators that only appear on post-patch or newer Windows versions:
 *
 *  1. TLS 1.3 → not vulnerable (no Windows Schannel version with Winshock supports TLS 1.3).
 *  2. MS14-066 patch rollup GCM ciphers (0x009C–0x009F) → not vulnerable (patch applied).
 *  3. Post-2012 ciphers: ECDHE-RSA-AES*-GCM-SHA* (0xC02F, 0xC030), ARIA, CHACHA, CCM,
 *     CAMELLIA → not vulnerable (Server 2016+ or non-Windows).
 *  4. HTTP Server header: only IIS/8.0 (Server 2012) and IIS/8.5 (Server 2012 R2) are
 *     affected. Any other IIS version or non-IIS → not vulnerable.
 *  5. If all elimination checks are exhausted and the server looks like IIS 8.x without
 *     the patch ciphers → flag as vulnerable.
 */
async function probeWinshock(host: string, port: number, servername: string): Promise<VulnerabilityResult> {
  const name = 'Winshock (CVE-2014-6321)';

  /** Try connecting with a specific cipher list and return whether the server accepted. */
  async function probeAcceptsCiphers(ciphers: number[]): Promise<boolean> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);
      const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], ciphers);
      sock.write(hello);
      const response = await readBytes(sock, 4_000);
      return hasServerHello(response);
    } catch {
      return false;
    } finally {
      sock?.destroy();
    }
  }

  /** Detect IIS version from HTTP Server header. */
  async function getServerBanner(): Promise<string> {
    try {
      const httpSock = await connectTcp(host, port, 3_000);
      const tlsSock = tls.connect({ socket: httpSock, servername, rejectUnauthorized: false });
      await new Promise<void>((res, rej) => {
        tlsSock.once('secureConnect', res);
        tlsSock.once('error', rej);
        setTimeout(rej, 3_000);
      });
      tlsSock.write(`HEAD / HTTP/1.1\r\nHost: ${servername}\r\nConnection: close\r\n\r\n`);
      const httpResp = await readBytes(tlsSock as unknown as net.Socket, 3_000);
      tlsSock.destroy();
      return httpResp.toString('utf8', 0, Math.min(httpResp.length, 2048));
    } catch {
      return '';
    }
  }

  try {
    // Step 1: Check if the MS14-066 rollup GCM ciphers are present.
    // These 4 ciphers were added by the patch: DHE-RSA-AES256-GCM-SHA384, DHE-RSA-AES128-GCM-SHA256,
    // AES256-GCM-SHA384, AES128-GCM-SHA256 (codes 0x009F, 0x009E, 0x009D, 0x009C).
    const rollupCiphers = [0x009f, 0x009e, 0x009d, 0x009c];

    // Step 2: Check for ciphers that only appear on Server 2016+ or non-Windows:
    // ECDHE-RSA-AES128-GCM-SHA256 (0xC02F), ECDHE-RSA-AES256-GCM-SHA384 (0xC030)
    const postWinshockCiphers = [0xc02f, 0xc030];

    // Step 3: Check for CHACHA/CCM/ARIA/CAMELLIA (definitely post-Winshock era)
    const modernCiphers = [
      0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      0xccaa, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      0xc09c, // TLS_RSA_WITH_AES_128_CCM
      0xc09d, // TLS_RSA_WITH_AES_256_CCM
      0xc03c, // TLS_RSA_WITH_ARIA_128_CBC_SHA256
    ];

    // Run probes in parallel
    const [hasRollup, hasPostWinshock, hasModern, serverBanner] = await Promise.all([
      probeAcceptsCiphers(rollupCiphers),
      probeAcceptsCiphers(postWinshockCiphers),
      probeAcceptsCiphers(modernCiphers),
      getServerBanner(),
    ]);

    // Elimination: if any post-patch or modern ciphers are present, server is patched or not affected
    if (hasRollup) {
      return {
        name, status: 'PASS',
        evidence: 'Server accepts MS14-066 rollup GCM ciphers (0x009C–0x009F) — patch is applied, not vulnerable.',
        remediation: 'No action required.',
      };
    }

    if (hasPostWinshock) {
      return {
        name, status: 'PASS',
        evidence: 'Server accepts ECDHE-RSA-AES-GCM ciphers (0xC02F/0xC030) — Windows Server 2016+ or non-Windows, not vulnerable.',
        remediation: 'No action required.',
      };
    }

    if (hasModern) {
      return {
        name, status: 'PASS',
        evidence: 'Server accepts CHACHA/CCM/ARIA cipher suites — post-Winshock era server, not vulnerable.',
        remediation: 'No action required.',
      };
    }

    // No post-patch ciphers found — check the server banner for IIS 8.x (Windows Server 2012/2012 R2)
    const iis80Match = /server\s*:\s*Microsoft-IIS\/8\.0/i.test(serverBanner);
    const iis85Match = /server\s*:\s*Microsoft-IIS\/8\.5/i.test(serverBanner);
    const httpApiMatch = /server\s*:\s*Microsoft-HTTPAPI\/2\.0/i.test(serverBanner);
    const isAnyIIS = /server\s*:\s*Microsoft-IIS/i.test(serverBanner);

    if (iis80Match) {
      return {
        name, status: 'FAIL',
        evidence: 'Server identified as Microsoft-IIS/8.0 (Windows Server 2012) without MS14-066 rollup GCM ciphers — likely vulnerable to Winshock (CVE-2014-6321). Check patches locally to confirm.',
        remediation: 'Apply Microsoft Security Bulletin MS14-066 (KB2992611) immediately.',
      };
    }

    if (iis85Match) {
      return {
        name, status: 'FAIL',
        evidence: 'Server identified as Microsoft-IIS/8.5 (Windows Server 2012 R2) without MS14-066 rollup GCM ciphers — probably vulnerable to Winshock (CVE-2014-6321). Check patches locally to confirm.',
        remediation: 'Apply Microsoft Security Bulletin MS14-066 (KB2992611) immediately.',
      };
    }

    if (httpApiMatch) {
      return {
        name, status: 'WARN',
        evidence: 'Server identified as Microsoft-HTTPAPI/2.0 without MS14-066 rollup GCM ciphers — may indicate an unpatched Windows Server 2012/2012 R2 (IIS not yet configured). Check patches locally.',
        remediation: 'Verify Windows version and apply MS14-066 (KB2992611) if applicable.',
      };
    }

    if (isAnyIIS) {
      // IIS version other than 8.0/8.5 (e.g. IIS/10.0 on Server 2016+, IIS/7.5 on Server 2008 R2)
      return {
        name, status: 'PASS',
        evidence: `Server is IIS but not version 8.0 or 8.5 — not affected by Winshock. Server header: ${serverBanner.match(/server\s*:\s*.+/i)?.[0] ?? 'unknown'}.`,
        remediation: 'No action required.',
      };
    }

    // Not IIS at all
    return {
      name, status: 'PASS',
      evidence: 'Server does not appear to be Microsoft IIS — Winshock (CVE-2014-6321) only affects Windows Schannel.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Winshock probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated exploit-grade scanner to confirm CVE-2014-6321.',
    };
  }
}

/** LUCKY13 (CVE-2013-0169): timing side-channel in TLS CBC MAC processing.
 *
 *  Background: TLS CBC cipher suites perform HMAC over plaintext + padding. A non-constant-time
 *  HMAC implementation leaks timing differences based on the padding length, allowing a
 *  chosen-plaintext attacker to recover plaintext incrementally over many probes.
 *
 *  Probe strategy:
 *  1. Send a TLS 1.2 ClientHello advertising only CBC cipher suites.
 *  2. If the server rejects CBC entirely → PASS (precondition not met).
 *  3. If the server accepts CBC, send two application-data records with maximally different
 *     padding lengths (1-block vs near-max padding) immediately after receiving the ServerHello,
 *     then measure the latency delta between alert responses.
 *  4. A statistically significant timing difference (delta > threshold) suggests non-constant-time
 *     MAC processing → WARN (inconclusive without statistical confirmation over many samples).
 *     No measurable difference → WARN (still inconclusive from a single sample, but lower signal).
 *     Note: a definitive LUCKY13 confirmation requires hundreds of timed probes across a controlled
 *     network path — single-shot probing can only flag the CBC precondition and rough timing anomaly.
 *
 *  Limitation: this probe runs over a public network where jitter dominates. Results are always
 *  WARN or PASS, never FAIL, unless CBC is completely absent (PASS).  Remediation is to disable
 *  CBC suites regardless of timing measurement — GCM / ChaCha20-Poly1305 are immune.
 */
async function probeLucky13(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'LUCKY13 (CVE-2013-0169)';
  let sock1: net.Socket | undefined;
  let sock2: net.Socket | undefined;

  async function sendCbcHelloAndRecord(paddingByte: number): Promise<{ accepted: boolean; responseMs: number }> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);
      const cbcCiphers = [
        0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
        0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      ];
      const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], cbcCiphers);
      sock.write(hello);
      const serverResp = await readBytes(sock, 4_000);
      if (!hasServerHello(serverResp)) return { accepted: false, responseMs: 0 };

      // Send a crafted application-data record with a specific padding byte value.
      // The record is unencrypted and will cause a bad_record_mac or decrypt_error alert —
      // what matters is the timing of the alert, which differs based on MAC re-computation cost.
      // We use a single-block (16-byte) payload filled with the padding byte.
      const payload = Buffer.alloc(16, paddingByte);
      const record = Buffer.concat([
        Buffer.from([0x17, 0x03, 0x03]),
        Buffer.from([(payload.length >> 8) & 0xff, payload.length & 0xff]),
        payload,
      ]);

      const t0 = performance.now();
      sock.write(record);
      await readBytes(sock, 3_000);
      const responseMs = performance.now() - t0;
      return { accepted: true, responseMs };
    } catch {
      return { accepted: false, responseMs: 0 };
    } finally {
      sock?.destroy();
    }
  }

  try {
    // Run both probes in parallel: one with minimal padding (0x00) and one with max padding (0x0f = 15)
    const [probe1, probe2] = await Promise.all([
      sendCbcHelloAndRecord(0x00),
      sendCbcHelloAndRecord(0x0f),
    ]);

    if (!probe1.accepted && !probe2.accepted) {
      return {
        name, status: 'PASS',
        evidence: 'Server does not negotiate CBC cipher suites — LUCKY13 timing side-channel precondition not met.',
        remediation: 'No action required.',
      };
    }

    const deltaMs = Math.abs(probe1.responseMs - probe2.responseMs);

    // A delta > 2ms on a single probe is a weak signal (network jitter dominates beyond ~1ms);
    // > 5ms is a stronger anomaly worth flagging explicitly.
    if (deltaMs > 5) {
      return {
        name, status: 'WARN',
        evidence: `Server negotiates CBC cipher suites. Timing delta between minimal-padding and max-padding probes: ${deltaMs.toFixed(2)}ms — noticeable difference detected. Statistical confirmation over many samples required; this single-shot result is inconclusive.`,
        remediation: 'Disable all CBC cipher suites and prefer AEAD suites (AES-GCM, ChaCha20-Poly1305). Apply patches for CVE-2013-0169 if running OpenSSL < 1.0.1e or a pre-patched NSS/GnuTLS version.',
      };
    }

    return {
      name, status: 'WARN',
      evidence: `Server negotiates CBC cipher suites (LUCKY13 precondition met). Single-shot timing delta: ${deltaMs.toFixed(2)}ms — insufficient for statistical confirmation. Definitive testing requires hundreds of timed probes on a controlled network path.`,
      remediation: 'Disable all CBC cipher suites and prefer AEAD suites (AES-GCM, ChaCha20-Poly1305). Apply patches for CVE-2013-0169 if running OpenSSL < 1.0.1e or a pre-patched NSS/GnuTLS version.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'LUCKY13 probe could not complete due to a network/connection error.',
      remediation: 'Disable CBC cipher suites. Run a dedicated timing-analysis scanner to confirm CVE-2013-0169.',
    };
  } finally {
    sock1?.destroy();
    sock2?.destroy();
  }
}

/** LOGJAM (CVE-2015-4000): weak / export-grade DHE key exchange.
 *
 *  Background: servers that offer DHE_EXPORT cipher suites (512-bit DH) or standard DHE with
 *  < 1024-bit primes allow an active MitM attacker to downgrade the connection and break the key
 *  exchange in real time using pre-computed number field sieve tables.  Even 1024-bit DH is
 *  considered breakable by nation-state adversaries; 2048-bit is the current minimum safe size.
 *
 *  Probe strategy (two passes):
 *  Pass 1 — Export DHE check:
 *    Send a TLS 1.2 ClientHello listing only DHE_EXPORT cipher suites (512-bit DH).
 *    If the server accepts → parse the ServerKeyExchange to extract DH prime length.
 *    Prime ≤ 512 bits (64 bytes) → FAIL (export-grade DH accepted).
 *    Prime 513–1023 bits → FAIL (weak DH, < 1024-bit).
 *    Prime 1024–2047 bits → WARN (marginal DH, < 2048-bit).
 *    Prime ≥ 2048 bits → PASS for this pass.
 *
 *  Pass 2 — Standard DHE check:
 *    Send a TLS 1.2 ClientHello listing standard DHE cipher suites.
 *    Parse the ServerKeyExchange DH prime length with identical thresholds.
 *
 *  ServerKeyExchange DHE format (RFC 5246 §7.4.3):
 *    dh_p  length (2 bytes) + dh_p bytes
 *    dh_g  length (2 bytes) + dh_g bytes
 *    dh_Ys length (2 bytes) + dh_Ys bytes
 *  The first field after the handshake header gives us the prime length immediately.
 */
async function probeLogjam(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'LOGJAM (CVE-2015-4000)';

  // DHE_EXPORT cipher suites (512-bit DH, all deprecated/removed from modern stacks)
  const exportDheCiphers = [
    0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
  ];

  // Standard DHE cipher suites
  const dheCiphers = [
    0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    0x006b, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  ];

  /**
   * Send a ClientHello with the given cipher list, wait for the server flight,
   * then locate the ServerKeyExchange (handshake type 0x0c) and extract the
   * DH prime length in bits from the first dh_p length field.
   * Returns { accepted: false } if no ServerKeyExchange is found.
   */
  async function probeDhe(ciphers: number[]): Promise<{ accepted: boolean; primeBits: number; cipherName: string }> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);
      const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], ciphers);
      sock.write(hello);
      // Read full server flight (ServerHello + Certificate + ServerKeyExchange + ServerHelloDone)
      const response = await readBytes(sock, 6_000);

      if (!hasServerHello(response)) return { accepted: false, primeBits: 0, cipherName: '' };

      // Extract negotiated cipher suite from ServerHello:
      // TLS record header (5) + HandshakeType (1) + length (3) + version (2) + random (32) + session_id_len (1)
      // + session_id (variable) + cipher_suite (2)
      let negotiatedCipher = 0;
      const shStart = 5; // start of handshake message inside first record
      if (response.length > shStart + 43) {
        const sessionIdLen = response[shStart + 43];
        const cipherOffset = shStart + 44 + sessionIdLen;
        if (response.length > cipherOffset + 1) {
          negotiatedCipher = response.readUInt16BE(cipherOffset);
        }
      }
      const cipherName = `0x${negotiatedCipher.toString(16).padStart(4, '0')}`;

      // Walk TLS records to find ServerKeyExchange (handshake type 0x0c)
      let offset = 0;
      while (offset + 5 <= response.length) {
        const contentType = response[offset];
        const recordLen = response.readUInt16BE(offset + 3);
        if (contentType === 0x16 && offset + 5 + recordLen <= response.length) {
          let hsOffset = offset + 5;
          while (hsOffset + 4 <= offset + 5 + recordLen) {
            const hsType = response[hsOffset];
            const hsLen = (response[hsOffset + 1] << 16) | (response[hsOffset + 2] << 8) | response[hsOffset + 3];
            if (hsType === 0x0c && hsLen >= 2) {
              // DHE ServerKeyExchange: first 2 bytes after header = dh_p length
              const dhpLenOffset = hsOffset + 4;
              if (response.length > dhpLenOffset + 1) {
                const dhpLen = response.readUInt16BE(dhpLenOffset);
                const primeBits = dhpLen * 8;
                return { accepted: true, primeBits, cipherName };
              }
            }
            hsOffset += 4 + hsLen;
          }
        }
        if (recordLen === 0) break; // safety
        offset += 5 + recordLen;
      }

      // Server accepted DHE ClientHello but didn't send ServerKeyExchange (e.g. non-DHE fallback)
      return { accepted: false, primeBits: 0, cipherName };
    } catch {
      return { accepted: false, primeBits: 0, cipherName: '' };
    } finally {
      sock?.destroy();
    }
  }

  function classifyPrime(primeBits: number, label: string, cipherName: string): VulnerabilityResult | null {
    if (primeBits <= 512) {
      return {
        name, status: 'FAIL',
        evidence: `${label}: server accepted DHE with a ${primeBits}-bit DH prime (cipher ${cipherName}) — export-grade key exchange. Trivially breakable by pre-computed NFS attack tables.`,
        remediation: 'Disable all DHE_EXPORT cipher suites. Configure DH parameters with a 2048-bit prime (RFC 3526 group 14+). Prefer ECDHE over DHE.',
      };
    }
    if (primeBits < 1024) {
      return {
        name, status: 'FAIL',
        evidence: `${label}: server accepted DHE with a ${primeBits}-bit DH prime (cipher ${cipherName}) — weak key exchange, breakable with moderate resources.`,
        remediation: 'Replace DH parameters with a 2048-bit prime (RFC 3526 group 14+). Disable DHE suites with primes < 1024 bits. Prefer ECDHE.',
      };
    }
    if (primeBits < 2048) {
      return {
        name, status: 'WARN',
        evidence: `${label}: server accepted DHE with a ${primeBits}-bit DH prime (cipher ${cipherName}) — marginal key size; 2048-bit minimum recommended. Nation-state level attacks are feasible against 1024-bit primes.`,
        remediation: 'Upgrade DH parameters to 2048-bit (RFC 3526 group 14). Generate custom DH params with: openssl dhparam -out dhparam.pem 2048',
      };
    }
    return null; // prime is strong enough
  }

  try {
    const [exportResult, dheResult] = await Promise.all([
      probeDhe(exportDheCiphers),
      probeDhe(dheCiphers),
    ]);

    // Check export DHE first — worst case
    if (exportResult.accepted) {
      const classification = classifyPrime(exportResult.primeBits, 'DHE_EXPORT', exportResult.cipherName);
      if (classification) return classification;
      // Export suite accepted but prime is surprisingly strong — still warn
      return {
        name, status: 'WARN',
        evidence: `DHE_EXPORT cipher suite accepted (cipher ${exportResult.cipherName}), DH prime ${exportResult.primeBits} bits. Export suites should be disabled regardless of prime size.`,
        remediation: 'Disable all DHE_EXPORT cipher suites. Prefer ECDHE with 256-bit curves.',
      };
    }

    // Check standard DHE
    if (dheResult.accepted) {
      const classification = classifyPrime(dheResult.primeBits, 'DHE', dheResult.cipherName);
      if (classification) return classification;
      return {
        name, status: 'PASS',
        evidence: `DHE cipher suite accepted (cipher ${dheResult.cipherName}) with a ${dheResult.primeBits}-bit prime — meets 2048-bit minimum safe key size.`,
        remediation: 'No action required. Continue monitoring for future DH prime strength guidance.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'Server does not accept DHE or DHE_EXPORT cipher suites — LOGJAM precondition not met.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'LOGJAM probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated scanner (testssl.sh --logjam) to confirm CVE-2015-4000.',
    };
  }
}

/** DROWN (CVE-2016-0800 / CVE-2016-0703): Decrypting RSA with Obsolete and Weakened eNcryption.
 *
 *  Background: DROWN allows an attacker to decrypt TLS 1.x RSA-encrypted sessions by exploiting
 *  an oracle on an SSLv2 endpoint that shares the same RSA private key.  Two attack variants:
 *
 *  - General DROWN (CVE-2016-0800): any SSLv2-capable server sharing the RSA key is sufficient.
 *    ~33% – 40% of HTTPS servers were vulnerable at disclosure (March 2016).
 *  - Special DROWN (CVE-2016-0703): exploits a specific OpenSSL bug (cleartext export cipher
 *    oracle) that makes the attack ~1000x faster.  Requires OpenSSL < 1.0.1 without the
 *    2015-01-08 patch for CVE-2015-0293.
 *
 *  Probe strategy (three steps):
 *
 *  Step 1 — Direct SSLv2 test:
 *    Send a raw SSLv2 ClientHello.  SSLv2 uses a 2-byte record header (0x80 | len_hi, len_lo)
 *    followed by ClientHello type (0x01) and version bytes (0x00, 0x02).
 *    If the server responds with an SSLv2 ServerHello (first byte 0x00, third byte 0x04 = ServerHello),
 *    the server itself accepts SSLv2 → FAIL (Direct DROWN — CVE-2016-0800).
 *
 *  Step 2 — RSA key-exchange detection (General DROWN precondition):
 *    Send a TLS 1.2 ClientHello offering only RSA key-exchange suites.
 *    If ServerHello is returned the server uses RSA key exchange — if that key is also used on
 *    any other SSLv2-capable host, DROWN is feasible.  Without cross-host correlation we report WARN.
 *
 *  Step 3 — Special DROWN (CVE-2016-0703) signal:
 *    After an SSLv2 ServerHello, send an SSLv2 ClientMasterKey with an export cipher
 *    (SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x07, 0x00, 0xC0) and a zero-length clear_key.
 *    A pre-patched OpenSSL will accept this without error — the absence of a SSLv2 error alert
 *    after a zero clear_key is the Special DROWN signal (WARN for now — inconclusive without
 *    full oracle loop, but the precondition detection is sufficient for a FAIL on General DROWN).
 */
async function probeDrown(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'DROWN (CVE-2016-0800 / CVE-2016-0703)';

  // ─── Step 1: SSLv2 ClientHello ───────────────────────────────────────────
  async function probeSSLv2(): Promise<{ acceptsSSLv2: boolean; specialDrownSignal: boolean }> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);

      // SSLv2 ClientHello:
      // 2-byte header: 0x80 | body_len_hi, body_len_lo
      // body: client_hello(0x01) + version(0x00,0x02) + cipher_specs_length(2) +
      //       session_id_length(2) + challenge_length(2) + cipher_specs + challenge
      // Cipher spec: SSL_CK_DES_192_EDE3_CBC_WITH_MD5 (3-byte code 0x07,0x00,0xC0)
      const challenge = Buffer.alloc(16, 0xab);
      const cipherSpec = Buffer.from([0x07, 0x00, 0xc0]); // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
      const body = Buffer.concat([
        Buffer.from([0x01]),             // MSG-CLIENT-HELLO
        Buffer.from([0x00, 0x02]),       // version: SSLv2
        Buffer.from([0x00, 0x03]),       // cipher_specs_length = 3
        Buffer.from([0x00, 0x00]),       // session_id_length = 0
        Buffer.from([0x00, 0x10]),       // challenge_length = 16
        cipherSpec,
        challenge,
      ]);
      // 2-byte SSLv2 record header: high bit set, length = body.length
      const header = Buffer.from([0x80 | ((body.length >> 8) & 0x7f), body.length & 0xff]);
      sock.write(Buffer.concat([header, body]));

      const response = await readBytes(sock, 4_000);
      if (response.length < 5) return { acceptsSSLv2: false, specialDrownSignal: false };

      // SSLv2 ServerHello: 2-byte header, then MSG-SERVER-HELLO (0x04)
      // Header high bit set means 2-byte header; third byte (index 2) should be 0x04
      const isSSLv2Header = (response[0] & 0x80) !== 0;
      const msgType = response[2];
      if (!isSSLv2Header || msgType !== 0x04) {
        return { acceptsSSLv2: false, specialDrownSignal: false };
      }

      // Server accepted SSLv2 — now probe Special DROWN (CVE-2016-0703):
      // Send a ClientMasterKey with a zero-length clear_key for the export cipher.
      // Format (simplified): MSG-CLIENT-MASTER-KEY (0x02) + cipher(3) + clear_key_len(2=0) +
      //                      encrypted_key_len(2) + key_arg_len(2) + encrypted_key + key_arg
      const encKey = Buffer.alloc(128, 0x00); // 128-byte fake RSA-encrypted key (zeros)
      const masterKeyBody = Buffer.concat([
        Buffer.from([0x02]),             // MSG-CLIENT-MASTER-KEY
        cipherSpec,                      // cipher
        Buffer.from([0x00, 0x00]),       // clear_key_length = 0 (Special DROWN trigger)
        Buffer.from([0x00, encKey.length & 0xff]), // encrypted_key_length
        Buffer.from([0x00, 0x00]),       // key_arg_length = 0
        encKey,
      ]);
      const mkHeader = Buffer.from([0x80 | ((masterKeyBody.length >> 8) & 0x7f), masterKeyBody.length & 0xff]);
      sock.write(Buffer.concat([mkHeader, masterKeyBody]));

      const mkResponse = await readBytes(sock, 3_000);
      // Special DROWN signal: server does NOT immediately send an error/close after zero clear_key
      // Vulnerable (pre-patch) server will respond with MSG-SERVER-VERIFY (0x06) or similar
      const specialDrownSignal = mkResponse.length > 0 && (mkResponse[2] === 0x06 || mkResponse[2] === 0x02);

      return { acceptsSSLv2: true, specialDrownSignal };
    } catch {
      return { acceptsSSLv2: false, specialDrownSignal: false };
    } finally {
      sock?.destroy();
    }
  }

  // ─── Step 2: RSA key-exchange detection ─────────────────────────────────
  async function probeRsaKeyExchange(): Promise<boolean> {
    let sock: net.Socket | undefined;
    try {
      sock = await connectTcp(host, port, 5_000);
      const rsaCiphers = [0x0035, 0x002f, 0x0005, 0x000a]; // RSA key exchange suites
      const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], rsaCiphers);
      sock.write(hello);
      const response = await readBytes(sock, 4_000);
      return hasServerHello(response);
    } catch {
      return false;
    } finally {
      sock?.destroy();
    }
  }

  try {
    const [sslv2Result, rsaAccepted] = await Promise.all([
      probeSSLv2(),
      probeRsaKeyExchange(),
    ]);

    if (sslv2Result.acceptsSSLv2) {
      if (sslv2Result.specialDrownSignal) {
        return {
          name, status: 'FAIL',
          evidence: 'Server accepts SSLv2 (Direct DROWN — CVE-2016-0800 confirmed) AND responded to zero-length clear_key ClientMasterKey without error — Special DROWN (CVE-2016-0703) signal detected. RSA sessions on this server are directly attackable.',
          remediation: 'Disable SSLv2 immediately. Upgrade OpenSSL to ≥ 1.0.2g / 1.0.1s. If the RSA key is shared across services, revoke and reissue the certificate.',
        };
      }
      return {
        name, status: 'FAIL',
        evidence: 'Server accepts SSLv2 handshakes (Direct DROWN — CVE-2016-0800). Any RSA-encrypted TLS session using the same private key can be decrypted by an attacker with access to this SSLv2 oracle.',
        remediation: 'Disable SSLv2 immediately. Upgrade OpenSSL to ≥ 1.0.2g / 1.0.1s. Revoke and reissue the certificate if the RSA key was shared with any SSLv2-capable service.',
      };
    }

    if (rsaAccepted) {
      return {
        name, status: 'WARN',
        evidence: 'Server uses RSA key exchange (General DROWN precondition — CVE-2016-0800). SSLv2 was not detected on this endpoint. If the same RSA private key is used on any other host that accepts SSLv2, DROWN decryption of TLS sessions is feasible.',
        remediation: 'Verify that no other service shares this RSA private key with an SSLv2-capable endpoint. Prefer ECDHE key exchange to eliminate RSA decryption risk entirely.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'Server does not accept SSLv2 and does not offer RSA key exchange suites — DROWN preconditions not met.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'DROWN probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated scanner (testssl.sh --drown) to confirm CVE-2016-0800 / CVE-2016-0703.',
    };
  }
}

/** FREAK (CVE-2015-0204): Factoring RSA Export Keys.
 *
 *  Background: servers that accept RSA_EXPORT cipher suites use 512-bit RSA keys for key
 *  exchange, which can be factored in ~7 hours using cloud computing (2015 research).  An active
 *  MitM attacker can therefore downgrade the handshake to export-grade RSA and decrypt the session.
 *
 *  Probe strategy:
 *    Send a TLS 1.2 ClientHello listing only RSA_EXPORT cipher suites.
 *    If the server responds with a ServerHello → FAIL (export-grade RSA accepted).
 *    No ServerHello → PASS.
 */
async function probeFreak(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'FREAK (CVE-2015-0204)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // RSA_EXPORT cipher suites (all deprecated/removed from modern stacks)
    const exportRsaCiphers = [
      0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
      0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
      0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
      0x000b, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
      0x000e, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
      0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
      0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
      0x0017, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
      0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    ];

    const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], exportRsaCiphers);
    sock.write(hello);
    const response = await readBytes(sock, 4_000);

    if (hasServerHello(response)) {
      // Extract negotiated cipher from ServerHello for evidence
      let cipherName = 'unknown';
      if (response.length > 48) {
        const sessionIdLen = response[5 + 43] ?? 0;
        const cipherOffset = 5 + 44 + sessionIdLen;
        if (response.length > cipherOffset + 1) {
          const code = response.readUInt16BE(cipherOffset);
          cipherName = `0x${code.toString(16).padStart(4, '0')}`;
        }
      }
      return {
        name, status: 'FAIL',
        evidence: `Server accepted an RSA_EXPORT cipher suite (negotiated cipher: ${cipherName}) — export-grade 512-bit RSA key exchange. The session key can be factored in hours and the connection decrypted by an active MitM attacker.`,
        remediation: 'Disable all RSA_EXPORT cipher suites immediately. Prefer ECDHE for key exchange. Upgrade OpenSSL to ≥ 1.0.1k / 1.0.2a (CVE-2015-0204 patch).',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'Server rejected all RSA_EXPORT cipher suites — FREAK precondition not met.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'FREAK probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated scanner (testssl.sh --freak) to confirm CVE-2015-0204.',
    };
  } finally {
    sock?.destroy();
  }
}

/** SWEET32 (CVE-2016-2183 / CVE-2016-6329): Birthday attacks on 64-bit block ciphers.
 *
 *  Background: cipher suites using 64-bit block ciphers (3DES/DES/IDEA/RC2) are vulnerable to
 *  birthday attacks after ~32 GB of traffic on the same session key.  An attacker who can capture
 *  that volume (e.g., on a long-lived HTTPS session) can recover plaintext blocks with ~50% probability.
 *  3DES (Triple-DES, TLS cipher names contain "3DES_EDE") is the most widely deployed 64-bit cipher.
 *
 *  Probe strategy:
 *    Send a TLS 1.2 ClientHello offering only 64-bit block cipher suites.
 *    If the server returns a ServerHello → FAIL (64-bit block cipher accepted).
 *    No ServerHello → PASS.
 */
async function probeSweet32(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'SWEET32 (CVE-2016-2183 / CVE-2016-6329)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // 64-bit block cipher suites: 3DES_EDE (0x0A, 0x000A family), DES, IDEA
    const sixtyfourBitCiphers = [
      0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
      0x000d, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
      0x0010, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
      0x0013, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
      0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
      0x001b, // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
      0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
      0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
      0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
      0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
      0x0007, // TLS_RSA_WITH_IDEA_CBC_SHA
      0x0009, // TLS_RSA_WITH_DES_CBC_SHA
      0x000c, // TLS_DH_DSS_WITH_DES_CBC_SHA
      0x000f, // TLS_DH_RSA_WITH_DES_CBC_SHA
      0x0012, // TLS_DHE_DSS_WITH_DES_CBC_SHA
      0x0015, // TLS_DHE_RSA_WITH_DES_CBC_SHA
    ];

    const hello = buildClientHello([0x03, 0x03], [0x03, 0x03], sixtyfourBitCiphers);
    sock.write(hello);
    const response = await readBytes(sock, 4_000);

    if (hasServerHello(response)) {
      let cipherName = 'unknown';
      if (response.length > 48) {
        const sessionIdLen = response[5 + 43] ?? 0;
        const cipherOffset = 5 + 44 + sessionIdLen;
        if (response.length > cipherOffset + 1) {
          const code = response.readUInt16BE(cipherOffset);
          cipherName = `0x${code.toString(16).padStart(4, '0')}`;
        }
      }
      const is3des = [0x000a, 0x000d, 0x0010, 0x0013, 0x0016, 0x001b, 0xc003, 0xc008, 0xc00d, 0xc012]
        .map((c) => `0x${c.toString(16).padStart(4, '0')}`).includes(cipherName);
      const cipherLabel = is3des ? '3DES (Triple-DES, 64-bit block)' : '64-bit block cipher (DES/IDEA)';
      return {
        name, status: 'FAIL',
        evidence: `Server accepted a ${cipherLabel} cipher suite (negotiated cipher: ${cipherName}). Birthday attacks are feasible after ~32 GB of traffic on the same session key.`,
        remediation: 'Disable all 3DES (TLS_RSA_WITH_3DES_EDE_CBC_SHA and variants), DES, and IDEA cipher suites. Use AES-GCM or ChaCha20-Poly1305. Apply OpenSSL ≥ 1.1.0 which disables 3DES by default.',
      };
    }

    return {
      name, status: 'PASS',
      evidence: 'Server rejected all 64-bit block cipher suites (3DES/DES/IDEA) — SWEET32 precondition not met.',
      remediation: 'No action required.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'SWEET32 probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated scanner (testssl.sh --sweet32) to confirm CVE-2016-2183.',
    };
  } finally {
    sock?.destroy();
  }
}

/** Opossum (CVE-2025-49812): TLS session-ticket / early-data state confusion.
 *
 *  Background: CVE-2025-49812 (disclosed 2025) affects certain TLS 1.3 implementations that
 *  incorrectly handle a ClientHello containing both a non-empty `session_ticket` extension (type
 *  0x0023) and an `early_data` extension (type 0x002a) simultaneously.  A vulnerable server enters
 *  an ambiguous state — it may send a `NewSessionTicket` (handshake type 0x04) or accept
 *  `EndOfEarlyData` (handshake type 0x05) before key confirmation, enabling session state
 *  confusion that can be leveraged for session hijacking or authentication bypass.
 *
 *  Probe strategy:
 *    Send a TLS 1.3 ClientHello that includes:
 *      - A non-empty (fake) session_ticket extension (type 0x0023)
 *      - An early_data extension (type 0x002a, zero-length)
 *      - supported_versions extension advertising TLS 1.3 (0x0304)
 *      - key_share extension with a P-256 public key placeholder
 *    If the server responds with a handshake message containing type 0x04 (NewSessionTicket)
 *    or 0x05 (EndOfEarlyData) before a complete key exchange → FAIL (state confusion detected).
 *    If the server sends a normal ServerHello / HelloRetryRequest / alert → behaviour is expected.
 *    Server does not respond or closes connection → PASS (not affected or not TLS 1.3).
 */
async function probeOpossum(host: string, port: number): Promise<VulnerabilityResult> {
  const name = 'Opossum (CVE-2025-49812)';
  let sock: net.Socket | undefined;
  try {
    sock = await connectTcp(host, port, 5_000);

    // Build a TLS 1.3 ClientHello with session_ticket + early_data + supported_versions + key_share

    // supported_versions: TLS 1.3 (0x0304)
    const supportedVersions = Buffer.from([
      0x00, 0x2b,       // extension type: supported_versions
      0x00, 0x03,       // extension length
      0x02,             // versions list length
      0x03, 0x04,       // TLS 1.3
    ]);

    // key_share: P-256 (0x0017) with 65-byte uncompressed public key placeholder
    const keyShareEntry = Buffer.alloc(65, 0x04); // uncompressed point, all zeros
    const keyShareList = Buffer.concat([
      Buffer.from([0x00, 0x17]),                      // group: secp256r1
      Buffer.from([0x00, keyShareEntry.length & 0xff]),
      keyShareEntry,
    ]);
    const keyShare = Buffer.concat([
      Buffer.from([0x00, 0x33]),                      // extension type: key_share
      Buffer.from([0x00, (keyShareList.length + 2) & 0xff]),
      Buffer.from([0x00, keyShareList.length & 0xff]),
      keyShareList,
    ]);

    // session_ticket: non-empty fake ticket (16 bytes) — triggers the confused path
    const fakeTicket = Buffer.alloc(16, 0xde);
    const sessionTicket = Buffer.concat([
      Buffer.from([0x00, 0x23]),                      // extension type: session_ticket
      Buffer.from([0x00, fakeTicket.length & 0xff]),
      fakeTicket,
    ]);

    // early_data: zero-length (just the extension type marker)
    const earlyData = Buffer.from([
      0x00, 0x2a,       // extension type: early_data
      0x00, 0x00,       // length 0
    ]);

    // renegotiation_info
    const riExt = Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]);

    const extensions = Buffer.concat([supportedVersions, keyShare, sessionTicket, earlyData, riExt]);

    const ciphers = [0x1301, 0x1302, 0x1303]; // TLS 1.3 cipher suites
    const cipherSuitesLen = ciphers.length * 2;
    const cipherBuf = Buffer.alloc(cipherSuitesLen);
    ciphers.forEach((c, i) => cipherBuf.writeUInt16BE(c, i * 2));

    const random = Buffer.alloc(32, 0xab);
    random.writeUInt32BE(Math.floor(Date.now() / 1000), 0);

    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]),          // legacy_version: TLS 1.2 (required by TLS 1.3 spec)
      random,
      Buffer.from([0x00]),                // session_id_length = 0
      Buffer.from([(cipherSuitesLen >> 8) & 0xff, cipherSuitesLen & 0xff]),
      cipherBuf,
      Buffer.from([0x01, 0x00]),          // compression methods: null only
      Buffer.from([(extensions.length >> 8) & 0xff, extensions.length & 0xff]),
      extensions,
    ]);

    const handshake = Buffer.concat([
      Buffer.from([0x01, 0x00, (body.length >> 8) & 0xff, body.length & 0xff]),
      body,
    ]);
    const record = Buffer.concat([
      Buffer.from([0x16, 0x03, 0x01]),    // TLS record: Handshake, legacy compat version
      Buffer.from([(handshake.length >> 8) & 0xff, handshake.length & 0xff]),
      handshake,
    ]);

    sock.write(record);
    const response = await readBytes(sock, 5_000);

    if (response.length === 0) {
      return {
        name, status: 'PASS',
        evidence: 'Server did not respond to TLS 1.3 ClientHello with session_ticket + early_data — not affected or TLS 1.3 not supported.',
        remediation: 'No action required.',
      };
    }

    // Scan all handshake records for NewSessionTicket (0x04) or EndOfEarlyData (0x05)
    // before a complete key exchange (EncryptedExtensions/Finished not yet seen)
    let foundStateConfusion = false;
    let foundServerHello = false;
    let confusionType = '';
    let offset = 0;

    while (offset + 5 <= response.length) {
      const contentType = response[offset];
      const recordLen = response.readUInt16BE(offset + 3);
      if (offset + 5 + recordLen > response.length) break;

      if (contentType === 0x16) {
        let hsOffset = offset + 5;
        while (hsOffset + 4 <= offset + 5 + recordLen) {
          const hsType = response[hsOffset];
          const hsLen = (response[hsOffset + 1] << 16) | (response[hsOffset + 2] << 8) | response[hsOffset + 3];
          if (hsType === 0x02) foundServerHello = true;
          if ((hsType === 0x04 || hsType === 0x05) && !foundServerHello) {
            foundStateConfusion = true;
            confusionType = hsType === 0x04 ? 'NewSessionTicket (0x04)' : 'EndOfEarlyData (0x05)';
          }
          if (hsLen === 0) break;
          hsOffset += 4 + hsLen;
        }
      }
      if (recordLen === 0) break;
      offset += 5 + recordLen;
    }

    if (foundStateConfusion) {
      return {
        name, status: 'FAIL',
        evidence: `Server sent ${confusionType} before completing key exchange in response to a ClientHello with conflicting session_ticket + early_data extensions — Opossum (CVE-2025-49812) state confusion detected.`,
        remediation: 'Apply vendor patch for CVE-2025-49812 immediately. As a mitigation, disable TLS 1.3 session tickets or early data (0-RTT) until patched.',
      };
    }

    if (hasServerHello(response)) {
      return {
        name, status: 'PASS',
        evidence: 'Server responded with a normal ServerHello to the conflicting ClientHello — no state confusion detected.',
        remediation: 'No action required.',
      };
    }

    const alert = parseTlsAlert(response);
    if (alert) {
      return {
        name, status: 'PASS',
        evidence: `Server rejected the conflicting ClientHello with TLS alert (level=${alert.level}, desc=${alert.description}) — expected behaviour, not vulnerable.`,
        remediation: 'No action required.',
      };
    }

    return {
      name, status: 'WARN',
      evidence: 'Server returned an unexpected response to the session_ticket + early_data ClientHello — inconclusive without full state-machine analysis.',
      remediation: 'Run a dedicated scanner to confirm CVE-2025-49812.',
    };
  } catch {
    return {
      name, status: 'WARN',
      evidence: 'Opossum probe could not complete due to a network/connection error.',
      remediation: 'Run a dedicated scanner to confirm CVE-2025-49812.',
    };
  } finally {
    sock?.destroy();
  }
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export async function evaluateVulnerabilityChecks(
  host: string,
  port: number,
  servername: string,
  protocolResults: PolicyCheckResult[],
  cipherResults: PolicyCheckResult[],
): Promise<VulnerabilityResult[]> {
  const tls10Supported = getProtocolSupport(protocolResults, 'TLSv1_0');
  const sslv3Supported = getProtocolSupport(protocolResults, 'SSLv3');
  const cbcSupported = hasSupported(cipherResults, (name) => /CBC/i.test(name));
  const rc4Supported = hasSupported(cipherResults, (name) => /RC4/i.test(name));

  const [
    poodleTls,
    downgrade,
    compression,
    heartbleed,
    ticketbleed,
    ccsInjection,
    robot,
    winshock,
    lucky13,
    logjam,
    drown,
    freak,
    sweet32,
    opossum,
  ] = await Promise.all([
    probePoodleTls(host, port),
    probeDowngrade(host, port),
    evaluateCompression(host, port, servername),
    probeHeartbleed(host, port),
    probeTicketbleed(host, port),
    probeCcsInjection(host, port),
    probeRobot(host, port),
    probeWinshock(host, port, servername),
    probeLucky13(host, port),
    probeLogjam(host, port),
    probeDrown(host, port),
    probeFreak(host, port),
    probeSweet32(host, port),
    probeOpossum(host, port),
  ]);

  const vulnerabilities: VulnerabilityResult[] = [];

  const beastVulnerable = tls10Supported && cbcSupported;
  vulnerabilities.push({
    name: 'BEAST attack',
    status: beastVulnerable ? 'FAIL' : 'PASS',
    evidence: beastVulnerable
      ? 'TLSv1.0 and CBC cipher support detected.'
      : 'TLSv1.0/CBC preconditions were not both present.',
    remediation: 'Disable TLSv1.0 and CBC suites for modern clients.',
  });

  // CVE-2011-3389 is the formal identifier for the BEAST attack; share the same precondition result.
  vulnerabilities.push({
    name: 'BEAST attack (CVE-2011-3389)',
    status: beastVulnerable ? 'FAIL' : 'PASS',
    evidence: beastVulnerable
      ? 'CVE-2011-3389: TLSv1.0 with CBC cipher negotiation detected — client-side BEAST exploit preconditions are present.'
      : 'CVE-2011-3389: TLSv1.0/CBC preconditions not met — not vulnerable.',
    remediation: 'Disable TLSv1.0 and all CBC cipher suites. Prefer TLSv1.2+ with ECDHE/GCM suites.',
  });

  vulnerabilities.push({
    name: 'POODLE (SSLv3) (CVE-2014-3566)',
    status: sslv3Supported && cbcSupported ? 'FAIL' : 'PASS',
    evidence: sslv3Supported && cbcSupported
      ? 'SSLv3 and CBC support detected.'
      : 'SSLv3/CBC exposure not detected.',
    remediation: 'Disable SSLv3 entirely and reject downgrade attempts.',
  });

  vulnerabilities.push(poodleTls);
  vulnerabilities.push(downgrade);
  vulnerabilities.push(compression);

  vulnerabilities.push({
    name: 'RC4 (CVE-2013-2566/CVE-2015-2808)',
    status: rc4Supported ? 'FAIL' : 'PASS',
    evidence: rc4Supported ? 'At least one RC4 cipher appears supported.' : 'No RC4 support detected in tested cipher set.',
    remediation: 'Disable RC4 cipher suites.',
  });

  vulnerabilities.push(heartbleed);
  vulnerabilities.push(ticketbleed);
  vulnerabilities.push(lucky13);
  vulnerabilities.push(logjam);
  vulnerabilities.push(freak);
  vulnerabilities.push(sweet32);
  vulnerabilities.push(drown);
  vulnerabilities.push(opossum);
  vulnerabilities.push(winshock);
  vulnerabilities.push(ccsInjection);
  vulnerabilities.push(robot);

  return vulnerabilities;
}
