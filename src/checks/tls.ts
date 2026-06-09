import tls, { type ConnectionOptions } from 'node:tls';
import type {
  CertificateInfo,
  CipherEntry,
  CipherRecommendation,
  PolicyCheckResult,
  ProtocolPolicyEntry,
  ProtocolStatus,
} from '../types/index.js';
import { runOpenSsl } from './openssl.js';

export interface TlsSessionInfo {
  certificate: CertificateInfo;
  negotiatedProtocol: string;
  negotiatedCipher: string;
}

const PROTOCOL_MAP: Record<string, ConnectionOptions['minVersion'] | null> = {
  TLSv1_0: 'TLSv1',
  TLSv1_1: 'TLSv1.1',
  TLSv1_2: 'TLSv1.2',
  TLSv1_3: 'TLSv1.3',
  SSLv2: null,
  SSLv3: null,
};

function protocolNameToNode(name: string): ConnectionOptions['minVersion'] | null {
  return PROTOCOL_MAP[name] ?? null;
}

function probeTlsVersion(host: string, port: number, servername: string, version: ConnectionOptions['minVersion'], timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port,
      servername,
      minVersion: version,
      maxVersion: version,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });

    let settled = false;
    const finish = (value: boolean) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(value);
      }
    };

    socket.on('secureConnect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
}

async function probeLegacySslv3(host: string, port: number, servername: string): Promise<boolean | null> {
  const result = await runOpenSsl(['s_client', '-connect', `${host}:${port}`, '-servername', servername, '-ssl3', '-brief'], 6_000);
  if (!result.ok) {
    const output = result.output.toLowerCase();
    if (
      output.includes('unknown option')
      || output.includes('unsupported protocol')
      || output.includes('wrong version number')
      || output.includes('handshake failure')
    ) {
      return false;
    }
    return null;
  }
  return /protocol\s*:\s*sslv3/i.test(result.output) || /protocol version:\s*SSLv3/i.test(result.output);
}

export async function getTlsSessionInfo(host: string, port: number, servername: string, timeoutMs = 8_000): Promise<TlsSessionInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      ALPNProtocols: ['h2', 'http/1.1'],
    });

    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`TLS handshake timed out after ${timeoutMs}ms`));
    }, timeoutMs + 200);

    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const cert = socket.getPeerCertificate(true) as tls.PeerCertificate;
      const hostnameMatchError = cert?.subject ? tls.checkServerIdentity(servername, cert) : new Error('No certificate subject available');

      resolve({
        certificate: {
          validFrom: cert?.valid_from,
          validTo: cert?.valid_to,
          trustValid: Boolean(socket.authorized),
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
          hostnameMatches: !hostnameMatchError,
        },
        negotiatedProtocol: socket.getProtocol() || 'UNKNOWN',
        negotiatedCipher: socket.getCipher()?.standardName || socket.getCipher()?.name || 'UNKNOWN',
      });

      socket.end();
    });

    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

export async function evaluateProtocolMatrix(
  host: string,
  port: number,
  servername: string,
  protocolPolicy: ProtocolPolicyEntry[],
): Promise<PolicyCheckResult[]> {
  const results: PolicyCheckResult[] = [];

  for (const protocol of protocolPolicy) {
    const nodeVersion = protocolNameToNode(protocol.name);
    let supported: boolean | null;

    if (protocol.name === 'SSLv3') {
      supported = await probeLegacySslv3(host, port, servername);
    } else if (nodeVersion) {
      supported = await probeTlsVersion(host, port, servername, nodeVersion, 5_000);
    } else {
      supported = false;
    }

    const success = supported === null
      ? false
      : (protocol.status === 'validated' ? supported : !supported);

    results.push({
      name: protocol.name,
      policy: protocol.status,
      supported,
      success,
      evidence: supported === null
        ? 'Probe inconclusive'
        : (supported ? 'Handshake accepted' : 'Handshake rejected'),
    });
  }

  return results;
}

function recommendationToPolicy(recommendation: CipherRecommendation): ProtocolStatus {
  return recommendation === 'Y' ? 'validated' : 'deprecated';
}

function shouldPrioritizeCipher(cipher: CipherEntry): boolean {
  return /(RC4|3DES|CBC|NULL|DES|EXPORT|MD5)/i.test(cipher.name) || cipher.recommended === 'Y';
}

function pickCipherCandidates(ciphers: CipherEntry[], negotiatedCipher: string): CipherEntry[] {
  const candidates: CipherEntry[] = [];
  const seen = new Set<string>();

  const add = (cipher: CipherEntry) => {
    if (!seen.has(cipher.name)) {
      seen.add(cipher.name);
      candidates.push(cipher);
    }
  };

  for (const cipher of ciphers) {
    if (cipher.name === negotiatedCipher) {
      add(cipher);
    }
  }

  const prioritized = ciphers.filter(shouldPrioritizeCipher);
  for (const cipher of prioritized.slice(0, 48)) {
    add(cipher);
  }

  return candidates;
}

async function getOpenSslMap(): Promise<Map<string, string>> {
  const result = await runOpenSsl(['ciphers', '-stdname', 'ALL'], 6_000);
  const map = new Map<string, string>();
  if (!result.ok) {
    return map;
  }

  for (const line of result.output.split(/\r?\n/)) {
    if (!line.includes(' - ')) continue;
    const parts = line.split(/\s+-\s+/);
    if (parts.length < 3) continue;
    const ianaName = parts[1]?.trim();
    const opensslName = parts[2]?.trim();
    if (ianaName && opensslName) {
      map.set(ianaName, opensslName);
    }
  }

  return map;
}

async function probeCipherWithOpenSsl(
  host: string,
  port: number,
  servername: string,
  cipherName: string,
  opensslName: string,
): Promise<boolean | null> {
  const isTls13Cipher = cipherName.startsWith('TLS_AES_') || cipherName.startsWith('TLS_CHACHA20_');
  const args = ['s_client', '-connect', `${host}:${port}`, '-servername', servername, '-brief'];

  if (isTls13Cipher) {
    args.push('-tls1_3', '-ciphersuites', opensslName);
  } else {
    args.push('-cipher', opensslName);
  }

  const result = await runOpenSsl(args, 7_000);
  if (!result.ok) {
    const output = result.output.toLowerCase();
    if (
      output.includes('handshake failure')
      || output.includes('no cipher match')
      || output.includes('sslv3 alert handshake failure')
    ) {
      return false;
    }
    return null;
  }

  const out = result.output;
  if (out.includes(opensslName) || out.includes(cipherName)) {
    return true;
  }

  if (/ciphersuite:\s*\(none\)/i.test(out)) {
    return false;
  }

  return null;
}

export async function evaluateCipherMatrix(
  host: string,
  port: number,
  servername: string,
  ciphers: CipherEntry[],
  negotiatedCipher: string,
): Promise<PolicyCheckResult[]> {
  const opensslMap = await getOpenSslMap();
  const candidates = pickCipherCandidates(ciphers, negotiatedCipher);
  const results: PolicyCheckResult[] = [];

  for (const cipher of candidates) {
    const policy = recommendationToPolicy(cipher.recommended);
    const mappedCipher = opensslMap.get(cipher.name) || cipher.name;
    const supported = await probeCipherWithOpenSsl(host, port, servername, cipher.name, mappedCipher);
    const success = supported === null ? false : (policy === 'validated' ? supported : !supported);

    results.push({
      name: cipher.name,
      policy,
      supported,
      success,
      evidence: supported === null
        ? `Probe inconclusive (${mappedCipher})`
        : (supported ? `Handshake accepted (${mappedCipher})` : `Handshake rejected (${mappedCipher})`),
    });
  }

  if (!results.some((item) => item.name === negotiatedCipher)) {
    results.unshift({
      name: negotiatedCipher,
      policy: 'validated',
      supported: true,
      success: true,
      evidence: 'Negotiated during default handshake',
    });
  }

  return results;
}

export function protocolStatusFromPolicy(negotiatedProtocol: string, protocolPolicy: ProtocolPolicyEntry[]): ProtocolStatus | 'UNKNOWN' {
  const normalized = negotiatedProtocol
    .replace('TLSv1.0', 'TLSv1_0')
    .replace('TLSv1.1', 'TLSv1_1')
    .replace('TLSv1.2', 'TLSv1_2')
    .replace('TLSv1.3', 'TLSv1_3');

  const direct = protocolPolicy.find((entry) => entry.name === negotiatedProtocol || entry.name === normalized);
  return direct?.status ?? 'UNKNOWN';
}

export function cipherStatusFromPolicy(negotiatedCipher: string, ciphers: CipherEntry[]): CipherRecommendation | 'UNKNOWN' {
  const entry = ciphers.find((cipher) => cipher.name === negotiatedCipher);
  return entry?.recommended ?? 'UNKNOWN';
}
