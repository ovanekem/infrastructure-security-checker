import { execFile } from 'node:child_process';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { IcmpCheckResult, PortPolicyEntry, PortScanResult, Severity } from '../types/index.js';

function toSeverityFromState(state: PortScanResult['state'], policy?: 'open' | 'closed'): Severity {
  if (policy === 'closed' && state === 'open') return 'FAIL';
  if (policy === 'closed' && state === 'open|filtered') return 'WARN';
  if (state === 'open') return 'WARN';
  if (state === 'open|filtered') return 'WARN';
  if (state === 'inconclusive') return 'WARN';
  return 'PASS';
}

export async function checkIcmp(host: string, timeoutSec = 3): Promise<IcmpCheckResult> {
  return new Promise((resolve) => {
    // Use ping with count=1 and timeout
    const args = process.platform === 'darwin'
      ? ['-c', '1', '-t', String(timeoutSec), host]
      : ['-c', '1', '-W', String(timeoutSec), host];

    execFile('ping', args, { timeout: (timeoutSec + 2) * 1000 }, (error) => {
      if (error) {
        resolve({
          reachable: false,
          status: 'PASS',
          evidence: 'ICMP echo request received no reply — ICMP appears disabled.',
        });
      } else {
        resolve({
          reachable: true,
          status: 'WARN',
          evidence: 'ICMP echo reply received — host responds to ping. ICMP should ideally be disabled on public-facing servers.',
        });
      }
    });
  });
}

async function probeBanner(host: string, port: number, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    const finish = (value: string | null) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(value);
      }
    };

    socket.setTimeout(timeoutMs, () => finish(null));
    socket.once('error', () => finish(null));
    socket.once('data', (data) => finish(data.toString('utf-8').trim()));
    socket.once('connect', () => {
      setTimeout(() => finish(null), Math.min(timeoutMs, 1_000));
    });
  });
}

async function probeHttp(host: string, port: number, secure: boolean, timeoutMs: number): Promise<{ status: Severity; evidence: string; }> {
  const client = secure ? https : http;
  return new Promise((resolve) => {
    const req = client.request(
      {
        host,
        port,
        method: 'HEAD',
        path: '/',
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (res) => {
        const server = res.headers.server || 'UNKNOWN';
        resolve({
          status: 'PASS',
          evidence: `${secure ? 'HTTPS' : 'HTTP'} responded with status ${res.statusCode}; server=${server}`,
        });
      },
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 'WARN', evidence: 'HTTP probe timed out' });
    });
    req.on('error', (error) => resolve({ status: 'WARN', evidence: `HTTP probe failed: ${error.message}` }));
    req.end();
  });
}

async function probeProtocol(host: string, entry: PortPolicyEntry, timeoutMs: number): Promise<{ status: Severity; evidence: string; }> {
  const protocol = entry.protocol.toLowerCase();

  if (protocol === 'http') {
    return probeHttp(host, entry.port, false, timeoutMs);
  }
  if (protocol === 'https') {
    return probeHttp(host, entry.port, true, timeoutMs);
  }
  if (protocol === 'ssh') {
    const banner = await probeBanner(host, entry.port, timeoutMs);
    if (banner && banner.toLowerCase().startsWith('ssh-')) {
      return { status: 'PASS', evidence: `SSH banner detected: ${banner}` };
    }
    return { status: 'WARN', evidence: 'SSH banner not detected' };
  }
  if (['smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s'].includes(protocol)) {
    const banner = await probeBanner(host, entry.port, timeoutMs);
    if (banner) {
      return { status: 'PASS', evidence: `Service banner: ${banner}` };
    }
    return { status: 'WARN', evidence: 'No service banner received' };
  }

  return {
    status: 'WARN',
    evidence: `No protocol-aware probe for '${entry.protocol}', marked inconclusive`,
  };
}

async function checkPortState(host: string, port: number, timeoutMs: number): Promise<{ state: PortScanResult['state']; evidence: string; }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    const finish = (state: PortScanResult['state'], evidence: string) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve({ state, evidence });
      }
    };

    socket.setTimeout(timeoutMs, () => finish('filtered', 'Connection timed out'));
    socket.once('connect', () => finish('open', 'TCP handshake succeeded'));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ECONNREFUSED') {
        finish('closed', 'Connection refused');
        return;
      }
      if (error.code === 'ETIMEDOUT') {
        finish('filtered', 'Connection timed out');
        return;
      }
      finish('inconclusive', `Connection error (${error.code || 'unknown'})`);
    });
  });
}

async function checkUdpPortState(host: string, port: number, timeoutMs: number): Promise<{ state: PortScanResult['state']; evidence: string; }> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;

    const finish = (state: PortScanResult['state'], evidence: string) => {
      if (!settled) {
        settled = true;
        socket.close();
        resolve({ state, evidence });
      }
    };

    const timeout = setTimeout(() => finish('filtered', 'No response received — port is likely filtered (no UDP reply or ICMP unreachable)'), timeoutMs);

    socket.on('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timeout);
      if (error.code === 'ECONNREFUSED') {
        finish('closed', 'ICMP port unreachable received');
      } else {
        finish('inconclusive', `UDP probe error (${error.code || 'unknown'})`);
      }
    });

    socket.on('message', () => {
      clearTimeout(timeout);
      finish('open', 'UDP response received');
    });

    // Send an empty probe packet
    const probe = Buffer.alloc(0);
    socket.send(probe, 0, 0, port, host, (err) => {
      if (err) {
        clearTimeout(timeout);
        finish('inconclusive', `UDP send failed: ${err.message}`);
      }
    });
  });
}

export async function scanPorts(host: string, ports: PortPolicyEntry[], timeoutMs = 2_500): Promise<PortScanResult[]> {
  const results: PortScanResult[] = [];

  for (const entry of ports) {
    const isUdp = entry.transport === 'udp';
    const stateInfo = isUdp
      ? await checkUdpPortState(host, entry.port, timeoutMs)
      : await checkPortState(host, entry.port, timeoutMs);

    const result: PortScanResult = {
      port: entry.port,
      transport: entry.transport,
      service: entry.service,
      protocol: entry.protocol,
      state: stateInfo.state,
      evidence: stateInfo.evidence,
    };

    if (stateInfo.state === 'open' && !isUdp) {
      const probeResult = await probeProtocol(host, entry, timeoutMs);
      if (entry.policy === 'closed') {
        result.probe = {
          status: 'FAIL',
          evidence: `${probeResult.evidence} — port ${entry.port} (${entry.service}) should not be publicly accessible.`,
        };
      } else {
        result.probe = probeResult;
      }
    } else if (stateInfo.state === 'open' && isUdp) {
      if (entry.policy === 'closed') {
        result.probe = {
          status: 'FAIL',
          evidence: `UDP port ${entry.port} (${entry.service}) is confirmed open — should not be publicly accessible.`,
        };
      } else {
        result.probe = {
          status: 'WARN',
          evidence: `UDP port confirmed open (received response); no protocol-level probe available.`,
        };
      }
    } else {
      result.probe = {
        status: toSeverityFromState(stateInfo.state, entry.policy),
        evidence: `Protocol probe skipped because state is ${stateInfo.state}`,
      };
    }

    results.push(result);
  }

  return results;
}
