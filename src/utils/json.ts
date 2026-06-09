import fs from 'node:fs/promises';
import type {
  CipherListFile,
  CipherRecommendation,
  PortPolicyEntry,
  PortsPolicyFile,
  ProtocolPolicyEntry,
  ProtocolPolicyFile,
  WebServerEntry,
  WebServersFile,
} from '../types/index.js';

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export async function readJsonFile<T>(filePath: string): Promise<T> {
  const raw = await fs.readFile(filePath, 'utf-8');
  return JSON.parse(raw) as T;
}

export function validateProtocolsFile(input: unknown): ProtocolPolicyFile {
  if (!isObject(input) || !Array.isArray(input.protocols)) {
    throw new Error('Invalid protocols-list.json format: missing protocols array');
  }

  const protocols: ProtocolPolicyEntry[] = input.protocols.map((item) => {
    if (!isObject(item) || typeof item.name !== 'string' || typeof item.status !== 'string') {
      throw new Error('Invalid protocols-list.json entry');
    }

    if (item.status !== 'validated' && item.status !== 'deprecated') {
      throw new Error(`Invalid protocol status for ${item.name}`);
    }

    return {
      name: item.name,
      status: item.status,
    };
  });

  return { protocols };
}

export function validatePortsFile(input: unknown): PortsPolicyFile {
  if (!isObject(input) || !Array.isArray(input.ports)) {
    throw new Error('Invalid ports-list.json format: missing ports array');
  }

  const seenPorts = new Set<string>();

  const ports: PortPolicyEntry[] = input.ports.map((item) => {
    if (
      !isObject(item)
      || typeof item.port !== 'number'
      || typeof item.service !== 'string'
      || typeof item.protocol !== 'string'
    ) {
      throw new Error('Invalid ports-list.json entry');
    }

    const transport = typeof item.transport === 'string' ? item.transport : 'tcp';
    if (transport !== 'tcp' && transport !== 'udp') {
      throw new Error(`Invalid transport value for port ${item.port}: ${transport}`);
    }

    if (!Number.isInteger(item.port) || item.port <= 0 || item.port > 65535) {
      throw new Error(`Invalid port value: ${item.port}`);
    }

    const key = `${transport}:${item.port}`;
    if (seenPorts.has(key)) {
      throw new Error(`Duplicate port entry: ${key}`);
    }
    seenPorts.add(key);

    return {
      port: item.port,
      transport,
      service: item.service,
      protocol: item.protocol,
      policy: item.policy === 'open' || item.policy === 'closed' ? item.policy : undefined,
      notes: typeof item.notes === 'string' ? item.notes : undefined,
    };
  });

  return { ports };
}

export function validateCiphersFile(input: unknown): CipherListFile {
  if (!isObject(input) || !isObject(input.metadata) || !Array.isArray(input.ciphers)) {
    throw new Error('Invalid ciphers-list.json format');
  }

  const metadata = input.metadata;
  if (
    typeof metadata.sourceUrl !== 'string'
    || typeof metadata.fetchedAt !== 'string'
    || metadata.registryId !== 'tls-parameters-4'
  ) {
    throw new Error('Invalid ciphers-list.json metadata');
  }

  const ciphers = input.ciphers.map((item) => {
    if (!isObject(item) || typeof item.name !== 'string' || typeof item.recommended !== 'string') {
      throw new Error('Invalid ciphers-list.json entry');
    }
    const recommended = item.recommended as CipherRecommendation;
    if (recommended !== 'Y' && recommended !== 'D' && recommended !== 'N') {
      throw new Error(`Invalid cipher recommendation for ${item.name}`);
    }
    return {
      name: item.name,
      recommended,
      value: typeof item.value === 'string' ? item.value : undefined,
      references: Array.isArray(item.references)
        ? item.references.filter((r): r is string => typeof r === 'string')
        : undefined,
    };
  });

  return {
    metadata: {
      sourceUrl: metadata.sourceUrl,
      fetchedAt: metadata.fetchedAt,
      registryId: 'tls-parameters-4',
    },
    ciphers,
  };
}

export function validateWebServersFile(input: unknown): WebServersFile {
  if (!isObject(input) || !Array.isArray(input.webServers)) {
    throw new Error('Invalid web-servers-list.json format: missing webServers array');
  }

  const webServers: WebServerEntry[] = input.webServers.map((item) => {
    if (
      !isObject(item)
      || typeof item.name !== 'string'
      || typeof item.pattern !== 'string'
      || typeof item.minimumSecureVersion !== 'string'
    ) {
      throw new Error('Invalid web-servers-list.json entry: name, pattern and minimumSecureVersion are required strings');
    }

    // Validate that the pattern compiles as a valid RegExp
    try {
      new RegExp(item.pattern); // eslint-disable-line no-new
    } catch {
      throw new Error(`Invalid regex pattern for web server "${item.name}": ${item.pattern}`);
    }

    return {
      name: item.name,
      pattern: item.pattern,
      minimumSecureVersion: item.minimumSecureVersion,
      notes: typeof item.notes === 'string' ? item.notes : undefined,
    };
  });

  return { webServers };
}

