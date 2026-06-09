import fs from 'node:fs/promises';
import { XMLParser } from 'fast-xml-parser';
import type { CipherEntry, CipherListFile } from '../types/index.js';
import { PATHS } from '../utils/paths.js';

const IANA_TLS_PARAMETERS_XML = 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xml';
const REGISTRY_ID = 'tls-parameters-4';

function normalizeText(value: unknown): string {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
}

function listify<T>(value: T | T[] | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function findRegistryById(node: unknown, registryId: string): Record<string, unknown> | null {
  if (!node || typeof node !== 'object') {
    return null;
  }

  if (!Array.isArray(node)) {
    const candidate = node as Record<string, unknown>;
    if (candidate.id === registryId) {
      return candidate;
    }

    for (const value of Object.values(candidate)) {
      const found = findRegistryById(value, registryId);
      if (found) {
        return found;
      }
    }
    return null;
  }

  for (const item of node) {
    const found = findRegistryById(item, registryId);
    if (found) {
      return found;
    }
  }

  return null;
}

export function parseCipherRegistryXml(xmlContent: string): CipherEntry[] {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '',
    trimValues: true,
  });

  const parsed = parser.parse(xmlContent);
  const registry = findRegistryById(parsed, REGISTRY_ID);
  if (!registry) {
    throw new Error(`Registry ${REGISTRY_ID} not found in IANA XML`);
  }

  const records = listify(registry.record as Record<string, unknown> | Array<Record<string, unknown>> | undefined);
  const ciphers: CipherEntry[] = [];

  for (const record of records) {
    if (!record || typeof record !== 'object') {
      continue;
    }

    const description = normalizeText(record.description);
    const recommended = normalizeText(record.rec) as CipherEntry['recommended'];
    const value = normalizeText(record.value);

    if (!description || !recommended || !['Y', 'D', 'N'].includes(recommended)) {
      continue;
    }

    if (/^(unassigned|reserved)$/i.test(description)) {
      continue;
    }

    const references = listify(record.xref as Record<string, unknown> | Array<Record<string, unknown>> | undefined)
      .map((ref) => {
        if (!ref || typeof ref !== 'object') return '';
        const data = normalizeText(ref.data);
        const type = normalizeText(ref.type);
        return data || type;
      })
      .filter(Boolean);

    ciphers.push({
      name: description,
      recommended,
      value: value || undefined,
      references: references.length ? references : undefined,
    });
  }

  ciphers.sort((a, b) => {
    const valueCmp = (a.value || '').localeCompare(b.value || '');
    if (valueCmp !== 0) {
      return valueCmp;
    }
    return a.name.localeCompare(b.name);
  });

  return ciphers;
}

async function fetchIanaXmlWithRetry(maxRetries = 2, timeoutMs = 30_000): Promise<string> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(IANA_TLS_PARAMETERS_XML, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'infrastructure-security-checker/1.0',
          Accept: 'application/xml,text/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (!response.ok) {
        throw new Error(`IANA request failed: HTTP ${response.status}`);
      }

      return await response.text();
    } catch (error) {
      lastError = error;
      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 1_000 * (attempt + 1)));
      }
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(`Unable to fetch IANA XML after retries: ${String(lastError)}`);
}

async function writeJsonAtomic(filePath: string, payload: string): Promise<void> {
  const tempPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  await fs.writeFile(tempPath, payload, 'utf-8');
  await fs.rename(tempPath, filePath);
}

export async function updateCiphersListFile(): Promise<CipherListFile> {
  const xmlContent = await fetchIanaXmlWithRetry();
  const ciphers = parseCipherRegistryXml(xmlContent);

  if (!ciphers.length) {
    throw new Error('No valid cipher entries extracted from IANA XML');
  }

  const payload: CipherListFile = {
    metadata: {
      sourceUrl: IANA_TLS_PARAMETERS_XML,
      fetchedAt: new Date().toISOString(),
      registryId: 'tls-parameters-4',
    },
    ciphers,
  };

  await writeJsonAtomic(PATHS.ciphersList, `${JSON.stringify(payload, null, 2)}\n`);
  return payload;
}
