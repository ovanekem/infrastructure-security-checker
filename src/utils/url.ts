export function normalizeTargetUrl(rawUrl: string): URL {
  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }

  if (!parsed.protocol || !parsed.hostname) {
    throw new Error(`Invalid URL (scheme and host are required): ${rawUrl}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported URL scheme: ${parsed.protocol}`);
  }

  return parsed;
}

export function sanitizeUrlForFilename(url: URL): string {
  const normalized = `${url.hostname}${url.port ? `-${url.port}` : ''}${url.pathname}${url.search}`;
  return normalized
    .replace(/[\\/:*?"<>|#%&{}$!'@+=`~]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

export function formatLocalDateStamp(date: Date): string {
  const year = date.getFullYear();
  const month = `${date.getMonth() + 1}`.padStart(2, '0');
  const day = `${date.getDate()}`.padStart(2, '0');
  return `${year}${month}${day}`;
}

export function formatDurationMs(durationMs: number): string {
  const sec = Math.floor(durationMs / 1000);
  const ms = durationMs % 1000;
  return `${sec}s ${ms}ms`;
}
