import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface OpenSslResult {
  ok: boolean;
  output: string;
  error?: string;
}

export async function runOpenSsl(args: string[], timeoutMs = 8_000): Promise<OpenSslResult> {
  try {
    const { stdout, stderr } = await execFileAsync('openssl', args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });

    return {
      ok: true,
      output: `${stdout || ''}${stderr || ''}`,
    };
  } catch (error) {
    const err = error as {
      stdout?: string;
      stderr?: string;
      message?: string;
      code?: string;
    };
    const output = `${err.stdout || ''}${err.stderr || ''}`.trim();
    const hasHandshakeSignal = /CONNECTION ESTABLISHED|Protocol version:|Ciphersuite:|Cipher is/i.test(output);
    return {
      ok: hasHandshakeSignal,
      output,
      error: hasHandshakeSignal ? undefined : (err.message || err.code || 'OpenSSL execution failed'),
    };
  }
}
