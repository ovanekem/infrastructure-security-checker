#!/usr/bin/env node
import fs from 'node:fs/promises';
import { analyzeWebsite } from '../checks/website-analysis.js';
import { updateCiphersListFile } from '../iana/update-ciphers-list.js';
import { printConsoleReport } from '../reporting/console.js';
import { writeMarkdownReport } from '../reporting/markdown.js';
import type { CipherListFile, PortsPolicyFile, ProtocolPolicyFile, WebServersFile } from '../types/index.js';
import { readJsonFile, validateCiphersFile, validatePortsFile, validateProtocolsFile, validateWebServersFile } from '../utils/json.js';
import { PATHS, PROJECT_ROOT } from '../utils/paths.js';
import { normalizeTargetUrl } from '../utils/url.js';

interface CliArgs {
  url?: string;
  updateCiphersList: boolean;
  help: boolean;
}

function printHelp(): void {
  console.log(`
Infrastructure Security Checker

Usage:
  node dist/cli/main.js --update-ciphers-list
  node dist/cli/main.js --url https://example.com
  node dist/cli/main.js --update-ciphers-list --url https://example.com

Options:
  --url <https://target>         Target website URL to analyze
  --update-ciphers-list          Download IANA TLS parameters and regenerate ciphers-list.json
  --help                         Show this help text
`);
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    updateCiphersList: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--help' || token === '-h') {
      args.help = true;
      continue;
    }
    if (token === '--update-ciphers-list') {
      args.updateCiphersList = true;
      continue;
    }
    if (token === '--url') {
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        throw new Error('Missing value for --url');
      }
      args.url = next;
      i += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${token}`);
  }

  return args;
}

async function loadAnalysisInputs(): Promise<{
  protocols: ProtocolPolicyFile;
  ports: PortsPolicyFile;
  ciphers: CipherListFile;
  webServers: WebServersFile;
}> {
  try {
    await fs.access(PATHS.protocolsList);
  } catch {
    throw new Error('protocols-list.json is missing or not readable');
  }
  try {
    await fs.access(PATHS.portsList);
  } catch {
    throw new Error('ports-list.json is missing or not readable');
  }
  try {
    await fs.access(PATHS.ciphersList);
  } catch {
    throw new Error('ciphers-list.json is missing; run with --update-ciphers-list first');
  }
  try {
    await fs.access(PATHS.webServersList);
  } catch {
    throw new Error('web-servers-list.json is missing or not readable');
  }

  const protocols = validateProtocolsFile(await readJsonFile(PATHS.protocolsList));
  const ports = validatePortsFile(await readJsonFile(PATHS.portsList));
  const ciphers = validateCiphersFile(await readJsonFile(PATHS.ciphersList));
  const webServers = validateWebServersFile(await readJsonFile(PATHS.webServersList));
  return { protocols, ports, ciphers, webServers };
}

async function run(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    return 0;
  }

  if (!args.updateCiphersList && !args.url) {
    printHelp();
    return 1;
  }

  if (args.updateCiphersList) {
    try {
      const payload = await updateCiphersListFile();
      console.log(`Updated ciphers-list.json with ${payload.ciphers.length} entries from IANA.`);
    } catch (error) {
      console.error(`Failed to update ciphers list: ${(error as Error).message}`);
      return 2;
    }
  }

  if (!args.url) {
    return 0;
  }

  let targetUrl: URL;
  try {
    targetUrl = normalizeTargetUrl(args.url);
  } catch (error) {
    console.error((error as Error).message);
    return 2;
  }

  try {
    const { protocols, ports, ciphers, webServers } = await loadAnalysisInputs();
    const analysis = await analyzeWebsite(targetUrl, protocols.protocols, ciphers, ports.ports, webServers);

    printConsoleReport(analysis);
    const reportPath = await writeMarkdownReport(PROJECT_ROOT, targetUrl, analysis);
    console.log(`\nMarkdown report generated: ${reportPath}`);

    return analysis.exitCode;
  } catch (error) {
    console.error(`Analysis failed: ${(error as Error).message}`);
    return 2;
  }
}

run()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(`Unhandled fatal error: ${(error as Error).message}`);
    process.exitCode = 2;
  });
