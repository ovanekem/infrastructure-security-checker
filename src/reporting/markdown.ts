import fs from 'node:fs/promises';
import path from 'node:path';
import type { AnalysisResult, PolicyCheckResult } from '../types/index.js';
import { formatDurationMs, formatLocalDateStamp, sanitizeUrlForFilename } from '../utils/url.js';
import { colorizePolicyResult, severityIcon } from './formatting.js';

function formatPolicyLine(check: PolicyCheckResult): string {
  const support = check.supported === null ? 'inconclusive' : check.supported ? 'supported' : 'not supported';
  const text = `${check.name} [${check.policy}] → ${support} (${check.evidence})`;
  return `- ${colorizePolicyResult(text, check)}`;
}

export function buildReportFilename(target: URL, when: Date): string {
  const dateStamp = formatLocalDateStamp(when);
  const sanitized = sanitizeUrlForFilename(target);
  return `${dateStamp}-${sanitized}-security-report.md`;
}

export function buildMarkdownReport(result: AnalysisResult): string {
  const startedAt = result.startedAt.toLocaleString();
  const openPorts = result.portResults.filter((port) => port.state === 'open');

  const protocolLines = result.protocolResults.map(formatPolicyLine).join('\n');
  const cipherLines = result.cipherResults.map(formatPolicyLine).join('\n');

  const portTable = result.portResults
    .map((port) => `| ${port.port} | ${port.transport.toUpperCase()} | ${port.service} | ${port.protocol} | ${port.state} | ${port.probe?.status || 'WARN'} | ${port.probe?.evidence || 'n/a'} |`)
    .join('\n');

  const vulnerabilityLines = result.vulnerabilityResults
    .map((check) => `- ${severityIcon(check.status)} **${check.name}**: ${check.status} — ${check.evidence}. Remediation: ${check.remediation}`)
    .join('\n');

  const simulationTable = result.clientSimulations
    .map((sim) => {
      const proto = sim.protocol ?? 'No connection';
      const fwdSec = sim.forwardSecrecy === null ? '-' : sim.forwardSecrecy ? '✅ Yes' : '❌ No';
      const cipher = sim.cipher ?? '-';
      const icon = sim.status === 'PASS' ? '✅' : sim.status === 'FAIL' ? '❌' : '⚠️';
      return `| ${icon} ${sim.client} | ${proto} | ${cipher} | ${fwdSec} |`;
    })
    .join('\n');

  const infrastructureLines = result.infrastructureChecks
    .map((check) => `- ${severityIcon(check.status)} **${check.name}**: ${check.evidence}. Remediation: ${check.remediation}`)
    .join('\n');

  const openPortsSummary = openPorts.length
    ? openPorts.map((port) => `- ${port.port}/${port.transport.toUpperCase()} ${port.service} (${port.protocol})`).join('\n')
    : '- None';

  return [
    `# Security Report`,
    '',
    `## General information`,
    `- URL used for testing: ${result.targetUrl}`,
    `- Date and time of the test: ${startedAt}`,
    `- Test duration: ${formatDurationMs(result.durationMs)}`,
    `- Detected web server and version: ${result.webServer}`,
    `- Overall status: ${severityIcon(result.globalStatus)} ${result.globalStatus}`,
    '',
    `## Infrastructure checks`,
    infrastructureLines || '- None',
    '',
    `## List of all ports tested (TCP & UDP)`,
    '| Port | Transport | Service | Protocol | State | Probe status | Evidence |',
    '|------|-----------|---------|----------|-------|--------------|----------|',
    portTable,
    '',
    `## ICMP check`,
    `- ${severityIcon(result.icmpCheck.status)} **ICMP ping**: ${result.icmpCheck.evidence}`,
    '',
    `## Open ports summary`,
    openPortsSummary,
    '',
    `## List of all protocols tested`,
    protocolLines || '- None',
    '',
    `## List of all ciphers tested`,
    cipherLines || '- None',
    '',
    `## Vulnerability test results`,
    vulnerabilityLines || '- None',
    '',
    `## Client simulations`,
    '| Client | Protocol | Cipher suite | Forward secrecy |',
    '| --- | --- | --- | --- |',
    simulationTable || '| - | - | - | - |',
    '',
  ].join('\n');
}

export async function writeMarkdownReport(projectRoot: string, target: URL, result: AnalysisResult): Promise<string> {
  const filename = buildReportFilename(target, result.startedAt);
  const reportPath = path.join(projectRoot, filename);
  const markdown = buildMarkdownReport(result);
  await fs.writeFile(reportPath, `${markdown}\n`, 'utf-8');
  return reportPath;
}
