import type { AnalysisResult } from '../types/index.js';
import { formatConsolePolicyResult, severityIcon } from './formatting.js';

function printSection(title: string): void {
  console.log(`\n${title}`);
  console.log('-'.repeat(title.length));
}

export function printConsoleReport(result: AnalysisResult): void {
  console.log(`\nOverall status: ${severityIcon(result.globalStatus)} ${result.globalStatus}`);
  console.log(`Target: ${result.targetUrl}`);
  console.log(`Duration: ${result.durationMs}ms`);

  printSection('General information');
  console.log(`- Web server: ${result.webServer}`);
  console.log(`- Negotiated protocol: ${result.negotiatedProtocol} (${result.negotiatedProtocolStatus})`);
  console.log(`- Negotiated cipher: ${result.negotiatedCipher} (${result.negotiatedCipherStatus})`);
  console.log(`- Certificate valid from: ${result.certificate.validFrom || 'UNKNOWN'}`);
  console.log(`- Certificate valid to: ${result.certificate.validTo || 'UNKNOWN'}`);

  printSection('Infrastructure checks');
  for (const check of result.infrastructureChecks) {
    console.log(`- ${severityIcon(check.status)} ${check.name}: ${check.evidence}`);
  }

  printSection('Protocol checks');
  for (const check of result.protocolResults) {
    const support = check.supported === null ? 'inconclusive' : check.supported ? 'supported' : 'not supported';
    const text = `${check.name} [${check.policy}] => ${support}; success=${check.success}`;
    console.log(`- ${formatConsolePolicyResult(text, check)}`);
  }

  printSection('Cipher checks');
  for (const check of result.cipherResults) {
    const support = check.supported === null ? 'inconclusive' : check.supported ? 'supported' : 'not supported';
    const text = `${check.name} [${check.policy}] => ${support}; success=${check.success}`;
    console.log(`- ${formatConsolePolicyResult(text, check)}`);
  }

  const openPorts = result.portResults.filter((port) => port.state === 'open');
  printSection('Port scan summary');
  console.log(`- Tested ports: ${result.portResults.length}`);
  console.log(`- Open ports: ${openPorts.length}`);
  console.log(`- Closed ports: ${result.portResults.filter((port) => port.state === 'closed').length}`);
  console.log(`- Filtered ports: ${result.portResults.filter((port) => port.state === 'filtered').length}`);
  console.log(`- Inconclusive ports: ${result.portResults.filter((port) => port.state === 'inconclusive').length}`);
  for (const port of result.portResults) {
    console.log(`  - ${port.port}/${port.transport} ${port.service}: ${port.state}; probe=${port.probe?.status || 'WARN'} (${port.probe?.evidence || 'n/a'})`);
  }

  printSection('ICMP check');
  console.log(`- ${severityIcon(result.icmpCheck.status)} ICMP: ${result.icmpCheck.evidence}`);

  printSection('Vulnerability tests');
  for (const check of result.vulnerabilityResults) {
    console.log(`- ${severityIcon(check.status)} ${check.name}: ${check.evidence}`);
  }

  printSection('Client simulations');
  console.log(
    '  Client'.padEnd(40)
    + 'Protocol'.padEnd(12)
    + 'Forward Secrecy'.padEnd(17)
    + 'Cipher',
  );
  console.log('-'.repeat(100));
  for (const sim of result.clientSimulations) {
    const proto = sim.protocol ?? 'No connection';
    const fs = sim.forwardSecrecy === null ? '-' : sim.forwardSecrecy ? 'Yes' : 'No';
    const cipher = sim.cipher ?? '-';
    const icon = sim.status === 'PASS' ? '✅' : sim.status === 'FAIL' ? '❌' : '⚠️';
    console.log(`${icon} ${sim.client.padEnd(38)} ${proto.padEnd(12)} ${fs.padEnd(17)} ${cipher}`);
  }
}
