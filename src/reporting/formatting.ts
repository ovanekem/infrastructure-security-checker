import type { PolicyCheckResult, Severity } from '../types/index.js';

const ANSI_RESET = '\u001b[0m';
const ANSI_GREEN = '\u001b[32m';
const ANSI_ORANGE = '\u001b[38;5;208m';
const ANSI_RED = '\u001b[31m';

export function severityIcon(status: Severity): string {
  if (status === 'PASS') return '✅';
  if (status === 'WARN') return '⚠️';
  return '❌';
}

export function colorizePolicyResult(text: string, check: PolicyCheckResult): string {
  if (check.success) return `<span style="color: green;">${text}</span>`;
  if (check.policy === 'validated' && check.supported === false) return `<span style="color: orange;">${text}</span>`;
  if (check.policy === 'deprecated' && check.supported === true) return `<span style="color: red;">${text}</span>`;
  return text;
}

export function formatConsolePolicyResult(text: string, check: PolicyCheckResult): string {
  if (check.success) return `${ANSI_GREEN}✅ ${text}${ANSI_RESET}`;
  if (check.policy === 'validated' && check.supported === false) return `${ANSI_ORANGE}⚠️ ${text}${ANSI_RESET}`;
  if (check.policy === 'deprecated' && check.supported === true) return `${ANSI_RED}❌ ${text}${ANSI_RESET}`;
  return `⚠️ ${text}`;
}
