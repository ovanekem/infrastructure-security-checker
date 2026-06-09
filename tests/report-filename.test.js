import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReportFilename } from '../dist/reporting/markdown.js';

test('buildReportFilename follows <YYYYMMDD>-<URL>-security-report.md format', () => {
  const url = new URL('https://Example.com:8443/path/to/page?x=1&y=2');
  const filename = buildReportFilename(url, new Date('2026-03-11T10:20:30Z'));

  assert.match(filename, /^20260311-.*-security-report\.md$/);
  assert.ok(filename.includes('example.com-8443_path_to_page_x_1_y_2'));
});
