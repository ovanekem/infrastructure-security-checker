import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

export const PATHS = {
  ciphersList: path.join(PROJECT_ROOT, 'ciphers-list.json'),
  protocolsList: path.join(PROJECT_ROOT, 'protocols-list.json'),
  portsList: path.join(PROJECT_ROOT, 'ports-list.json'),
  webServersList: path.join(PROJECT_ROOT, 'web-servers-list.json'),
};
