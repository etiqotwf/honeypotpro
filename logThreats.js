// logThreats.js (ESM)
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOGS_DIR = path.join(__dirname, 'logs');
const OUTPUT_CSV = path.join(LOGS_DIR, 'threats.csv');

function ensureLogsCsv() {
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
  if (!fs.existsSync(OUTPUT_CSV)) {
    fs.writeFileSync(OUTPUT_CSV, 'Timestamp,IP,Method,ThreatType,Action\n', 'utf8');
  } else {
    // تأكد من وجود الهيدر "Action"
    const content = fs.readFileSync(OUTPUT_CSV, 'utf8');
    const lines = content.split(/\r?\n/);
    if (lines.length && !lines[0].includes('Action')) {
      lines[0] = 'Timestamp,IP,Method,ThreatType,Action';
      fs.writeFileSync(OUTPUT_CSV, lines.join('\n') + '\n', 'utf8');
    }
  }
}

export function logThreat(ip, method, threatType, action = 'ignored', timestamp = new Date().toISOString()) {
  ensureLogsCsv();
  const row = `${timestamp},${ip},${method},${threatType},${action}\n`;
  fs.appendFileSync(OUTPUT_CSV, row, 'utf8');
}
