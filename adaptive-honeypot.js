// dqn-honeypot-ai.js
import * as tf from '@tensorflow/tfjs';
// إذا حابب أداء أعلى على Node شغّل: npm i @tensorflow/tfjs-node
// وبدّل السطر السابق إلى: import '@tensorflow/tfjs-node';

import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import figlet from 'figlet';
import gradient from 'gradient-string';
import boxen from 'boxen';

import { logThreat } from './logThreats.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// المسارات
const INPUT_PUBLIC_CSV = path.join(__dirname, 'public', 'logs', 'threats.csv'); // مصدر البيانات (public)
const OUTPUT_PROJECT_CSV = path.join(__dirname, 'logs', 'threats.csv');       // مكان حفظ النتائج (project logs)
const REPLAY_FILE = path.join(__dirname, 'logs', 'replay.json');             // ذاكرة للتدريب
const MODEL_FILE = path.join(__dirname, 'model.json');
const WEIGHTS_FILE = path.join(__dirname, 'weights.bin');

const ACTIONS = ['block', 'alert', 'ignore'];
const LEARNING_RATE = 0.01;
const EPOCHS = 50;
const FINETUNE_EPOCHS = 5;
const BATCH_LIMIT = 2000;

let model;

function welcomeBanner() {
  console.clear();
  const title = figlet.textSync('DQN Honeypot', { horizontalLayout: 'full' });
  const banner = boxen(gradient.pastel.multiline(title), { padding: 1, margin: 1, borderStyle: 'round' });
  console.log(banner);
}

/* ---------- Encoding / heuristics ---------- */

function encodeStateFromString(logLine) {
  const ipSuspicion = logLine.includes('192.168') ? 0 : 1;
  const requestType = logLine.includes('POST') ? 1 : 0;
  const keywordDetected = /(malware|attack|scan)/i.test(logLine) ? 1 : 0;
  return [ipSuspicion, requestType, keywordDetected, 0, 0, 0, 0, 0];
}

function encodeStateFromRecord({ ip = '', method = '', threatType = '' }) {
  const ipSuspicion = ip.startsWith('192.168.') ? 0 : 1;
  const requestType = method === 'POST' ? 1 : 0;
  const keywordDetected = /(malware|attack|scan)/i.test(threatType) ? 1 : 0;
  return [ipSuspicion, requestType, keywordDetected, 0, 0, 0, 0, 0];
}

function inferLabelHeuristic(logLine) {
  if (/(malware|attack|scan)/i.test(logLine)) return 'block';
  if (/POST/i.test(logLine)) return 'alert';
  return 'ignore';
}

function encodeAction(action) {
  return ACTIONS.map(a => (a === action ? 1 : 0));
}

/* ---------- Model create / save / load ---------- */

function createModel() {
  const m = tf.sequential();
  m.add(tf.layers.dense({ units: 64, inputShape: [8], activation: 'relu' }));
  m.add(tf.layers.dense({ units: 64, activation: 'relu' }));
  m.add(tf.layers.dense({ units: ACTIONS.length, activation: 'softmax' }));
  m.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy' });
  return m;
}

async function saveModelDisk(m) {
  const artifacts = await m.save(tf.io.withSaveHandler(async (artifacts) => artifacts));
  fs.writeFileSync(MODEL_FILE, JSON.stringify({ modelTopology: artifacts.modelTopology, weightSpecs: artifacts.weightSpecs }), 'utf8');
  fs.writeFileSync(WEIGHTS_FILE, Buffer.from(artifacts.weightData));
  console.log(chalk.greenBright('✅ Model saved to disk.'));
}

async function loadOrInitModel() {
  if (fs.existsSync(MODEL_FILE) && fs.existsSync(WEIGHTS_FILE)) {
    try {
      const modelData = JSON.parse(fs.readFileSync(MODEL_FILE, 'utf8'));
      const weightData = fs.readFileSync(WEIGHTS_FILE);
      const artifacts = {
        modelTopology: modelData.modelTopology,
        weightSpecs: modelData.weightSpecs,
        weightData: new Uint8Array(weightData).buffer
      };
      model = await tf.loadLayersModel(tf.io.fromMemory(artifacts));
      model.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy' });
      console.log(chalk.green('📦 Model loaded and compiled.'));
      return;
    } catch (err) {
      console.log(chalk.yellow('⚠️ Failed to load model from disk, will re-initialize. Error:'), err.message);
    }
  }

  model = createModel();
  console.log(chalk.cyan('🧪 No saved model found — bootstrap training...'));

  const bootstrap = [
    { ip: '192.168.0.2', method: 'POST', threatType: 'malware detected' },
    { ip: '10.0.0.5', method: 'GET', threatType: 'normal traffic' },
    { ip: '172.16.0.1', method: 'POST', threatType: 'scan attempt' },
    { ip: '8.8.8.8', method: 'GET', threatType: 'attack vector' },
  ];

  const data = bootstrap.map(r => ({ state: encodeStateFromRecord(r), action: inferLabelHeuristic(`${r.method} ${r.threatType}`) }));
  await trainModel(data, EPOCHS);
}

async function trainModel(pairs, epochs = EPOCHS) {
  if (!pairs || pairs.length === 0) return;
  const xs = tf.tensor2d(pairs.map(p => p.state));
  const ys = tf.tensor2d(pairs.map(p => encodeAction(p.action)));
  console.log(chalk.cyan(`🔧 Training on ${pairs.length} samples for ${epochs} epochs...`));
  await model.fit(xs, ys, {
    epochs,
    shuffle: true,
    callbacks: {
      onEpochEnd: (epoch, logs) => console.log(chalk.gray(`Epoch ${epoch + 1}: loss=${(logs.loss || 0).toFixed(6)}`))
    }
  });
  await saveModelDisk(model);
  xs.dispose();
  ys.dispose();
}

/* ---------- Inference ---------- */

async function selectAction(state) {
  const input = tf.tensor2d([state]);
  const pred = model.predict(input);
  const idx = (await pred.argMax(-1).data())[0];
  input.dispose();
  if (pred.dispose) pred.dispose();
  return ACTIONS[idx];
}

/* ---------- CSV reading / processing ---------- */

function readPublicCsv() {
  if (!fs.existsSync(INPUT_PUBLIC_CSV)) return [];
  const text = fs.readFileSync(INPUT_PUBLIC_CSV, 'utf8').trim();
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  // نفترض الهيدر في أول سطر
  const header = lines.shift();
  if (!lines.length) return [];
  return lines
    .filter(Boolean)
    .map(line => {
      const parts = line.split(',');
      const timestamp = (parts[0] || '').trim() || new Date().toISOString();
      const ip = (parts[1] || '').trim();
      const method = (parts[2] || '').trim();
      const threatType = (parts.slice(3).join(',') || '').trim() || 'unknown';
      return { timestamp, ip, method, threatType };
    })
    .filter(r => r.ip && r.method);
}

function loadAlreadyProcessedKeys() {
  if (!fs.existsSync(OUTPUT_PROJECT_CSV)) return new Set();
  const text = fs.readFileSync(OUTPUT_PROJECT_CSV, 'utf8').trim();
  if (!text) return new Set();
  const lines = text.split(/\r?\n/);
  lines.shift(); // header
  const set = new Set();
  for (const ln of lines) {
    if (!ln) continue;
    const parts = ln.split(',');
    const ip = (parts[1] || '').trim();
    const method = (parts[2] || '').trim();
    const threatType = (parts[3] || '').trim();
    set.add(`${ip}|${method}|${threatType}`);
  }
  return set;
}

function loadReplayMemory() {
  try {
    if (!fs.existsSync(REPLAY_FILE)) return [];
    const arr = JSON.parse(fs.readFileSync(REPLAY_FILE, 'utf8'));
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function saveReplayMemory(mem) {
  const trimmed = mem.slice(-BATCH_LIMIT);
  fs.writeFileSync(REPLAY_FILE, JSON.stringify(trimmed, null, 2), 'utf8');
}

function ensureOutputHeader() {
  const dir = path.join(__dirname, 'logs');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(OUTPUT_PROJECT_CSV)) {
    fs.writeFileSync(OUTPUT_PROJECT_CSV, 'Timestamp,IP,Method,ThreatType,Action\n', 'utf8');
  } else {
    // تأكد من وجود العمود Action
    const content = fs.readFileSync(OUTPUT_PROJECT_CSV, 'utf8');
    const lines = content.split(/\r?\n/);
    if (lines.length && !lines[0].includes('Action')) {
      lines[0] = 'Timestamp,IP,Method,ThreatType,Action';
      fs.writeFileSync(OUTPUT_PROJECT_CSV, lines.join('\n') + '\n', 'utf8');
    }
  }
}

async function processPublicRecords() {
  const records = readPublicCsv();
  if (!records.length) {
    console.log(chalk.yellow('ℹ️ لا توجد سجلات في public/logs/threats.csv للمعالجة.'));
    return;
  }
  console.log(chalk.cyan(`📥 قرأت ${records.length} سجلاً من public/logs/threats.csv`));

  const processedKeys = loadAlreadyProcessedKeys();
  const replay = loadReplayMemory();
  const newPairs = [];
  let written = 0;

  for (const r of records) {
    const key = `${r.ip}|${r.method}|${r.threatType}`;
    if (processedKeys.has(key)) continue;

    const state = encodeStateFromRecord(r);
    const action = await selectAction(state);

    // سجل النتيجة في ملف المشروع logs/threats.csv
    logThreat(r.ip, r.method, r.threatType, action, r.timestamp);
    newPairs.push({ state, action });
    processedKeys.add(key);
    written++;
  }

  if (written) {
    console.log(chalk.greenBright(`✅ تمت معالجة وكتابة ${written} سجل جديد إلى logs/threats.csv`));
  } else {
    console.log(chalk.yellow('ℹ️ لا توجد سجلات جديدة لمعالجتها (كلها موجودة مسبقًا).'));
  }

  if (newPairs.length) {
    const updatedReplay = replay.concat(newPairs).slice(-BATCH_LIMIT);
    saveReplayMemory(updatedReplay);
    console.log(chalk.cyan('⚙️ إجراء Fine-tune (reinforcement-like) على البيانات الجديدة...'));
    await trainModel(updatedReplay, FINETUNE_EPOCHS);
    console.log(chalk.green('🧠 Fine-tune اكتمل.'));
  }
}

/* ---------- Backward compatibility: process local honeypot.log ---------- */

function ensureHoneypotLogExists() {
  const logPath = path.join(__dirname, 'logs');
  const logFile = path.join(logPath, 'honeypot.log');
  if (!fs.existsSync(logPath)) fs.mkdirSync(logPath, { recursive: true });
  if (!fs.existsSync(logFile)) {
    fs.writeFileSync(logFile, [
      "192.168.0.2 POST malware detected",
      "10.0.0.5 GET normal traffic",
      "172.16.0.1 POST scan attempt",
      "8.8.8.8 GET attack vector"
    ].join('\n'), 'utf8');
  }
  return logFile;
}

async function processHoneypotLog(logFile) {
  const rl = readline.createInterface({ input: fs.createReadStream(logFile), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    const state = encodeStateFromString(line);
    const action = await selectAction(state);

    const parts = line.split(' ');
    const ip = parts[0] || '0.0.0.0';
    const method = parts[1] || 'GET';
    const threatType = parts.slice(2).join(' ') || 'unknown';

    logThreat(ip, method, threatType, action, new Date().toISOString());
    console.log(chalk.gray(`Processed honeypot.log: ${ip} ${method} ${threatType} -> ${action}`));
  }
}

/* ---------- Main ---------- */

(async () => {
  welcomeBanner();
  ensureOutputHeader();
  await loadOrInitModel();

  // معالجة ملف public/logs/threats.csv الآن
  await processPublicRecords();

  // optional: process local honeypot.log (back-compat)
  // const hf = ensureHoneypotLogExists();
  // await processHoneypotLog(hf);

  // Watcher بسيط لإعادة المعالجة عند تعديل الملف (debounced)
  if (fs.existsSync(INPUT_PUBLIC_CSV)) {
    let timer = null;
    fs.watch(INPUT_PUBLIC_CSV, (eventType) => {
      if (eventType) {
        if (timer) clearTimeout(timer);
        timer = setTimeout(async () => {
          console.log(chalk.cyan('🔁 تم الكشف عن تعديل في public/logs/threats.csv — إعادة المعالجة...'));
          try {
            await processPublicRecords();
          } catch (err) {
            console.error('Error processing updated CSV:', err);
          }
        }, 500);
      }
    });
    console.log(chalk.gray('👁️ Watching public/logs/threats.csv for changes...'));
  } else {
    console.log(chalk.yellow('⚠️ لا يوجد ملف public/logs/threats.csv — انسخه إلى المكان المطلوب ليبدأ المعالج.'));
  }
})();
