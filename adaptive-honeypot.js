// dqn-honeypot-ai-llm.js
import * as tf from '@tensorflow/tfjs';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import figlet from 'figlet';
import gradient from 'gradient-string';
import boxen from 'boxen';

import { logThreat } from './logThreats.js';
import { pipeline } from '@xenova/transformers'; // 🟢 LLM local

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const INPUT_PUBLIC_CSV = path.join(__dirname, 'public', 'logs', 'threats.csv');
const OUTPUT_PROJECT_CSV = path.join(__dirname, 'logs', 'threats.csv');
const REPLAY_FILE = path.join(__dirname, 'logs', 'replay.json');
const MODEL_FILE = path.join(__dirname, 'model.json');
const WEIGHTS_FILE = path.join(__dirname, 'weights.bin');

const ACTIONS = ['block', 'alert', 'ignore'];
const LEARNING_RATE = 0.01;
const EPOCHS = 50;
const FINETUNE_EPOCHS = 5;
const BATCH_LIMIT = 2000;

let model;
let localLLM;

// -------------------- Banner --------------------
function welcomeBanner() {
  console.clear();
  const title = figlet.textSync('DQN Honeypot', { horizontalLayout: 'full' });
  const banner = boxen(gradient.pastel.multiline(title), { padding: 1, margin: 1, borderStyle: 'round' });
  console.log(banner);
}

// -------------------- State / Action Encoding --------------------
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

// -------------------- Model --------------------
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

// -------------------- LLM Integration --------------------
async function initLLM() {
  if (!localLLM) {
    console.log('🤖 Loading local LLM...');
    localLLM = await pipeline('text-classification', 'Xenova/bart-large-mnli'); // يمكن تغيير النموذج حسب الحاجة
    console.log('✅ LLM ready.');
  }
}

async function analyzeWithLLM(record) {
  await initLLM();
  try {
    const input = `Analyze the following traffic:\nIP: ${record.ip}\nMethod: ${record.method}\nThreatType: ${record.threatType}`;
    const result = await localLLM(input);
    const top = result[0];
    let severity = 'low';
    if (top.score >= 0.85) severity = 'high';
    else if (top.score >= 0.6) severity = 'medium';
    return { type: top.label, severity, summary: `Label=${top.label} score=${top.score.toFixed(2)}` };
  } catch (err) {
    console.log(chalk.red('⚠️ LLM failed:', err.message));
    return { type: 'Other', severity: 'unknown', summary: 'LLM error' };
  }
}

// -------------------- Inference --------------------
async function selectAction(state, llmResult = null) {
  const input = tf.tensor2d([state]);
  const pred = model.predict(input);
  const idx = (await pred.argMax(-1).data())[0];
  input.dispose();
  if (pred.dispose) pred.dispose();
  let action = ACTIONS[idx];

  // تعديل القرار بناءً على LLM
  if (llmResult && llmResult.severity === 'high') action = 'block';
  else if (llmResult && llmResult.severity === 'medium' && action === 'ignore') action = 'alert';

  return action;
}

// -------------------- CSV Handling --------------------
function readPublicCsv() {
  if (!fs.existsSync(INPUT_PUBLIC_CSV)) return [];
  const text = fs.readFileSync(INPUT_PUBLIC_CSV, 'utf8').trim();
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  lines.shift();
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
  lines.shift();
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
    const content = fs.readFileSync(OUTPUT_PROJECT_CSV, 'utf8');
    const lines = content.split(/\r?\n/);
    if (lines.length && !lines[0].includes('Action')) {
      lines[0] = 'Timestamp,IP,Method,ThreatType,Action';
      fs.writeFileSync(OUTPUT_PROJECT_CSV, lines.join('\n') + '\n', 'utf8');
    }
  }
}
// -------------------- Process Last Record --------------------
async function processLastPublicRecord() {
  const records = readPublicCsv();
  if (!records.length) {
    console.log(chalk.yellow('ℹ️ No records found in public/logs/threats.csv to process.'));
    return;
  }

  const lastRecord = records[records.length - 1];
  const processedKeys = loadAlreadyProcessedKeys();
  const key = `${lastRecord.ip}|${lastRecord.method}|${lastRecord.threatType}`;
  if (processedKeys.has(key)) {
    console.log(chalk.gray('ℹ️ Last entry has already been processed.'));
    return;
  }

  const state = encodeStateFromRecord(lastRecord);
  const llm = await analyzeWithLLM(lastRecord);
  console.log(chalk.blue(`🤖 LLM analysis: type=${llm.type}, severity=${llm.severity}`));
  const action = await selectAction(state, llm);

  logThreat(lastRecord.ip, lastRecord.method, lastRecord.threatType, action, lastRecord.timestamp);
  console.log(chalk.greenBright(`✅ Last entry processed: ${lastRecord.ip} ${lastRecord.method} ${lastRecord.threatType} -> ${action}`));

  const replay = loadReplayMemory();
  replay.push({ state, action });
  saveReplayMemory(replay);
  console.log(chalk.cyan('⚙️ Fine-tuning on last record...'));
  await trainModel(replay, FINETUNE_EPOCHS);
  console.log(chalk.green('🧠 Fine-tuning completed.'));
}

// -------------------- Main --------------------
(async () => {
  welcomeBanner();
  ensureOutputHeader();
  
  await loadOrInitModel();

  await processLastPublicRecord();

  if (fs.existsSync(INPUT_PUBLIC_CSV)) {
    let timer = null;
    fs.watch(INPUT_PUBLIC_CSV, (eventType) => {
      if (eventType) {
        if (timer) clearTimeout(timer);
        timer = setTimeout(async () => {
          console.log(chalk.cyan('🔁 Change detected in public/logs/threats.csv — processing last entry...'));
          try {
            await processLastPublicRecord();
          } catch (err) {
            console.error('Error processing updated CSV:', err);
          }
        }, 500);
      }
    });
    console.log(chalk.gray('👁️ Watching public/logs/threats.csv for changes...'));
  } else {
    console.log(chalk.yellow('⚠️ public/logs/threats.csv not found — copy it to the required location to start processing.'));
  }
})();


import os from 'os';
import process from 'process';

// -------------------- Helper: Log RAM & CPU Usage --------------------
function logSystemUsage(stage = '') {
  const mem = process.memoryUsage();
  const cpus = os.cpus();
  const cpuLoad = cpus.map((c, i) => {
    const total = Object.values(c.times).reduce((a,b) => a+b, 0);
    const idle = c.times.idle;
    return ((1 - idle/total)*100).toFixed(1);
  });
  console.log(`\n💾 [${stage}] RAM usage:`);
  console.log(`  rss       : ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  heapTotal : ${(mem.heapTotal / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  heapUsed  : ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  console.log(`  external  : ${(mem.external / 1024 / 1024).toFixed(2)} MB`);
  console.log(`🖥️ CPU load per core: ${cpuLoad.join('% | ')}%\n`);
}
