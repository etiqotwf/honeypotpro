// dqn-honeypot-ai-llm.js (modified by assistant)
// ------------------------------------------------
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
const DECISIONS_FILE = path.join(__dirname, 'logs', 'decisions.json');

const ACTIONS = ['block', 'alert', 'ignore'];
const TRAINEE_ACTIONS = ['recommendExtraTraining', 'sendAlertToAdmin', 'markAsGood'];

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

// -------------------- Encode Trainee State --------------------
function encodeTraineeState(trainee) {
  // افترضنا بعض الخصائص في قاعدة البيانات traineeDB
  // مثل: score, attendance, assignmentsCompleted, behavior
  const score = trainee.score || 0; // 0-100
  const attendance = trainee.attendance || 0; // 0-100%
  const assignmentsCompleted = trainee.assignmentsCompleted || 0; // عدد المهام المنجزة
  const behavior = trainee.behavior || 0; // 0-2 (0=سيء،1=متوسط،2=جيد)

  // ترميز الحالة كنطاق [0,1]
  return [
    score / 100,
    attendance / 100,
    Math.min(assignmentsCompleted / 10, 1),
    behavior / 2
  ];
}

// -------------------- Create / Compile Trainee Model --------------------
let traineeModel;

function createTraineeModel() {
  const model = tf.sequential();

  // Input shape = 4 (score, attendance, assignmentsCompleted, behavior)
  model.add(tf.layers.dense({ units: 32, inputShape: [4], activation: 'relu' }));
  model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
  
  // Output = عدد TRAINEE_ACTIONS
  model.add(tf.layers.dense({ units: TRAINEE_ACTIONS.length, activation: 'softmax' }));

  model.compile({
    optimizer: tf.train.adam(LEARNING_RATE),
    loss: 'categoricalCrossentropy',
    metrics: ['accuracy']
  });

  return model;
}

// -------------------- Initialize or Load Model --------------------
async function loadOrInitTraineeModel() {
  if (!traineeModel) {
    traineeModel = createTraineeModel();
    console.log('🧠 Trainee model initialized.');
  }
}


// -------------------- Encode Action for Trainee Model --------------------
function encodeTraineeAction(action) {
  return TRAINEE_ACTIONS.map(a => (a === action ? 1 : 0));
}

// -------------------- Train Trainee Model --------------------
async function trainTraineeModel(pairs, epochs = EPOCHS) {
  if (!pairs || pairs.length === 0) return;

  // تحويل الحالات والإجراءات لمصفوفات tensors
  const xs = tf.tensor2d(pairs.map(p => p.state)); // مصفوفة الحالات
  const ys = tf.tensor2d(pairs.map(p => encodeTraineeAction(p.action))); // مصفوفة الإجراءات

  console.log(`🔧 Training Trainee model on ${pairs.length} samples for ${epochs} epochs...`);

  await traineeModel.fit(xs, ys, {
    epochs,
    shuffle: true,
    callbacks: {
      onEpochEnd: (epoch, logs) =>
        console.log(`Epoch ${epoch + 1}: loss=${(logs.loss || 0).toFixed(6)}, accuracy=${(logs.acc || logs.accuracy || 0).toFixed(3)}`)
    }
  });

  xs.dispose();
  ys.dispose();

  console.log('✅ Trainee model training completed.');
}

// -------------------- Prepare Training Data from traineeDB --------------------
async function prepareTraineeTrainingData(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('trainees', 'readonly');
    const store = tx.objectStore('trainees');
    const request = store.getAll();

    request.onsuccess = () => {
      const records = request.result;
      const trainingPairs = [];

      records.forEach(record => {
        // تحويل كل سجل إلى state
        const state = encodeTraineeState(record);

        // تحديد الإجراء المناسب لكل سجل
        // مثال: لو معدل النجاح أقل من 70% => recommendExtraTraining
        // لو غياب كثير => sendAlertToAdmin
        // غير ذلك => markAsGood
        let action;
        if (record.successRate < 70) action = 'recommendExtraTraining';
        else if (record.absences > 5) action = 'sendAlertToAdmin';
        else action = 'markAsGood';

        trainingPairs.push({ state, action });
      });

      resolve(trainingPairs);
    };

    request.onerror = () => reject(request.error);
  });
}

// -------------------- Train model on traineeDB dynamically --------------------
async function trainTraineeModelFromDB(db) {
  const trainingPairs = await prepareTraineeTrainingData(db);
  if (!trainingPairs || trainingPairs.length === 0) return;

  const xs = tf.tensor2d(trainingPairs.map(p => p.state));
  const ys = tf.tensor2d(trainingPairs.map(p => encodeTraineeAction(p.action)));

  console.log(`🔧 Training traineeDB model on ${trainingPairs.length} samples for ${EPOCHS} epochs...`);

  await traineeModel.fit(xs, ys, {
    epochs: EPOCHS,
    shuffle: true,
    callbacks: {
      onEpochEnd: (epoch, logs) => console.log(`Epoch ${epoch + 1}: loss=${(logs.loss || 0).toFixed(4)}`)
    }
  });

  xs.dispose();
  ys.dispose();

  console.log('✅ TraineeDB model training completed.');
}

// -------------------- Watch traineeDB for changes --------------------
function watchTraineeDB(db) {
  const storeName = 'trainees';
  const dbRequest = indexedDB.open(db);

  dbRequest.onsuccess = () => {
    const database = dbRequest.result;

    // كل مرة تتغير البيانات
    database.onversionchange = () => {
      console.log('ℹ️ TraineeDB version change detected.');
    };

    const transaction = database.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);

    const request = store.getAll();
    request.onsuccess = async (event) => {
      const allRecords = event.target.result;
      console.log(`👁️ Detected ${allRecords.length} trainee records, retraining model...`);
      await trainTraineeModelFromDB(db);
    };
  };

  dbRequest.onerror = (err) => console.error('❌ Failed to open traineeDB for watching:', err);
}

// -------------------- Take AI decision for a trainee --------------------
async function selectTraineeAction(trainee) {
  if (!traineeModel) {
    console.warn('⚠️ Trainee model not initialized.');
    return null;
  }

  const state = encodeTraineeState(trainee); // حول بيانات المتدرب لمصفوفة أرقام
  const input = tf.tensor2d([state]);
  const pred = traineeModel.predict(input);
  const idx = (await pred.argMax(-1).data())[0];
  input.dispose();
  if (pred.dispose) pred.dispose();

  const action = TRAINEE_ACTIONS[idx];
  console.log(`🤖 AI Decision for ${trainee.name || trainee.id}: ${action}`);
  return action;
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

function encodeAction(action) {
  return ACTIONS.map(a => (a === action ? 1 : 0));
}

// ======= محسّن: تحليل مبدئي بالقواعد (Heuristic) =======
function inferLabelHeuristic(logLineOrRecord) {
  const line = typeof logLineOrRecord === 'string'
    ? logLineOrRecord
    : `${logLineOrRecord.method || ''} ${logLineOrRecord.threatType || ''} ${logLineOrRecord.ip || ''}`;

  // قواعد قوية لاكتشاف SQLi / XSS / RCE / Scans
  const sqlPatterns = [
    /\b(union\s+select)\b/i,
    /\b(select\b.+\bfrom\b)/i,
    /\b(or|and)\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i,
    /--/i,
    /;\s*--?/i,
    /\b(drop|truncate|delete|insert|update)\b/i,
    /(\bunion\b|\binto\b.*\boutfile\b)/i,
    /\bselect\b\s+.*\bfrom\b/i,
    /\bunion\b.*\bselect\b/i
  ];

  const xssPatterns = [
    /<script\b[^>]*>([\s\S]*?)<\/script>/i,
    /onerror\s*=/i,
    /javascript:/i,
    /<img\b[^>]*src=.*>/i,
    /<iframe\b/i
  ];

  const rcePatterns = [
    /(\.exe\b|\/bin\/sh\b|\/bin\/bash\b|system\(|exec\(|popen\()/i,
    /curl\s+http/i
  ];

  const scanPatterns = [
    /\bnmap\b/i,
    /\bnikto\b/i,
    /masscan/i,
    /sqlmap/i,
    /wp-login\.php/i,
    /\bportscan\b/i
  ];

  // فحص كل مجموعة
  for (const rx of sqlPatterns) if (rx.test(line)) return { actionSuggested: 'block', reason: 'sql injection pattern', severityHint: 'high' };
  for (const rx of xssPatterns) if (rx.test(line)) return { actionSuggested: 'block', reason: 'xss pattern', severityHint: 'high' };
  for (const rx of rcePatterns) if (rx.test(line)) return { actionSuggested: 'block', reason: 'rce/command execution pattern', severityHint: 'high' };
  for (const rx of scanPatterns) if (rx.test(line)) return { actionSuggested: 'alert', reason: 'scan/tool fingerprint', severityHint: 'medium' };

  // كلمات عامة
  if (/(malware|attack|exploit|virus)/i.test(line)) return { actionSuggested: 'block', reason: 'malware/attack keyword', severityHint: 'high' };
  if (/post/i.test(line)) return { actionSuggested: 'alert', reason: 'http method POST', severityHint: 'low' };

  // افتراضي
  return { actionSuggested: 'ignore', reason: 'no heuristic match', severityHint: 'low' };
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

  const data = bootstrap.map(r => ({ state: encodeStateFromRecord(r), action: inferLabelHeuristic(`${r.method} ${r.threatType}`).actionSuggested }));
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
    return { type: top.label, severity, score: top.score, summary: `Label=${top.label} score=${top.score.toFixed(2)}` };
  } catch (err) {
    console.log(chalk.red('⚠️ LLM failed:', err.message));
    return { type: 'Other', severity: 'unknown', summary: 'LLM error' };
  }
}

// ======= محسّن: اختيار الإجراء مع تتبع مسار القرار =======
async function selectAction(state, llmResult = null, rawRecord = null) {
  // 1) احصل على قرار الـ DQN الافتراضي
  const input = tf.tensor2d([state]);
  const pred = model.predict(input);
  const idx = (await pred.argMax(-1).data())[0];
  input.dispose();
  if (pred.dispose) pred.dispose();
  let dqnAction = ACTIONS[idx];

  // 2) احصل على نتيجة الـ heuristic (نستخدم rawRecord لو متاح)
  const heuristic = inferLabelHeuristic(rawRecord || state);

  // 3) ابدأ بالإجراء المبدئي من DQN ثم نطبّق Overrides
  let finalAction = dqnAction;
  const decisionLog = {
    timestamp: new Date().toISOString(),
    ip: rawRecord?.ip || null,
    record: rawRecord || null,
    dqnAction,
    heuristic,
    llm: llmResult,
    finalAction: null,
    reason: null
  };

  // إذا الـ heuristic يطالب بالـ block مباشرة => override
  if (heuristic && heuristic.actionSuggested === 'block') {
    finalAction = 'block';
    decisionLog.reason = 'heuristic override (high confidence)';
  } else if (llmResult && llmResult.severity === 'high') {
    finalAction = 'block';
    decisionLog.reason = 'llm severity high';
  } else if (llmResult && llmResult.severity === 'medium' && finalAction === 'ignore') {
    finalAction = 'alert';
    decisionLog.reason = 'llm medium increased to alert';
  } else {
    decisionLog.reason = 'trusted dqn output';
  }

  decisionLog.finalAction = finalAction;

  // اطبع مسار القرار كاملًا
  console.log(chalk.magenta('🔎 Decision path:'), JSON.stringify(decisionLog, null, 2));

  // خزّن القرار في ملف decisions.json
  try {
    if (!fs.existsSync(path.dirname(DECISIONS_FILE))) fs.mkdirSync(path.dirname(DECISIONS_FILE), { recursive: true });
    let arr = [];
    if (fs.existsSync(DECISIONS_FILE)) {
      try { arr = JSON.parse(fs.readFileSync(DECISIONS_FILE, 'utf8')) || []; } catch { arr = []; }
    }
    arr.push(decisionLog);
    // احتفظ بآخر 500 قرار لتقليل النموذج
    if (arr.length > 500) arr = arr.slice(-500);
    fs.writeFileSync(DECISIONS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch (err) {
    console.error('❌ Failed to write decision log:', err.message);
  }

  return finalAction;
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
      return { timestamp, ip, method, threatType, raw: line };
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
  console.log(chalk.blue(`🤖 LLM analysis: type=${llm.type}, severity=${llm.severity} score=${llm.score || 0}`));
  const action = await selectAction(state, llm, lastRecord);

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


  // 🔹 نموذج المتدربين
 await loadOrInitModel();
  await loadOrInitTraineeModel();

  console.log(chalk.cyan('📡 Monitoring public CSV logs...'));
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.on('line', async () => {
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
