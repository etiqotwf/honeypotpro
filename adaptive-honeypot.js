// dqn-honeypot-ai.js
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


// تحديد مسار الملف
const logFilePath = path.join('logs', 'threats.csv');

// إنشاء الفولدر إذا مش موجود
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// إضافة رأس الأعمدة لو الملف جديد
if (!fs.existsSync(logFilePath)) {
  fs.writeFileSync(logFilePath, 'Timestamp,IP,Method,ThreatType\n');
}

 


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ACTIONS = ['block', 'alert', 'ignore'];
const MODEL_FILE = 'model.json';
const WEIGHTS_FILE = 'weights.bin';
const LEARNING_RATE = 0.01;
const EPOCHS = 50;

let model;

function encodeState(log) {
    const ipSuspicion = log.includes('192.168') ? 0 : 1;
    const requestType = log.includes('POST') ? 1 : 0;
    const keywordDetected = /(malware|attack|scan)/i.test(log) ? 1 : 0;
return [ipSuspicion, requestType, keywordDetected, 0, 0, 0, 0, 0]; // padding بـ 5 أصفار مؤقتًا
}

function inferLabel(log) {
    if (/malware|attack|scan/.test(log)) return 'block';
    if (/POST/.test(log)) return 'alert';
    return 'ignore';
}

function encodeAction(action) {
    return ACTIONS.map(a => (a === action ? 1 : 0));
}

function welcomeBanner() {
    console.clear();
    const title = figlet.textSync('DQN Honeypot', { horizontalLayout: 'full' });
    const banner = boxen(gradient.pastel.multiline(title), {
        padding: 1,
        margin: 1,
        borderStyle: 'round'
    });
    console.log(banner);
}

function generateTrainingData() {
    const logs = [
        "192.168.0.2 POST malware detected",
        "10.0.0.5 GET normal traffic",
        "172.16.0.1 POST scan attempt",
        "8.8.8.8 GET attack vector"
    ];
    return logs.map(log => ({ state: encodeState(log), action: inferLabel(log) }));
}

function createModel() {
    const model = tf.sequential();
model.add(tf.layers.dense({ units: 64, inputShape: [8], activation: 'relu' }));
    model.add(tf.layers.dense({ units: 64, activation: 'relu' }));
    model.add(tf.layers.dense({ units: ACTIONS.length, activation: 'softmax' }));
    model.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy' });
    return model;
}

async function saveModel(model) {
    const artifacts = await model.save(tf.io.withSaveHandler(async (artifacts) => artifacts));
    fs.writeFileSync(MODEL_FILE, JSON.stringify({
        modelTopology: artifacts.modelTopology,
        weightSpecs: artifacts.weightSpecs
    }));
    fs.writeFileSync(WEIGHTS_FILE, Buffer.from(artifacts.weightData));
    console.log(chalk.greenBright('✅ Model manually saved.'));
}

async function loadModel() {
    if (fs.existsSync(MODEL_FILE) && fs.existsSync(WEIGHTS_FILE)) {
        const modelData = JSON.parse(fs.readFileSync(MODEL_FILE));
        const weightData = fs.readFileSync(WEIGHTS_FILE);

        const artifacts = {
            modelTopology: modelData.modelTopology,
            weightSpecs: modelData.weightSpecs,
            weightData: new Uint8Array(weightData).buffer
        };

        model = await tf.loadLayersModel(tf.io.fromMemory(artifacts));
        model.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy' });
        console.log(chalk.green('📦 Model loaded and compiled.'));
    } else {
        model = createModel();
        const data = generateTrainingData();
        await trainModel(data);
    }
}

async function trainModel(data) {
    const xs = tf.tensor2d(data.map(d => d.state));
    const ys = tf.tensor2d(data.map(d => encodeAction(d.action)));

    console.log(chalk.cyan('🔧 Training model...'));

    await model.fit(xs, ys, {
        epochs: EPOCHS,
        callbacks: {
            onEpochEnd: (epoch, logs) => {
                console.log(chalk.gray(`Epoch ${epoch + 1}: Loss = ${logs.loss.toFixed(5)}`));
            }
        }
    });

    await saveModel(model);
    console.log(chalk.greenBright('✅ Training completed.'));
}

async function selectAction(state) {
    const input = tf.tensor2d([state]);
    const prediction = model.predict(input);
    const actionIdx = (await prediction.argMax(1).data())[0];
    return ACTIONS[actionIdx];
}

function executeAction(action, log, ip, method, threatType) {
    switch (action) {
        case 'block':
            console.log(chalk.redBright(`[BLOCKED] ${log}`));
            logThreat(ip, method, threatType); // ← تسجيل في CSV
            break;
        case 'alert':
            console.log(chalk.yellowBright(`[ALERT] ${log}`));
            break;
        default:
            console.log(chalk.gray(`[IGNORED] ${log}`));
    }
}


function ensureLogFileExists() {
    const logPath = path.join(__dirname, 'logs');
    const logFile = path.join(logPath, 'honeypot.log');

    if (!fs.existsSync(logPath)) fs.mkdirSync(logPath);

    if (!fs.existsSync(logFile)) {
        fs.writeFileSync(logFile, [
            "192.168.0.2 POST malware detected",
            "10.0.0.5 GET normal traffic",
            "172.16.0.1 POST scan attempt",
            "8.8.8.8 GET attack vector"
        ].join('\n'));
    }

    return logFile;
}

async function processLogs(logFile) {
    const rl = readline.createInterface({
        input: fs.createReadStream(logFile),
        crlfDelay: Infinity
    });

   for await (const line of rl) {
    const state = encodeState(line);
    const action = await selectAction(state);

    const [ip, method, ...rest] = line.split(' ');
    const threatType = rest.join(' ') || 'unknown';

    if (!ip || !method || !threatType) {
        console.log(chalk.bgRed(`❌ خطأ في تنسيق السطر: ${line}`));
        continue;
    }

    executeAction(action, line, ip, method, threatType);
}

}

(async () => {
    welcomeBanner();
    const logFile = ensureLogFileExists();
    await loadModel();
    await processLogs(logFile);
})();
