// dqn-trainee-ai.js
// ملف مستقل لمعالجة وتدريب نموذج المتدربين (Trainee AI)
// الهدف: إزالة منطق الـ Honeypot الأمني واستبداله بمنطق المتدربين
// تشغيل: node dqn-trainee-ai.js

import * as tf from '@tensorflow/tfjs';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import figlet from 'figlet';
import boxen from 'boxen';
import gradient from 'gradient-string';

const __dirname = path.resolve();

// ==== ملفات ومسارات ==== 
const SAMPLE_CSV = path.join(__dirname, 'data', 'trainees_sample.csv');
const OUT_CSV = path.join(__dirname, 'outputs', 'recommendations.csv');
const TRAINEE_MODEL_JSON = path.join(__dirname, 'models', 'trainee_model.json');
const TRAINEE_WEIGHTS = path.join(__dirname, 'models', 'trainee_weights.bin');

// ==== إعدادات التدريب ==== 
const LEARNING_RATE = 0.01;
const EPOCHS = 40;
const BATCH_SIZE = 16;

// ==== شعار ترحيبي ====
function welcomeBanner() {
  console.clear();
  const title = figlet.textSync('Trainee AI', { horizontalLayout: 'full' });
  const banner = boxen(gradient.pastel.multiline(title), { padding: 1, margin: 1, borderStyle: 'round' });
  console.log(banner);
}

// ==== تعريف نموذج المتدرب (شبكة بسيطة) ====
let traineeModel = null;

function createTraineeModel(inputDim = 5) {
  const model = tf.sequential();
  model.add(tf.layers.dense({ units: 64, activation: 'relu', inputShape: [inputDim] }));
  model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 3, activation: 'softmax' })); // 3 فئات: recommendExtraTraining, sendAlertToAdmin, markAsGood
  model.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy', metrics: ['accuracy'] });
  return model;
}

async function loadOrInitTraineeModel() {
  // حاول تحميل من ملف إن ووجود ملفات
  try {
    if (fs.existsSync(TRAINEE_MODEL_JSON) && fs.existsSync(TRAINEE_WEIGHTS)) {
      console.log(chalk.cyan('📦 Found saved trainee model, loading...'));
      const modelData = JSON.parse(fs.readFileSync(TRAINEE_MODEL_JSON, 'utf8'));
      const weightData = fs.readFileSync(TRAINEE_WEIGHTS);
      const artifacts = {
        modelTopology: modelData.modelTopology,
        weightSpecs: modelData.weightSpecs,
        weightData: new Uint8Array(weightData).buffer,
      };
      traineeModel = await tf.loadLayersModel(tf.io.fromMemory(artifacts));
      traineeModel.compile({ optimizer: tf.train.adam(LEARNING_RATE), loss: 'categoricalCrossentropy' });
      console.log(chalk.green('✅ Trainee model loaded.'));
      return;
    }
  } catch (e) {
    console.log(chalk.yellow('⚠️ Failed to load existing trainee model, will create new one.'), e.message);
  }

  traineeModel = createTraineeModel();
  console.log(chalk.cyan('🧠 New trainee model initialized.'));
}

async function saveTraineeModelToDisk(m) {
  const artifacts = await m.save(tf.io.withSaveHandler(async (artifacts) => artifacts));
  // نكتب modelTopology and weightSpecs ثم weightData
  if (!fs.existsSync(path.dirname(TRAINEE_MODEL_JSON))) fs.mkdirSync(path.dirname(TRAINEE_MODEL_JSON), { recursive: true });
  fs.writeFileSync(TRAINEE_MODEL_JSON, JSON.stringify({ modelTopology: artifacts.modelTopology, weightSpecs: artifacts.weightSpecs }), 'utf8');
  fs.writeFileSync(TRAINEE_WEIGHTS, Buffer.from(artifacts.weightData));
  console.log(chalk.greenBright('✅ Trainee model saved to disk.'));
}

// ==== تحويل تقييم عربي إلى قيمة عددية 0-100 ====
function mapArabicRatingToScore(rating) {
  if (!rating) return 50;
  rating = String(rating).toLowerCase();
  if (rating.includes('ممتاز') || rating.includes('جيد جداً')) return 90;
  if (rating.includes('جيد')) return 75;
  if (rating.includes('متوسط')) return 60;
  if (rating.includes('ضعيف')) return 40;
  if (rating.includes('جداً ضعيف') || rating.includes('ضعيف جداً')) return 20;
  return 50;
}

// ==== استخراج ميزات من صف المتدرب ====
function featurizeRow(row) {
  // نفترض رؤوس الأعمدة بالعربية كما اتفقنا
  const ratingScore = mapArabicRatingToScore(row['تقييم_عام'] || row['تقييم'] || '');
  const notes = String(row['ملاحظات'] || '').toLowerCase();
  const hasNotes = notes.trim() ? 1 : 0;
  const course = String(row['اسم الدورة'] || row['📘 اسم الدورة'] || '').toLowerCase();
  const hasExcel = /excel|اكسل|إكسل/.test(course) ? 1 : 0;
  const hasPowerBI = /power bi|باور بي/i.test(course) ? 1 : 0;
  let daysSinceReg = 0;
  try {
    const dateStr = row['تاريخ_التسجيل'] || row['📅 بداية الدورة'] || '';
    if (dateStr) {
      const d = new Date(dateStr);
      if (!isNaN(d)) {
        daysSinceReg = Math.floor((Date.now() - d.getTime()) / (1000*60*60*24));
        daysSinceReg = Math.min(daysSinceReg, 3650);
      }
    }
  } catch (e) { daysSinceReg = 0; }

  const f_rating = ratingScore / 100; // 0..1
  const f_hasNotes = hasNotes;
  const f_hasExcel = hasExcel;
  const f_hasPowerBI = hasPowerBI;
  const f_days = Math.tanh(daysSinceReg / 365);

  return [f_rating, f_hasNotes, f_hasExcel, f_hasPowerBI, f_days];
}

// ==== استنتاج تسمية مبدئية (Bootstrap label) ====
function inferLabel(row) {
  const rating = String(row['تقييم_عام'] || row['تقييم'] || '').toLowerCase();
  const notes = String(row['ملاحظات'] || '').toLowerCase();
  const course = String(row['اسم الدورة'] || row['📘 اسم الدورة'] || '').toLowerCase();

  if (rating.includes('ضعيف') || notes.includes('ضع') || notes.includes('لم يحضر') || notes.includes('غائب')) return 'recommendExtraTraining';
  if (/excel|اكسل|إكسل/.test(course) || /مبتدئ|تمهيدى|تمهيدي/.test(course)) return 'recommendExtraTraining';
  if (rating.includes('ممتاز') || rating.includes('جيد')) return 'markAsGood';
  return 'markAsGood';
}

// ==== قراءة CSV بسيط ====
function readCsvSimple(csvPath) {
  if (!fs.existsSync(csvPath)) return [];
  const text = fs.readFileSync(csvPath, 'utf8').trim();
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  const header = lines.shift().split(',').map(h => h.trim());
  const rows = lines.map(line => {
    const parts = line.split(',');
    const obj = {};
    for (let i=0;i<header.length;i++) obj[header[i]] = (parts[i] || '').trim();
    return obj;
  });
  return rows;
}

// ==== تحويل label إلى one-hot vector ====
function encodeLabel(action) {
  const mapping = { 'recommendExtraTraining': 0, 'sendAlertToAdmin': 1, 'markAsGood': 2 };
  const idx = mapping[action] !== undefined ? mapping[action] : 2;
  const arr = [0,0,0]; arr[idx] = 1; return arr;
}

// ==== تدريب النموذج على عيّنة CSV ====
async function trainTraineeFromCsv(csvPath, epochs = EPOCHS) {
  const rows = readCsvSimple(csvPath);
  if (!rows.length) { console.log(chalk.yellow('⚠️ لا يوجد بيانات في ملف العينة.')); return; }

  const pairs = rows.map(r => ({ state: featurizeRow(r), action: inferLabel(r), raw: r }));
  const X = tf.tensor2d(pairs.map(p => p.state));
  const y = tf.tensor2d(pairs.map(p => encodeLabel(p.action)));

  console.log(chalk.cyan(`🔧 تدريب النموذج على ${pairs.length} عينة لعدد ${epochs} epochs...`));
  await traineeModel.fit(X, y, { epochs, batchSize: Math.min(BATCH_SIZE, pairs.length), shuffle: true, callbacks: { onEpochEnd: (epoch, logs) => console.log(`Epoch ${epoch+1}: loss=${(logs.loss||0).toFixed(5)} accuracy=${((logs.acc||logs.accuracy)||0).toFixed(3)}`) } });

  await saveTraineeModelToDisk(traineeModel);
  X.dispose(); y.dispose();
  console.log(chalk.green('✅ تم تدريب وحفظ نموذج المتدربين.'));
}

// ==== توليد توصية نصية مبسطة لكل صف وحفظها في CSV خروجى ====
function generateRecommendationsCsv(rows, outPath) {
  const header = ['الاسم','البريد الإلكتروني','الإدارة','اسم الدورة','توصية_نصية','label'];
  const lines = [header.join(',')];
  for (const r of rows) {
    const features = featurizeRow(r);
    const pred = traineeModel.predict(tf.tensor2d([features]));
    const idx = pred.argMax(-1).dataSync()[0];
    pred.dispose();
    const label = idx === 0 ? 'recommendExtraTraining' : (idx === 1 ? 'sendAlertToAdmin' : 'markAsGood');
    let textRec = '';
    if (label === 'recommendExtraTraining') textRec = 'نقترح التحقُّق بحضور دورات متقدمة أو إعادة متابعة المحتوى العملى.';
    else if (label === 'sendAlertToAdmin') textRec = 'يوجد مؤشرات تستدعى تنبيه الإدارة (غياب متكرر أو ملاحظات).';
    else textRec = 'أداء جيد — متابعة دورية فقط.';

    const line = [ (r['الاسم']||r['👤 الاسم']||''), (r['البريد الإلكتروني']||r['📧 البريد الإلكتروني']||''), (r['الإدارة']||r['🏢 الإدارة']||''), (r['اسم الدورة']||r['📘 اسم الدورة']||''), textRec.replace(/,/g,' '), label ].join(',');
    lines.push(line);
  }
  if (!fs.existsSync(path.dirname(outPath))) fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
  console.log(chalk.green(`📄 تم حفظ توصيات المتدربين إلى ${outPath}`));
}

// ==== وظيفة مساعدة لتشغيل كل الخطوات ====
async function runBootstrapFlow() {
  welcomeBanner();
  await loadOrInitTraineeModel();
  // تدريب مبدئي من CSV
  await trainTraineeFromCsv(SAMPLE_CSV, Math.min(40, EPOCHS));
  // قراءة نفس الملف وإنتاج توصيات
  const rows = readCsvSimple(SAMPLE_CSV);
  generateRecommendationsCsv(rows, OUT_CSV);
  console.log(chalk.blue('🎯 انتهت مرحلة الـ Bootstrap - راجع الملف المصدّر outputs/recommendations.csv'));
}

// ==== Exports: وظائف يمكن استدعاؤها من ملف آخر ====
export {
  loadOrInitTraineeModel,
  trainTraineeFromCsv,
  featurizeRow,
  inferLabel,
  traineeModel,
  runBootstrapFlow,
  generateRecommendationsCsv,
};

// ==== شغّل مباشرة لو تم تشغيل الملف كـ CLI ====
if (process.argv[1] && process.argv[1].endsWith('dqn-trainee-ai.js')) {
  runBootstrapFlow().catch(err => console.error('Fatal:', err));
}
