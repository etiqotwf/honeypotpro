import * as tf from '@tensorflow/tfjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// **جعل الملفات موجودة داخل فولدر public**
const PUBLIC_DIR = path.join(__dirname, 'public');
const MODEL_FILE = path.join(__dirname, 'model.json');
const WEIGHTS_FILE = path.join(__dirname, 'weights.bin');
const OUT_JSON = path.join(PUBLIC_DIR, 'weights-readable.json');

async function loadModelFromDisk(modelPath, weightsPath) {
  if (!fs.existsSync(modelPath) || !fs.existsSync(weightsPath)) {
    throw new Error('model.json أو weights.bin غير موجودين في المسار المحدد');
  }
  const modelData = JSON.parse(fs.readFileSync(modelPath, 'utf8'));
  const weightData = fs.readFileSync(weightsPath);
  const artifacts = {
    modelTopology: modelData.modelTopology,
    weightSpecs: modelData.weightSpecs,
    weightData: new Uint8Array(weightData).buffer
  };
  const model = await tf.loadLayersModel(tf.io.fromMemory(artifacts));
  return { model, artifacts };
}

function summarizeTensorArray(arr, maxElems = 10) {
  const flat = arr.flat(Infinity);
  const preview = flat.slice(0, maxElems);
  return { totalValues: flat.length, preview };
}

async function inspect() {
  try {
    const { model, artifacts } = await loadModelFromDisk(MODEL_FILE, WEIGHTS_FILE);
    console.log('✅ تم تحميل الموديل من القرص.');

    const weights = model.getWeights();
    const specs = artifacts.weightSpecs || [];
    const readable = [];

    for (let i = 0; i < weights.length; i++) {
      const t = weights[i];
      const spec = specs[i] || {};
      const shape = t.shape;
      const arr = await t.array();
      const summary = summarizeTensorArray(Array.isArray(arr) ? arr : [arr], 12);

      const explanation = `
هذا الوزن يخص الطبقة "${spec.name || 'n/a'}" من نوع ${t.dtype}.
الشكل (Dimensions) = [${shape.join(', ')}]
عدد القيم الكلي = ${summary.totalValues}.
المعنى: هذا الوزن يستخدم لضبط تأثير الإدخالات على مخرجات الطبقة.
الـ preview يوضح أول القيم القليلة لتقريب فكرة توزيع القيم.
بعد حفظ المعلومات، يتم تحرير الذاكرة لتجنب استهلاك زائد.
      `.trim();

      readable.push({
        index: i,
        name: spec.name || null,
        shape,
        dtype: t.dtype,
        totalValues: summary.totalValues,
        preview: summary.preview,
        explanation_ar: explanation
      });

      t.dispose && t.dispose();
    }

    const jsonOutput = {
      description: "ملخص الأوزان لكل طبقة في النموذج مع شرح تفصيلي بالعربية لكل خطوة.",
      layers: model.layers.map(l => ({
        name: l.name,
        className: l.getClassName(),
        explanation_ar: `هذه الطبقة من نوع ${l.getClassName()} وهي المسؤولة عن معالجة البيانات الداخلة وتحويلها للطبقة التالية.`
      })),
      weights: readable
    };

    fs.writeFileSync(OUT_JSON, JSON.stringify(jsonOutput, null, 2), 'utf8');
    console.log(`✅ تم حفظ ملخص الأوزان والشروحات في: ${OUT_JSON}`);

    model.dispose && model.dispose();
  } catch (err) {
    console.error('❌ خطأ أثناء الفحص:', err.message);
  }
}

inspect();
