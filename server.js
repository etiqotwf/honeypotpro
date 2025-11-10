import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { exec, spawn } from 'child_process';

// لو محتاج __dirname في ES Module
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const blockedFile = path.join(__dirname, 'blocked.json');



import { fork } from 'child_process';
import { execSync } from "child_process"; // ✅ ممكن نحتفظ بالاستدعاء لو احتجناه لاحقًا

// NOTE: تم تعطيل أي تفاعل مع GitHub — "local only mode"
// منع تحذير LF → CRLF في Git (اختياري، لا يؤثر على رفع أي شيء)
exec('git config core.autocrlf false', (error) => {
  if (error) {
    console.warn('⚠️ Warning: Failed to set Git config for autocrlf');
  }
});

const app = express();
const PORT = 3000;

let serverUrl = "";
const logDir = './public/logs';
const logPath = path.join(logDir, 'threats.csv');


// === ملاحظة هامة ===
// تم إزالة فحص GITHUB_TOKEN وإيقاف أي push أو interactions مع GitHub.
// إذا حبيت ترجّع الرفع لاحقًا، أقدر أرجعها لكن بنمط آمن (اختياري).

// ===== Concurrency / scheduling helpers =====
let honeypotProcessing = false;
let honeypotPending = false;
let pushTimer = null;
const PUSH_DEBOUNCE_MS = 15 * 1000; // اجمع push واحد كل 15 ثانية كحد أدنى

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({ origin: "*" }));
app.use(bodyParser.json());


// ===== Blocklist / Firewall helpers =====
let blockedSet = new Set();

// Load persisted blocked IPs on startup
try {
  if (fs.existsSync(blockedFile)) {
  const arr = JSON.parse(fs.readFileSync(blockedFile, 'utf8') || '[]');
  // trim لكل قيمة عشان لا توجد فراغات أو محارف مخفية
  blockedSet = new Set(Array.isArray(arr) ? arr.map(s => s.toString().trim()) : []);
  console.log(`🔒 Loaded ${blockedSet.size} blocked IP(s) from blocked.json`);
}

} catch (e) {
  console.error('⚠️ Failed to load blocked.json:', e.message);
}


// Middleware لتحسين التسجيل وفحص الحظر المبكر
app.use((req, res, next) => {
  try {
    let ip = getClientIp(req);           // استخرج IP من request
    let normIp = normalizeIp(ip);        // تطبيع IP (::ffff:127.0.0.1 → 127.0.0.1)

    // Debug log لكل request

    // ----- فحص الحظر المبكر -----
    if (blockedSet.has(normIp)) {
      console.log(`⛔ BLOCKED (blockedSet): request from ${normIp}`);
      try {
        fs.appendFileSync(logPath, `${new Date().toISOString()},${normIp},${req.method},"blocked (early)",auto\n`);
      } catch (e) {
        console.error('⚠️ Failed to append early-block log:', e.message);
      }
      return res.status(403).send('⛔ Access Denied (blockedSet)');
    }

    // ----- فحص localhost -----
    if (isLocalhost(normIp)) {
      return next();  // السماح دائمًا للـ localhost
    }

    // ----- فحص IP محظور مؤقتًا في الذاكرة -----
    if (blockedIPs.has(normIp)) {
      console.log(`⛔ BLOCKED (in-memory): request from ${normIp}`);
      return res.status(403).send('⛔ Access Denied (in-memory)');
    }

    // ----- تسجيل الطلبات العادية -----
    const method = req.method;
    const originalUrl = req.originalUrl || req.url || "";
    const bodyData = Object.keys(req.body || {}).length ? JSON.stringify(req.body) : "";
    const combined = `${originalUrl} ${bodyData}`.trim();
    const lowerData = combined.toLowerCase();

    // 🧠 تحليل مبدئي (Heuristic)
    let threatType = "normal visit";
    if (/(malware|\.exe|virus|exploit)/i.test(lowerData)) threatType = "malware detected";
    else if (/(nmap|scan|banner grab|sqlmap)/i.test(lowerData)) threatType = "scan attempt";
    else if (/union\s+select|drop\s+table|\bor\b\s+['"]?1['"]?\s*=\s*['"]?1|or 1=1/i.test(lowerData)) threatType = "sql injection attempt";
    else if (/(<script\b|onerror=|javascript:)/i.test(lowerData)) threatType = "xss attempt";
    else if (/(login attempt|password guess|brute force)/i.test(lowerData)) threatType = "brute force attempt";
    else if (/post/i.test(method)) threatType = "post request";

    const timestamp = new Date().toISOString();
    const safeOriginal = originalUrl.replace(/,/g, ";").replace(/\"/g, '\\"');
    const logLine = `${timestamp},${normIp},${method},"${threatType} | ${safeOriginal}",auto\n`;

    fs.appendFileSync(logPath, logLine);
    console.log(`📥 [AUTO] ${normIp} ${method} ${originalUrl} => ${threatType}`);

  } catch (err) {
    console.error("❌ Middleware error writing to threats.csv:", err);
  }

  next();
});

// استجابة خاصة للروت الرئيسي
app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'fake_login.html'));
});
app.use(express.static('public'));

// ✅ إنشاء مجلد logs داخل public إن لم يكن موجودًا
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}
if (!fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, 'Timestamp,IP,Method,ThreatType,Action,Attempts\n');
}






// Reload blocked.json automatically when changed on disk (helps when you edit the file manually)
fs.watchFile(blockedFile, { interval: 2000 }, () => {
  try {
    const arr = JSON.parse(fs.readFileSync(blockedFile, 'utf8') || '[]');
    blockedSet = new Set(Array.isArray(arr) ? arr.map(s => s.toString().trim()) : []);
    console.log(`🔁 Reloaded blocked.json — ${blockedSet.size} entries`);
  } catch (ex) {
    console.error('⚠️ Failed to reload blocked.json:', ex.message);
  }
});


// Save blockedSet to disk
function persistBlocked() {
  try {
    fs.writeFileSync(blockedFile, JSON.stringify([...blockedSet], null, 2), 'utf8');
    console.log(`💾 Saved ${blockedSet.size} blocked IP(s) to ${blockedFile}`);
  } catch (e) {
    console.error('⚠️ Failed to persist blocked.json:', e.message);
  }
}

// Helper to detect localhost-like IPs and normalize
function normalizeIp(raw) {
  if (!raw) return 'unknown';
  return raw.replace(/^::ffff:/, '');
}
function isLocalhost(rawIp) {
  const ip = normalizeIp(rawIp || '').trim();
  return ip === '::1' || ip === '127.0.0.1' || ip === 'localhost' || ip === '0:0:0:0:0:0:0:1';
}



// Middleware لتحسين التسجيل — لا يقوم بأي push إلى GitHub الآن
// مؤقت: تخزين محلي لعناوين محظورة (يُستخدم لأغراض وقتية داخل الذاكرة)
const blockedIPs = new Set();

// Helper to get client IP reliably (prefers X-Forwarded-For)
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'];
  if (xff && typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
  if (req.socket && req.socket.remoteAddress) return req.socket.remoteAddress.replace(/^::ffff:/, '').trim();
  return 'unknown';
}



// ✅ تسجيل التهديدات من الهونى بوت فقط
app.post('/api/logs', (req, res) => {
    const { timestamp, ip, method, threatType } = req.body;
    const logLine = `${timestamp},${ip},${method},${threatType},manual\n`;
    fs.appendFileSync(logPath, logLine);
    console.log(`📥 [BOT] ${ip} ${method} => ${threatType}`);
    res.status(200).json({ message: '✅ Threat logged (manual)' });
});

// ✅ API لعرض التهديدات
app.get('/api/logs', (req, res) => {
    if (!fs.existsSync(logPath)) return res.json([]);
    const data = fs.readFileSync(logPath, 'utf-8').trim().split('\n').slice(1);
    const logs = data.map(line => {
        const [timestamp, ip, method, threatType, action] = line.split(',');
        return { timestamp, ip, method, threatType, action };
    });
    res.json(logs.reverse());
});

app.get('/api/threats', (req, res) => {
    const rootLogPath = path.join(process.cwd(), 'logs', 'threats.csv');
    if (!fs.existsSync(rootLogPath)) return res.status(404).send('File not found');

    const data = fs.readFileSync(rootLogPath, 'utf8');
    res.type('text/csv').send(data);
});

// ✅ تحميل CSV
app.get('/download/csv', (req, res) => res.download(logPath));

// ✅ تحميل JSON
app.get('/download/json', (req, res) => {
    const data = fs.readFileSync(logPath, 'utf8')
        .split('\n').slice(1).filter(Boolean).map(row => {
            const [Timestamp, IP, Method, ThreatType] = row.split(',');
            return { Timestamp, IP, Method, ThreatType };
        });
    res.json(data);
});

// ✅ API للحصول على ngrok URL
app.get("/ngrok-url", (req, res) => {
    if (serverUrl) res.json({ serverUrl });
    else res.status(500).json({ message: "ngrok has not started yet!" });
});

// بث مباشر للتيرمينال في المتصفح
let clients = [];

app.get('/events', (req, res) => {
  // ضروري: نرسل headers ثم نبقي الاتصال مفتوحاً
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  // CORS معمول global لكن نضيف هنا للتأكيد
  res.setHeader('Access-Control-Allow-Origin', '*');

  // إرسال ترويسة فورية لضمان فتح الاتصال في المتصفح
  if (res.flushHeaders) res.flushHeaders();
  // رسالة افتتاحية (event: system) والبيانات بصيغة JSON
  res.write(`event: system\n`);
  res.write(`data: ${JSON.stringify({ msg: 'SSE connected', ts: new Date().toISOString() })}\n\n`);

  // احتفظ بالعميل في المصفوفة
  clients.push(res);

  // إرسال نبضة كل 15 ثانية للحفاظ على الاتصال حيًّا (تجنّب timeouts / proxies)
  const keepAlive = setInterval(() => {
    try {
      // تعليق بسيط (SSE comment) — لا ينتج حدث افتراضي لكنه يحافظ على الاتصال
      res.write(`: keep-alive ${Date.now()}\n\n`);
    } catch (e) {
      // إذا الكتابة فشلت، نصفي العميل
      clearInterval(keepAlive);
    }
  }, 15000);

  // تنظيف عند إغلاق الطلب
  req.on('close', () => {
    clearInterval(keepAlive);
    clients = clients.filter(c => c !== res);
  });
});


function sendToClients(data, type = 'line') {
  clients.forEach(res => {
    res.write(`data: ${JSON.stringify({ type, msg: data })}\n\n`);
  });
}

// مثال على تشغيل PowerShell
app.post('/start-powershell', (req, res) => {
  const ps = spawn('powershell.exe', ['-NoProfile', '-Command', 'Get-Process']); // مثال: يمكن تعديل أي أمر

  ps.stdout.on('data', chunk => {
    sendToClients(chunk.toString(), 'line'); // إرسال stdout
  });

  ps.stderr.on('data', chunk => {
    sendToClients(chunk.toString(), 'attack'); // إرسال stderr بلون مختلف
  });

  ps.on('close', code => {
    sendToClients(`[System] PowerShell exited with code ${code}`, 'system');
  });

  res.json({ status: 'started' });
});

// دالة تبث أى سطر يظهر في التيرمينال
function broadcastLine(line) {
  for (const c of clients) {
    c.write(`event: line\n`);
    c.write(`data: ${JSON.stringify(line)}\n\n`);
  }
}

// تعديل console.log و console.error ليبثوا للواجهة
const origLog = console.log;
const origErr = console.error;

console.log = (...args) => {
  const msg = args.join(' ');
  broadcastLine(msg);
  origLog.apply(console, args);
};

console.error = (...args) => {
  const msg = args.join(' ');
  broadcastLine(`[ERROR] ${msg}`);
  origErr.apply(console, args);
};

// بدء الخادم و ngrok
function startNgrokWithPolling() {
  const killCmd = process.platform === 'win32'
    ? 'taskkill /im ngrok.exe /f'
    : "pgrep -f 'ngrok' && pkill -f 'ngrok'";

  exec(killCmd, () => {
    exec("ngrok.exe http 3000 --log=stdout", (err) => {
      if (err) console.error("❌ Error starting ngrok (start command):", err.message || err);
      else console.log("✅ ngrok start command issued (process may take a moment).");
    });

    const pollInterval = 5000; // كل 5 ثواني نجرب
    const poller = setInterval(() => {
      exec("curl -s http://127.0.0.1:4040/api/tunnels", (err, stdout) => {
        if (err || !stdout) {
          if (process.platform === 'win32') {
            exec("powershell -Command \"(Invoke-WebRequest -Uri 'http://127.0.0.1:4040/api/tunnels' -UseBasicParsing).Content\"", (psErr, psStdout) => {
              if (psErr || !psStdout) {
                console.log("🔁 ngrok not ready yet — retrying...");
                return;
              }
              try {
                processNgrokResponse(psStdout);
                clearInterval(poller);
              } catch (e) {
                console.error("❌ Error parsing ngrok response (ps fallback):", e.message || e);
              }
            });
            return;
          }

          console.log("🔁 ngrok not ready yet — retrying...");
          return;
        }

        try {
          processNgrokResponse(stdout);
          clearInterval(poller);
        } catch (e) {
          console.error("❌ Error parsing ngrok response:", e.message || e);
        }
      });
    }, pollInterval);
  });
}

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  // Sync مبدئي للنماذج
  syncModelToPublic();
  startNgrokWithPolling();
});

function processNgrokResponse(response) {
  try {
    const tunnels = JSON.parse(response);
    serverUrl = tunnels.tunnels[0]?.public_url || null;
    console.log(`✅ Server URL (ngrok) is: ${serverUrl || 'not used'}`);
    fs.writeFileSync("serverUrl.json", JSON.stringify({ serverUrl }));

    // أرسل حدث ngrok لجميع عملاء الSSE فوراً
    if (serverUrl) {
      sendToClients(serverUrl, 'ngrok'); // سيُستقبل في الواجهة كـ ngrok event
    }

    const terminalUrl = `http://localhost:${PORT}/terminal.html`;

    setTimeout(() => {
      try {
        openTerminal(terminalUrl);
      } catch (e) {
        console.error('❌ Error while trying to open terminal page:', e);
      }
    }, 1500);
  } catch (e) {
    console.error("❌ Error parsing ngrok response:", e);
  }
}

function openTerminal(url) {
  const platform = process.platform;
  const launchDetached = (command, args = [], useShell = false) => {
    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
        shell: useShell
      });
      child.unref();
      return true;
    } catch {
      return false;
    }
  };

  if (platform === 'win32') {
    const chromePaths = [
      process.env['PROGRAMFILES'] ? path.join(process.env['PROGRAMFILES'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['PROGRAMFILES(X86)'] ? path.join(process.env['PROGRAMFILES(X86)'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['LOCALAPPDATA'] ? path.join(process.env['LOCALAPPDATA'], 'Google\\Chrome\\Application\\chrome.exe') : null
    ].filter(Boolean);

    for (const p of chromePaths) {
      if (fs.existsSync(p)) {
        if (launchDetached(p, ['--new-window', url])) {
          console.log('✅ Terminal opened in Google Chrome (detached).');
          return;
        }
      }
    }

    exec(`start "" "${url}"`, (err) => {
      if (err) console.error('❌ Failed to open terminal (fallback):', err);
      else console.log('✅ Terminal opened in default browser (fallback).');
    });
    return;
  }

  if (platform === 'darwin') {
    if (!launchDetached('open', ['-g', '-a', 'Google Chrome', url])) {
      exec(`open "${url}"`, (err) => {
        if (err) console.error('❌ Failed to open terminal on macOS:', err);
        else console.log('✅ Terminal opened on macOS.');
      });
    } else {
      console.log('✅ Terminal opened in Chrome on macOS.');
    }
    return;
  }

  const linuxCommands = ['google-chrome', 'google-chrome-stable', 'chromium-browser', 'chromium', 'firefox', 'xdg-open'];
  for (const cmd of linuxCommands) {
    if (launchDetached(cmd, [url])) {
      console.log(`✅ Terminal opened on Linux using ${cmd}.`);
      return;
    }
  }

  exec(`xdg-open "${url}"`, (err) => {
    if (err) console.error('❌ Failed to open terminal on Linux:', err);
    else console.log('✅ Terminal opened on Linux (fallback).');
  });
}

// تم تعديل pushToGitHub ليصبح no-op: لا يقوم بأي عمليات Git أو Push
function pushToGitHub() {
  console.log('🚫 GitHub push disabled — running in local-only mode.');
  // لو عايز في المستقبل تفعّل ربط آمن، أرجع نضيف هنا منطق مصادقة آمنة وإرسال فقط ملفات اللوج.
}

// API لإضافة تهديد يدويًا — الآن لا يدفع لGitHub
app.post('/api/add-threat', (req, res) => {
    const { ip, method, threatType } = req.body;
    if (!ip || !method || !threatType) return res.status(400).json({ message: '❌ Missing threat data' });
    const timestamp = new Date().toISOString();
    const newLine = `${timestamp},${ip},${method},${threatType},manual\n`;
    try {
        fs.appendFileSync(logPath, newLine);
        console.log(`✅ Threat added: ${ip}, ${method}, ${threatType}`);
        // مُعطّل: pushToGitHub();
        res.status(200).json({ message: '✅ Threat added (local only)'});
    } catch (err) {
        console.error("❌ Failed to write threat:", err);
        res.status(500).json({ message: '❌ Failed to write threat' });
    }
});



// محاكاة هجوم/دخول: يكتب سطر في public/logs/threats.csv لتشغيل الـ watchers والـ AI
app.post('/simulate-attack', (req, res) => {
  try {
    const ip = getClientIp(req) || '127.0.0.1';
    const timestamp = new Date().toISOString();

    // تأكد أن logPath معرف ويشير إلى ./public/logs/threats.csv
    // تنسيق الأعمدة: Timestamp,IP,Method,ThreatType,Action,Attempts
    const newLine = `${timestamp},${ip},GET,simulated-attack,manual,1\n`;

    fs.appendFileSync(logPath, newLine, 'utf8');

    // أخبر عملاء SSE عن الحدث (اختياري لكن مفيد)
    try {
      sendToClients({ type: 'simulate-attack', msg: `Simulated attack logged: ${ip}` }, 'system');
    } catch (e) { /* لا تقاطع التنفيذ لو فشل البث */ }

    console.log(`✅ Simulated attack logged: ${ip}`);
    return res.json({ ok: true, message: 'Simulated attack logged' });
  } catch (err) {
    console.error('❌ /simulate-attack error:', err);
    return res.status(500).json({ ok: false, error: String(err) });
  }
});




// المسارات
const aiDecisionPath = path.join(__dirname, 'logs', 'decisions.json');
const threatLogPath = path.join(__dirname, 'logs', 'threats.csv');

// ✅ إنشاء المجلد logs إذا مش موجود
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

// ✅ إنشاء ملف فارغ decisions.json إذا غير موجود
if (!fs.existsSync(aiDecisionPath)) {
  fs.writeFileSync(aiDecisionPath, '[]');
}


fs.watch(aiDecisionPath, async (eventType) => {
  if (eventType === 'change') {
    try {
      const content = fs.readFileSync(aiDecisionPath, 'utf8');
      const decisions = JSON.parse(content);

      if (Array.isArray(decisions) && decisions.length) {
        const last = decisions[decisions.length - 1];
        const { ip, record, finalAction, reason } = last;

        if (finalAction === 'block') {
          // ✳️ Skip blocking localhost to avoid self-blocking during local testing
          if (isLocalhost(ip)) {
            console.log(`🟢 Localhost detected (${ip}) — skipping block by AI decision (${reason})`);

            // Log the decision but do NOT persist to blocked.json
            fs.appendFileSync(
              threatLogPath,
              `${new Date().toISOString()},${ip},${record?.method || 'N/A'},${record?.threatType || 'N/A'},IGNORED-BLOCK (localhost)\n`
            );

            sendToClients({ type: 'ai-decision', action: 'ignored-block-local', ip, reason });
            return;
          }

          blockedSet.add(ip);
          persistBlocked(); // ✅ هي دي اللي بتنشئ blocked.json فعليًا

          fs.appendFileSync(
            threatLogPath,
            `${new Date().toISOString()},${ip},${record?.method || 'N/A'},${record?.threatType || 'N/A'},BLOCKED by AI (${reason})\n`
          );

          console.log(`🚫 [AI Decision] Blocked IP ${ip} — ${reason}`);
          sendToClients({ type: 'ai-decision', action: finalAction, ip, reason });
        }
      }
    } catch (err) {
      console.error('⚠️ Error reading AI decision file:', err.message);
    }
  }
});

console.log('👁️ Watching logs/decisions.json for AI decisions...');


// Sync Model to Public (only if changed)
function copyIfChanged(src, dest) {
  if (!fs.existsSync(src)) return;
  const srcStat = fs.statSync(src);
  const destStat = fs.existsSync(dest) ? fs.statSync(dest) : null;

  if (!destStat || srcStat.mtimeMs !== destStat.mtimeMs || srcStat.size !== destStat.size) {
    fs.copyFileSync(src, dest);
  }
}

function syncModelToPublic() {
  const ROOT_DIR = process.cwd();
  const PUBLIC_DIR = path.join(ROOT_DIR, "public");

  const MODEL_JSON = path.join(ROOT_DIR, "model.json");
  const MODEL_BIN = path.join(ROOT_DIR, "weights.bin");

  const PUBLIC_MODEL_JSON = path.join(PUBLIC_DIR, "model.json");
  const PUBLIC_MODEL_BIN = path.join(PUBLIC_DIR, "weights.bin");

  try {
    copyIfChanged(MODEL_JSON, PUBLIC_MODEL_JSON);
    copyIfChanged(MODEL_BIN, PUBLIC_MODEL_BIN);
  } catch (err) {
    console.error("❌ Error copying model files to public:", err);
  }
}

// Watch for model/weights changes
const modelPath = path.join(process.cwd(), 'model.json');
const weightsPath = path.join(process.cwd(), 'weights.bin');

[modelPath, weightsPath].forEach(file => {
  if (fs.existsSync(file)) {
    fs.watchFile(file, { interval: 5000 }, (curr, prev) => {
      if (curr.mtime !== prev.mtime) {
        syncModelToPublic();
      }
    });
  }
});

// مراقبة ملف threats.csv في مجلد logs (جذر المشروع)
const projectLogPath = path.join(process.cwd(), 'logs', 'threats.csv');

if (fs.existsSync(projectLogPath)) {
    fs.watchFile(projectLogPath, { interval: 5000 }, (curr, prev) => {
        if (curr.mtime !== prev.mtime) {
            console.log("📝 Detected change in project logs/threats.csv");
            // معطّل: pushToGitHub();
        }
    });
} else {
    console.warn("⚠️ Project logs/threats.csv not found, skipping watch...");
}

// مراقبة public/logs/threats.csv وتشغيل الـ Adaptive Honeypot على آخر سطر
const publicLogPath = path.join(process.cwd(), 'public', 'logs', 'threats.csv');

if (fs.existsSync(publicLogPath)) {
  fs.watchFile(publicLogPath, { interval: 3000 }, (curr, prev) => {
    if (curr.mtime !== prev.mtime) {
      console.log("👁️ Detected new entry in public/logs/threats.csv");

      const content = fs.readFileSync(publicLogPath, 'utf8').trim();
      const lines = content.split(/\r?\n/);
      const lastLine = lines[lines.length - 1];

      if (lastLine && !lastLine.startsWith("Timestamp")) {
    console.log(`🆕 New line detected: ${lastLine}`);

    const runHoneypot = () => {
        if (honeypotProcessing) {
            honeypotPending = true;
            console.log('⏳ Honeypot busy — scheduling pending run.');
            return;
        }
        honeypotProcessing = true;

        const child = spawn(process.execPath, ['adaptive-honeypot.js', lastLine], { cwd: process.cwd() });

        child.stdout.on('data', (data) => {
            const text = data.toString();
            sendToClients(`[HONEYPOT] ${text}`, 'line');
            process.stdout.write(`[HONEYPOT] ${text}`);
        });

        child.stderr.on('data', (data) => {
            const text = data.toString();
            sendToClients(`[HONEYPOT-ERR] ${text}`, 'attack');
            process.stderr.write(`[HONEYPOT-ERR] ${text}`);
        });

        child.on('close', (code) => {
            const msg = `🤖 Honeypot process exited with code ${code}`;
            sendToClients(msg, 'system');
            console.log(msg);

            honeypotProcessing = false;
            if (honeypotPending) {
                honeypotPending = false;
                setTimeout(runHoneypot, 500);
            }
        });
    };

    runHoneypot();
}
    }
  });
} else {
  console.warn("⚠️ public/logs/threats.csv not found, skipping watch...");
}

// أي طلب غير static و API يرجع صفحة الفيك
app.get('*', (req, res) => {
  if (
    req.path.startsWith('/api') ||
    req.path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|json)$/)
  ) {
    return res.status(404).send('Not Found');
  }

  res.sendFile(path.join(process.cwd(), 'public', 'fake_login.html'));
});
