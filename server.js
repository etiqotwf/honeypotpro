import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { exec, spawn } from 'child_process';
import { fork } from 'child_process';
import { execSync } from "child_process"; // ✅ أضف هذا السطر هنا
// ✅ منع تحذير LF → CRLF في Git
exec('git config core.autocrlf false', (error) => {
  if (error) {
    console.warn('⚠️ Warning: Failed to set Git config for autocrlf');
  } else {
   // console.log('✅ Git line ending config set (LF preserved)');
  }
});



const app = express();
const PORT = 3000;

let serverUrl = "";
const logDir = './public/logs';
const logPath = path.join(logDir, 'threats.csv');
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

if (!GITHUB_TOKEN) {
    console.error("❌ GitHub token not found in environment variables!");
    process.exit(1);
}



// ===== Concurrency / scheduling helpers =====
let honeypotProcessing = false;
let honeypotPending = false;
let pushTimer = null;
const PUSH_DEBOUNCE_MS = 15 * 1000; // اجمع push واحد كل 15 ثانية كحد أدنى




app.use(bodyParser.urlencoded({ extended: true }));


app.use(cors({ origin: "*" }));
app.use(bodyParser.json());
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


// Middleware القديم اللي كان يسجل كل زيارة تلقائيًا أصبح معلق
// ---- Enhanced logging middleware (replace existing middleware) ----
app.use((req, res, next) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const method = req.method;
    const originalUrl = req.originalUrl || req.url || '';
    const bodyData = Object.keys(req.body || {}).length ? JSON.stringify(req.body) : '';
    const combined = `${originalUrl} ${bodyData}`.trim();
    const lowerData = combined.toLowerCase();

    // heuristic simple improved
    let threatType = "normal visit";
    if (/(malware|\.exe|virus|exploit)/i.test(lowerData)) threatType = "malware detected";
    else if (/(nmap|scan|banner grab|sqlmap)/i.test(lowerData)) threatType = "scan attempt";
    else if (/union\s+select|drop\s+table|\bor\b\s+['"]?1['"]?\s*=\s*['"]?1|or 1=1/i.test(lowerData)) threatType = "sql injection attempt";
    else if (/(<script\b|onerror=|javascript:)/i.test(lowerData)) threatType = "xss attempt";
    else if (/(login attempt|password guess|brute force)/i.test(lowerData)) threatType = "brute force attempt";
    else if (/post/i.test(method)) threatType = "post request";

    const timestamp = new Date().toISOString();
    // احفظ originalUrl مع نوع التهديد (نستبدل الفاصلة علشان لا تكسر CSV)
    const safeOriginal = originalUrl.replace(/,/g, ';').replace(/"/g, '\\"');
    const logLine = `${timestamp},${ip},${method},"${threatType} | ${safeOriginal}",auto\n`;
    fs.appendFileSync(logPath, logLine);
    console.log(`📥 [AUTO] ${ip} ${method} ${originalUrl} => ${threatType}`);

    // جدولة push جماعي بعد debounce بدل كل request
    if (pushTimer) clearTimeout(pushTimer);
    pushTimer = setTimeout(() => {
      try {
        pushToGitHub();
      } catch (e) {
        console.error('Push scheduled failed:', e.message);
      }
    }, PUSH_DEBOUNCE_MS);

  } catch (err) {
    console.error("❌ Middleware error writing to threats.csv:", err);
  }
  next();
});


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

// ✅ API لعرض ملف CSV من GitHub
app.get('/api/threats', (req, res) => {
    const githubUrl = 'https://raw.githubusercontent.com/etiqotwf/honeypotpro/main/public/logs/threats.csv';
    https.get(githubUrl, (githubRes) => {
        let data = '';
        githubRes.on('data', chunk => data += chunk);
        githubRes.on('end', () => res.send(data));
    }).on('error', (err) => {
        console.error('❌ Error fetching CSV from GitHub:', err.message);
        res.status(500).send('Error fetching data');
    });
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



// ✅ بث مباشر للتيرمينال في المتصفح
let clients = [];

app.get('/events', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.flushHeaders();
  clients.push(res);

  req.on('close', () => {
    clients = clients.filter(c => c !== res);
  });
});

// ✅ دالة تبث أى سطر يظهر في التيرمينال
function broadcastLine(line) {
  for (const c of clients) {
    c.write(`event: line\n`);
    c.write(`data: ${JSON.stringify(line)}\n\n`);
  }
}

// ✅ تعديل console.log و console.error ليبثوا للواجهة
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





// ✅ بدء الخادم و ngrok
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
    

  // 🟢 نسخ أولي عند تشغيل السيرفر
    syncModelToPublic();

    exec("pgrep -f 'ngrok' && pkill -f 'ngrok'", () => {
        exec("ngrok.exe http 3000 --log=stdout", (err) => {
            if (err) return console.error("❌ Error starting ngrok:", err);
            console.log("✅ ngrok started successfully!");
        });

        setTimeout(() => {
            exec("curl -s http://127.0.0.1:4040/api/tunnels", (err, stdout) => {
                if (err || !stdout) {
                    exec("powershell -Command \"(Invoke-WebRequest -Uri 'http://127.0.0.1:4040/api/tunnels' -UseBasicParsing).Content\"", (psErr, psStdout) => {
                        if (psErr || !psStdout) return console.error("❌ Error fetching ngrok URL:", psErr);
                        processNgrokResponse(psStdout);
                    });
                } else {
                    processNgrokResponse(stdout);
                }
            });
        }, 5000);
    });
});

// ✅ تحليل رد ngrok + فتح الرابط تلقائياً في المتصفح
function processNgrokResponse(response) {
  try {
    const tunnels = JSON.parse(response);
    serverUrl = tunnels.tunnels[0]?.public_url;
    if (serverUrl) {
      console.log(`✅ Server is available at: 🔗 ${serverUrl}`);
      fs.writeFileSync("serverUrl.json", JSON.stringify({ serverUrl }));
      pushToGitHub();

      // ✅ بدلاً من فتح ngrok تلقائيًا، افتح التيرمينال فقط
      openInBrowser(`http://localhost:${PORT}/terminal.html`);
      console.log("🖥️ Opened terminal page — waiting for user action to start attack...");

    } else {
      console.log("⚠️ No ngrok URL found.");
    }
  } catch (e) {
    console.error("❌ Error parsing ngrok response:", e);
  }
}

// فتح الرابط في المتصفح الافتراضي (Windows / macOS / Linux)

function openInBrowser(url) {
  const platform = process.platform; // 'win32', 'darwin', 'linux'
  // helper: spawn detached (non-blocking) and ignore output
  const launchDetached = (command, args = [], useShell = false) => {
    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
        shell: useShell
      });
      // Allow parent to exit independently of the child
      child.unref();
      return true;
    } catch (err) {
      return false;
    }
  };

  if (platform === 'win32') {
    // مواقع محتملة لملف chrome.exe
    const chromePaths = [
      process.env['PROGRAMFILES'] ? path.join(process.env['PROGRAMFILES'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['PROGRAMFILES(X86)'] ? path.join(process.env['PROGRAMFILES(X86)'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['LOCALAPPDATA'] ? path.join(process.env['LOCALAPPDATA'], 'Google\\Chrome\\Application\\chrome.exe') : null
    ].filter(Boolean);

    // 1) إذا وُجد exe حاول فتحه مباشرة (non-blocking)
    for (const p of chromePaths) {
      try {
        if (fs.existsSync(p)) {
          // فتح نافذة جديدة بدون ربط للتيرمينال
          const args = ['--new-window', url];
          // اختياري - لتقليل فرصة سرقة الفوكس يمكنك إضافة حدود حجم/موقع:
          // args.push('--window-position=0,0', '--window-size=800,600');
          const ok = launchDetached(p, args, false);
          if (ok) {
            console.log('✅ Opened URL in Google Chrome (detached exe):', p);
            return;
          }
        }
      } catch (e) {
        // تجاهل واستمر في المحاولات
      }
    }

    // 2) Fallback: استخدم start /min عبر shell (أيضًا detached)
    const fallbackCmds = [
      `start "" /min chrome "${url}"`,
      `start "" /min firefox "${url}"`,
      `start "" /min "${url}"`
    ];

    for (const cmd of fallbackCmds) {
      if (launchDetached(cmd, [], true)) {
        console.log('✅ Opened URL on Windows (fallback start):', cmd);
        return;
      }
    }

    console.warn('⚠️ Failed to open browser on Windows.');
    return;
  }

  // macOS
  if (platform === 'darwin') {
    const attempts = [
      { cmd: 'open', args: ['-g', '-a', 'Google Chrome', url] }, // -g do not bring to foreground
      { cmd: 'open', args: ['-g', '-a', 'Firefox', url] },
      { cmd: 'open', args: ['-g', url] } // default browser without activation
    ];
    for (const a of attempts) {
      if (launchDetached(a.cmd, a.args, false)) {
        console.log('✅ Opened URL on macOS without stealing focus using:', a.cmd, a.args.join(' '));
        return;
      }
    }
    console.warn('⚠️ Failed to open browser on macOS.');
    return;
  }

  // Linux / Unix-like
  const linuxAttempts = [
    { cmd: 'setsid', args: ['google-chrome', url], useShell: false },
    { cmd: 'setsid', args: ['google-chrome-stable', url], useShell: false },
    { cmd: 'setsid', args: ['chromium-browser', url], useShell: false },
    { cmd: 'setsid', args: ['chromium', url], useShell: false },
    { cmd: 'setsid', args: ['firefox', url], useShell: false },
    { cmd: 'nohup', args: ['xdg-open', url], useShell: false },
    { cmd: 'xdg-open', args: [url], useShell: false }
  ];

  for (const a of linuxAttempts) {
    if (launchDetached(a.cmd, a.args, a.useShell || false)) {
      console.log('✅ Opened URL on Linux without stealing focus using:', a.cmd);
      return;
    }
  }

  console.warn('⚠️ Failed to open browser on Linux.');
}


// ✅ رفع الملفات إلى GitHub
// ✅ تنفيذ الأوامر مع معالجة دقيقة للأخطاء
function runCommand(command, args, callback, options = {}) {
  const fullCommand = `${command} ${args.join(" ")}`;
  exec(fullCommand, options, (error, stdout, stderr) => {
    if (error) {
      if (fullCommand.includes("git pull")) {
        console.warn(`⚠️ Warning during git pull (ignored): ${stderr || error.message}`);
      } else {
        console.error(`❌ Error executing: ${fullCommand}`);
        console.error(stderr || error.message);
        return; // ⛔ وقف التنفيذ
      }
    }

    if (callback) callback();
  });
}

// ✅ رفع الملفات إلى GitHub بدون node_modules + إعداد README تلقائي
// ✅ رفع الملفات إلى GitHub تلقائيًا (مع git add و commit قبل push)
function pushToGitHub() {
  console.log("📤 Preparing to push updates to GitHub...");

  // ✅ استبعاد node_modules من الرفع
  const gitignorePath = ".gitignore";
  if (!fs.existsSync(gitignorePath)) {
    fs.writeFileSync(gitignorePath, "node_modules/\n", "utf8");
    console.log("🧩 Created .gitignore and excluded node_modules/");
  } else {
    const content = fs.readFileSync(gitignorePath, "utf8");
    if (!content.includes("node_modules/")) {
      fs.appendFileSync(gitignorePath, "\nnode_modules/\n", "utf8");
      console.log("🧩 Updated .gitignore to exclude node_modules/");
    }
  }

  // ✅ إنشاء README.md أو تحديثه
  const readmePath = "README.md";
  const setupInstructions = `
# 🧠 Honeypot AI Project

This project uses Node.js and AI model integration (Hugging Face + TensorFlow.js).

## 🚀 Setup Instructions
After cloning this repository, run the following commands:

\`\`\`bash
npm install
node server.js
\`\`\`

✅ The server will start at: http://localhost:3000
`;
  if (!fs.existsSync(readmePath)) {
    fs.writeFileSync(readmePath, setupInstructions, "utf8");
    console.log("📝 Created README.md");
  }

  try {
    // ✅ إضافة الملفات والتأكد من وجود تغييرات
    execSync("git add -A");
    const changes = execSync("git status --porcelain").toString().trim();

    if (!changes) {
      console.log("🟡 No changes detected — skipping push.");
      return;
    }

    // ✅ عمل commit قبل الـ push
    execSync(`git commit -m "Auto commit before push: ${new Date().toISOString()}"`);
    // console.log("✅ Auto commit created.");

    // ✅ سحب آخر التحديثات مع تجاهل التعارضات
    try {
      execSync("git pull --rebase origin main", { stdio: "pipe" });
    } catch (e) {
      console.warn("⚠️ Warning during git pull (ignored).");
    }

    // ✅ تنفيذ الـ push
    execSync(
      `git push https://etiqotwf:${process.env.GITHUB_TOKEN}@github.com/etiqotwf/honeypotpro.git main`,
      { stdio: "pipe" }
    );

    console.log("✅ Project pushed successfully!");
    console.log("🛡️ Server is now monitoring — waiting for any attack to analyze and activate the intelligent defense system...");
  } catch (err) {
    console.error("❌ Error pushing to GitHub:", err.message);
  }
}


// ✅ API لإضافة تهديد يدويًا
app.post('/api/add-threat', (req, res) => {
    const { ip, method, threatType } = req.body;
    if (!ip || !method || !threatType) return res.status(400).json({ message: '❌ Missing threat data' });
    const timestamp = new Date().toISOString();
    const newLine = `${timestamp},${ip},${method},${threatType},manual\n`;
    try {
        fs.appendFileSync(logPath, newLine);
        console.log(`✅ Threat added: ${ip}, ${method}, ${threatType}`);
        pushToGitHub();
        res.status(200).json({ message: '✅ Threat added and pushed to GitHub' });
    } catch (err) {
        console.error("❌ Failed to write threat:", err);
        res.status(500).json({ message: '❌ Failed to write threat' });
    }
});


// ========== Sync Model to Public (only if changed) ==========
function copyIfChanged(src, dest) {
  if (!fs.existsSync(src)) return;
  const srcStat = fs.statSync(src);
  const destStat = fs.existsSync(dest) ? fs.statSync(dest) : null;

  // ✅ انسخ فقط إذا الملف مختلف في الحجم أو تاريخ التعديل
  if (!destStat || srcStat.mtimeMs !== destStat.mtimeMs || srcStat.size !== destStat.size) {
    fs.copyFileSync(src, dest);
    // console.log(`📝 File updated and copied: ${path.basename(src)}`);
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

// ========== Watch for model/weights changes ==========
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




// ✅ مراقبة ملف threats.csv في مجلد logs (جذر المشروع)
const projectLogPath = path.join(process.cwd(), 'logs', 'threats.csv');

if (fs.existsSync(projectLogPath)) {
    fs.watchFile(projectLogPath, { interval: 5000 }, (curr, prev) => {
        if (curr.mtime !== prev.mtime) {
            console.log("📝 Detected change in project logs/threats.csv");
            pushToGitHub();
        }
    });
} else {
    console.warn("⚠️ Project logs/threats.csv not found, skipping watch...");
}



// ✅ مراقبة ملف public/logs/threats.csv وتشغيل الـ Adaptive Honeypot على آخر سطر
const publicLogPath = path.join(process.cwd(), 'public', 'logs', 'threats.csv');

if (fs.existsSync(publicLogPath)) {
  fs.watchFile(publicLogPath, { interval: 3000 }, (curr, prev) => {
    if (curr.mtime !== prev.mtime) {
      console.log("👁️ Detected new entry in public/logs/threats.csv");

      // اقرأ آخر سطر بشكل آمن
      const content = fs.readFileSync(publicLogPath, 'utf8').trim();
      const lines = content.split(/\r?\n/);
      const lastLine = lines[lines.length - 1];

      if (lastLine && !lastLine.startsWith("Timestamp")) {
        console.log(`🆕 New line detected: ${lastLine}`);

        // جدولة تشغيل honeypot لكن امنع التداخل
        const runHoneypot = () => {
          if (honeypotProcessing) {
            honeypotPending = true;
            console.log('⏳ Honeypot busy — scheduling pending run.');
            return;
          }
          honeypotProcessing = true;
          // استخدم spawn بدلاً من exec لتجنب مشاكل الاقتباسات
          const child = spawn(process.execPath, ['adaptive-honeypot.js', lastLine], { cwd: process.cwd() });

          child.stdout.on('data', (data) => {
            process.stdout.write(`[HONEYPOT] ${data.toString()}`);
          });
          child.stderr.on('data', (data) => {
            process.stderr.write(`[HONEYPOT-ERR] ${data.toString()}`);
          });

          child.on('close', (code) => {
            console.log(`🤖 Honeypot process exited with code ${code}`);
            honeypotProcessing = false;
            if (honeypotPending) {
              honeypotPending = false;
              // تأخير بسيط قبل التشغيل التالي لتجميع أحداث إضافية
              setTimeout(runHoneypot, 500);
            }
          });
        };

        // شغّل
        runHoneypot();
      }
    }
  });
} else {
  console.warn("⚠️ public/logs/threats.csv not found, skipping watch...");
}






// ✅ أي طلب غير static و API يرجع صفحة الفيك
app.get('*', (req, res) => {
  // استثناء ملفات static و api
  if (
    req.path.startsWith('/api') ||
    req.path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico|json)$/)
  ) {
    return res.status(404).send('Not Found');
  }

  res.sendFile(path.join(process.cwd(), 'public', 'fake_login.html'));
});


// ✅ API لفتح ngrok عند الضغط من التيرمينال
app.post('/api/open-ngrok', (req, res) => {
  if (!serverUrl) return res.status(400).json({ message: "❌ ngrok URL not ready yet" });

  console.log("🚀 Launching ngrok URL in Chrome by user action...");
  openInBrowser(serverUrl);
  res.json({ message: "✅ ngrok URL opened successfully!", url: serverUrl });
});
