import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { exec, spawn } from 'child_process';
import { fork } from 'child_process';
import { execSync } from "child_process"; // ✅ أضف هذا السطر هنا


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
app.use(async (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const method = req.method;
    const pathReq = req.originalUrl || '';
    const bodyData = Object.keys(req.body || {}).length ? JSON.stringify(req.body) : '';
    const lowerData = (pathReq + bodyData).toLowerCase();

    let threatType = "normal visit";
    if (lowerData.includes("malware") || lowerData.includes(".exe") || lowerData.includes("virus"))
        threatType = "malware detected";
    else if (lowerData.includes("nmap") || lowerData.includes("scan") || lowerData.includes("banner grab"))
        threatType = "scan attempt";
    else if (lowerData.includes("attack") || lowerData.includes("exploit"))
        threatType = "attack vector";
    else if (lowerData.includes("union select") || lowerData.includes("drop table") || lowerData.includes("' or '1'='1"))
        threatType = "sql injection attempt";
    else if (lowerData.includes("<script>") || lowerData.includes("onerror="))
        threatType = "xss attempt";
    else if (lowerData.includes("login attempt") || lowerData.includes("password guess"))
        threatType = "brute force attempt";

    const timestamp = new Date().toISOString();
    const logLine = `${timestamp},${ip},${method},${threatType},auto\n`;
    try {
        fs.appendFileSync(logPath, logLine);
        console.log(`📥 [AUTO] ${ip} ${method} ${pathReq} => ${threatType}`);
        await pushToGitHub();
    } catch (err) {
        console.error("❌ Error writing to threats.csv or pushing to GitHub:", err);
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

// ✅ تحليل رد ngrok
// ✅ تحليل رد ngrok + فتح الرابط تلقائياً في المتصفح
function processNgrokResponse(response) {
  try {
    const tunnels = JSON.parse(response);
    serverUrl = tunnels.tunnels[0]?.public_url;
    if (serverUrl) {
      console.log(`✅ Server is available at: 🔗 ${serverUrl}`);
      fs.writeFileSync("serverUrl.json", JSON.stringify({ serverUrl }));
      pushToGitHub();

      // حاول فتح الرابط في المتصفح الافتراضي بحسب النظام
      openInBrowser(serverUrl);
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
  const launchDetached = (command, args = []) => {
    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
        shell: false
      });
      child.unref();
      return true;
    } catch (err) {
      return false;
    }
  };

  if (platform === 'win32') {
    // حاول أولًا مسارات Chrome المعروفة (أسرع وأكثر دقة)
    const chromePaths = [
      process.env['PROGRAMFILES'] + '\\Google\\Chrome\\Application\\chrome.exe',
      process.env['PROGRAMFILES(X86)'] + '\\Google\\Chrome\\Application\\chrome.exe',
      process.env['LOCALAPPDATA'] + '\\Google\\Chrome\\Application\\chrome.exe'
    ].filter(Boolean);

    for (const p of chromePaths) {
      if (fs.existsSync(p)) {
        const ok = launchDetached(p, ['--new-window', url]);
        if (ok) {
          console.log('✅ Opened URL in Google Chrome (direct exe):', p);
          return;
        }
      }
    }

    // إذا لم يُعثر على المسار، حاول start with chrome ثم firefox ثم default
    const attempts = [
      { cmd: 'cmd', args: ['/c', 'start', '""', 'chrome', url] },
      { cmd: 'cmd', args: ['/c', 'start', '""', 'firefox', url] },
      { cmd: 'cmd', args: ['/c', 'start', '""', url] }
    ];

    for (const a of attempts) {
      if (launchDetached(a.cmd, a.args)) {
        console.log('✅ Opened URL using:', a.cmd, a.args.join(' '));
        return;
      }
    }

    console.warn('⚠️ Failed to open browser on Windows.');
    return;
  }

  if (platform === 'darwin') {
    // macOS: Chrome -> Firefox -> default
    const attempts = [
      { cmd: 'open', args: ['-a', 'Google Chrome', url] },
      { cmd: 'open', args: ['-a', 'Firefox', url] },
      { cmd: 'open', args: [url] }
    ];
    for (const a of attempts) {
      if (launchDetached(a.cmd, a.args)) {
        console.log('✅ Opened URL on macOS using:', a.cmd, a.args.join(' '));
        return;
      }
    }
    console.warn('⚠️ Failed to open browser on macOS.');
    return;
  }

  // Linux / other unix-like
  // نحاول تشغيل المتصفحات مباشرة في الخلفية (no hang)
  const linuxAttempts = [
    { cmd: 'google-chrome', args: [url] },
    { cmd: 'google-chrome-stable', args: [url] },
    { cmd: 'chromium-browser', args: [url] },
    { cmd: 'chromium', args: [url] },
    { cmd: 'firefox', args: [url] },
    { cmd: 'xdg-open', args: [url] }
  ];
  for (const a of linuxAttempts) {
    if (launchDetached(a.cmd, a.args)) {
      console.log('✅ Opened URL on Linux using:', a.cmd);
      return;
    }
  }
  console.warn('⚠️ Failed to open browser on Linux.');
}

// ✅ رفع الملفات إلى GitHub


// runCommand using spawn to avoid shell escaping issues and to capture stderr/stdout
function runCommand(cmd, args = [], callback, options = {}) {
  const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
  let stdout = '';
  let stderr = '';

  child.stdout.on('data', (d) => { stdout += d.toString(); });
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  child.on('close', (code) => {
    if (code !== 0) {
      console.error(`❌ Command failed: ${cmd} ${args.join(' ')} (exit ${code})`);
      if (stdout) console.error('--- stdout ---\n', stdout);
      if (stderr) console.error('--- stderr ---\n', stderr);
      // continue (do not throw) so caller can decide
    } else {
      // success (but we won't print by default)
    }
    if (typeof callback === 'function') callback(code === 0, { stdout, stderr, code });
  });

  child.on('error', (err) => {
    console.error(`❌ Failed to spawn ${cmd}:`, err);
    if (typeof callback === 'function') callback(false, { error: err });
  });
}

// Updated pushToGitHub — safer and logs clear error messages
function pushToGitHub() {
  console.log("📤 Preparing to push updates to GitHub...");

  const hasGit = fs.existsSync(".git");
  let hasChanges = true;
  if (hasGit) {
    try {
      const status = execSync("git status --porcelain").toString().trim();
      hasChanges = status !== "";
    } catch (e) {
      console.warn("⚠️ git status failed — proceeding with push attempt (will show detailed error if fails).");
    }
  }

  if (!hasChanges) {
    console.log("🟡 No changes detected — skipping GitHub push.");
    return;
  }

  // ensure .gitignore and package.json/README exist as before...
  // (ابقي احتفظ بالكود الموجود لديك لإنشائها — لم أكررها هنا لتقليل الطول)

  // ننفّذ سلسلة أوامر git خطوة بخطوة ونتعامل مع الأخطاء:
  runCommand('git', ['add', '-A'], (ok) => {
    if (!ok) return console.error('❌ git add failed, aborting push sequence.');

    runCommand('git', ['commit', '-m', `Auto update (excluding node_modules): ${new Date().toISOString()}`], (ok2, info2) => {
      // لو لم يحدث commit (مثلاً لا تغييرات لعبت دور) استمر للمحاولة التالية
      if (!ok2) {
        // قد يكون سبب الفشل: "nothing to commit" — نفحص stderr
        if (info2 && /nothing to commit/.test((info2.stdout || '') + (info2.stderr || ''))) {
          console.log('ℹ️ Nothing to commit — continuing to pull/push.');
        } else {
          console.warn('⚠️ git commit failed — continuing anyway to pull/push (you may inspect logs).');
        }
      }

      // git pull --rebase
      runCommand('git', ['pull', '--rebase', 'origin', 'main'], (ok3, info3) => {
        if (!ok3) {
          console.warn('⚠️ git pull failed — continuing to push attempt (may fail).');
        }

        // ***** IMPORTANT: Use remote without embedding token in printed logs *****
        // Two options:
        // 1) If remote is already set (git remote get-url origin) -> just 'git push origin main'
        // 2) Otherwise, you can temporarily set remote URL with token but avoid printing it.
        // We'll attempt plain 'git push origin main' which will use saved credentials.
        runCommand('git', ['push', 'origin', 'main'], (ok4, info4) => {
          if (!ok4) {
            console.error('❌ git push failed. Inspect stderr above to see reason (auth / network / branch).');
            // if stderr contains authentication error, inform user:
            const combined = (info4 && (info4.stderr || '') + (info4.stdout || '')) || '';
            if (/authentication|permission|403|401|fatal/.test(combined.toLowerCase())) {
              console.error('🔐 Possible auth error: check GITHUB_TOKEN, remote URL, or credential helper.');
            }
            return;
          }
          console.log('✅ Project pushed successfully!');
          console.log('🛡️ Server is now monitoring — waiting for any attack to analyze and activate the intelligent defense system...');
        });
      });
    });
  });
}

// ========== Sync Model to Public (only if changed) ==========
function copyIfChanged(src, dest) {
  if (!fs.existsSync(src)) return;
  const srcStat = fs.statSync(src);
  const destStat = fs.existsSync(dest) ? fs.statSync(dest) : null;

  // ✅ انسخ فقط إذا الملف مختلف في الحجم أو تاريخ التعديل
  if (!destStat || srcStat.mtimeMs !== destStat.mtimeMs || srcStat.size !== destStat.size) {
    fs.copyFileSync(src, dest);
    console.log(`📝 File updated and copied: ${path.basename(src)}`);
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

            // اقرأ آخر سطر
            const content = fs.readFileSync(publicLogPath, 'utf8').trim();
            const lines = content.split(/\r?\n/);
            const lastLine = lines[lines.length - 1];

            if (lastLine && !lastLine.startsWith("Timestamp")) {
                console.log(`🆕 New line detected: ${lastLine}`);

                // شغّل honeypot مع تمرير آخر سطر كـ argument
                exec(`node adaptive-honeypot.js "${lastLine}"`, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`❌ Error running adaptiveHoneypot.js: ${error.message}`);
                        return;
                    }
                    if (stderr) console.error(`⚠️ STDERR: ${stderr}`);
                    console.log(`🤖 Honeypot Output:\n${stdout}`);
                });
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
