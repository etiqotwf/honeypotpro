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
  const launchDetached = (command, args = [], useShell = false) => {
    try {
      const child = spawn(command, args, {
        detached: true,
        stdio: 'ignore',
        shell: useShell // sometimes we need shell for start command on Windows
      });
      child.unref();
      return true;
    } catch (err) {
      return false;
    }
  };

  if (platform === 'win32') {
    // أسرع وموثوق: حاول chromium exe مباشرة (لكن افتح مصغّر باستخدام start /min)
    const chromePaths = [
      process.env['PROGRAMFILES'] ? path.join(process.env['PROGRAMFILES'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['PROGRAMFILES(X86)'] ? path.join(process.env['PROGRAMFILES(X86)'], 'Google\\Chrome\\Application\\chrome.exe') : null,
      process.env['LOCALAPPDATA'] ? path.join(process.env['LOCALAPPDATA'], 'Google\\Chrome\\Application\\chrome.exe') : null
    ].filter(Boolean);

    // إذا وُجد exe مباشر سنحاول فتحه مصغّراً عبر start /min (shell required)
    for (const p of chromePaths) {
      if (fs.existsSync(p)) {
        // استخدم start /min لتجنّب سرقة الفوكس
        const cmd = `start "" /min "${p}" --new-window "${url}"`;
        if (launchDetached(cmd, [], true)) {
          console.log('✅ Opened URL in Google Chrome (minimized via start):', p);
          return;
        }
      }
    }

    // fallback: جرب chrome عبر start minimized، ثم firefox، ثم default (كلها باستخدام shell start)
    const attempts = [
      `start "" /min chrome "${url}"`,
      `start "" /min firefox "${url}"`,
      `start "" /min "${url}"`
    ];

    for (const cmd of attempts) {
      if (launchDetached(cmd, [], true)) {
        console.log('✅ Opened URL on Windows (minimized) using:', cmd);
        return;
      }
    }

    console.warn('⚠️ Failed to open browser on Windows.');
    return;
  }

  if (platform === 'darwin') {
    // macOS: -g => do not bring application to foreground (no-activate)
    const attempts = [
      { cmd: 'open', args: ['-g', '-a', 'Google Chrome', url] },
      { cmd: 'open', args: ['-g', '-a', 'Firefox', url] },
      { cmd: 'open', args: ['-g', url] } // default browser without activation
    ];
    for (const a of attempts) {
      if (launchDetached(a.cmd, a.args)) {
        console.log('✅ Opened URL on macOS without stealing focus using:', a.cmd, a.args.join(' '));
        return;
      }
    }
    console.warn('⚠️ Failed to open browser on macOS.');
    return;
  }

  // Linux / Unix-like
  // ننفّذ في الخلفية عبر setsid/nohup أو xdg-open. عادةً لا يخطف الفوكس.
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
function pushToGitHub() {
  console.log("📤 Preparing to push updates to GitHub...");

  const hasChanges = fs.existsSync(".git")
    ? execSync("git status --porcelain").toString().trim() !== ""
    : true;

  if (!hasChanges) {
    console.log("🟡 No changes detected — skipping GitHub push.");
    return;
  }

  // 🚫 استبعاد node_modules من الرفع
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

  // ✅ التأكد من وجود package.json
  if (!fs.existsSync("package.json")) {
    console.warn("⚠️ package.json not found — creating default file...");
    runCommand("npm", ["init", "-y"], () => console.log("📦 Created default package.json"));
  }

  // 🧾 إنشاء أو تحديث README.md
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
    console.log("📝 Created new README.md with setup instructions.");
  } else {
    const content = fs.readFileSync(readmePath, "utf8");
    if (!content.includes("npm install")) {
      fs.appendFileSync(readmePath, "\n" + setupInstructions, "utf8");
      console.log("📝 Updated README.md with setup instructions.");
    }
  }

  const execOptions = { stdio: "ignore" };

  runCommand("git", ["add", "-A"], () => {
    runCommand("git", ["commit", "-m", `"Auto update (excluding node_modules): ${new Date().toISOString()}"`], () => {
      runCommand("git", ["pull", "--rebase", "origin", "main"], () => {
        runCommand(
          "git",
          [
            "push",
            `https://etiqotwf:${process.env.GITHUB_TOKEN}@github.com/etiqotwf/honeypotpro.git`,
            "main",
          ],
          () => {
            console.log("✅ Project pushed successfully!");
            console.log("🛡️ Server is now monitoring — waiting for any attack to analyze and activate the intelligent defense system...");
          },
          execOptions
        );
      }, execOptions);
    }, execOptions);
  }, execOptions);
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
