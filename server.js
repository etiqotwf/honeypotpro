import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { exec, spawn } from 'child_process';
import { fork } from 'child_process';

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

app.use(cors({ origin: "*" }));
app.use(bodyParser.json());
app.use(express.static('public'));

// ✅ إنشاء مجلد logs داخل public إن لم يكن موجودًا
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}
if (!fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, 'Timestamp,IP,Method,ThreatType,Action\n');
}

// ✅ Middleware لتسجيل أي دخول تلقائيًا
app.use((req, res, next) => {
    const ip =
        req.headers['x-forwarded-for']?.split(',')[0] ||
        req.socket.remoteAddress ||
        'unknown';

    const method = req.method;
    const pathReq = req.originalUrl;
    const lowerPath = (pathReq + JSON.stringify(req.body)).toLowerCase();

    let threatType = "normal visit";
    if (lowerPath.includes("malware")) threatType = "malware detected";
    else if (lowerPath.includes("scan")) threatType = "scan attempt";
    else if (lowerPath.includes("attack")) threatType = "attack vector";

    const timestamp = new Date().toISOString();
    const logLine = `${timestamp},${ip},${method},${threatType},auto\n`;
    fs.appendFileSync(logPath, logLine);

    console.log(`📥 [AUTO] ${ip} ${method} ${pathReq} => ${threatType}`);
    next();
});

// ✅ API لتسجيل التهديد يدويًا
app.post('/api/logs', (req, res) => {
    const { timestamp, ip, method, threatType } = req.body;
    const logLine = `${timestamp},${ip},${method},${threatType},manual\n`;
    fs.appendFileSync(logPath, logLine);
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
function processNgrokResponse(response) {
    try {
        const tunnels = JSON.parse(response);
        serverUrl = tunnels.tunnels[0]?.public_url;
        if (serverUrl) {
            console.log(`✅ Server is available at: 🔗 ${serverUrl}`);
            fs.writeFileSync("serverUrl.json", JSON.stringify({ serverUrl }));
            pushToGitHub();
        } else {
            console.log("⚠️ No ngrok URL found.");
        }
    } catch (e) {
        console.error("❌ Error parsing ngrok response:", e);
    }
}

// ✅ رفع الملفات إلى GitHub
function runCommand(command, args, callback) {
    const process = spawn(command, args);
    process.stdout.on("data", (data) => console.log(`stdout: ${data}`));
    process.stderr.on("data", (data) => console.error(`stderr: ${data}`));
    process.on("close", (code) => {
        if (code !== 0) return console.error(`❌ Command failed: ${command} ${args.join(" ")}`);
        callback();
    });
}

function pushToGitHub() {
    console.log("📤 Pushing updates to GitHub...");
    runCommand("git", ["add", "."], () => {
        runCommand("git", ["commit", "-m", "Auto update"], () => {
            runCommand("git", ["push", `https://etiqotwf:${GITHUB_TOKEN}@github.com/etiqotwf/honeypotpro.git`, "main"], () => {
                console.log("✅ All changes successfully pushed to GitHub!");
            });
        });
    });
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
