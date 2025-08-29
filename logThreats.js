// logThreats.js
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';

export function logThreat(ip, method, threatType) {
    const logPath = path.join('./logs', 'threats.csv');
    const timestamp = new Date().toISOString();
    const logLine = `${timestamp},${ip},${method},${threatType}\n`;

    // 📝 حفظ السطر في CSV
    fs.appendFileSync(logPath, logLine);

    // 🚀 إرسال للسيرفر إذا كان يعمل
    fetch('http://localhost:3000/api/logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            timestamp,
            ip,
            method,
            threatType
        })
    }).catch(err => {
        console.error('❌ فشل في إرسال التهديد إلى السيرفر:', err.message);
    });
}
