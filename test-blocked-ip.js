import http from 'http';

const testIP = "156.203.235.39"; // الـ IP اللي عايز تختبره
const PORT = 3000;

const options = {
  hostname: 'localhost',
  port: PORT,
  path: '/',
  method: 'GET',
  headers: {
    'X-Forwarded-For': testIP
  }
};

const req = http.request(options, res => {
  console.log(`StatusCode: ${res.statusCode}`);
  if (res.statusCode === 403) {
    console.log(`✅ Test passed: IP ${testIP} is blocked.`);
  } else {
    console.log(`❌ Test failed: IP ${testIP} is NOT blocked.`);
  }

  res.on('data', d => process.stdout.write(d));
});

req.on('error', error => {
  console.error(error);
});

req.end();
