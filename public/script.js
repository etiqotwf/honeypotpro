async function fetchThreats() {
  const res = await fetch('/api/logs'); // ✅ هذا هو الصحيح
  const data = await res.json();
  renderTable(data);
  renderChart(data); // الرسم البياني
}


// تحديث كل دقيقة
setInterval(fetchThreats, 60000);
fetchThreats();
let chart;
function renderChart(data) {
  const counts = {};
  data.forEach(t => {
    counts[t.ThreatType] = (counts[t.ThreatType] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const values = Object.values(counts);

  if (chart) chart.destroy();
  chart = new Chart(document.getElementById('threatChart'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Threat Count',
        data: values,
        backgroundColor: 'rgba(255,99,132,0.6)',
      }]
    }
  });
}


document.getElementById('filterIP').addEventListener('input', () => renderTable(globalThreatData));
document.getElementById('filterType').addEventListener('change', () => renderTable(globalThreatData));


function renderTable(data) {
  const ipFilter = document.getElementById('filterIP').value;
  const typeFilter = document.getElementById('filterType').value;
  

  const filtered = data.filter(row => {
    return (!ipFilter || row.IP.includes(ipFilter)) &&
           (!typeFilter || row.ThreatType === typeFilter);
  });

  const tableBody = document.getElementById('threatTableBody');
  tableBody.innerHTML = '';
  filtered.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${row.Timestamp}</td><td>${row.IP}</td><td>${row.Method}</td><td>${row.ThreatType}</td>`;
    tableBody.appendChild(tr);
  });
}

document.getElementById('addForm').addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target;
  const res = await fetch('/api/threats', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ip: form.ip.value,
      method: form.method.value,
      type: form.type.value
    })
  });
  if (res.ok) {
    fetchThreats();
    form.reset();
  }
});

let globalThreatData = [];

async function fetchThreats() {
  const res = await fetch('/api/logs'); // تأكد إن endpoint ده بيرجع البيانات
  const data = await res.json();
  globalThreatData = data;
  renderTable(globalThreatData);
  drawThreatChart(globalThreatData); // لو عندك دالة رسم
}




