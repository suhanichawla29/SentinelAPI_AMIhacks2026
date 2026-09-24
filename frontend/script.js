let activeScan = null;

const byId = id => document.getElementById(id);
function valueOf(...ids) { const el = ids.map(byId).find(Boolean); return el ? el.value : ''; }
function setText(ids, text) { ids.map(byId).filter(Boolean).forEach(el => el.textContent = text); }
function badge(text, className = '') {
  const el = document.createElement('span'); el.className = `badge ${className}`; el.textContent = text || '—'; return el;
}

function renderReport(data) {
  activeScan = data;
  const checks = Array.isArray(data?.checks) ? data.checks : [];
  const overall = String(data?.overall_result || data?.status || (checks.some(c => c.status === 'VULNERABLE') ? 'VULNERABLE' : 'PASS')).toUpperCase();
  const overallEl = byId('overall-badge');
  if (overallEl) { overallEl.className = 'status badge ' + (overall === 'PASS' ? 'pass' : overall === 'VULNERABLE' ? 'vul' : 'amber'); overallEl.textContent = overall; }
  setText(['timestamp', 'checked-at', 'checked_at_utc'], data?.checked_at_utc || data?.timestamp || new Date().toISOString());
  setText(['tests-run'], checks.length || '—');
  setText(['passed'], checks.filter(c => c.status === 'PASS').length);
  setText(['vulns'], checks.filter(c => c.status === 'VULNERABLE').length);
  const results = byId('results'); if (!results) return;
  results.innerHTML = '';
  checks.forEach(check => {
    const card = document.createElement('article'); card.className = 'audit-card panel';
    const heading = document.createElement('h3'); heading.textContent = check.name || 'Unnamed check';
    const priority = badge(String(check.priority || data.priority || 'NORMAL').toUpperCase(), 'priority');
    const status = badge(String(check.status || 'INCONCLUSIVE').toUpperCase(), String(check.status || '').toLowerCase());
    const explanation = document.createElement('p'); explanation.textContent = check.explanation || '';
    const fix = document.createElement('p'); fix.textContent = `Suggested fix: ${check.suggested_fix || check.recommendation || 'No recommendation provided.'}`;
    card.append(heading, priority, status, explanation, fix); results.appendChild(card);
  });
}

async function runScan() {
  const btn = byId('run-scan'); if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  setText(['scan-status', 'loading-status'], 'Scan in progress…');
  try {
    const response = await fetch('/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ target_url: valueOf('target-url', 'target_url', 'target'), priority: valueOf('priority'), custom_token: valueOf('auth-token', 'custom-token', 'custom_token', 'token') }) });
    if (!response.ok) throw new Error('Unable to start scan');
    const started = await response.json(); const scanId = started.scan_id;
    if (!scanId) throw new Error('No scan ID returned');
    while (true) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const report = await (await fetch(`/report/${encodeURIComponent(scanId)}`)).json();
      if (report.status === 'completed' || Array.isArray(report.checks)) { renderReport(report); break; }
    }
    setText(['scan-status', 'loading-status'], 'Scan completed');
  } catch (error) { setText(['scan-status', 'loading-status'], error.message); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Run Security Scan'; } }
}

function downloadReport() { if (!activeScan) return; const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(activeScan, null, 2)], {type:'application/json'})); a.download = 'security-report.json'; a.click(); URL.revokeObjectURL(a.href); }
function copyRaw() { if (activeScan) navigator.clipboard.writeText(JSON.stringify(activeScan, null, 2)); }
byId('run-scan')?.addEventListener('click', runScan);
byId('download-report')?.addEventListener('click', downloadReport);
byId('copy-raw-json')?.addEventListener('click', copyRaw);
