let activeReport = null;
let activeScanId = null;

const byId = id => document.getElementById(id);
const text = value => String(value ?? '');
const html = value => text(value).replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));

function setStatus(message) {
  byId('scan-status').textContent = message;
}

function statusBadge(status) {
  const value = text(status || 'UNKNOWN').toUpperCase();
  const className = value === 'PASS' ? 'status-pass' : 'status-vulnerable';
  return `<span class="badge ${className}">${html(value)}</span>`;
}

function severityBadge(severity) {
  const value = text(severity || 'LOW').toLowerCase();
  const className = ['critical', 'high', 'medium', 'low'].includes(value) ? value : 'low';
  return `<span class="badge severity-${className}">${html(severity || 'LOW')}</span>`;
}

function renderFinding(finding, index) {
  const status = text(finding.status || 'UNKNOWN').toUpperCase();
  const severity = text(finding.severity || 'LOW').toLowerCase();
  const curl = finding.poc_curl || 'No cURL proof of concept was provided.';
  return `<article class="finding ${html(severity)}">
    <div class="finding-top"><h3>${html(finding.name || 'Unnamed finding')}</h3><div class="finding-labels">
      <span class="badge category">${html(finding.category || 'Uncategorized')}</span>${severityBadge(finding.severity)}${statusBadge(status)}
    </div></div>
    <p class="finding-copy">${html(finding.explanation || 'No explanation provided.')}</p>
    <p class="fix"><strong>Suggested Fix:</strong> ${html(finding.suggested_fix || 'No remediation guidance provided.')}</p>
    <details><summary>Reproduce with cURL</summary><div class="curl-row"><pre><code>${html(curl)}</code></pre><button class="copy-curl" type="button" data-curl-index="${index}">Copy cURL</button></div></details>
  </article>`;
}

function renderReport(report) {
  activeReport = report;
  const checks = Array.isArray(report?.checks) ? report.checks : [];
  const vulnerabilities = checks.filter(check => text(check.status).toUpperCase() === 'VULNERABLE').length;
  const health = text(report?.overall_result || (vulnerabilities ? 'VULNERABLE' : 'PASS')).toUpperCase();
  byId('metric-target').textContent = report?.target_url || byId('target-url').value || '—';
  byId('metric-health').innerHTML = statusBadge(health);
  byId('metric-checks').textContent = checks.length;
  byId('metric-vulnerabilities').textContent = vulnerabilities;
  byId('finding-count').textContent = `${checks.length} finding${checks.length === 1 ? '' : 's'}`;
  byId('findings').innerHTML = checks.length ? checks.map(renderFinding).join('') : `<p class="muted">${html(report?.error || 'No checks found in this report.')}</p>`;
  byId('raw-json-content').textContent = JSON.stringify(report, null, 2);
  byId('findings').querySelectorAll('[data-curl-index]').forEach(button => button.addEventListener('click', async () => {
    await navigator.clipboard.writeText(checks[Number(button.dataset.curlIndex)]?.poc_curl || '');
    button.textContent = 'Copied';
    window.setTimeout(() => { button.textContent = 'Copy cURL'; }, 1200);
  }));
}

async function fetchReport() {
  try {
    const response = await fetch('/report');
    if (!response.ok) throw new Error(`Report request failed (${response.status})`);
    renderReport(await response.json());
    setStatus('Latest report loaded');
  } catch (error) {
    setStatus(error.message);
  }
}

async function runScan() {
  const button = byId('run-scan');
  button.disabled = true;
  setStatus('Queueing scan...');
  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url: byId('target-url').value.trim(),
        spec_url: byId('spec-url').value.trim() || null,
        priority: byId('priority-select').value,
      }),
    });
    if (!response.ok) throw new Error(`Unable to start scan (${response.status})`);
    const started = await response.json();
    activeScanId = started.scan_id;
    setStatus(`Scanning ${activeScanId}...`);
    while (activeScanId) {
      await new Promise(resolve => window.setTimeout(resolve, 1200));
      const pollResponse = await fetch(`/report/${encodeURIComponent(activeScanId)}`);
      if (!pollResponse.ok) throw new Error(`Polling failed (${pollResponse.status})`);
      const report = await pollResponse.json();
      if (report.status === 'completed' || report.status === 'failed' || Array.isArray(report.checks)) {
        renderReport(report);
        setStatus(report.status === 'failed' ? 'Scan failed' : 'Scan completed');
        activeScanId = null;
      }
    }
  } catch (error) {
    setStatus(error.message);
    activeScanId = null;
  } finally {
    button.disabled = false;
  }
}

function openJsonModal() { byId('raw-json').style.display = 'grid'; }
function closeJsonModal() { byId('raw-json').style.display = 'none'; }
function downloadReport() {
  if (!activeReport) return;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([JSON.stringify(activeReport, null, 2)], { type: 'application/json' }));
  link.download = 'scan_report.json';
  link.click();
  URL.revokeObjectURL(link.href);
}

byId('run-scan').addEventListener('click', runScan);
byId('refresh-result').addEventListener('click', fetchReport);
byId('view-json').addEventListener('click', openJsonModal);
byId('raw-json-link').addEventListener('click', event => { event.preventDefault(); openJsonModal(); });
byId('close-json').addEventListener('click', closeJsonModal);
byId('raw-json').addEventListener('click', event => { if (event.target === byId('raw-json')) closeJsonModal(); });
byId('copy-json').addEventListener('click', async () => {
  if (!activeReport) return;
  await navigator.clipboard.writeText(JSON.stringify(activeReport, null, 2));
  byId('copy-json').textContent = 'Copied';
  window.setTimeout(() => { byId('copy-json').textContent = 'Copy JSON'; }, 1200);
});
byId('download-report').addEventListener('click', downloadReport);
fetchReport();
