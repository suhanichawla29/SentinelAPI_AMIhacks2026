async function fetchReport(){
  try{
    const res = await fetch('/report');
    if(!res.ok) throw new Error('No report');
    return await res.json();
  }catch(e){
    return null;
  }
}

function setBadge(el, status){
  el.className = 'status badge';
  if(status==='PASS') { el.classList.add('pass'); el.textContent='PASS' }
  else if(status==='VULNERABLE') { el.classList.add('vul'); el.textContent='VULNERABLE' }
  else { el.classList.add('amber'); el.textContent=status }
}

function createRow(check){
  const row = document.createElement('div'); row.className='row';
  const name = document.createElement('div'); name.className='col'; name.textContent = check.name;
  const expl = document.createElement('div'); expl.className='col'; expl.textContent = check.explanation || '';
  const status = document.createElement('div'); status.className='col small';
  const badge = document.createElement('span'); badge.className='badge';
  badge.textContent = check.status;
  if(check.status==='PASS') badge.classList.add('pass');
  else if(check.status==='VULNERABLE') badge.classList.add('vul');
  else badge.classList.add('inc');
  status.appendChild(badge);

  const httpc = document.createElement('div'); httpc.className='col small'; httpc.textContent = check.status_code || '—';
  row.appendChild(name); row.appendChild(status); row.appendChild(httpc); row.appendChild(expl);
  return row;
}

function render(report){
  if(!report){
    document.getElementById('results').innerHTML = '<div class="panel">No report available. Run a scan.</div>';
    document.getElementById('overall-badge').textContent='INCONCLUSIVE';
    return;
  }
  const overall = (report.overall_result||'INCONCLUSIVE').toUpperCase();
  const checks = Array.isArray(report.checks)?report.checks:[];
  const total = checks.length;
  const passed = checks.filter(c=>c.status==='PASS').length;
  const vulns = checks.filter(c=>c.status==='VULNERABLE').length;
  document.getElementById('tests-run').textContent = total||'—';
  document.getElementById('passed').textContent = passed;
  document.getElementById('vulns').textContent = vulns;
  setBadge(document.getElementById('overall-badge'), overall);

  const results = document.getElementById('results'); results.innerHTML='';
  checks.forEach(c=> results.appendChild(createRow(c)));

  // Issue panel
  const issuePanel = document.getElementById('issue-panel');
  if(vulns>0){
    issuePanel.className='issue vul';
    issuePanel.innerHTML = '<strong>Vulnerability Detected</strong><div>Broken Object Level Authorization: the API allowed one authenticated user to access another user\'s order.</div>';
    document.getElementById('vul-other-status').textContent = checks.find(ch=>ch.name.toLowerCase().includes('other'))?.status_code || '—';
    document.getElementById('secure-other-status').textContent = checks.find(ch=>ch.name.toLowerCase().includes('other'))?.status_code || '—';
    issuePanel.classList.remove('hidden');
  } else if(total>0){
    issuePanel.className='issue pass';
    issuePanel.innerHTML = '<strong>Security Check Passed</strong><div>Unauthorized access to another user\'s order was blocked — authorization is working correctly.</div>';
    issuePanel.classList.remove('hidden');
  } else {
    issuePanel.classList.add('hidden');
  }
}

async function refresh(){
  const r = await fetchReport();
  render(r);
}

async function runScan(){
  const btn = document.getElementById('run-scan');
  btn.disabled = true; btn.textContent='Running...';
  try{
    const res = await fetch('/scan', {method:'POST'});
    // allow server to finish writing report; poll a few times
    for(let i=0;i<6;i++){
      await new Promise(s=>setTimeout(s,600));
      const r = await fetchReport();
      if(r && r.checked_at_utc) { render(r); break }
    }
  }catch(e){
    console.error(e);
  }finally{
    btn.disabled=false; btn.textContent='Run Security Scan';
  }
}

document.getElementById('refresh').addEventListener('click', refresh);
document.getElementById('run-scan').addEventListener('click', runScan);
window.addEventListener('load', refresh);
