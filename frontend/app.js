let timelineChart;
let ipChart;
let refreshInProgress = false;
let selectedHours = 24;
let searchQuery = '';
let searchTimer;
let selectedImportFile;
let currentDetailAlertId;

const $ = (selector) => document.querySelector(selector);
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#039;',
})[character]);
const fmt = (date) => new Intl.DateTimeFormat('en', {
  dateStyle: 'medium',
  timeStyle: 'short',
}).format(new Date(date));
const queryString = () => {
  const params = new URLSearchParams({hours: String(selectedHours)});
  if (searchQuery) params.set('q', searchQuery);
  return params.toString();
};

// The clock is deliberately initialized before charts or API requests.
// It therefore keeps working even when another dashboard component fails.
function updateClock() {
  $('#clock').textContent = new Date().toLocaleTimeString();
}
updateClock();
setInterval(updateClock, 1000);

if (window.Chart) {
  Chart.defaults.color = '#8492a8';
  Chart.defaults.borderColor = '#202c40';
}

async function getJSON(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      ...options,
      signal: controller.signal,
    });
    if (!response.ok) {
      if (response.status === 401) {
        window.location.replace('/login');
      }
      throw new Error(`Request failed with status ${response.status}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function setEngineStatus(state, label) {
  const status = $('#engine-status');
  status.classList.remove('online', 'offline', 'checking');
  status.classList.add(state);
  status.querySelector('span').textContent = label;
}

function showBanner(title, message) {
  $('#banner-title').textContent = title;
  $('#banner-message').textContent = message;
  $('#system-banner').hidden = false;
}

function hideBanner() {
  $('#system-banner').hidden = true;
}

function finishMetricLoading() {
  document.querySelectorAll('.metric').forEach((card) => card.classList.remove('loading'));
}

function setChartState(selector, state, message = '') {
  const wrap = $(selector).closest('.chart-wrap');
  wrap.classList.remove('loading', 'error');
  if (state) wrap.classList.add(state);
  wrap.querySelector('.chart-state').textContent = message;
}

async function checkHealth() {
  const health = await getJSON('/health');
  if (health.status !== 'healthy' || health.database !== 'connected') {
    throw new Error('Database health check failed');
  }
  return health;
}

async function loadOverview() {
  const data = await getJSON(`/api/stats/overview?${queryString()}`);
  $('#total-events').textContent = data.total_events.toLocaleString();
  $('#failed-logins').textContent = data.failed_logins.toLocaleString();
  $('#active-alerts').textContent = data.active_alerts.toLocaleString();
  $('#unique-ips').textContent = data.unique_ips.toLocaleString();
  finishMetricLoading();
}

async function loadCharts() {
  if (!window.Chart) {
    setChartState('#timeline-chart', 'error', 'Chart component unavailable.');
    setChartState('#ip-chart', 'error', 'Chart component unavailable.');
    throw new Error('Local Chart.js failed to load');
  }

  const [timeline, ips] = await Promise.all([
    getJSON(`/api/stats/timeline?${queryString()}`),
    getJSON(`/api/stats/top-ips?${queryString()}`),
  ]);

  timelineChart?.destroy();
  timelineChart = new Chart($('#timeline-chart'), {
    type: 'line',
    data: {
      labels: timeline.map((item) => selectedHours <= 24
        ? new Date(item.hour).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})
        : new Date(item.hour).toLocaleDateString([], {month: 'short', day: 'numeric'})),
      datasets: [
        {label: 'All events', data: timeline.map((item) => item.total), borderColor: '#21d4fd', backgroundColor: '#21d4fd16', fill: true, tension: 0.35},
        {label: 'Failed', data: timeline.map((item) => item.failed), borderColor: '#ff5263', backgroundColor: '#ff526316', fill: true, tension: 0.35},
      ],
    },
    options: {maintainAspectRatio: false, plugins: {legend: {labels: {boxWidth: 8, usePointStyle: true}}}, scales: {x: {grid: {display: false}}, y: {beginAtZero: true, ticks: {precision: 0}}}},
  });
  setChartState('#timeline-chart', '');

  ipChart?.destroy();
  ipChart = new Chart($('#ip-chart'), {
    type: 'bar',
    data: {
      labels: ips.map((item) => item.ip),
      datasets: [{label: 'Failed logins', data: ips.map((item) => item.count), backgroundColor: ['#ff5263', '#ff715f', '#ff9062', '#ffae65', '#ffca70'], borderRadius: 5}],
    },
    options: {indexAxis: 'y', maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {x: {beginAtZero: true, ticks: {precision: 0}}, y: {grid: {display: false}}}},
  });
  setChartState('#ip-chart', '');
}

async function loadAlerts() {
  const severity = $('#severity-filter').value;
  const alertStatus = $('#alert-status-filter').value;
  const statusParam = alertStatus === 'open' ? '&acknowledged=false' : alertStatus === 'acknowledged' ? '&acknowledged=true' : '';
  const data = await getJSON(`/api/alerts?page_size=20&${queryString()}${severity ? `&severity=${severity}` : ''}${statusParam}`);
  $('#alerts-body').innerHTML = data.items.map((alert) => {
    const severity = ['high', 'medium', 'low'].includes(alert.severity) ? alert.severity : 'low';
    const id = Number(alert.id);
    return `<tr><td><span class="badge ${severity}">${escapeHTML(severity)}</span></td><td><strong>${escapeHTML(alert.title)}</strong><br><span class="muted">${escapeHTML(alert.rule_name)}</span></td><td class="mono">${escapeHTML(alert.source_ip)}</td><td>${escapeHTML(fmt(alert.created_at))}</td><td>${alert.acknowledged ? 'Acknowledged' : 'Open'}</td><td><div class="row-actions"><button class="detail-button" data-id="${id}">View details</button><button class="ack" data-id="${id}" ${alert.acknowledged ? 'disabled' : ''}>Acknowledge</button></div></td></tr>`;
  }).join('');
  $('#alerts-empty').hidden = data.items.length > 0;
  document.querySelectorAll('.detail-button').forEach((button) => button.addEventListener('click', () => {
    openAlertDetail(button.dataset.id);
  }));
  document.querySelectorAll('.ack:not(:disabled)').forEach((button) => button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await getJSON(`/api/alerts/${button.dataset.id}/acknowledge`, {method: 'PATCH'});
      await Promise.all([loadAlerts(), loadOverview()]);
    } catch (error) {
      showBanner('Action failed', 'The alert could not be acknowledged. Please retry.');
      button.disabled = false;
    }
  }));
}

function closeAlertDetail() {
  $('#alert-modal').hidden = true;
  currentDetailAlertId = undefined;
}

function setDetailValue(selector, value) {
  $(selector).textContent = value || '—';
}

async function openAlertDetail(alertId) {
  currentDetailAlertId = alertId;
  $('#alert-modal').hidden = false;
  setDetailValue('#detail-incident', 'LOADING INCIDENT');
  setDetailValue('#detail-title', 'Loading alert...');
  setDetailValue('#detail-description', 'Retrieving detection context and source log.');
  $('#detail-ack').disabled = true;

  try {
    const alert = await getJSON(`/api/alerts/${alertId}`);
    if (String(currentDetailAlertId) !== String(alert.id)) return;
    const log = alert.log;
    setDetailValue('#detail-incident', alert.incident_id);
    setDetailValue('#detail-title', alert.title);
    setDetailValue('#detail-description', alert.description);
    setDetailValue('#detail-rule', alert.rule_name);
    setDetailValue('#detail-ip', alert.source_ip);
    setDetailValue('#detail-time', fmt(alert.created_at));
    setDetailValue('#detail-username', log?.username);
    setDetailValue('#detail-event', log?.event_type);
    setDetailValue('#detail-result', log ? `${log.status} / ${log.country || 'Unknown'}` : undefined);
    $('#detail-severity').className = `badge ${alert.severity}`;
    setDetailValue('#detail-severity', alert.severity);
    setDetailValue('#detail-status', alert.acknowledged ? 'Acknowledged' : 'Open');
    $('#detail-status').className = `incident-state ${alert.acknowledged ? 'acknowledged' : 'open'}`;
    $('#detail-raw').textContent = log ? JSON.stringify(log, null, 2) : 'No source log attached.';
    $('#detail-ack').disabled = alert.acknowledged;
    $('#detail-ack').textContent = alert.acknowledged ? 'Incident acknowledged' : 'Acknowledge incident';
  } catch (error) {
    console.error('Alert detail failed:', error);
    setDetailValue('#detail-incident', 'INCIDENT UNAVAILABLE');
    setDetailValue('#detail-title', 'Could not load alert');
    setDetailValue('#detail-description', 'The incident endpoint could not be reached. Close this panel and retry.');
  }
}

async function acknowledgeDetailAlert() {
  if (!currentDetailAlertId) return;
  const button = $('#detail-ack');
  button.disabled = true;
  button.textContent = 'Acknowledging...';
  try {
    await getJSON(`/api/alerts/${currentDetailAlertId}/acknowledge`, {method: 'PATCH'});
    await Promise.all([loadAlerts(), loadOverview()]);
    await openAlertDetail(currentDetailAlertId);
  } catch (error) {
    showBanner('Action failed', 'The incident could not be acknowledged. Please retry.');
    button.disabled = false;
    button.textContent = 'Acknowledge incident';
  }
}

function exportIncidentReport() {
  if (!currentDetailAlertId) return;
  window.open(`/api/alerts/${currentDetailAlertId}/report`, '_blank', 'noopener');
}

async function loadEvents() {
  const status = $('#event-status-filter').value;
  const logs = await getJSON(`/api/logs?limit=20&${queryString()}${status ? `&status=${status}` : ''}`);
  $('#events-body').innerHTML = logs.map((log) => {
    const status = ['success', 'failed'].includes(log.status) ? log.status : 'failed';
    return `<tr><td>${escapeHTML(fmt(log.timestamp))}</td><td class="mono">${escapeHTML(log.source_ip)}</td><td>${escapeHTML(log.username)}</td><td>${escapeHTML(log.event_type)}</td><td><span class="badge ${status}">${escapeHTML(status)}</span></td><td>${escapeHTML(log.country || '—')}</td></tr>`;
  }).join('');
  $('#events-empty').hidden = logs.length > 0;
}

async function refresh() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  setEngineStatus('checking', 'Checking detection engine...');
  $('#retry-button').disabled = true;

  try {
    await checkHealth();
    hideBanner();
    setEngineStatus('online', 'Detection engine online');

    const results = await Promise.allSettled([
      loadOverview(),
      loadCharts(),
      loadAlerts(),
      loadEvents(),
    ]);
    const failures = results.filter((result) => result.status === 'rejected');
    if (failures.length) {
      console.error('Dashboard component failures:', failures);
      showBanner('Some data could not be loaded', 'The backend is online, but one or more dashboard components failed.');
    }
  } catch (error) {
    console.error('Backend health check failed:', error);
    finishMetricLoading();
    setEngineStatus('offline', 'Detection engine offline');
    setChartState('#timeline-chart', 'error', 'Backend unavailable.');
    setChartState('#ip-chart', 'error', 'Backend unavailable.');
    showBanner('Backend offline', 'Could not connect to the API or PostgreSQL. Check Docker, then retry.');
  } finally {
    refreshInProgress = false;
    $('#retry-button').disabled = false;
  }
}

$('#severity-filter').addEventListener('change', () => loadAlerts().catch(() => {
  showBanner('Filter failed', 'Alert data could not be refreshed.');
}));
$('#alert-status-filter').addEventListener('change', () => loadAlerts().catch(() => {
  showBanner('Filter failed', 'Alert status could not be refreshed.');
}));
$('#event-status-filter').addEventListener('change', () => loadEvents().catch(() => {
  showBanner('Filter failed', 'Event results could not be refreshed.');
}));
$('#time-filter').addEventListener('change', (event) => {
  selectedHours = Number(event.target.value);
  const labels = {1: 'Events (1h)', 24: 'Events (24h)', 168: 'Events (7d)', 720: 'Events (30d)'};
  $('#events-range-label').textContent = labels[selectedHours];
  document.querySelectorAll('.metric').forEach((card) => card.classList.add('loading'));
  setChartState('#timeline-chart', 'loading', 'Loading selected time range...');
  setChartState('#ip-chart', 'loading', 'Loading selected time range...');
  refresh();
});
$('#search-input').addEventListener('input', (event) => {
  clearTimeout(searchTimer);
  const value = event.target.value.trim();
  $('#search-clear').hidden = !value;
  searchTimer = setTimeout(() => {
    searchQuery = value;
    document.querySelectorAll('.metric').forEach((card) => card.classList.add('loading'));
    setChartState('#timeline-chart', 'loading', value ? `Searching for “${value}”...` : 'Loading all security events...');
    setChartState('#ip-chart', 'loading', value ? `Searching for “${value}”...` : 'Loading all source data...');
    refresh();
  }, 400);
});
$('#search-clear').addEventListener('click', () => {
  $('#search-input').value = '';
  $('#search-clear').hidden = true;
  searchQuery = '';
  refresh();
});
$('#retry-button').addEventListener('click', refresh);

async function loadAnalystIdentity() {
  const data = await getJSON('/auth/me');
  $('#analyst-user').textContent = data.username;
}

async function logoutAnalyst() {
  $('#logout-button').disabled = true;
  try {
    await fetch('/auth/logout', {method: 'POST'});
  } finally {
    window.location.replace('/login');
  }
}

$('#logout-button').addEventListener('click', logoutAnalyst);

function resetImportModal() {
  selectedImportFile = undefined;
  $('#log-file').value = '';
  $('#selected-file').textContent = 'Required: timestamp, source_ip, username, status';
  $('#import-result').hidden = true;
  $('#import-result').className = 'import-result';
  $('#import-submit').disabled = true;
  $('#import-submit').textContent = 'Import logs';
}

function openImportModal() {
  resetImportModal();
  $('#import-modal').hidden = false;
}

function closeImportModal() {
  $('#import-modal').hidden = true;
}

function chooseImportFile(file) {
  if (!file) return;
  selectedImportFile = file;
  $('#selected-file').textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
  $('#import-submit').disabled = false;
  $('#import-result').hidden = true;
}

async function uploadImportFile() {
  if (!selectedImportFile) return;
  const submit = $('#import-submit');
  const result = $('#import-result');
  submit.disabled = true;
  submit.textContent = 'Importing...';
  result.hidden = true;

  const form = new FormData();
  form.append('file', selectedImportFile);
  try {
    const data = await getJSON('/api/logs/upload', {method: 'POST', body: form});
    result.className = 'import-result success';
    result.textContent = `Imported ${data.imported} logs, rejected ${data.rejected}, and created ${data.alerts_created} alerts.`;
    result.hidden = false;
    submit.textContent = 'Imported';
    await refresh();
  } catch (error) {
    console.error('Log import failed:', error);
    result.className = 'import-result error';
    result.textContent = 'Import failed. Check the file type and required columns, then try again.';
    result.hidden = false;
    submit.disabled = false;
    submit.textContent = 'Retry import';
  }
}

$('#import-open').addEventListener('click', openImportModal);
$('#import-close').addEventListener('click', closeImportModal);
$('#import-cancel').addEventListener('click', closeImportModal);
$('#log-file').addEventListener('change', (event) => chooseImportFile(event.target.files[0]));
$('#import-submit').addEventListener('click', uploadImportFile);
$('#detail-close').addEventListener('click', closeAlertDetail);
$('#detail-dismiss').addEventListener('click', closeAlertDetail);
$('#detail-ack').addEventListener('click', acknowledgeDetailAlert);
$('#detail-report').addEventListener('click', exportIncidentReport);
$('#alert-modal').addEventListener('click', (event) => {
  if (event.target === $('#alert-modal')) closeAlertDetail();
});
$('#import-modal').addEventListener('click', (event) => {
  if (event.target === $('#import-modal')) closeImportModal();
});
$('#drop-zone').addEventListener('dragover', (event) => {
  event.preventDefault();
  $('#drop-zone').classList.add('dragging');
});
$('#drop-zone').addEventListener('dragleave', () => $('#drop-zone').classList.remove('dragging'));
$('#drop-zone').addEventListener('drop', (event) => {
  event.preventDefault();
  $('#drop-zone').classList.remove('dragging');
  chooseImportFile(event.dataTransfer.files[0]);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !$('#import-modal').hidden) closeImportModal();
  if (event.key === 'Escape' && !$('#alert-modal').hidden) closeAlertDetail();
});

loadAnalystIdentity().catch(() => window.location.replace('/login'));
refresh();
setInterval(refresh, 30_000);
