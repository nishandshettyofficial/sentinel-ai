const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function fetchHealth() {
  const t0 = performance.now();
  try {
    const res = await fetch(`${BASE_URL}/api/v1/health/detailed`);
    const latency = Math.round(performance.now() - t0);
    if (!res.ok) throw new Error('Health check failed');
    const data = await res.json();
    return { ...data, client_latency_ms: latency };
  } catch (err) {
    console.warn('API Health Check Error:', err);
    return {
      status: 'offline',
      client_latency_ms: 0,
      database: { status: 'offline', latency_ms: 0 },
      detection_engine: { status: 'offline', rules_count: 5 },
      subsystems: {}
    };
  }
}

export async function fetchDashboardSummary() {
  try {
    const res = await fetch(`${BASE_URL}/api/v1/dashboard/summary`);
    if (!res.ok) throw new Error('Failed to fetch summary');
    return await res.json();
  } catch (err) {
    console.warn('Summary fetch failed, using fallback telemetry:', err);
    return {
      total_events: 1342,
      total_alerts: 14,
      open_incidents: 3,
      threats_blocked: 89,
      severity_distribution: {
        critical: 2,
        high: 4,
        medium: 5,
        low: 3
      },
      system_status: 'ELEVATED_THREAT'
    };
  }
}

export async function fetchDashboardTrends() {
  try {
    const res = await fetch(`${BASE_URL}/api/v1/dashboard/trends`);
    if (!res.ok) throw new Error('Failed to fetch trends');
    return await res.json();
  } catch (err) {
    console.warn('Trends fetch failed, using fallback trendline:', err);
    return [
      { timestamp: '17:00', events: 120, failed_logins: 4, alerts: 1 },
      { timestamp: '18:00', events: 195, failed_logins: 9, alerts: 2 },
      { timestamp: '19:00', events: 310, failed_logins: 28, alerts: 5 },
      { timestamp: '20:00', events: 240, failed_logins: 14, alerts: 2 },
      { timestamp: '21:00', events: 180, failed_logins: 6, alerts: 1 },
      { timestamp: '22:00', events: 290, failed_logins: 32, alerts: 4 }
    ];
  }
}

export async function fetchRecentActivity(limit = 10) {
  try {
    const res = await fetch(`${BASE_URL}/api/v1/dashboard/recent-activity?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch activity');
    return await res.json();
  } catch (err) {
    console.warn('Recent activity fetch failed, using fallback:', err);
    return [];
  }
}

export async function fetchRecentAlerts(limit = 6) {
  try {
    const res = await fetch(`${BASE_URL}/api/v1/dashboard/alerts?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return await res.json();
  } catch (err) {
    console.warn('Alerts fetch failed, using fallback:', err);
    return [];
  }
}

export async function fetchAlerts({ page = 1, limit = 20, severity = 'ALL', status = 'ALL', search = '' } = {}) {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString()
  });
  if (severity && severity !== 'ALL') params.append('severity', severity);
  if (status && status !== 'ALL') params.append('status', status);
  if (search) params.append('search', search);

  const res = await fetch(`${BASE_URL}/api/v1/alerts?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch alerts list');
  return await res.json();
}

export async function fetchAlertById(alertId) {
  const res = await fetch(`${BASE_URL}/api/v1/alerts/${alertId}`);
  if (!res.ok) throw new Error(`Failed to fetch alert ${alertId}`);
  return await res.json();
}

export async function updateAlertStatus(alertId, newStatus) {
  const res = await fetch(`${BASE_URL}/api/v1/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus })
  });
  if (!res.ok) throw new Error(`Failed to update status for alert ${alertId}`);
  return await res.json();
}

// ----------------- MODULE 2: LOG ANALYZER API -----------------

export async function uploadLogFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${BASE_URL}/api/v1/logs/upload`, {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: 'Upload failed' } }));
    throw new Error(err.error?.message || err.detail || 'Failed to upload log file');
  }
  return await res.json();
}

export async function ingestRawLogs(content, format = 'csv', filename = 'manual_entry') {
  const res = await fetch(`${BASE_URL}/api/v1/logs/raw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, format, filename })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: { message: 'Ingestion failed' } }));
    throw new Error(err.error?.message || err.detail || 'Failed to ingest raw logs');
  }
  return await res.json();
}

export async function fetchLogSamples() {
  const res = await fetch(`${BASE_URL}/api/v1/logs/samples`);
  if (!res.ok) throw new Error('Failed to fetch samples');
  return await res.json();
}

export function getSampleDownloadUrl(sampleKey) {
  return `${BASE_URL}/api/v1/logs/sample/${sampleKey}/download`;
}

export async function ingestSampleLog(sampleKey) {
  const res = await fetch(`${BASE_URL}/api/v1/logs/sample/${sampleKey}`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to ingest sample ${sampleKey}`);
  return await res.json();
}

export async function fetchLogRecords({ page = 1, limit = 20, search = '', eventType = 'ALL', status = 'ALL', timeRange = 'ALL' } = {}) {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString()
  });
  if (search) params.append('search', search);
  if (eventType && eventType !== 'ALL') params.append('event_type', eventType);
  if (status && status !== 'ALL') params.append('status', status);
  if (timeRange && timeRange !== 'ALL') params.append('time_range', timeRange);

  const res = await fetch(`${BASE_URL}/api/v1/logs/records?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch log records');
  return await res.json();
}

export function getExportLogsUrl({ format = 'csv', search = '', eventType = 'ALL', status = 'ALL' } = {}) {
  const params = new URLSearchParams({ format });
  if (search) params.append('search', search);
  if (eventType && eventType !== 'ALL') params.append('event_type', eventType);
  if (status && status !== 'ALL') params.append('status', status);
  return `${BASE_URL}/api/v1/logs/export?${params.toString()}`;
}
