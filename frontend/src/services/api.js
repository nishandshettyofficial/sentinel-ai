const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function fetchHealth() {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch (err) {
    console.warn('API Health Check Error:', err);
    return { status: 'offline', subsystems: {} };
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
    return [
      {
        id: 1,
        timestamp: new Date().toISOString(),
        event_type: 'AUTH_FAILED',
        action: 'SSH_LOGIN',
        source_ip: '185.220.101.45',
        user_identity: 'root',
        status: 'BLOCKED',
        severity: 'CRITICAL',
        details: { port: 22, attempts: 5 }
      }
    ];
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

// ----------------- MODULE 2: LOG ANALYZER API -----------------

export async function uploadLogFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${BASE_URL}/api/v1/logs/upload`, {
    method: 'POST',
    body: formData
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(err.detail || 'Failed to upload log file');
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
    const err = await res.json().catch(() => ({ detail: 'Ingestion failed' }));
    throw new Error(err.detail || 'Failed to ingest raw logs');
  }
  return await res.json();
}

export async function fetchLogSamples() {
  const res = await fetch(`${BASE_URL}/api/v1/logs/samples`);
  if (!res.ok) throw new Error('Failed to fetch samples');
  return await res.json();
}

export async function ingestSampleLog(sampleKey) {
  const res = await fetch(`${BASE_URL}/api/v1/logs/sample/${sampleKey}`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to ingest sample ${sampleKey}`);
  return await res.json();
}

export async function fetchLogRecords({ page = 1, limit = 20, search = '', eventType = 'ALL', status = 'ALL' } = {}) {
  const params = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString()
  });
  if (search) params.append('search', search);
  if (eventType && eventType !== 'ALL') params.append('event_type', eventType);
  if (status && status !== 'ALL') params.append('status', status);

  const res = await fetch(`${BASE_URL}/api/v1/logs/records?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch log records');
  return await res.json();
}
