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
      },
      {
        id: 2,
        timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
        event_type: 'C2_BEACON',
        action: 'DNS_TUNNEL_QUERY',
        source_ip: '192.168.1.77',
        user_identity: 'workstation-07',
        status: 'BLOCKED',
        severity: 'HIGH',
        details: { domain: 'sync-cdn-telemetry.xyz' }
      },
      {
        id: 3,
        timestamp: new Date(Date.now() - 35 * 60000).toISOString(),
        event_type: 'PORT_SCAN',
        action: 'TCP_SYN_SWEEP',
        source_ip: '45.154.255.89',
        user_identity: null,
        status: 'BLOCKED',
        severity: 'HIGH',
        details: { scanned_ports: [22, 80, 443, 3389] }
      },
      {
        id: 4,
        timestamp: new Date(Date.now() - 60 * 60000).toISOString(),
        event_type: 'AUTH_SUCCESS',
        action: 'LOGIN_WEB',
        source_ip: '192.168.1.105',
        user_identity: 'sarah.dev',
        status: 'SUCCESS',
        severity: 'LOW',
        details: { mfa: true }
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
    return [
      {
        id: 101,
        title: 'SSH Brute-Force Password Spraying Detected',
        description: '5 consecutive failed attempts against root account from 185.220.101.45 within 10 minutes.',
        severity: 'CRITICAL',
        status: 'INVESTIGATING',
        rule_name: 'RULE_AUTH_BRUTE_FORCE',
        source_ip: '185.220.101.45',
        target_user: 'root',
        created_at: new Date().toISOString()
      },
      {
        id: 102,
        title: 'Suspected Command & Control (C2) DNS Tunneling',
        description: 'High-frequency DNS queries to newly registered domain sync-cdn-telemetry.xyz.',
        severity: 'HIGH',
        status: 'NEW',
        rule_name: 'RULE_NETWORK_C2_BEACON',
        source_ip: '192.168.1.77',
        target_user: 'workstation-07',
        created_at: new Date(Date.now() - 25 * 60000).toISOString()
      }
    ];
  }
}
