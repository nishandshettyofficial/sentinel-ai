import React, { useState, useEffect } from 'react';
import { 
  Globe2, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  HelpCircle, 
  AlertTriangle, 
  Terminal, 
  MapPin, 
  Server, 
  Activity, 
  Clock, 
  ExternalLink, 
  ArrowRight, 
  RefreshCw,
  Cpu,
  Layers,
  CheckCircle2,
  XCircle,
  FileSearch,
  Key,
  ShieldX
} from 'lucide-react';
import { 
  investigateIndicator, 
  fetchThreatIntelSamples, 
  fetchThreatIntelStatus 
} from '../services/api';

export default function ThreatIntelView({ onNavigateToLogs }) {
  const [query, setQuery] = useState('185.220.101.45');
  const [report, setReport] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [samples, setSamples] = useState([]);
  const [providerStatus, setProviderStatus] = useState(null);
  const [searchHistory, setSearchHistory] = useState(['185.220.101.45', 'tunnel-stage-verify.top', '8.8.8.8']);

  useEffect(() => {
    // Load samples and provider status on mount
    fetchThreatIntelSamples().then(setSamples).catch(console.warn);
    fetchThreatIntelStatus().then(setProviderStatus).catch(console.warn);
    // Auto-run initial investigation on sample indicator
    handleSearch('185.220.101.45');
  }, []);

  const handleSearch = async (indicatorToSearch) => {
    const target = (indicatorToSearch || query).trim();
    if (!target) return;
    setIsLoading(true);
    setErrorMessage('');
    try {
      const data = await investigateIndicator(target);
      setReport(data);
      setQuery(target);
      setSearchHistory(prev => [target, ...prev.filter(item => item !== target)].slice(0, 8));
    } catch (err) {
      setErrorMessage(err.message || 'Failed to complete threat intelligence lookup');
      setReport(null);
    } finally {
      setIsLoading(false);
    }
  };

  const getVerdictStyle = (verdict) => {
    switch (verdict) {
      case 'MALICIOUS':
        return {
          banner: 'bg-rose-950/40 border-rose-500/50 text-rose-300',
          badge: 'bg-rose-950/80 text-rose-400 border-rose-500/40 glow-rose',
          icon: ShieldX,
          label: 'CONFIRMED MALICIOUS'
        };
      case 'SUSPICIOUS':
        return {
          banner: 'bg-amber-950/40 border-amber-500/50 text-amber-300',
          badge: 'bg-amber-950/80 text-amber-400 border-amber-500/40',
          icon: AlertTriangle,
          label: 'SUSPICIOUS ANOMALY'
        };
      case 'BENIGN':
        return {
          banner: 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300',
          badge: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40',
          icon: ShieldCheck,
          label: 'BENIGN / TRUSTED'
        };
      default:
        return {
          banner: 'bg-slate-900 border-slate-700 text-slate-300',
          badge: 'bg-slate-800 text-slate-300 border-slate-700',
          icon: HelpCircle,
          label: 'UNKNOWN / UNRATED'
        };
    }
  };

  const verdictMeta = report ? getVerdictStyle(report.verdict) : null;
  const VerdictIcon = verdictMeta?.icon || HelpCircle;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Globe2 className="w-5 h-5 animate-spin-slow" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white flex items-center space-x-2">
              <span>THREAT INTELLIGENCE RADAR // REPUTATION ANALYSIS</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-500/40">
                MODULE 3
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Query external threat feeds (VirusTotal, AbuseIPDB) and cross-reference with internal SOC event telemetry.
            </p>
          </div>
        </div>

        {/* Threat Provider Readiness Badges */}
        <div className="flex flex-wrap items-center gap-2 self-start md:self-auto text-[10px] font-mono">
          <span className={`px-2 py-1 rounded border flex items-center space-x-1.5 ${
            providerStatus?.virustotal?.configured
              ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
              : 'bg-slate-800/80 text-slate-400 border-slate-700'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${providerStatus?.virustotal?.configured ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`}></span>
            <span>VirusTotal: {providerStatus?.virustotal?.configured ? 'API Connected' : 'Curated Fallback'}</span>
          </span>
          <span className={`px-2 py-1 rounded border flex items-center space-x-1.5 ${
            providerStatus?.abuseipdb?.configured
              ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
              : 'bg-slate-800/80 text-slate-400 border-slate-700'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${providerStatus?.abuseipdb?.configured ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`}></span>
            <span>AbuseIPDB: {providerStatus?.abuseipdb?.configured ? 'API Connected' : 'Curated Fallback'}</span>
          </span>
        </div>
      </div>

      {/* Investigation Search Bar & Sample Chips */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <form onSubmit={(e) => { e.preventDefault(); handleSearch(); }} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter IP address or domain (e.g. 185.220.101.45, 1[.]1[.]1[.]1, evil-c2.top)..."
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !query.trim()}
            className="flex items-center justify-center space-x-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium shadow transition shrink-0"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>QUERYING FEEDS...</span>
              </>
            ) : (
              <>
                <FileSearch className="w-3.5 h-3.5" />
                <span>INVESTIGATE INDICATOR</span>
              </>
            )}
          </button>
        </form>

        {/* Sample Indicator Chips */}
        <div className="pt-2 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-slate-400 uppercase tracking-wider text-[10px]">Quick Test Indicators:</span>
            {searchHistory.length > 0 && (
              <span className="text-slate-500 text-[10px]">
                History: {searchHistory.slice(0, 3).join(', ')}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {samples.map((s, idx) => (
              <button
                key={idx}
                onClick={() => handleSearch(s.indicator)}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono border transition flex items-center space-x-1.5 ${
                  query === s.indicator
                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40 glow-cyan'
                    : 'bg-slate-950/80 hover:bg-slate-800/90 text-slate-300 border-slate-800'
                }`}
              >
                <span>{s.indicator}</span>
                <span className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                  s.risk === 'CRITICAL' ? 'bg-rose-950 text-rose-400' :
                  s.risk === 'HIGH' ? 'bg-amber-950 text-amber-400' :
                  s.risk === 'MEDIUM' ? 'bg-cyan-950 text-cyan-400' :
                  s.risk === 'UNKNOWN' ? 'bg-slate-800 text-slate-400' :
                  'bg-emerald-950 text-emerald-400'
                }`}>
                  {s.risk}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error state */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center space-x-2.5">
          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Error: {errorMessage}</span>
        </div>
      )}

      {/* Investigation Report Display */}
      {report && (
        <div className="space-y-6">
          {/* Top Verdict Banner */}
          <div className={`p-5 rounded-2xl border ${verdictMeta.banner} space-y-4`}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-start sm:items-center space-x-3.5">
                <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 shrink-0">
                  <VerdictIcon className="w-7 h-7 text-white" />
                </div>
                <div>
                  <div className="flex items-center space-x-2.5 mb-1">
                    <span className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${verdictMeta.badge}`}>
                      {verdictMeta.label}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      INDICATOR TYPE: <b className="text-white">{report.indicator_type}</b>
                    </span>
                    {report.is_private_ip && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                        RFC1918 PRIVATE
                      </span>
                    )}
                  </div>
                  <h3 className="text-lg font-mono font-bold text-white tracking-wide">
                    {report.indicator}
                  </h3>
                </div>
              </div>

              {/* Confidence Risk Score Meter */}
              <div className="flex items-center space-x-4 bg-slate-950/70 p-3 rounded-xl border border-slate-800/80 shrink-0">
                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">Risk Score</span>
                  <span className={`text-xl font-mono font-bold ${
                    report.confidence_score >= 70 ? 'text-rose-400' :
                    report.confidence_score >= 30 ? 'text-amber-400' :
                    report.verdict === 'UNKNOWN' ? 'text-slate-400' :
                    'text-emerald-400'
                  }`}>
                    {report.confidence_score}/100
                  </span>
                </div>
                <div className="w-16 h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div 
                    className={`h-full ${
                      report.confidence_score >= 70 ? 'bg-rose-500' :
                      report.confidence_score >= 30 ? 'bg-amber-500' :
                      'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.max(4, report.confidence_score)}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Unknown Indicator Explicit Clarification Notice */}
            {report.verdict === 'UNKNOWN' && (
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-start space-x-2">
                <HelpCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <b className="text-cyan-300 block mb-0.5">UNKNOWN / UNRATED INDICATOR NOTICE:</b>
                  This indicator was not found in active abuse blocklists or malicious feed signatures. Sentinel AI explicitly distinguishes unrated indicators from confirmed benign entities. Continue passive telemetry observation.
                </div>
              </div>
            )}

            {/* Summary narrative */}
            <p className="text-xs text-slate-200 leading-relaxed font-sans pt-1 border-t border-slate-800/60">
              {report.summary}
            </p>

            {/* Threat Categories / Tags */}
            {report.threat_categories?.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-[10px] font-mono text-slate-400 uppercase mr-1">Classification Tags:</span>
                {report.threat_categories.map((cat, i) => (
                  <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/90 text-cyan-300 border border-slate-700">
                    {cat}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* 3 Core Intelligence Cards: AbuseIPDB, VirusTotal, Internal SOC */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Source 1: AbuseIPDB */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-1.5">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    <span>AbuseIPDB Telemetry</span>
                  </h4>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {report.abuseipdb?.status || (report.indicator_type === 'DOMAIN' ? 'N/A (Domain)' : 'OFFLINE')}
                  </span>
                </div>

                {report.abuseipdb ? (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Abuse Confidence:</span>
                      <span className={`font-bold ${report.abuseipdb.abuse_score >= 80 ? 'text-rose-400' : report.abuseipdb.abuse_score >= 20 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {report.abuseipdb.abuse_score}%
                      </span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Total Reports:</span>
                      <span className="text-slate-200">{report.abuseipdb.total_reports} reports</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">ISP / ASN:</span>
                      <span className="text-slate-300 truncate max-w-[140px]">{report.abuseipdb.isp || 'N/A'}</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Tor Exit Node:</span>
                      <span className={report.abuseipdb.is_tor ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                        {report.abuseipdb.is_tor ? 'YES (Confirmed)' : 'No'}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-6 text-center text-[11px] font-mono text-slate-500">
                    {report.indicator_type === 'DOMAIN' 
                      ? 'AbuseIPDB queries apply specifically to IPv4/IPv6 addresses.' 
                      : 'No AbuseIPDB record available for this private/internal range.'}
                  </div>
                )}
              </div>

              {report.abuseipdb?.last_reported_at && (
                <p className="text-[10px] font-mono text-slate-500 border-t border-slate-800 pt-2">
                  Last Reported: {new Date(report.abuseipdb.last_reported_at).toLocaleDateString()}
                </p>
              )}
            </div>

            {/* Source 2: VirusTotal */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    <span>VirusTotal Reputation</span>
                  </h4>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {report.virustotal?.status || 'OFFLINE'}
                  </span>
                </div>

                {report.virustotal ? (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Security Vendors:</span>
                      <span className="text-slate-200">
                        <b className="text-rose-400">{report.virustotal.malicious_votes}</b> / {report.virustotal.malicious_votes + report.virustotal.harmless_votes + report.virustotal.undetected_votes} flagged
                      </span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Community Score:</span>
                      <span className={report.virustotal.reputation_score < 0 ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                        {report.virustotal.reputation_score}
                      </span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Registrar / ASN:</span>
                      <span className="text-slate-300 truncate max-w-[140px]">{report.virustotal.registrar_or_as_owner || 'N/A'}</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px]">Country:</span>
                      <span className="text-slate-300">{report.virustotal.country || report.geolocation?.country || 'Unknown'}</span>
                    </div>
                  </div>
                ) : (
                  <div className="p-6 text-center text-[11px] font-mono text-slate-500">
                    VirusTotal data unavailable for RFC1918 private subnets.
                  </div>
                )}
              </div>

              {report.virustotal?.categories?.length > 0 && (
                <div className="border-t border-slate-800 pt-2 flex flex-wrap gap-1">
                  {report.virustotal.categories.map((c, i) => (
                    <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {c}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Source 3: Sentinel AI Internal SOC Telemetry Correlation */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Internal Sentinel AI Telemetry</span>
                  </h4>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                    report.internal_soc_activity.observed_in_local_logs
                      ? 'bg-amber-950/80 text-amber-300 border-amber-500/40 animate-pulse'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {report.internal_soc_activity.observed_in_local_logs ? 'DETECTED LOCALLY' : 'NOT IN LOGS'}
                  </span>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                    <span className="text-slate-400 text-[11px]">Logged Events:</span>
                    <span className="text-white font-bold">{report.internal_soc_activity.events_count} occurrences</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                    <span className="text-slate-400 text-[11px]">Triggered Alerts:</span>
                    <span className={report.internal_soc_activity.alerts_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                      {report.internal_soc_activity.alerts_count} alerts
                    </span>
                  </div>
                  {report.internal_soc_activity.associated_users?.length > 0 && (
                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800/60">
                      <span className="text-slate-400 text-[11px] block mb-1">Targeted User Accounts:</span>
                      <div className="flex flex-wrap gap-1">
                        {report.internal_soc_activity.associated_users.map((u, i) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300">
                            {u}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {report.internal_soc_activity.observed_in_local_logs && onNavigateToLogs && (
                <button
                  onClick={() => onNavigateToLogs(report.indicator)}
                  className="w-full flex items-center justify-center space-x-1.5 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition"
                >
                  <span>PIVOT TO LOG ANALYZER</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

          </div>

          {/* Actionable SOC Recommendation */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start space-x-3">
            <Terminal className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <span className="font-mono text-cyan-400 font-bold uppercase tracking-wider text-[10px] block">
                SOC Analyst Mitigation Guidance:
              </span>
              <p className="text-slate-300 leading-relaxed">
                {report.recommendation}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
