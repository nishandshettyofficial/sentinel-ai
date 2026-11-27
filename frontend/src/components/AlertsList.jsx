import React, { useState } from 'react';
import { 
  AlertCircle, 
  Clock, 
  ShieldX, 
  Terminal, 
  ArrowUpRight, 
  Info, 
  CheckCircle2, 
  XCircle, 
  Search, 
  Filter,
  Eye,
  X,
  FileCode2,
  ExternalLink
} from 'lucide-react';
import { updateAlertStatus } from '../services/api';

export default function AlertsList({ alerts = [], onAlertUpdated }) {
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [isUpdating, setIsUpdating] = useState(false);

  const getSeverityStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-400 border-rose-500/40 glow-rose';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-400 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-cyan-950/80 text-cyan-400 border-cyan-500/40';
      default:
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'NEW':
        return 'bg-rose-950/60 text-rose-400 border-rose-500/30';
      case 'INVESTIGATING':
        return 'bg-amber-950/60 text-amber-400 border-amber-500/30';
      case 'RESOLVED':
        return 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30';
      case 'DISMISSED':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const handleStatusChange = async (alertId, newStatus) => {
    setIsUpdating(true);
    try {
      const updated = await updateAlertStatus(alertId, newStatus);
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(updated);
      }
      if (onAlertUpdated) {
        onAlertUpdated();
      }
    } catch (err) {
      console.error('Failed to update alert triage status:', err);
    } finally {
      setIsUpdating(false);
    }
  };

  const filteredAlerts = alerts.filter((al) => {
    if (severityFilter === 'ALL') return true;
    return al.severity === severityFilter;
  });

  return (
    <div className="space-y-3">
      {/* Filter Tabs */}
      <div className="flex items-center justify-between pb-1 border-b border-slate-800/80 text-[11px] font-mono">
        <div className="flex items-center space-x-1">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-0.5 rounded transition ${
                severityFilter === sev
                  ? 'bg-slate-800 text-cyan-300 font-bold border border-slate-700'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
        <span className="text-slate-500 text-[10px]">
          Showing {filteredAlerts.length} of {alerts.length}
        </span>
      </div>

      {filteredAlerts.length === 0 ? (
        <div className="p-8 text-center text-xs font-mono text-slate-500 border border-dashed border-slate-800 rounded-xl">
          NO UNRESOLVED SECURITY ALERTS MATCHING FILTER
        </div>
      ) : (
        <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
          {filteredAlerts.map((alert) => (
            <div 
              key={alert.id}
              onClick={() => setSelectedAlert(alert)}
              className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 hover:bg-slate-900/80 transition flex flex-col justify-between space-y-2.5 cursor-pointer group"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start space-x-2.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 mt-0.5 ${getSeverityStyle(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <div>
                    <h4 className="text-xs font-semibold text-slate-100 group-hover:text-cyan-300 transition leading-snug">
                      {alert.title}
                    </h4>
                    <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                      {alert.description}
                    </p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getStatusBadge(alert.status)}`}>
                    {alert.status}
                  </span>
                  <span className="text-[9px] font-mono text-amber-400/80 bg-amber-950/40 px-1.5 py-0.2 rounded border border-amber-500/20">
                    UNCONFIRMED
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400">
                <div className="flex items-center space-x-3">
                  <span className="text-cyan-400 flex items-center space-x-1">
                    <Terminal className="w-3 h-3" />
                    <span>{alert.rule_name}</span>
                  </span>
                  {alert.source_ip && (
                    <span>SRC: <span className="text-slate-200">{alert.source_ip}</span></span>
                  )}
                  {alert.target_user && (
                    <span>TGT: <span className="text-slate-200">{alert.target_user}</span></span>
                  )}
                </div>
                <div className="flex items-center space-x-2">
                  <div className="flex items-center space-x-1 text-slate-500">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                  <Eye className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Forensic Evidence Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 space-y-5 text-xs text-slate-200 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div className="space-y-1.5">
                <div className="flex items-center space-x-2">
                  <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityStyle(selectedAlert.severity)}`}>
                    {selectedAlert.severity}
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getStatusBadge(selectedAlert.status)}`}>
                    STATUS: {selectedAlert.status}
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">
                    ID #{selectedAlert.id}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">
                  {selectedAlert.title}
                </h3>
              </div>
              <button 
                onClick={() => setSelectedAlert(null)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Non-Definitive Anomaly Warning Banner */}
            <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/40 text-amber-200 text-[11px] leading-relaxed flex items-start space-x-3">
              <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-amber-300 uppercase tracking-wide text-[10px] font-mono mb-0.5">
                  Unconfirmed Behavioral Anomaly • SOC Triage Required
                </p>
                <p className="text-slate-300">
                  {selectedAlert.evidence?.disclaimer || "Alert represents a detected behavioral anomaly and must be investigated before confirming as malicious."}
                </p>
              </div>
            </div>

            {/* Alert Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-[11px]">
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block text-[10px]">CORRELATION RULE</span>
                <span className="text-cyan-400 font-semibold truncate block mt-0.5">{selectedAlert.rule_name}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block text-[10px]">SOURCE IP</span>
                <span className="text-slate-200 font-semibold block mt-0.5">{selectedAlert.source_ip || 'Internal / N/A'}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block text-[10px]">TARGET ACCOUNT</span>
                <span className="text-slate-200 font-semibold block mt-0.5">{selectedAlert.target_user || 'Multiple / System'}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <span className="text-slate-500 block text-[10px]">TIMESTAMP</span>
                <span className="text-slate-300 block mt-0.5">{new Date(selectedAlert.created_at).toLocaleString()}</span>
              </div>
            </div>

            {/* Description */}
            <div className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-800/80 space-y-1">
              <span className="text-slate-400 font-mono text-[10px] font-bold uppercase tracking-wider">
                Observation Narrative
              </span>
              <p className="text-xs text-slate-200 leading-relaxed">
                {selectedAlert.description}
              </p>
            </div>

            {/* Forensic Evidence Detail Breakdown */}
            {selectedAlert.evidence && (
              <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                <span className="text-cyan-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1.5">
                  <FileCode2 className="w-3.5 h-3.5" />
                  <span>Forensic Telemetry Evidence</span>
                </span>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                  {Object.entries(selectedAlert.evidence).map(([key, val]) => {
                    if (key === 'disclaimer' || key === 'recommendation') return null;
                    return (
                      <div key={key} className="p-2 rounded bg-slate-900 border border-slate-800/60 flex items-start justify-between gap-2">
                        <span className="text-slate-400 uppercase text-[10px]">{key.replace(/_/g, ' ')}:</span>
                        <span className="text-slate-200 text-right truncate font-medium">
                          {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {selectedAlert.evidence.recommendation && (
                  <div className="mt-3 p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/30 text-cyan-200 text-[11px]">
                    <span className="font-bold block text-cyan-400 mb-0.5 text-[10px] uppercase font-mono">
                      Recommended SOC Response:
                    </span>
                    {selectedAlert.evidence.recommendation}
                  </div>
                )}
              </div>
            )}

            {/* Triage Status Actions */}
            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <span className="text-[11px] font-mono text-slate-400">
                Change Status:
              </span>
              <div className="flex items-center space-x-2">
                <button
                  disabled={isUpdating}
                  onClick={() => handleStatusChange(selectedAlert.id, 'INVESTIGATING')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                    selectedAlert.status === 'INVESTIGATING'
                      ? 'bg-amber-600 text-white font-bold'
                      : 'bg-slate-800 hover:bg-slate-700 text-amber-300'
                  }`}
                >
                  Investigate
                </button>
                <button
                  disabled={isUpdating}
                  onClick={() => handleStatusChange(selectedAlert.id, 'RESOLVED')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                    selectedAlert.status === 'RESOLVED'
                      ? 'bg-emerald-600 text-white font-bold'
                      : 'bg-slate-800 hover:bg-slate-700 text-emerald-300'
                  }`}
                >
                  Resolve
                </button>
                <button
                  disabled={isUpdating}
                  onClick={() => handleStatusChange(selectedAlert.id, 'DISMISSED')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                    selectedAlert.status === 'DISMISSED'
                      ? 'bg-slate-600 text-white font-bold'
                      : 'bg-slate-800 hover:bg-slate-700 text-slate-400'
                  }`}
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
