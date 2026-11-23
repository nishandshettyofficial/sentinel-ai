import React from 'react';
import { AlertCircle, Clock, ShieldX, Terminal, ArrowUpRight } from 'lucide-react';

export default function AlertsList({ alerts = [] }) {
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

  if (!alerts || alerts.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500 border border-dashed border-slate-800 rounded-xl">
        NO UNRESOLVED SECURITY ALERTS IN CURRENT QUEUE
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {alerts.map((alert) => (
        <div 
          key={alert.id}
          className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-2.5"
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-start space-x-2.5">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border shrink-0 mt-0.5 ${getSeverityStyle(alert.severity)}`}>
                {alert.severity}
              </span>
              <div>
                <h4 className="text-xs font-semibold text-slate-100 leading-snug">
                  {alert.title}
                </h4>
                <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
                  {alert.description}
                </p>
              </div>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 shrink-0">
              {alert.status}
            </span>
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
            <div className="flex items-center space-x-1 text-slate-500">
              <Clock className="w-3 h-3" />
              <span>{new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
