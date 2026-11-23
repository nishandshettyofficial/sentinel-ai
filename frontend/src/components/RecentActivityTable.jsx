import React, { useState } from 'react';
import { Search, Filter, ShieldCheck, ShieldAlert, Ban } from 'lucide-react';

export default function RecentActivityTable({ activities = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('ALL');

  const filtered = activities.filter((item) => {
    const matchesSearch = 
      (item.source_ip && item.source_ip.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.user_identity && item.user_identity.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.event_type && item.event_type.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.action && item.action.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus = filterStatus === 'ALL' || item.status === filterStatus;
    return matchesSearch && matchesStatus;
  });

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            <span>ALLOW</span>
          </span>
        );
      case 'BLOCKED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/60 text-rose-400 border border-rose-500/30 glow-rose">
            <Ban className="w-3 h-3" />
            <span>BLOCKED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/60 text-amber-400 border border-amber-500/30">
            <ShieldAlert className="w-3 h-3" />
            <span>FAIL</span>
          </span>
        );
    }
  };

  const getSeverityPill = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="text-rose-400 font-mono font-bold">CRIT</span>;
      case 'HIGH':
        return <span className="text-amber-400 font-mono font-bold">HIGH</span>;
      case 'MEDIUM':
        return <span className="text-cyan-400 font-mono">MED</span>;
      default:
        return <span className="text-slate-500 font-mono">LOW</span>;
    }
  };

  return (
    <div className="space-y-3">
      {/* Search & Filter Header */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP, user, type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>

        <div className="flex items-center space-x-1 self-end sm:self-auto text-xs font-mono">
          <span className="text-slate-500 text-[11px] mr-1">STATUS:</span>
          {['ALL', 'SUCCESS', 'BLOCKED', 'FAILURE'].map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-2 py-1 rounded text-[11px] transition ${
                filterStatus === st 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' 
                  : 'text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Event Type</th>
              <th className="py-2.5 px-3">Action</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Identity</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3 text-right">Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                  NO MATCHING SECURITY TELEMETRY FOUND
                </td>
              </tr>
            ) : (
              filtered.map((ev) => (
                <tr key={ev.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td className="py-2.5 px-3 text-cyan-300 font-semibold">
                    {ev.event_type}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {ev.action}
                  </td>
                  <td className="py-2.5 px-3 text-slate-200">
                    <span className="bg-slate-950/80 px-1.5 py-0.5 rounded border border-slate-800">
                      {ev.source_ip}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {ev.user_identity || <span className="text-slate-600">N/A</span>}
                  </td>
                  <td className="py-2.5 px-3">
                    {getSeverityPill(ev.severity)}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    {getStatusBadge(ev.status)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
