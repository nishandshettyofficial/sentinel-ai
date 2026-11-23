import React from 'react';
import { ShieldCheck, Flame, AlertCircle, Info } from 'lucide-react';

export default function SeverityDistribution({ severity }) {
  const counts = severity || { critical: 0, high: 0, medium: 0, low: 0 };
  const total = counts.critical + counts.high + counts.medium + counts.low || 1;

  const items = [
    { label: 'Critical', count: counts.critical, color: 'text-rose-400', bg: 'bg-rose-500', icon: Flame, border: 'border-rose-500/30' },
    { label: 'High', count: counts.high, color: 'text-amber-400', bg: 'bg-amber-500', icon: AlertCircle, border: 'border-amber-500/30' },
    { label: 'Medium', count: counts.medium, color: 'text-cyan-400', bg: 'bg-cyan-500', icon: Info, border: 'border-cyan-500/30' },
    { label: 'Low', count: counts.low, color: 'text-emerald-400', bg: 'bg-emerald-500', icon: ShieldCheck, border: 'border-emerald-500/30' }
  ];

  return (
    <div className="space-y-4">
      {/* Progress Bars */}
      <div className="w-full h-3 rounded-full overflow-hidden flex bg-slate-800">
        <div style={{ width: `${(counts.critical / total) * 100}%` }} className="bg-rose-500 transition-all duration-500" title={`Critical: ${counts.critical}`} />
        <div style={{ width: `${(counts.high / total) * 100}%` }} className="bg-amber-500 transition-all duration-500" title={`High: ${counts.high}`} />
        <div style={{ width: `${(counts.medium / total) * 100}%` }} className="bg-cyan-500 transition-all duration-500" title={`Medium: ${counts.medium}`} />
        <div style={{ width: `${(counts.low / total) * 100}%` }} className="bg-emerald-500 transition-all duration-500" title={`Low: ${counts.low}`} />
      </div>

      {/* Grid of badges */}
      <div className="grid grid-cols-2 gap-3">
        {items.map((item) => {
          const Icon = item.icon;
          const percentage = Math.round((item.count / total) * 100);
          return (
            <div key={item.label} className={`p-3 rounded-lg bg-slate-900/50 border ${item.border} flex items-center justify-between`}>
              <div className="flex items-center space-x-2.5">
                <div className={`p-1.5 rounded ${item.bg}/10`}>
                  <Icon className={`w-4 h-4 ${item.color}`} />
                </div>
                <div>
                  <p className="text-xs font-medium text-slate-300">{item.label}</p>
                  <p className="text-[10px] font-mono text-slate-500">{percentage}% of total</p>
                </div>
              </div>
              <span className={`text-lg font-bold font-mono ${item.color}`}>
                {item.count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
