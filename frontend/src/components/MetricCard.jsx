import React from 'react';

export default function MetricCard({ title, value, subtitle, icon: Icon, color = 'cyan', change, trend = 'up' }) {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      text: 'text-cyan-400',
      bgIcon: 'bg-cyan-500/10 text-cyan-400',
      glow: 'group-hover:glow-cyan'
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/40',
      text: 'text-rose-400',
      bgIcon: 'bg-rose-500/10 text-rose-400',
      glow: 'group-hover:glow-rose'
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      text: 'text-amber-400',
      bgIcon: 'bg-amber-500/10 text-amber-400',
      glow: ''
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      text: 'text-emerald-400',
      bgIcon: 'bg-emerald-500/10 text-emerald-400',
      glow: 'group-hover:glow-emerald'
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      text: 'text-purple-400',
      bgIcon: 'bg-purple-500/10 text-purple-400',
      glow: ''
    }
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div className={`group relative p-4 rounded-xl bg-slate-900/60 border ${scheme.border} transition-all duration-300 ${scheme.glow}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono text-slate-400 tracking-wider uppercase">{title}</span>
        <div className={`p-2 rounded-lg ${scheme.bgIcon}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <div className="mt-3 flex items-baseline space-x-2">
        <span className="text-2xl font-bold font-mono text-white tracking-tight">{value}</span>
        {change && (
          <span className={`text-[11px] font-mono font-medium ${
            trend === 'up' ? 'text-rose-400' : 'text-emerald-400'
          }`}>
            {change}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-1 text-[11px] text-slate-400 leading-tight">
          {subtitle}
        </p>
      )}
    </div>
  );
}
