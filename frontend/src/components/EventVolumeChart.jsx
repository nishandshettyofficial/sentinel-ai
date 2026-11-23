import React from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';

export default function EventVolumeChart({ data }) {
  if (!data || data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-xs font-mono text-slate-500">
        NO TELEMETRY POINTS RECORDED
      </div>
    );
  }

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl text-xs font-mono">
          <p className="text-slate-400 font-bold mb-1.5">{label}</p>
          <div className="space-y-1">
            <p className="text-cyan-400 flex items-center justify-between space-x-4">
              <span>Total Events:</span>
              <span className="font-bold">{payload[0]?.value || 0}</span>
            </p>
            <p className="text-amber-400 flex items-center justify-between space-x-4">
              <span>Failed Logins:</span>
              <span className="font-bold">{payload[1]?.value || 0}</span>
            </p>
            <p className="text-rose-400 flex items-center justify-between space-x-4">
              <span>Threat Alerts:</span>
              <span className="font-bold">{payload[2]?.value || 0}</span>
            </p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="w-full h-72">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
            </linearGradient>
            <linearGradient id="colorFailed" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4}/>
              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0}/>
            </linearGradient>
            <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5}/>
              <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis 
            dataKey="timestamp" 
            stroke="#64748b" 
            fontSize={11} 
            tickLine={false} 
            fontFamily="JetBrains Mono" 
          />
          <YAxis 
            stroke="#64748b" 
            fontSize={11} 
            tickLine={false} 
            fontFamily="JetBrains Mono" 
          />
          <Tooltip content={<CustomTooltip />} />
          <Area 
            type="monotone" 
            dataKey="events" 
            stroke="#06b6d4" 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorEvents)" 
            name="Events"
          />
          <Area 
            type="monotone" 
            dataKey="failed_logins" 
            stroke="#f59e0b" 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorFailed)" 
            name="Failed Logins"
          />
          <Area 
            type="monotone" 
            dataKey="alerts" 
            stroke="#f43f5e" 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorAlerts)" 
            name="Alerts"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
