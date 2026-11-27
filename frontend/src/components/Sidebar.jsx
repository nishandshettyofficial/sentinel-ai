import React from 'react';
import { 
  LayoutDashboard, 
  FileText, 
  Globe2, 
  Bot, 
  AlertTriangle, 
  FileSpreadsheet,
  Cpu,
  Database
} from 'lucide-react';

const NAVIGATION_ITEMS = [
  { id: 'dashboard', name: 'Security Dashboard', icon: LayoutDashboard, badge: 'Live', active: true },
  { id: 'logs', name: 'Log Analyzer', icon: FileText, badge: 'Active', active: true },
  { id: 'threats', name: 'Threat Intelligence', icon: Globe2, badge: 'Mod 3', active: false },
  { id: 'ai', name: 'AI Security Analyst', icon: Bot, badge: 'Gemini', active: false },
  { id: 'incidents', name: 'Incident Management', icon: AlertTriangle, badge: 'Mod 5', active: false },
  { id: 'reports', name: 'Reports Generator', icon: FileSpreadsheet, badge: 'PDF', active: false }
];

export default function Sidebar({ currentTab, onSelectTab, systemStatus, systemHealth }) {
  const dbEngine = systemHealth?.database?.engine || 'SQL';
  const dbLatency = systemHealth?.database?.latency_ms || 0;
  const rulesCount = systemHealth?.detection_engine?.rules_count || 5;

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#090d16]/80 flex flex-col justify-between p-4 shrink-0 hidden md:flex">
      <div className="space-y-6">
        <div>
          <p className="text-[11px] font-mono text-slate-500 uppercase tracking-wider px-3 mb-2">
            SOC Operations Center
          </p>
          <nav className="space-y-1">
            {NAVIGATION_ITEMS.map((item) => {
              const Icon = item.icon;
              const isSelected = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition ${
                    isSelected
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 glow-cyan'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <span>{item.name}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      isSelected
                        ? 'bg-cyan-500/20 text-cyan-300'
                        : item.badge === 'Active' || item.badge === 'Live'
                          ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-800/80 text-slate-400'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Security Readiness Status Card */}
        <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 flex items-center space-x-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>DEFENSE MATRIX</span>
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
              systemStatus === 'OPERATIONAL' 
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                : 'bg-rose-950 text-rose-400 border border-rose-500/30 animate-pulse'
            }`}>
              {systemStatus || 'ONLINE'}
            </span>
          </div>

          <div className="space-y-1 text-[11px] font-mono text-slate-400 border-t border-slate-800/80 pt-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center space-x-1 text-slate-500">
                <Database className="w-3 h-3" />
                <span>DB Engine:</span>
              </span>
              <span className="text-slate-300 uppercase">{dbEngine} ({dbLatency}ms)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Detection Rules:</span>
              <span className="text-cyan-400 font-bold">{rulesCount} Active</span>
            </div>
          </div>

          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full w-[96%]"></div>
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>SOC Integrity</span>
            <span>96% Optimal</span>
          </div>
        </div>
      </div>

      {/* Bottom Metadata */}
      <div className="border-t border-slate-800/80 pt-3 px-1 text-[11px] font-mono text-slate-500 flex justify-between items-center">
        <span>Sentinel Engine v1.0</span>
        <span className="text-cyan-500">FastAPI • React</span>
      </div>
    </aside>
  );
}
