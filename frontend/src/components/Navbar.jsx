import React, { useState, useEffect } from 'react';
import { ShieldAlert, RefreshCw, Terminal, Activity, Wifi, WifiOff } from 'lucide-react';

export default function Navbar({ onRefresh, isRefreshing, isConnected }) {
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString());

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="h-16 border-b border-slate-800 bg-[#090d16]/90 backdrop-blur-md sticky top-0 z-50 flex items-center justify-between px-6">
      {/* Brand & SOC Status */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center glow-cyan shadow-lg">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-wider text-white">SENTINEL</span>
              <span className="text-xs px-1.5 py-0.5 rounded font-mono font-semibold bg-cyan-950/80 border border-cyan-500/40 text-cyan-400">
                AI SOC
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono tracking-tight">AUTONOMOUS CYBER DEFENSE</p>
          </div>
        </div>

        <div className="h-6 w-px bg-slate-800 hidden md:block"></div>

        {/* Live Status Indicator */}
        <div className="hidden sm:flex items-center space-x-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-slate-300 font-mono text-[11px] tracking-wide">SURVEILLANCE ACTIVE</span>
        </div>
      </div>

      {/* Right Telemetry & Controls */}
      <div className="flex items-center space-x-4">
        {/* Live Clock */}
        <div className="hidden lg:flex items-center space-x-2 text-xs font-mono text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded border border-slate-800/80">
          <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>{currentTime}</span>
        </div>

        {/* Connection status */}
        <div className={`flex items-center space-x-1.5 text-xs font-mono px-2.5 py-1 rounded border ${
          isConnected 
            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400' 
            : 'bg-amber-950/40 border-amber-500/30 text-amber-400'
        }`}>
          {isConnected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
          <span className="text-[11px] hidden md:inline">{isConnected ? 'API CONNECTED' : 'OFFLINE CACHE'}</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition disabled:opacity-50"
          title="Refresh SOC Telemetry"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">SYNC</span>
        </button>
      </div>
    </header>
  );
}
