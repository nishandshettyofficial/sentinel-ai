import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Ban, 
  AlertTriangle, 
  TrendingUp, 
  Flame, 
  Layers,
  ArrowRight,
  Radio
} from 'lucide-react';
import MetricCard from './MetricCard';
import EventVolumeChart from './EventVolumeChart';
import SeverityDistribution from './SeverityDistribution';
import AlertsList from './AlertsList';
import RecentActivityTable from './RecentActivityTable';

export default function DashboardView({ 
  summary, 
  trends, 
  activities, 
  alerts, 
  onNavigateTab 
}) {
  return (
    <div className="space-y-6">
      {/* Top SOC Status Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white flex items-center space-x-2">
              <span>ACTIVE PERIMETER DEFENSE // SOC DASHBOARD</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-500/40">
                MODULE 1
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Continuous network event ingestion, rule evaluation, and automated alert correlation.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 self-start md:self-auto">
          <button
            onClick={() => onNavigateTab('logs')}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium shadow transition"
          >
            <span>INGEST LOG FILE</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 4 Core Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Security Events"
          value={summary?.total_events ?? '...'}
          subtitle="Events recorded across monitored endpoints"
          icon={Activity}
          color="cyan"
          change="+18.4%"
          trend="up"
        />
        <MetricCard
          title="Correlated Alerts"
          value={summary?.total_alerts ?? '...'}
          subtitle="Rule matches requiring triage"
          icon={ShieldAlert}
          color="rose"
          change="+3 new"
          trend="up"
        />
        <MetricCard
          title="Open Incidents"
          value={summary?.open_incidents ?? '...'}
          subtitle="Under active investigation"
          icon={AlertTriangle}
          color="amber"
          change="1 In Progress"
          trend="up"
        />
        <MetricCard
          title="Threats Mitigated"
          value={summary?.threats_blocked ?? '...'}
          subtitle="Packets dropped & IPs rate-limited"
          icon={Ban}
          color="emerald"
          change="100% blocked"
          trend="down"
        />
      </div>

      {/* Charts & Severity Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Event Volume Trend */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <span>Security Event Volume & Alert Frequency</span>
              </h3>
              <p className="text-[11px] text-slate-500">Timeline of incoming telemetry (Past 6 hours)</p>
            </div>
            <div className="flex items-center space-x-3 text-[11px] font-mono">
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
                <span className="text-slate-400">Events</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                <span className="text-slate-400">Failed Logins</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
                <span className="text-slate-400">Alerts</span>
              </span>
            </div>
          </div>
          <EventVolumeChart data={trends} />
        </div>

        {/* Severity Distribution */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Severity Breakdown</span>
            </h3>
            <p className="text-[11px] text-slate-500">Categorization by threat impact rating</p>
          </div>
          <SeverityDistribution severity={summary?.severity_distribution} />
        </div>
      </div>

      {/* Alerts Feed and Recent Activity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Active Alerts Feed */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>Active Alerts Queue</span>
              </h3>
              <p className="text-[11px] text-slate-500">Prioritized triage pipeline</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {alerts.length} ALERTS
            </span>
          </div>
          <AlertsList alerts={alerts} />
        </div>

        {/* Real-time Activity Stream */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Live Security Event Stream</span>
              </h3>
              <p className="text-[11px] text-slate-500">Real-time parsed audit and authentication events</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {activities.length} LOGS
            </span>
          </div>
          <RecentActivityTable activities={activities} />
        </div>
      </div>
    </div>
  );
}
