import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import { 
  fetchHealth, 
  fetchDashboardSummary, 
  fetchDashboardTrends, 
  fetchRecentActivity, 
  fetchRecentAlerts 
} from './services/api';
import { 
  FileText, 
  Globe2, 
  Bot, 
  AlertTriangle, 
  FileSpreadsheet,
  CheckCircle2,
  Construction
} from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState([]);
  const [activities, setActivities] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  const loadData = async () => {
    setIsRefreshing(true);
    try {
      const health = await fetchHealth();
      setIsConnected(health.status === 'healthy');

      const [sumData, trendData, actData, alertData] = await Promise.all([
        fetchDashboardSummary(),
        fetchDashboardTrends(),
        fetchRecentActivity(15),
        fetchRecentAlerts(6)
      ]);

      setSummary(sumData);
      setTrends(trendData);
      setActivities(actData);
      setAlerts(alertData);
    } catch (err) {
      console.error('Error loading SOC telemetry:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    // Auto-refresh telemetry every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar 
        onRefresh={loadData} 
        isRefreshing={isRefreshing} 
        isConnected={isConnected} 
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar 
          currentTab={currentTab} 
          onSelectTab={setCurrentTab} 
          systemStatus={summary?.system_status}
        />

        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
          <div className="max-w-7xl mx-auto space-y-6">
            {currentTab === 'dashboard' && (
              <DashboardView
                summary={summary}
                trends={trends}
                activities={activities}
                alerts={alerts}
                onNavigateTab={setCurrentTab}
              />
            )}

            {currentTab !== 'dashboard' && (
              <div className="p-12 rounded-2xl bg-slate-900/40 border border-slate-800 text-center space-y-4 max-w-2xl mx-auto my-12">
                <div className="w-14 h-14 rounded-2xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400 glow-cyan">
                  <Construction className="w-7 h-7 animate-bounce" />
                </div>
                <h3 className="text-lg font-bold text-white tracking-wide">
                  {currentTab === 'logs' && 'Module 2: Log Analyzer (CSV / JSON)'}
                  {currentTab === 'threats' && 'Module 3: Threat Intelligence'}
                  {currentTab === 'ai' && 'Module 4: AI Security Analyst (Gemini)'}
                  {currentTab === 'incidents' && 'Module 5: Incident Management'}
                  {currentTab === 'reports' && 'Module 6: PDF Security Report Generator'}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed font-mono">
                  Module architecture verified & queued. Development will proceed progressively milestone by milestone.
                </p>
                <button
                  onClick={() => setCurrentTab('dashboard')}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-400 border border-slate-700 transition"
                >
                  Return to Security Dashboard
                </button>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
