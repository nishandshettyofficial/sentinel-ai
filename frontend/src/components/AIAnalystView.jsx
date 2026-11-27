import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, 
  Sparkles, 
  Send, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Clock, 
  HelpCircle, 
  Cpu, 
  Layers, 
  ArrowRight, 
  RefreshCw,
  Info,
  ShieldCheck,
  FileCode2,
  ChevronRight
} from 'lucide-react';
import { 
  fetchAIAnalystExplanation, 
  sendAIAnalystChat, 
  fetchAIAnalystStatus 
} from '../services/api';

export default function AIAnalystView({ alerts = [], initialAlertId = null }) {
  const [selectedAlertId, setSelectedAlertId] = useState(
    initialAlertId || (alerts.length > 0 ? alerts[0].id : null)
  );
  const [explanation, setExplanation] = useState(null);
  const [isExplaining, setIsExplaining] = useState(false);
  const [explainError, setExplainError] = useState('');

  // Chat State
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Hello, I am Sentinel AI's Senior SOC Analyst assistant powered by Google Gemini. Select an alert on the left to review an in-depth forensic explanation, or ask me any question regarding containment, firewall rules, or threat actors."
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isSendingChat, setIsSendingChat] = useState(false);
  const [aiStatus, setAiStatus] = useState(null);
  const chatBottomRef = useRef(null);

  useEffect(() => {
    fetchAIAnalystStatus().then(setAiStatus).catch(console.warn);
  }, []);

  // When selected alert changes, load explanation
  useEffect(() => {
    if (selectedAlertId) {
      loadExplanation(selectedAlertId);
    }
  }, [selectedAlertId]);

  // Auto-scroll chat to bottom
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isSendingChat]);

  const loadExplanation = async (alertId) => {
    if (!alertId) return;
    setIsExplaining(true);
    setExplainError('');
    try {
      const data = await fetchAIAnalystExplanation(alertId);
      setExplanation(data);
    } catch (err) {
      setExplainError(err.message || 'Failed to generate AI alert explanation');
      setExplanation(null);
    } finally {
      setIsExplaining(false);
    }
  };

  const handleSendMessage = async (customText) => {
    const textToSend = (customText || inputMessage).trim();
    if (!textToSend || isSendingChat) return;

    const userMsg = { role: 'user', content: textToSend };
    const updatedHistory = [...messages, userMsg];
    setMessages(updatedHistory);
    setInputMessage('');
    setIsSendingChat(true);

    try {
      const chatPayloadHistory = updatedHistory.slice(-6).map(m => ({
        role: m.role,
        content: m.content
      }));

      const res = await sendAIAnalystChat({
        message: textToSend,
        alertId: selectedAlertId,
        chatHistory: chatPayloadHistory
      });

      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: res.reply,
          provider: res.provider
        }
      ]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ Error contacting AI Analyst service: ${err.message}. Please check backend logs or retry.`
        }
      ]);
    } finally {
      setIsSendingChat(false);
    }
  };

  const selectedAlert = alerts.find(a => a.id === Number(selectedAlertId)) || null;

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

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Sparkles className="w-5 h-5 text-cyan-400 animate-pulse" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white flex items-center space-x-2">
              <span>AI SECURITY ANALYST // GEMINI ASSISTANT</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-500/40">
                MODULE 4
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated alert explanations, grounded forensic reasoning, and interactive containment guidance.
            </p>
          </div>
        </div>

        {/* Engine status indicator */}
        <div className="flex items-center space-x-2 text-[10px] font-mono">
          <span className={`px-2.5 py-1 rounded border flex items-center space-x-1.5 ${
            aiStatus?.gemini_configured
              ? 'bg-emerald-950/80 text-emerald-400 border-emerald-500/40'
              : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
          }`}>
            <Cpu className="w-3.5 h-3.5" />
            <span>Model: {aiStatus?.gemini_configured ? 'Gemini 2.5 Flash (Live)' : 'Grounded SOC Engine'}</span>
          </span>
        </div>
      </div>

      {/* Main 2-Column Split: Explanation & Chat */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* Left Column (5 Cols): Alert Selector & Structured Analysis */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* Alert Selector Card */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                <span>Select Alert To Analyze</span>
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                {alerts.length} ALERTS IN QUEUE
              </span>
            </div>

            {alerts.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 p-3 bg-slate-950 rounded">
                No security alerts currently recorded. Ingest logs to generate alerts.
              </p>
            ) : (
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {alerts.map((al) => (
                  <button
                    key={al.id}
                    onClick={() => setSelectedAlertId(al.id)}
                    className={`w-full text-left p-2.5 rounded-lg border text-xs transition flex items-center justify-between ${
                      selectedAlertId === al.id
                        ? 'bg-cyan-950/70 border-cyan-500/50 text-cyan-200'
                        : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-900 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold shrink-0 border ${getSeverityStyle(al.severity)}`}>
                        {al.severity}
                      </span>
                      <span className="font-medium truncate text-[11px]">{al.title}</span>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 shrink-0 ${selectedAlertId === al.id ? 'text-cyan-400' : 'text-slate-600'}`} />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Loading State */}
          {isExplaining && (
            <div className="p-10 rounded-xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
              <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
              <p className="text-xs font-mono text-slate-400">Synthesizing forensic alert evidence...</p>
            </div>
          )}

          {/* Error State */}
          {explainError && (
            <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-500/40 text-rose-300 text-xs font-mono">
              Error: {explainError}
            </div>
          )}

          {/* Structured Analysis Results */}
          {!isExplaining && explanation && (
            <div className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
              {/* Alert Header Metadata */}
              <div className="border-b border-slate-800/80 pb-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityStyle(explanation.severity)}`}>
                      {explanation.severity}
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400">{explanation.rule_name}</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">
                    Engine: {explanation.provider === 'GEMINI_2_5_FLASH' ? 'Gemini 2.5 Flash' : 'Grounded Engine'}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">
                  {explanation.alert_title}
                </h3>
              </div>

              {/* Section 1: What Happened */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center space-x-1">
                  <Clock className="w-3 h-3" />
                  <span>1. What Happened (Incident Narrative)</span>
                </span>
                <p className="text-xs text-slate-200 leading-relaxed p-3 rounded-lg bg-slate-950/70 border border-slate-800/60">
                  {explanation.what_happened}
                </p>
              </div>

              {/* Section 2: Why It Is Suspicious */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-amber-400 font-bold uppercase tracking-wider flex items-center space-x-1">
                  <AlertTriangle className="w-3 h-3" />
                  <span>2. Why It Is Suspicious (Correlation Trigger)</span>
                </span>
                <p className="text-xs text-slate-200 leading-relaxed p-3 rounded-lg bg-slate-950/70 border border-slate-800/60">
                  {explanation.why_suspicious}
                </p>
              </div>

              {/* Section 3: Potential Impact */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-rose-400 font-bold uppercase tracking-wider flex items-center space-x-1">
                  <ShieldAlert className="w-3 h-3" />
                  <span>3. Potential Security Impact</span>
                </span>
                <p className="text-xs text-slate-200 leading-relaxed p-3 rounded-lg bg-slate-950/70 border border-slate-800/60">
                  {explanation.potential_impact}
                </p>
              </div>

              {/* Section 4: Tactical Defensive Actions */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase tracking-wider flex items-center space-x-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>4. Recommended Defensive Actions</span>
                </span>
                <ul className="space-y-1.5 text-xs">
                  {explanation.defensive_recommendations?.map((rec, i) => (
                    <li key={i} className="flex items-start space-x-2 p-2 rounded-lg bg-slate-950/60 border border-slate-800/60 text-slate-200">
                      <span className="text-emerald-400 font-mono font-bold shrink-0 mt-0.5">{i+1}.</span>
                      <span className="leading-snug">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* MITRE ATT&CK Mapping */}
              {explanation.mitre_attack_mapping && (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs font-mono">
                  <div>
                    <span className="text-slate-500 text-[10px] block">MITRE ATT&CK TECHNIQUE</span>
                    <span className="text-cyan-300 font-semibold">{explanation.mitre_attack_mapping.technique}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-slate-500 text-[10px] block">TACTIC</span>
                    <span className="text-slate-300">{explanation.mitre_attack_mapping.tactic}</span>
                  </div>
                </div>
              )}

              {/* Grounding & Ethics Disclaimer */}
              <div className="p-2.5 rounded bg-amber-950/20 border border-amber-500/30 text-[10px] font-mono text-amber-200/90 leading-tight flex items-start space-x-2">
                <Info className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <span>{explanation.disclaimer}</span>
              </div>
            </div>
          )}
        </div>

        {/* Right Column (7 Cols): Interactive AI Analyst Chat */}
        <div className="lg:col-span-7 flex flex-col h-[740px] rounded-2xl bg-slate-900/60 border border-slate-800 overflow-hidden">
          
          {/* Chat Header */}
          <div className="p-3.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white flex items-center space-x-2">
                  <span>SOC ANALYST COPILOT CHAT</span>
                  {selectedAlert && (
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                      Ref: Alert #{selectedAlert.id}
                    </span>
                  )}
                </h3>
                <p className="text-[10px] font-mono text-slate-500">Live Q&A • Ask about attack scope, rules, containment</p>
              </div>
            </div>

            <button
              onClick={() => setMessages([{
                role: 'assistant',
                content: "Chat session refreshed. Select an alert or ask a question regarding your current security events."
              }])}
              className="text-[10px] font-mono px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
            >
              CLEAR CHAT
            </button>
          </div>

          {/* Chat Messages Log */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 font-sans text-xs">
            {messages.map((msg, idx) => (
              <div 
                key={idx} 
                className={`flex items-start space-x-2.5 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role !== 'user' && (
                  <div className="w-6 h-6 rounded-md bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
                    <Bot className="w-3.5 h-3.5" />
                  </div>
                )}

                <div className={`p-3.5 rounded-2xl max-w-[85%] leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-600 text-white font-medium rounded-tr-none'
                    : 'bg-slate-950/80 border border-slate-800 text-slate-200 rounded-tl-none whitespace-pre-wrap'
                }`}>
                  {msg.content}
                </div>
              </div>
            ))}

            {isSendingChat && (
              <div className="flex items-center space-x-2 text-slate-400 text-xs font-mono p-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Gemini Analyst is formulating response...</span>
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          {/* Quick Prompt Suggestion Chips */}
          <div className="p-2.5 bg-slate-950/70 border-t border-slate-800/80 flex flex-wrap gap-1.5">
            {[
              "What should I do first to contain this threat?",
              "Draft an iptables firewall block rule",
              "Is this an automated bot or human?",
              "Map this alert to MITRE ATT&CK"
            ].map((promptText, i) => (
              <button
                key={i}
                disabled={isSendingChat}
                onClick={() => handleSendMessage(promptText)}
                className="text-[10px] font-mono px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
              >
                {promptText}
              </button>
            ))}
          </div>

          {/* Input Bar */}
          <form 
            onSubmit={(e) => { e.preventDefault(); handleSendMessage(); }}
            className="p-3 bg-slate-950 border-t border-slate-800 flex items-center space-x-2"
          >
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder={selectedAlert ? `Ask about Alert #${selectedAlert.id} (${selectedAlert.rule_name})...` : "Ask AI Analyst about threats, containment, or rules..."}
              className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition font-mono"
            />
            <button
              type="submit"
              disabled={isSendingChat || !inputMessage.trim()}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium flex items-center space-x-1.5 shadow transition"
            >
              <span>SEND</span>
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>

        </div>

      </div>
    </div>
  );
}
