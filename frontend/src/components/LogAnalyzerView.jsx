import React, { useState, useEffect, useRef } from 'react';
import { 
  Upload, 
  FileText, 
  FileCode, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Search, 
  RefreshCw, 
  ChevronDown, 
  ChevronUp, 
  Filter, 
  ShieldCheck, 
  Ban, 
  ArrowRight,
  Flame,
  Play
} from 'lucide-react';
import { 
  uploadLogFile, 
  ingestRawLogs, 
  fetchLogSamples, 
  ingestSampleLog, 
  fetchLogRecords 
} from '../services/api';

export default function LogAnalyzerView({ onTelemetryUpdated }) {
  // Upload & Input state
  const [activeInputTab, setActiveInputTab] = useState('upload'); // 'upload' | 'raw'
  const [rawContent, setRawContent] = useState('');
  const [rawFormat, setRawFormat] = useState('csv');
  const [isProcessing, setIsProcessing] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [samples, setSamples] = useState([]);
  const fileInputRef = useRef(null);

  // Log Records Explorer state
  const [records, setRecords] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [isLoadingRecords, setIsLoadingRecords] = useState(false);
  const [expandedRowId, setExpandedRowId] = useState(null);

  // Load samples on mount
  useEffect(() => {
    fetchLogSamples().then(setSamples).catch(() => {});
    loadRecords(1);
  }, []);

  const loadRecords = async (targetPage = 1) => {
    setIsLoadingRecords(true);
    try {
      const res = await fetchLogRecords({
        page: targetPage,
        limit: 15,
        search,
        eventType: eventTypeFilter,
        status: statusFilter
      });
      setRecords(res.items);
      setTotalRecords(res.total);
      setPage(res.page);
      setTotalPages(res.total_pages);
    } catch (err) {
      console.error('Failed to load records:', err);
    } finally {
      setIsLoadingRecords(false);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    setIsProcessing(true);
    setUploadResult(null);
    try {
      const result = await uploadLogFile(file);
      setUploadResult(result);
      loadRecords(1);
      if (onTelemetryUpdated) onTelemetryUpdated();
    } catch (err) {
      setUploadResult({
        filename: file.name,
        records_parsed: 0,
        records_stored: 0,
        errors: [err.message || 'File processing failed'],
        alerts_detected: 0,
        alerts: []
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRawSubmit = async (e) => {
    e.preventDefault();
    if (!rawContent.trim()) return;
    setIsProcessing(true);
    setUploadResult(null);
    try {
      const result = await ingestRawLogs(rawContent, rawFormat, `manual_entry.${rawFormat}`);
      setUploadResult(result);
      setRawContent('');
      loadRecords(1);
      if (onTelemetryUpdated) onTelemetryUpdated();
    } catch (err) {
      setUploadResult({
        filename: 'manual_entry',
        records_parsed: 0,
        records_stored: 0,
        errors: [err.message || 'Ingestion failed'],
        alerts_detected: 0,
        alerts: []
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSampleIngest = async (sampleKey) => {
    setIsProcessing(true);
    setUploadResult(null);
    try {
      const result = await ingestSampleLog(sampleKey);
      setUploadResult(result);
      loadRecords(1);
      if (onTelemetryUpdated) onTelemetryUpdated();
    } catch (err) {
      console.error('Sample ingestion error:', err);
    } finally {
      setIsProcessing(false);
    }
  };

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
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/60 text-rose-400 border border-rose-500/30">
            <Ban className="w-3 h-3" />
            <span>BLOCKED</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/60 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            <span>FAIL</span>
          </span>
        );
    }
  };

  const getSeverityStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-400 border-rose-500/40';
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
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-sm font-bold text-white tracking-wide">
              LOG ANALYZER & THREAT CORRELATION ENGINE
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-500/40">
              MODULE 2
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Ingest CSV and JSON audit trails, parse system telemetry, evaluate rule-based brute force and authentication anomalies, and correlate alerts.
          </p>
        </div>

        {/* Quick Ingest Sample Button Pills */}
        <div className="flex flex-wrap items-center gap-2">
          {samples.map((s) => (
            <button
              key={s.key}
              onClick={() => handleSampleIngest(s.key)}
              disabled={isProcessing}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700 transition disabled:opacity-50"
              title={s.description}
            >
              <Play className="w-3 h-3 text-cyan-400 fill-cyan-400" />
              <span>{s.key === 'ssh_bruteforce' ? 'SSH Brute Force' : s.key === 'password_spraying' ? 'Password Spray' : 'Recon & Sudo'}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Upload & Ingestion Container */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setActiveInputTab('upload')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeInputTab === 'upload' 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload CSV / JSON File</span>
            </button>
            <button
              onClick={() => setActiveInputTab('raw')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition ${
                activeInputTab === 'raw' 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' 
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Paste Raw Logs</span>
            </button>
          </div>
          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
            Supports: RFC 4180 CSV, JSON Array, NDJSON
          </span>
        </div>

        {/* Tab 1: File Drop Zone */}
        {activeInputTab === 'upload' && (
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
            }}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition ${
              dragOver 
                ? 'border-cyan-400 bg-cyan-950/20' 
                : 'border-slate-800 hover:border-slate-700 bg-slate-900/40'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
              accept=".csv,.json,.ndjson,.txt,.log"
              className="hidden"
            />
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400 mb-3">
              <Upload className={`w-6 h-6 ${isProcessing ? 'animate-bounce' : ''}`} />
            </div>
            <p className="text-xs font-semibold text-slate-200">
              {isProcessing ? 'Parsing Telemetry & Correlating Threats...' : 'Drop CSV or JSON log file here, or click to browse'}
            </p>
            <p className="text-[11px] text-slate-500 font-mono mt-1">
              Automated schema normalization & threat signature matching
            </p>
          </div>
        )}

        {/* Tab 2: Raw Log Paste */}
        {activeInputTab === 'raw' && (
          <form onSubmit={handleRawSubmit} className="space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">PASTE RAW AUDIT LOG RECORDS:</span>
              <div className="flex items-center space-x-2">
                <span className="text-slate-500 text-[11px]">FORMAT:</span>
                <button
                  type="button"
                  onClick={() => setRawFormat('csv')}
                  className={`px-2 py-0.5 rounded text-[11px] ${rawFormat === 'csv' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400'}`}
                >
                  CSV
                </button>
                <button
                  type="button"
                  onClick={() => setRawFormat('json')}
                  className={`px-2 py-0.5 rounded text-[11px] ${rawFormat === 'json' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400'}`}
                >
                  JSON
                </button>
              </div>
            </div>
            <textarea
              rows={5}
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              placeholder={
                rawFormat === 'csv'
                  ? 'timestamp,source_ip,user_identity,event_type,action,status\n2026-11-27T08:00:00Z,192.168.1.10,admin,AUTH_FAILED,LOGIN,FAILURE'
                  : '[{"timestamp": "2026-11-27T08:00:00Z", "source_ip": "192.168.1.10", "user_identity": "admin", "event_type": "AUTH_FAILED", "status": "FAILURE"}]'
              }
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={isProcessing || !rawContent.trim()}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium disabled:opacity-50 transition"
              >
                {isProcessing ? 'Analyzing...' : 'Ingest & Run Detection Rules'}
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Analysis Result Banner & Detected Alerts Preview */}
      {uploadResult && (
        <div className={`p-4 rounded-xl border space-y-3 ${
          uploadResult.alerts_detected > 0
            ? 'bg-rose-950/20 border-rose-500/40'
            : 'bg-emerald-950/20 border-emerald-500/40'
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              {uploadResult.alerts_detected > 0 ? (
                <Flame className="w-5 h-5 text-rose-400 animate-pulse" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              )}
              <h3 className="text-xs font-bold font-mono text-white">
                INGESTION COMPLETE: {uploadResult.filename}
              </h3>
            </div>
            <div className="flex items-center space-x-3 text-xs font-mono">
              <span className="text-slate-400">
                Parsed: <span className="text-cyan-400 font-bold">{uploadResult.records_parsed}</span>
              </span>
              <span className="text-slate-400">
                Stored: <span className="text-emerald-400 font-bold">{uploadResult.records_stored}</span>
              </span>
              <span className="text-slate-400">
                Threats Detected: <span className="text-rose-400 font-bold">{uploadResult.alerts_detected}</span>
              </span>
            </div>
          </div>

          {/* Errors list if any */}
          {uploadResult.errors?.length > 0 && (
            <div className="p-2.5 rounded bg-slate-900 border border-amber-500/30 text-[11px] font-mono text-amber-300">
              <p className="font-bold mb-1">Parsing Diagnostics ({uploadResult.errors.length} notices):</p>
              <ul className="list-disc list-inside space-y-0.5 text-slate-400">
                {uploadResult.errors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Generated Alerts Cards */}
          {uploadResult.alerts?.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <p className="text-[11px] font-mono text-rose-300 font-bold uppercase tracking-wider flex items-center space-x-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Correlated Threat Alerts Generated:</span>
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {uploadResult.alerts.map((al) => (
                  <div key={al.id} className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityStyle(al.severity)}`}>
                        {al.severity}
                      </span>
                      <span className="text-[10px] font-mono text-cyan-400">{al.rule_name}</span>
                    </div>
                    <h4 className="font-semibold text-slate-200">{al.title}</h4>
                    <p className="text-[11px] text-slate-400">{al.description}</p>
                    {al.evidence && (
                      <div className="pt-1.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-400">
                        {al.source_ip && <span>SRC: <b className="text-slate-300">{al.source_ip}</b> </span>}
                        {al.target_user && <span>• TGT: <b className="text-slate-300">{al.target_user}</b></span>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Database Log Records Explorer */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Parsed Security Event Repository</span>
            </h3>
            <p className="text-[11px] text-slate-500">
              Showing {records.length} of {totalRecords} normalized security records
            </p>
          </div>

          {/* Search & Filter Controls */}
          <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
            <div className="relative flex-1 md:w-56">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search IP, user, type..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && loadRecords(1)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
              />
            </div>

            <select
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setTimeout(() => loadRecords(1), 0); }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Types</option>
              <option value="AUTH_FAILED">AUTH_FAILED</option>
              <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
              <option value="PORT_SCAN">PORT_SCAN</option>
              <option value="C2_BEACON">C2_BEACON</option>
              <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setTimeout(() => loadRecords(1), 0); }}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none"
            >
              <option value="ALL">All Status</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILURE">FAILURE</option>
              <option value="BLOCKED">BLOCKED</option>
            </select>

            <button
              onClick={() => loadRecords(page)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh logs"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingRecords ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Records Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Target User</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    {isLoadingRecords ? 'QUERYING DATABASE LOGS...' : 'NO MATCHING SECURITY LOGS FOUND'}
                  </td>
                </tr>
              ) : (
                records.map((row) => {
                  const isExpanded = expandedRowId === row.id;
                  return (
                    <React.Fragment key={row.id}>
                      <tr 
                        onClick={() => setExpandedRowId(isExpanded ? null : row.id)}
                        className="hover:bg-slate-900/80 transition cursor-pointer"
                      >
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {new Date(row.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                        </td>
                        <td className="py-2.5 px-3 text-cyan-300 font-semibold">
                          {row.event_type}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {row.action}
                        </td>
                        <td className="py-2.5 px-3 text-slate-200">
                          <span className="bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                            {row.source_ip}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">
                          {row.user_identity || <span className="text-slate-600">—</span>}
                        </td>
                        <td className="py-2.5 px-3">
                          {getStatusBadge(row.status)}
                        </td>
                        <td className="py-2.5 px-3 text-right text-slate-500">
                          {isExpanded ? <ChevronUp className="w-4 h-4 ml-auto" /> : <ChevronDown className="w-4 h-4 ml-auto" />}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-950 border-y border-cyan-500/20">
                          <td colSpan={7} className="p-4 text-xs font-mono">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <p className="text-[10px] text-slate-500 uppercase mb-1">Normalized Event Metadata</p>
                                <div className="space-y-1 text-slate-300">
                                  <p>Event ID: <span className="text-cyan-400">#{row.id}</span></p>
                                  <p>Source IP: <span className="text-slate-100">{row.source_ip}</span></p>
                                  {row.destination_ip && <p>Destination IP: <span className="text-slate-100">{row.destination_ip}</span></p>}
                                  {row.user_identity && <p>Identity: <span className="text-slate-100">{row.user_identity}</span></p>}
                                  <p>Severity Rating: <span className="text-amber-400">{row.severity}</span></p>
                                </div>
                              </div>
                              <div>
                                <p className="text-[10px] text-slate-500 uppercase mb-1">Payload / Details JSON</p>
                                <pre className="p-2.5 rounded bg-slate-900 text-[11px] text-slate-300 overflow-x-auto border border-slate-800">
                                  {JSON.stringify(row.details || {}, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-2">
          <span>
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => { const p = Math.max(1, page - 1); setPage(p); loadRecords(p); }}
              disabled={page <= 1 || isLoadingRecords}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition"
            >
              Previous
            </button>
            <button
              onClick={() => { const p = Math.min(totalPages, page + 1); setPage(p); loadRecords(p); }}
              disabled={page >= totalPages || isLoadingRecords}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
