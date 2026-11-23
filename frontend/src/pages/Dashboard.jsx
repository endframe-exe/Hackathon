import React, { useState, useEffect } from 'react';
import { analyzeUrl, analyzeMessage, getHistory, checkHealth } from '../services/api';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('url'); // 'url' | 'message'
  const [urlInput, setUrlInput] = useState('');
  const [messageInput, setMessageInput] = useState('');
  const [senderInput, setSenderInput] = useState('');
  const [subjectInput, setSubjectInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    checkHealth()
      .then((data) => setHealth(data))
      .catch(() => setHealth({ status: 'offline' }));
  }, []);

  const handleFetchHistory = async () => {
    try {
      const data = await getHistory(15, 0);
      setHistory(data.items || []);
      setShowHistory(true);
    } catch (err) {
      console.error('Failed to load history', err);
    }
  };

  const handleScanUrl = async (e) => {
    e?.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const data = await analyzeUrl(urlInput);
      setReport(data);
    } catch (err) {
      setError(err.message || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  const handleScanMessage = async (e) => {
    e?.preventDefault();
    if (!messageInput.trim()) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const data = await analyzeMessage({
        message: messageInput,
        sender: senderInput || null,
        subject: subjectInput || null,
      });
      setReport(data);
    } catch (err) {
      setError(err.message || 'Failed to analyze message');
    } finally {
      setLoading(false);
    }
  };

  const loadSampleUrl = (sample) => {
    setUrlInput(sample);
    setError(null);
  };

  const loadSampleMessage = (sampleMsg, sampleSub = '', sampleSender = '') => {
    setMessageInput(sampleMsg);
    setSubjectInput(sampleSub);
    setSenderInput(sampleSender);
    setError(null);
  };

  const getRiskBadgeColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'LOW':
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-300 border-red-700';
      case 'HIGH':
        return 'bg-orange-950 text-orange-300 border-orange-700';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-10 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header & Status Bar */}
        <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div>
            <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
              PhishGuard AI — Threat Intelligence & Phishing DNA
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Autonomous multi-vector phishing heuristic analyzer & VirusTotal API v3 adapter
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleFetchHistory}
              className="text-xs font-semibold px-3 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-lg text-slate-300 transition"
            >
              📜 Scan History
            </button>
            <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono">
              <span className={`w-2 h-2 rounded-full ${health?.status === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
              <span className="text-slate-400">VT:</span>
              <span className={health?.threat_intelligence?.configured ? 'text-emerald-400' : 'text-amber-400'}>
                {health?.threat_intelligence?.configured ? 'Active' : 'Stateless/Fallback'}
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">DB:</span>
              <span className={health?.database?.connected ? 'text-emerald-400' : 'text-slate-400'}>
                {health?.database?.connected ? 'MySQL 8.4' : 'Memory'}
              </span>
            </div>
          </div>
        </header>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 space-x-6 text-sm font-semibold">
          <button
            onClick={() => setActiveTab('url')}
            className={`pb-3 transition-colors ${
              activeTab === 'url'
                ? 'border-b-2 border-blue-500 text-blue-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            🔗 URL Scanner (FR-01)
          </button>
          <button
            onClick={() => setActiveTab('message')}
            className={`pb-3 transition-colors ${
              activeTab === 'message'
                ? 'border-b-2 border-blue-500 text-blue-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            ✉️ Message & Email Scanner (FR-02)
          </button>
        </div>

        {/* Input Forms */}
        {activeTab === 'url' ? (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <form onSubmit={handleScanUrl} className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter suspect URL (e.g. http://paypal-security-update.account-verify.xyz/login)..."
                className="flex-1 bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
              />
              <button
                type="submit"
                disabled={loading || !urlInput.trim()}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold px-6 py-3 rounded-lg shadow transition duration-200 text-sm"
              >
                {loading ? 'Analyzing DNA...' : 'Analyze URL'}
              </button>
            </form>

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="font-semibold text-slate-500">Quick Samples:</span>
              <button
                onClick={() => loadSampleUrl('http://paypal.com-verification-user.tk/webscr/login.php')}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700"
              >
                🚨 PayPal Phish (Abused TLD + Impersonation)
              </button>
              <button
                onClick={() => loadSampleUrl('http://192.168.1.100:8080/secure/update-account')}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700"
              >
                ⚠️ Raw IP Host + Non-standard Port
              </button>
              <button
                onClick={() => loadSampleUrl('https://github.com/torvalds/linux')}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700"
              >
                ✅ Legitimate URL (GitHub)
              </button>
            </div>
          </div>
        ) : (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <form onSubmit={handleScanMessage} className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <input
                  type="text"
                  value={senderInput}
                  onChange={(e) => setSenderInput(e.target.value)}
                  placeholder="Optional Sender (e.g. IT Helpdesk <admin@support-security.xyz>)"
                  className="bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                />
                <input
                  type="text"
                  value={subjectInput}
                  onChange={(e) => setSubjectInput(e.target.value)}
                  placeholder="Optional Subject (e.g. URGENT: Your Microsoft 365 Account is Scheduled for Deletion)"
                  className="bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                />
              </div>
              <textarea
                rows={4}
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste suspicious email, SMS, or notification content here..."
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
              />
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={loading || !messageInput.trim()}
                  className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold px-6 py-2.5 rounded-lg shadow transition duration-200 text-sm"
                >
                  {loading ? 'Analyzing DNA...' : 'Analyze Message'}
                </button>
              </div>
            </form>

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="font-semibold text-slate-500">Quick Samples:</span>
              <button
                onClick={() =>
                  loadSampleMessage(
                    'Your Microsoft 365 access expires within 24 hours. Immediate action required: verify your password now at http://login-microsoft-portal.xyz/verify or your account will be permanently locked.',
                    'URGENT: Microsoft 365 Password Expiration',
                    'it-security-admin@gmail.com'
                  )
                }
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700"
              >
                🚨 Microsoft IT Phishing (Urgency + Credential Trap)
              </button>
              <button
                onClick={() =>
                  loadSampleMessage(
                    'Hey team, attaching the quarterly marketing presentation deck for tomorrow review meeting.',
                    'Quarterly Marketing Slides',
                    'sarah@company.com'
                  )
                }
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700"
              >
                ✅ Normal Benign Memo
              </button>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="bg-red-950/60 border border-red-800 rounded-lg p-4 text-red-300 text-sm flex items-center justify-between">
            <span>⚠️ {error}</span>
            <button onClick={() => setError(null)} className="text-red-400 font-bold hover:text-white">✕</button>
          </div>
        )}

        {/* Full Phishing DNA Report (FR-01, FR-02, Section 8) */}
        {report && (
          <div className="space-y-6">
            {/* Top Score Banner */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div>
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 text-xs font-extrabold uppercase rounded-full border ${getRiskBadgeColor(report.risk_level)}`}>
                      {report.risk_level} RISK
                    </span>
                    <span className="text-xs font-mono text-slate-500">ID: {report.analysis_id.slice(0, 8)}...</span>
                  </div>
                  <h2 className="text-2xl font-bold mt-2 text-white">
                    {report.target_analyzed}
                  </h2>
                  <p className="text-slate-300 text-sm mt-1 max-w-2xl leading-relaxed">
                    {report.verdict}
                  </p>
                </div>

                <div className="flex items-center gap-4 bg-slate-950/80 border border-slate-800 p-4 rounded-xl self-start md:self-auto">
                  <div className="text-right">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Risk Score</div>
                    <div className="text-xs text-slate-500">Calibrated (0-100)</div>
                  </div>
                  <div className={`text-4xl font-black ${
                    report.risk_score >= 80 ? 'text-red-400' :
                    report.risk_score >= 55 ? 'text-orange-400' :
                    report.risk_score >= 25 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {report.risk_score}
                  </div>
                </div>
              </div>
            </div>

            {/* Phishing DNA Dimensional Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Lexical DNA */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 space-y-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  🧬 Lexical DNA
                </h3>
                {report.phishing_dna?.lexical ? (
                  <div className="text-xs space-y-1.5 text-slate-300">
                    <div className="flex justify-between">
                      <span className="text-slate-500">URL Length:</span>
                      <span className="font-mono">{report.phishing_dna.lexical.url_length} chars</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Subdomains:</span>
                      <span className="font-mono">{report.phishing_dna.lexical.subdomain_count}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Domain Entropy:</span>
                      <span className="font-mono">{report.phishing_dna.lexical.entropy}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">IP Host / Shortener:</span>
                      <span className="font-mono">
                        {report.phishing_dna.lexical.has_ip_address ? '🚨 Yes (IP)' : (report.phishing_dna.lexical.is_shortener ? '⚠️ Shortener' : 'Standard')}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 italic">Not applicable (Message analysis)</div>
                )}
              </div>

              {/* Identity DNA */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 space-y-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  🎭 Identity DNA
                </h3>
                {report.phishing_dna?.identity ? (
                  <div className="text-xs space-y-1.5 text-slate-300">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Targeted Brand:</span>
                      <span className="font-semibold text-blue-300">{report.phishing_dna.identity.targeted_brand || 'None'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Impersonation:</span>
                      <span className={report.phishing_dna.identity.is_brand_impersonation ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {report.phishing_dna.identity.is_brand_impersonation ? '🚨 Flagged' : 'Normal'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Punycode / IDN:</span>
                      <span className="font-mono">{report.phishing_dna.identity.has_homoglyphs ? '⚠️ Punycode' : 'None'}</span>
                    </div>
                    <div className="flex justify-between truncate">
                      <span className="text-slate-500">Domain:</span>
                      <span className="font-mono truncate">{report.phishing_dna.identity.registered_domain || 'N/A'}</span>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 italic">Extracted from message cues</div>
                )}
              </div>

              {/* Behavior DNA */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 space-y-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  🧠 Behavior DNA
                </h3>
                {report.phishing_dna?.behavior ? (
                  <div className="text-xs space-y-1.5 text-slate-300">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Urgency Pressure:</span>
                      <span className={report.phishing_dna.behavior.urgency_detected ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                        {report.phishing_dna.behavior.urgency_detected ? '⚠️ Detected' : 'None'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Credential Intent:</span>
                      <span className={report.phishing_dna.behavior.credential_intent ? 'text-red-400 font-bold' : 'text-slate-400'}>
                        {report.phishing_dna.behavior.credential_intent ? '🚨 Solicitation' : 'None'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Authority Impersonation:</span>
                      <span className="font-mono">{report.phishing_dna.behavior.authority_pressure ? '⚠️ Flagged' : 'None'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Call to Action:</span>
                      <span className="font-mono">{report.phishing_dna.behavior.call_to_action ? 'Present' : 'None'}</span>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-slate-500 italic">Standard URL behavior markers</div>
                )}
              </div>

              {/* Threat Intel DNA (VirusTotal) */}
              <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 space-y-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  🛡️ VirusTotal v3 Intel
                </h3>
                <div className="text-xs space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Status:</span>
                    <span className="font-mono uppercase font-semibold text-cyan-300">
                      {report.phishing_dna?.threat_intel?.status || 'Unconfigured'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Malicious Engines:</span>
                    <span className={`font-mono font-bold ${
                      (report.phishing_dna?.threat_intel?.malicious_engines || 0) > 0 ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {report.phishing_dna?.threat_intel?.malicious_engines || 0}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Total Scanned:</span>
                    <span className="font-mono">{report.phishing_dna?.threat_intel?.total_engines || 0} vendors</span>
                  </div>
                  <div className="text-[10px] text-slate-500 italic">
                    {report.phishing_dna?.threat_intel?.source_attribution || 'External Third-Party Evidence'}
                  </div>
                </div>
              </div>
            </div>

            {/* Identified Threat Indicators */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-base font-bold text-white flex items-center justify-between">
                <span>Threat Indicators ({report.indicators?.length || 0})</span>
                <span className="text-xs text-slate-400 font-normal">Identified risk signals & anomalies</span>
              </h3>

              {report.indicators?.length > 0 ? (
                <div className="space-y-3">
                  {report.indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-sm"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(ind.severity)}`}>
                            {ind.severity}
                          </span>
                          <span className="font-semibold text-slate-100">{ind.title}</span>
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed">{ind.description}</p>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono bg-slate-900 px-2 py-1 rounded border border-slate-800 self-start sm:self-auto shrink-0">
                        {ind.source}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 text-center text-slate-500 text-sm italic">
                  No threat indicators flagged during this inspection.
                </div>
              )}
            </div>

            {/* Actionable Recommendations */}
            {report.recommendations?.length > 0 && (
              <div className="bg-indigo-950/20 border border-indigo-900/50 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-bold text-indigo-300 uppercase tracking-wider flex items-center gap-2">
                  🔒 Recommended Security Actions
                </h3>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-300">
                  {report.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-slate-900/60 p-2.5 rounded border border-indigo-900/30">
                      <span className="text-indigo-400 font-bold">✓</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Limitations & Disclaimers */}
            <div className="space-y-3">
              {report.limitations?.length > 0 && (
                <div className="bg-slate-900/40 border border-slate-800 rounded-lg p-4 text-xs space-y-1.5">
                  <div className="font-semibold text-slate-400 uppercase tracking-wider">Analysis Limitations:</div>
                  <ul className="list-disc list-inside space-y-1 text-slate-400">
                    {report.limitations.map((lim, idx) => (
                      <li key={idx}>{lim}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="bg-slate-900/20 border border-slate-800/60 rounded-lg p-4 text-[11px] text-slate-500 leading-relaxed">
                <span className="font-semibold text-slate-400">Safety Notice: </span>
                {report.safety_disclaimer}
              </div>
            </div>
          </div>
        )}

        {/* Scan History Drawer */}
        {showHistory && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex justify-end">
            <div className="w-full max-w-md bg-slate-900 border-l border-slate-800 h-full p-6 overflow-y-auto space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <h2 className="text-lg font-bold text-white">Scan History (MySQL 8.4)</h2>
                <button
                  onClick={() => setShowHistory(false)}
                  className="text-slate-400 hover:text-white text-lg font-bold"
                >
                  ✕
                </button>
              </div>

              {history.length > 0 ? (
                <div className="space-y-3">
                  {history.map((item, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getRiskBadgeColor(item.risk_level)}`}>
                          {item.risk_level} ({item.risk_score})
                        </span>
                        <span className="text-slate-500 font-mono text-[10px]">
                          {item.created_at ? new Date(item.created_at).toLocaleTimeString() : 'Recent'}
                        </span>
                      </div>
                      <div className="font-semibold text-slate-200 truncate">{item.target_summary || 'Analysis'}</div>
                      <p className="text-slate-400 text-[11px] line-clamp-2">{item.verdict}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 text-sm">
                  No scan records found in database. Run a scan to see records here.
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
