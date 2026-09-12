import React, { useState, useEffect } from 'react';
import { Mail, ShieldCheck, ShieldAlert, Cpu, CheckCircle2, RefreshCw, AlertTriangle, X } from 'lucide-react';
import { dashboardApi } from '../services/dashboardApi';
import { gmailApi } from '../services/gmailApi';
import { analysisApi } from '../services/analysisApi';
import { DashboardStats, EmailMessage, AnalysisResult } from '../types';
import { StatCard } from '../components/dashboard/StatCard';
import { InboxRiskMeter } from '../components/dashboard/InboxRiskMeter';
import { ThreatCategoryChart } from '../components/dashboard/ThreatCategoryChart';
import { WeeklyAnalyticsChart } from '../components/dashboard/WeeklyAnalyticsChart';
import { RecentThreatsList } from '../components/dashboard/RecentThreatsList';
import { ExplainableAiModal } from '../components/analysis/ExplainableAiModal';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

const formatSyncLabel = (syncedAt: number | null, now: number) => {
  if (!syncedAt) {
    return 'Sync Gmail';
  }

  const elapsedMinutes = Math.floor((now - syncedAt) / 60000);

  if (elapsedMinutes < 1) {
    return 'Synced just now';
  }

  if (elapsedMinutes < 60) {
    return `Synced ${elapsedMinutes} min${elapsedMinutes === 1 ? '' : 's'} ago`;
  }

  const elapsedHours = Math.floor(elapsedMinutes / 60);

  if (elapsedHours < 24) {
    return `Synced ${elapsedHours} hour${elapsedHours === 1 ? '' : 's'} ago`;
  }

  const elapsedDays = Math.floor(elapsedHours / 24);
  return `Synced ${elapsedDays} day${elapsedDays === 1 ? '' : 's'} ago`;
};

export const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [tierCounts, setTierCounts] = useState<{ suspicious: number; dangerous: number } | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<number | null>(null);
  const [now, setNow] = useState<number>(Date.now());
  
  const [selectedThreat, setSelectedThreat] = useState<EmailMessage | null>(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AnalysisResult | null>(null);

  // Sync and Scan success modal states
  const [syncResult, setSyncResult] = useState<{ count: number; message: string } | null>(null);
  const [showSyncModal, setShowSyncModal] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<{ analyzed_count: number; high_risk_count: number } | null>(null);
  const [showScanModal, setShowScanModal] = useState<boolean>(false);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardApi.getStats();
      setStats(data);

      try {
        const batchRes = await analysisApi.batchAnalyze();
        if (batchRes && batchRes.results) {
          let suspicious = 0;
          let dangerous = 0;
          batchRes.results.forEach((r) => {
            if (r.risk_score >= 71) {
              dangerous++;
            } else if (r.risk_score >= 31) {
              suspicious++;
            }
          });
          setTierCounts({ suspicious, dangerous });
        }
      } catch (err) {
        console.warn('Batch analyze fetch in dashboard skipped:', err);
      }
    } catch (err: any) {
      console.error('Failed to load dashboard statistics:', err);
      setError(err.response?.data?.detail || err.message || 'Unable to load dashboard intelligence.');
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    setError(null);
    try {
      const res = await gmailApi.syncMessages(20);
      setSyncResult(res);
      setShowSyncModal(true);
      setLastSyncedAt(Date.now());
      await fetchStats();
    } catch (err: any) {
      console.error('Failed to sync Gmail messages:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to sync with Gmail API.');
    } finally {
      setSyncing(false);
    }
  };

  const handleBatchAnalyze = async () => {
    setAnalyzing(true);
    setError(null);
    try {
      const res = await analysisApi.batchAnalyze();
      setScanResult(res);
      setShowScanModal(true);
      await fetchStats();
    } catch (err: any) {
      console.error('Failed batch AI analysis:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to run AI threat scan.');
    } finally {
      setAnalyzing(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000);
    return () => window.clearInterval(timer);
  }, []);

  const handleSelectThreat = (threat: EmailMessage) => {
    setSelectedThreat(threat);
    if (threat.analysis) {
      setSelectedAnalysis(threat.analysis);
    }
  };

  const handleTrustRefresh = async (updatedEmail: EmailMessage) => {
    await fetchStats();
    if (selectedThreat && selectedThreat.id === updatedEmail.id) {
      setSelectedThreat(updatedEmail);
      setSelectedAnalysis(updatedEmail.analysis || null);
    }
  };

  if (loading) {
    return (
      <div className="py-20 flex flex-col items-center justify-center space-y-4 text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-400" />
        <p className="text-sm font-mono">Aggregating MailShield Inbox Security Intelligence...</p>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <Card className="p-8 text-center space-y-4 max-w-md mx-auto my-8">
        <AlertTriangle className="w-10 h-10 text-rose-500 mx-auto" />
        <h3 className="text-lg font-bold text-white">Dashboard Intelligence Error</h3>
        <p className="text-xs text-slate-400">{error}</p>
        <Button variant="primary" onClick={fetchStats}>
          Reload Dashboard
        </Button>
      </Card>
    );
  }

  // Client-side computation of suspicious (31-70) vs confirmed dangerous (71-100)
  const suspiciousEmailsCount = tierCounts
    ? tierCounts.suspicious
    : (stats.recent_threats || []).filter(
        (t) => (t.analysis?.risk_score ?? 0) >= 31 && (t.analysis?.risk_score ?? 0) <= 70
      ).length;

  const confirmedDangerousCount = tierCounts
    ? tierCounts.dangerous
    : (stats.recent_threats || []).filter(
        (t) => (t.analysis?.risk_score ?? 0) >= 71
      ).length;

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-6 rounded-2xl border border-blue-500/20 glow-blue">
        <div className="space-y-1">
          <h2 className="text-2xl font-black text-white tracking-tight">mailshield threat dashboard</h2>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm"
            variant="primary"
            onClick={handleBatchAnalyze}
            isLoading={analyzing}
            className="text-xs font-mono"
          >
            <Cpu className="w-3.5 h-3.5 mr-1.5" /> Run AI Threat Scan
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={handleSync}
            isLoading={syncing}
            className="text-xs font-mono"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> {formatSyncLabel(lastSyncedAt, now)}
          </Button>

          <Button size="sm" variant="secondary" onClick={fetchStats} className="text-xs font-mono">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh Analytics
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start space-x-3 text-xs">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold">Dashboard Diagnostic Error</p>
            <p className="text-rose-400/80">{error}</p>
          </div>
        </div>
      )}

      {/* Metric Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
        <StatCard
          title="Total Inbox Emails"
          value={stats.total_emails}
          subtitle="Synced via Gmail API"
          icon={<Mail className="w-6 h-6 text-blue-400" />}
          glow="blue"
        />
        <StatCard
          title="Verified Safe Emails"
          value={stats.safe_emails}
          subtitle="Non-malicious messages"
          icon={<ShieldCheck className="w-6 h-6 text-emerald-400" />}
          glow="emerald"
        />
        <StatCard
          title="Suspicious — Needs Review"
          value={suspiciousEmailsCount}
          subtitle="Tier: 31-70 risk score"
          icon={<AlertTriangle className="w-6 h-6 text-amber-400" />}
          glow="amber"
        />
        <StatCard
          title="Confirmed Dangerous"
          value={confirmedDangerousCount}
          subtitle="Tier: 71-100 risk score"
          icon={<ShieldAlert className="w-6 h-6 text-rose-400" />}
          glow="rose"
        />
        <StatCard
          title="% Emails Flagged"
          value={`${stats.threat_detection_rate}%`}
          subtitle="AI Flagged Ratio"
          icon={<Cpu className="w-6 h-6 text-cyan-400" />}
        />
      </div>

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <InboxRiskMeter score={stats.inbox_security_score} totalEmails={stats.total_emails} />
        <div className="lg:col-span-2">
          <ThreatCategoryChart categories={stats.threat_categories} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <WeeklyAnalyticsChart data={stats.weekly_analytics} />
        </div>

        {/* Security Recommendations Card */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Recommended Security Actions</h3>
          </div>
          <div className="space-y-2.5 text-xs text-slate-300">
            {stats.security_recommendations.map((rec, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-start space-x-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span className="leading-relaxed font-sans">{rec}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Recent Threats Panel */}
      <RecentThreatsList threats={stats.recent_threats} onSelectThreat={handleSelectThreat} />

      {/* Explainable AI Modal for Threats */}
      <ExplainableAiModal
        email={selectedThreat}
        analysis={selectedAnalysis}
        onClose={() => {
          setSelectedThreat(null);
          setSelectedAnalysis(null);
        }}
        onTrustRefresh={handleTrustRefresh}
      />

      {/* Sync Success Modal */}
      {showSyncModal && syncResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
          <div
            className="glass-panel w-full max-w-md rounded-2xl border border-slate-700/80 shadow-2xl p-6 flex flex-col space-y-4 animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Gmail Synchronization Status</h3>
              </div>
              <button
                onClick={() => setShowSyncModal(false)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            
            <div className="py-2 space-y-3">
              {syncResult.count === 0 ? (
                <div className="space-y-2 text-center py-4">
                  <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 flex items-center justify-center mx-auto mb-3">
                    <ShieldCheck className="w-6 h-6 animate-pulse" />
                  </div>
                  <h4 className="text-sm font-bold text-white">You're Already Synced Up!</h4>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans max-w-xs mx-auto">
                    All messages in your inbox are up to date. No new emails were found on Google servers.
                  </p>
                </div>
              ) : (
                <div className="space-y-2 text-center py-4">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto mb-3">
                    <Mail className="w-6 h-6 animate-bounce" />
                  </div>
                  <h4 className="text-sm font-bold text-white">New Emails Synced!</h4>
                  <p className="text-xs text-slate-400 leading-relaxed font-sans max-w-xs mx-auto">
                    Successfully synced <span className="text-emerald-400 font-bold font-mono text-sm">{syncResult.count}</span> new email message{syncResult.count === 1 ? '' : 's'} into your MailShield threat matrix.
                  </p>
                </div>
              )}
            </div>

            <Button
              variant="secondary"
              onClick={() => setShowSyncModal(false)}
              className="w-full text-xs font-mono"
            >
              Continue to Dashboard
            </Button>
          </div>
        </div>
      )}

      {/* AI Threat Scan Success Modal */}
      {showScanModal && scanResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
          <div
            className="glass-panel w-full max-w-md rounded-2xl border border-slate-700/80 shadow-2xl p-6 flex flex-col space-y-4 animate-in zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-cyan-400">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">AI Threat Scan Report</h3>
              </div>
              <button
                onClick={() => setShowScanModal(false)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            
            <div className="py-2 space-y-4">
              <div className="w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto mb-1">
                <Cpu className="w-6 h-6 animate-pulse" />
              </div>
              <div className="text-center">
                <h4 className="text-sm font-bold text-white">Inbox Intelligence Scan Completed</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed font-sans max-w-xs mx-auto mt-1">
                  MailShield AI processed your email payload against our multi-vector zero-shot NLP models.
                </p>
              </div>

              {/* Matrix Stats */}
              <div className="grid grid-cols-2 gap-3 pt-2 font-mono text-center">
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider">Processed</span>
                  <p className="text-lg font-bold text-slate-200">{scanResult.analyzed_count}</p>
                </div>
                <div className={`p-3 rounded-xl border space-y-1 ${
                  scanResult.high_risk_count > 0 
                    ? 'bg-rose-500/10 border-rose-500/20' 
                    : 'bg-emerald-500/10 border-emerald-500/20'
                }`}>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider">High Risk</span>
                  <p className={`text-lg font-bold ${
                    scanResult.high_risk_count > 0 ? 'text-rose-400' : 'text-emerald-400'
                  }`}>{scanResult.high_risk_count}</p>
                </div>
              </div>
            </div>

            <Button
              variant="secondary"
              onClick={() => setShowScanModal(false)}
              className="w-full text-xs font-mono"
            >
              Update Threat Analytics
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
