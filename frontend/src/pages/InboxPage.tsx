import React, { useState, useEffect, useCallback } from 'react';
import { Search, RefreshCw, Mail, ChevronLeft, ChevronRight, AlertTriangle, Cpu, ShieldCheck, X, CheckCircle } from 'lucide-react';
import { gmailApi } from '../services/gmailApi';
import { analysisApi } from '../services/analysisApi';
import { EmailMessage, AnalysisResult } from '../types';
import { EmailCard } from '../components/inbox/EmailCard';
import { ExplainableAiModal } from '../components/analysis/ExplainableAiModal';
import { EmailDetailModal } from '../components/inbox/EmailDetailModal';
import { InboxSkeleton } from '../components/inbox/InboxSkeleton';
import { EmptyState } from '../components/inbox/EmptyState';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';

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

export const InboxPage: React.FC = () => {
  const [emails, setEmails] = useState<EmailMessage[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pages, setPages] = useState<number>(1);
  const [search, setSearch] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<number | null>(null);
  const [now, setNow] = useState<number>(Date.now());
  
  const [selectedEmail, setSelectedEmail] = useState<EmailMessage | null>(null);
  const [selectedAiEmail, setSelectedAiEmail] = useState<EmailMessage | null>(null);
  const [selectedAnalysis, setSelectedAnalysis] = useState<AnalysisResult | null>(null);

  // Sync and Scan success modal states
  const [syncResult, setSyncResult] = useState<{ count: number; message: string } | null>(null);
  const [showSyncModal, setShowSyncModal] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<{ analyzed_count: number; high_risk_count: number } | null>(null);
  const [showScanModal, setShowScanModal] = useState<boolean>(false);

  const fetchEmailsAndAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await gmailApi.getMessages(page, 20, search);
      
      // Automatically batch analyze items for instant AI risk scores
      const batchRes = await analysisApi.batchAnalyze();
      const analysisMap = new Map<string, AnalysisResult>();
      batchRes.results.forEach((r) => analysisMap.set(r.email_id, r));

      const mergedItems = data.items.map((item) => ({
        ...item,
        analysis: analysisMap.get(item.id),
      }));

      setEmails(mergedItems);
      setTotal(data.total);
      setPages(data.pages);
    } catch (err: any) {
      console.error('Failed to fetch Gmail messages or AI analysis:', err);
      setError(err.response?.data?.detail || err.message || 'Unable to retrieve Gmail messages.');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => {
    fetchEmailsAndAnalysis();

    const interval = setInterval(async () => {
      try {
        await gmailApi.syncMessages(10);
        // Silently load new messages and analysis to avoid screen flashing or loader overlays
        const data = await gmailApi.getMessages(page, 20, search);
        const batchRes = await analysisApi.batchAnalyze();
        const analysisMap = new Map<string, AnalysisResult>();
        batchRes.results.forEach((r) => analysisMap.set(r.email_id, r));

        const mergedItems = data.items.map((item) => ({
          ...item,
          analysis: analysisMap.get(item.id),
        }));

        setEmails(mergedItems);
        setTotal(data.total);
        setPages(data.pages);
      } catch (err) {
        console.error('Background real-time sync failed:', err);
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [fetchEmailsAndAnalysis, page, search]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60000);
    return () => window.clearInterval(timer);
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setError(null);
    try {
      const res = await gmailApi.syncMessages(20);
      setSyncResult(res);
      setShowSyncModal(true);
      setLastSyncedAt(Date.now());
      setPage(1);
      await fetchEmailsAndAnalysis();
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
      await fetchEmailsAndAnalysis();
    } catch (err: any) {
      console.error('Failed batch AI analysis:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to run AI threat scan.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleSelectEmail = (email: EmailMessage) => {
    setSelectedEmail(email);
  };

  const handleInspectAi = async (email: EmailMessage) => {
    setSelectedAiEmail(email);
    if (email.analysis) {
      setSelectedAnalysis(email.analysis);
    } else {
      try {
        const result = await analysisApi.analyzeEmail(email.id);
        setSelectedAnalysis(result);
      } catch (err) {
        console.error('Email AI analysis failed:', err);
      }
    }
  };

  const handleTrustRefresh = async (updatedEmail: EmailMessage) => {
    await fetchEmailsAndAnalysis();
    if (selectedEmail && selectedEmail.id === updatedEmail.id) {
      setSelectedEmail(updatedEmail);
    }
    if (selectedAiEmail && selectedAiEmail.id === updatedEmail.id) {
      setSelectedAiEmail(updatedEmail);
      setSelectedAnalysis(updatedEmail.analysis || null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-6 rounded-2xl border border-blue-500/20 glow-blue">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <Mail className="w-5 h-5 text-blue-400" />
            <h2 className="text-xl font-bold text-white">mailshield inbox</h2>
            <Badge variant="info">{total} Messages</Badge>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="md"
            variant="primary"
            onClick={handleBatchAnalyze}
            isLoading={analyzing}
            className="text-xs font-mono"
          >
            <Cpu className="w-4 h-4 mr-2" />
            Run AI Threat Scan
          </Button>

          <Button
            size="md"
            variant="outline"
            onClick={handleSync}
            isLoading={syncing}
            className="text-xs font-mono"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
              {formatSyncLabel(lastSyncedAt, now)}
          </Button>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search sender, subject, or message content..."
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900/80 border border-slate-800 focus:border-blue-500/60 focus:outline-none text-xs text-slate-200 placeholder-slate-500 transition-colors"
          />
        </div>

        {/* Pagination Indicator */}
        <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono">
          <span>
            Page <strong className="text-white">{page}</strong> of <strong className="text-white">{pages}</strong>
          </span>
          <div className="flex items-center space-x-1">
            <Button
              size="sm"
              variant="secondary"
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="p-1.5"
            >
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={page >= pages || loading}
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              className="p-1.5"
            >
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-start space-x-3 text-xs">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold">Inbox Diagnostic Error</p>
            <p className="text-rose-400/80">{error}</p>
            <Button size="sm" variant="danger" onClick={handleSync} className="mt-2 text-[11px]">
              Re-try Gmail Sync
            </Button>
          </div>
        </div>
      )}

      {/* Inbox List / Skeleton / Empty State */}
      {loading ? (
        <InboxSkeleton />
      ) : emails.length === 0 ? (
        <EmptyState isSearch={search.length > 0} onRefresh={handleSync} />
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {emails.map((email) => (
            <EmailCard
              key={email.id}
              email={email}
              onClick={handleSelectEmail}
              onInspect={handleInspectAi}
            />
          ))}
        </div>
      )}

      {/* Pagination Footer */}
      {pages > 1 && (
        <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs text-slate-400">
          <p className="font-mono">
            Showing messages {((page - 1) * 20) + 1} - {Math.min(page * 20, total)} of {total}
          </p>
          <div className="flex items-center space-x-2">
            <Button
              size="sm"
              variant="outline"
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous Page
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={page >= pages || loading}
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
            >
              Next Page
            </Button>
          </div>
        </div>
      )}

      {/* Normal Email Viewer Modal */}
      <EmailDetailModal
        email={selectedEmail}
        onClose={() => setSelectedEmail(null)}
        onTrustRefresh={handleTrustRefresh}
      />

      {/* Single Email Explainable AI Inspector Modal */}
      <ExplainableAiModal
        email={selectedAiEmail}
        analysis={selectedAnalysis}
        onClose={() => {
          setSelectedAiEmail(null);
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
                <CheckCircle className="w-5 h-5" />
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
              Continue to Inbox
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
