import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Search,
  FileText,
  AlertTriangle,
  Radio,
  ArrowRight,
  X,
  Layers,
  Inbox,
  RefreshCw,
  Mail,
  CheckCircle2,
  User as UserIcon,
  AlertOctagon
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { forensicsApi } from '../services/forensicsApi';
import { gmailApi } from '../services/gmailApi';
import { Investigation, InvestigationMetrics, EmailMessage } from '../types';

interface ForensicsPageProps {
  onOpenInvestigation?: (id: string) => void;
  onGoToInbox?: () => void;
}

export const ForensicsPage: React.FC<ForensicsPageProps> = ({
  onOpenInvestigation,
  onGoToInbox,
}) => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [metrics, setMetrics] = useState<InvestigationMetrics>({
    total_investigations: 0,
    dangerous_count: 0,
    suspicious_count: 0,
    reports_generated_count: 0,
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Scan Email Modal State
  const [showScanModal, setShowScanModal] = useState<boolean>(false);
  const [syncEmails, setSyncEmails] = useState<EmailMessage[]>([]);
  const [loadingEmails, setLoadingEmails] = useState<boolean>(false);
  const [emailSearch, setEmailSearch] = useState<string>('');
  const [selectedScanEmailId, setSelectedScanEmailId] = useState<string | null>(null);
  const [openingInvestigation, setOpeningInvestigation] = useState<boolean>(false);

  const fetchInvestigations = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await forensicsApi.getInvestigations();
      setInvestigations(data.investigations || []);
      setMetrics(
        data.metrics || {
          total_investigations: 0,
          dangerous_count: 0,
          suspicious_count: 0,
          reports_generated_count: 0,
        }
      );
    } catch (err: any) {
      console.error('Failed to fetch forensic investigations:', err);
      setError(
        err.response?.data?.detail ||
          err.message ||
          'Unable to retrieve forensic investigations from database.'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  // Load real synced emails when Scan Email modal is opened
  const handleOpenScanModal = async () => {
    setShowScanModal(true);
    setLoadingEmails(true);
    try {
      const res = await gmailApi.getMessages(1, 50);
      setSyncEmails(res.items || []);
    } catch (err) {
      console.error('Failed to load mailbox emails for scanning:', err);
    } finally {
      setLoadingEmails(false);
    }
  };

  const handleStartInvestigation = async (emailId: string) => {
    setOpeningInvestigation(true);
    try {
      const inv = await forensicsApi.openInvestigation(emailId);
      setShowScanModal(false);
      if (onOpenInvestigation) {
        onOpenInvestigation(inv.id);
      }
    } catch (err: any) {
      console.error('Failed to start forensic investigation:', err);
      alert(err.response?.data?.detail || 'Failed to open forensic investigation.');
    } finally {
      setOpeningInvestigation(false);
    }
  };

  const filteredScanEmails = syncEmails.filter((email) => {
    if (!emailSearch.trim()) return true;
    const term = emailSearch.toLowerCase();
    return (
      (email.subject || '').toLowerCase().includes(term) ||
      (email.sender || '').toLowerCase().includes(term)
    );
  });

  const getThreatBadgeVariant = (severity: string, score: number) => {
    if (score >= 75 || severity === 'critical') return 'danger';
    if (score >= 25 || severity === 'high' || severity === 'suspicious') return 'warning';
    return 'success';
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-6 rounded-2xl border border-blue-500/20 glow-blue">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <Radio className="w-5 h-5 text-blue-400 animate-pulse" />
            <h2 className="text-2xl font-black text-white tracking-tight">Forensic Investigations</h2>
            <Badge variant="info" className="font-mono text-[10px]">
              EVIDENCE MATRIX
            </Badge>
          </div>
          <p className="text-xs text-slate-400">
            Persistent forensic case files, network telemetry, deterministic 3-layer threat analysis, and chain of custody.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            size="md"
            variant="secondary"
            onClick={fetchInvestigations}
            disabled={loading}
            className="text-xs font-mono"
          >
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <Button
            size="md"
            variant="primary"
            onClick={handleOpenScanModal}
            className="text-xs font-mono shadow-lg shadow-blue-600/20"
          >
            <Search className="w-4 h-4 mr-2" />
            Scan Email
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-950/30 text-rose-300 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <Button size="sm" variant="secondary" onClick={fetchInvestigations} className="text-xs">
            Retry
          </Button>
        </div>
      )}

      {/* Investigation Summary Cards (Real Backend Metrics) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <Card glow="blue" className="p-5 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Total Investigations
            </span>
            <Layers className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl md:text-3xl font-black text-white font-mono">
            {loading ? '...' : metrics.total_investigations}
          </div>
          <p className="text-[11px] text-slate-500 font-sans">Active forensic cases</p>
        </Card>

        <Card glow="rose" className="p-5 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Dangerous</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl md:text-3xl font-black text-white font-mono">
            {loading ? '...' : metrics.dangerous_count}
          </div>
          <p className="text-[11px] text-slate-500 font-sans">Confirmed malicious threats</p>
        </Card>

        <Card glow="amber" className="p-5 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Suspicious</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl md:text-3xl font-black text-white font-mono">
            {loading ? '...' : metrics.suspicious_count}
          </div>
          <p className="text-[11px] text-slate-500 font-sans">Elevated risk anomalies</p>
        </Card>

        <Card glow="none" className="p-5 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Reports Generated
            </span>
            <FileText className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl md:text-3xl font-black text-white font-mono">
            {loading ? '...' : metrics.reports_generated_count}
          </div>
          <p className="text-[11px] text-slate-500 font-sans">Exported audit packages</p>
        </Card>
      </div>

      {/* Recent Investigations Table / Section */}
      <Card className="p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-bold text-white">Recent Investigations</h3>
            <p className="text-xs text-slate-400">
              Investigate suspicious emails, inspect forensic header evidence, and verify tamper-proof audit trails.
            </p>
          </div>
          <Badge variant="neutral" className="font-mono text-xs">
            {investigations.length} {investigations.length === 1 ? 'CASE' : 'CASES'}
          </Badge>
        </div>

        {/* Loading State */}
        {loading ? (
          <div className="space-y-3 py-6">
            {[1, 2, 3].map((n) => (
              <div
                key={n}
                className="h-16 rounded-xl bg-slate-900/60 border border-slate-800 animate-pulse flex items-center px-4 justify-between"
              >
                <div className="space-y-2">
                  <div className="w-48 h-3.5 bg-slate-800 rounded"></div>
                  <div className="w-32 h-2.5 bg-slate-800/60 rounded"></div>
                </div>
                <div className="w-24 h-6 bg-slate-800 rounded"></div>
              </div>
            ))}
          </div>
        ) : investigations.length === 0 ? (
          /* Empty State */
          <div className="py-16 text-center space-y-4 max-w-md mx-auto">
            <div className="w-14 h-14 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400 flex items-center justify-center mx-auto shadow-inner">
              <Search className="w-7 h-7" />
            </div>
            <div className="space-y-1.5">
              <h4 className="text-base font-bold text-white">No investigations yet</h4>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Open an email from Gmail Inbox and select &ldquo;Open Investigation&rdquo; or click &ldquo;Scan Email&rdquo; to begin forensic analysis.
              </p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              {onGoToInbox && (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={onGoToInbox}
                  className="text-xs font-mono"
                >
                  <Inbox className="w-3.5 h-3.5 mr-1.5" />
                  Go to Gmail Inbox
                </Button>
              )}
              <Button
                variant="primary"
                size="sm"
                onClick={handleOpenScanModal}
                className="text-xs font-mono"
              >
                <Search className="w-3.5 h-3.5 mr-1.5" />
                Scan Email
              </Button>
            </div>
          </div>
        ) : (
          /* Table of Real Investigations */
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead className="text-[11px] text-slate-400 font-mono uppercase bg-slate-900/60 border-y border-slate-800">
                <tr>
                  <th className="py-3 px-4">Case ID</th>
                  <th className="py-3 px-4">Email / Subject</th>
                  <th className="py-3 px-4">Threat Verdict</th>
                  <th className="py-3 px-4">Threat Score</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {investigations.map((item) => {
                  const badgeVariant = getThreatBadgeVariant(item.severity, item.score);
                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-900/40 transition-colors group cursor-pointer"
                      onClick={() => onOpenInvestigation?.(item.id)}
                    >
                      <td className="py-3 px-4 font-mono text-slate-400">
                        <span className="text-blue-400 font-semibold">
                          CASE-{item.id.slice(0, 8).toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        <div className="text-white font-medium truncate group-hover:text-blue-300 transition-colors">
                          {item.subject}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate flex items-center gap-1">
                          <UserIcon className="w-3 h-3 text-slate-500 inline" />
                          <span>{item.sender}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <Badge variant={badgeVariant} className="font-mono text-[10px]">
                          {item.verdict}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <div className="flex items-center space-x-1.5">
                          <span
                            className={`font-black text-sm ${
                              item.score >= 75
                                ? 'text-rose-400'
                                : item.score >= 25
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {item.score}
                          </span>
                          <span className="text-[10px] text-slate-500">/100</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                        {new Date(item.created_at).toLocaleDateString(undefined, {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </td>
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-950/60 border border-emerald-800/50 text-emerald-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                          Active
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenInvestigation?.(item.id);
                          }}
                          className="text-xs font-mono group-hover:bg-blue-600 group-hover:text-white transition-all shadow-sm"
                        >
                          Open Investigation <ArrowRight className="w-3 h-3 ml-1" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Real Scan Email Modal */}
      {showScanModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-2xl rounded-2xl border border-slate-700/80 p-6 space-y-4 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-blue-400">
                <Search className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Scan Email for Forensics</h3>
              </div>
              <button
                onClick={() => setShowScanModal(false)}
                className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Select an email from your synced Gmail mailbox to initiate forensic header parsing, Received hop tracing, and deterministic threat scoring.
            </p>

            {/* Email Search Box */}
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search synced emails by sender or subject..."
                value={emailSearch}
                onChange={(e) => setEmailSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-sans"
              />
            </div>

            {/* List of Real Emails */}
            <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[200px] max-h-[400px]">
              {loadingEmails ? (
                <div className="py-12 text-center text-slate-400 text-xs font-mono flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
                  Loading synced emails from mailbox...
                </div>
              ) : filteredScanEmails.length === 0 ? (
                <div className="py-12 text-center text-slate-400 text-xs font-sans space-y-2">
                  <Mail className="w-8 h-8 text-slate-600 mx-auto" />
                  <p>No matching emails found.</p>
                </div>
              ) : (
                filteredScanEmails.map((email) => {
                  const isSelected = selectedScanEmailId === email.id;
                  const score = email.analysis?.risk_score;

                  return (
                    <div
                      key={email.id}
                      onClick={() => setSelectedScanEmailId(email.id)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-center justify-between gap-3 ${
                        isSelected
                          ? 'bg-blue-950/40 border-blue-500/80 shadow-lg shadow-blue-950/50'
                          : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900'
                      }`}
                    >
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-xs text-white truncate">
                            {email.subject || '(No Subject)'}
                          </span>
                          {score !== undefined && (
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                                score >= 75
                                  ? 'bg-rose-950/70 text-rose-400 border border-rose-800/50'
                                  : score >= 25
                                  ? 'bg-amber-950/70 text-amber-400 border border-amber-800/50'
                                  : 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/50'
                              }`}
                            >
                              {score}/100
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate flex items-center gap-2">
                          <span className="truncate">{email.sender}</span>
                          <span>•</span>
                          <span className="text-slate-500 font-mono text-[10px] shrink-0">
                            {new Date(email.date).toLocaleDateString()}
                          </span>
                        </div>
                      </div>

                      <div className="shrink-0">
                        {isSelected ? (
                          <div className="w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center shadow-md">
                            <CheckCircle2 className="w-4 h-4" />
                          </div>
                        ) : (
                          <div className="w-6 h-6 rounded-full border border-slate-700 hover:border-slate-500"></div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowScanModal(false)}
                className="text-xs font-mono"
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={!selectedScanEmailId || openingInvestigation}
                onClick={() => selectedScanEmailId && handleStartInvestigation(selectedScanEmailId)}
                className="text-xs font-mono"
              >
                {openingInvestigation ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                    Opening Case...
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5 mr-1.5" />
                    Start Forensic Investigation
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
