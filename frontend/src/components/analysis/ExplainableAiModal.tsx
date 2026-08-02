import React, { useState } from 'react';
import { X, ShieldAlert, Cpu, AlertCircle, CheckCircle, Link2, UserCheck, RefreshCw } from 'lucide-react';
import { EmailMessage, AnalysisResult } from '../../types';
import { RiskScoreMeter } from './RiskScoreMeter';
import { UrlAnalysisCard } from './UrlAnalysisCard';
import { MisinformationCard } from './MisinformationCard';
import { Badge } from '../ui/Badge';
import { formatDate } from '../../utils/formatters';
import { trustedSenderApi } from '../../services/trustedSenderApi';
import { analysisApi } from '../../services/analysisApi';

interface ExplainableAiModalProps {
  email: EmailMessage | null;
  analysis: AnalysisResult | null;
  onClose: () => void;
  onTrustRefresh?: (updatedEmail: EmailMessage) => void;
}

export const ExplainableAiModal: React.FC<ExplainableAiModalProps> = ({
  email,
  analysis,
  onClose,
  onTrustRefresh
}) => {
  const [trusting, setTrusting] = useState(false);

  if (!email || !analysis) return null;

  const getThreatBadgeVariant = (threat: string) => {
    if (threat === 'Safe') return 'success';
    if (threat === 'Phishing' || threat === 'Scam') return 'danger';
    return 'warning';
  };

  const handleTrustSender = async () => {
    setTrusting(true);
    try {
      const match = email.sender.match(/<([^>]+)>/);
      const cleanEmail = match ? match[1].trim().toLowerCase() : email.sender.trim().toLowerCase();

      // 1. Save sender as trusted
      await trustedSenderApi.addTrustedSender({
        type: 'email',
        value: cleanEmail
      });

      // 2. Forced backend re-scan
      const updatedAnalysis = await analysisApi.analyzeEmail(email.id, true);

      // 3. Trigger parent state refresh
      if (onTrustRefresh) {
        onTrustRefresh({
          ...email,
          analysis: updatedAnalysis
        });
      }
    } catch (err) {
      console.error('Failed to trust sender:', err);
    } finally {
      setTrusting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <div
        className="glass-panel w-full max-w-4xl max-h-[92vh] rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-900/80">
          <div className="space-y-2 pr-6">
            <div className="flex items-center space-x-2 flex-wrap gap-y-1">
              <Badge variant="info" className="flex items-center gap-1 py-0.5">
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
                EXPLAINABLE AI THREAT ANALYSIS
              </Badge>
              <Badge variant={getThreatBadgeVariant(analysis.threat_type)} className="uppercase font-bold py-0.5">
                {analysis.threat_type}
              </Badge>
              {analysis.is_trusted_sender ? (
                <Badge variant="success" className="font-semibold flex items-center gap-1.5 py-0.5">
                  <UserCheck className="w-3.5 h-3.5" />
                  Trusted Sender
                </Badge>
              ) : (
                <button
                  onClick={handleTrustSender}
                  disabled={trusting}
                  className="flex items-center gap-1.5 py-0.5 px-2.5 rounded bg-emerald-600 hover:bg-emerald-500 text-[10px] text-white font-bold transition-all focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed uppercase font-mono"
                >
                  {trusting ? (
                    <>
                      <RefreshCw className="w-3 h-3 animate-spin" />
                      Trusting...
                    </>
                  ) : (
                    <>
                      <UserCheck className="w-3 h-3" />
                      Trust Sender
                    </>
                  )}
                </button>
              )}
            </div>
            <h2 className="text-xl font-bold text-white leading-snug">{email.subject}</h2>
            <p className="text-xs text-slate-400 font-mono">
              From: <strong className="text-slate-200">{email.sender}</strong> &bull; Received: {formatDate(email.date)}
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors shrink-0 focus:outline-none"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Main Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          {/* Top Diagnostics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
            {/* Risk Gauge */}
            <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-slate-800 pb-4 md:pb-0 md:pr-4">
              <RiskScoreMeter score={analysis.risk_score} size="md" />
              <div className="mt-3 text-center">
                <span className="text-[11px] font-mono text-slate-400">AI Confidence Level</span>
                <p className="text-sm font-bold text-cyan-400 font-mono">{(analysis.confidence * 100).toFixed(0)}% Certainty</p>
              </div>
            </div>

            {/* AI Reasoning List */}
            <div className="md:col-span-2 space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-amber-500" />
                Explainable Threat Evidences ({analysis.reasons.length})
              </h3>
              <ul className="space-y-2 text-xs text-slate-300">
                {analysis.reasons.map((reason, i) => (
                  <li key={i} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/80">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0"></span>
                    <span className="leading-relaxed select-text">{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Recommendations List */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
              <AlertCircle className="w-4 h-4 text-emerald-500" />
              Cybersecurity Recommendations & Mitigations
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.recommendations.map((rec, i) => (
                <div key={i} className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/10 flex items-start space-x-3">
                  <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-slate-300 leading-relaxed select-text">{rec}</p>
                </div>
              ))}
            </div>
          </div>

          {/* URL Intelligence Center */}
          {email.links.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Link2 className="w-4 h-4 text-indigo-400" />
                URL Intelligence & Reputation Center ({email.links.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {email.links.map((link, i) => (
                  <UrlAnalysisCard key={i} url={link} />
                ))}
              </div>
            </div>
          )}

          {/* Misinformation Detection Panel */}
          {analysis.threat_type === 'Misinformation' && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-purple-400" />
                Misinformation & AI Fact Checking Analysis
              </h3>
              <MisinformationCard detail={analysis.misinformation_detail} />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex justify-between items-center text-xs text-slate-400">
          <span className="font-mono">Message ID: {email.id}</span>
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold transition-colors"
          >
            Close Diagnostics
          </button>
        </div>
      </div>
    </div>
  );
};
