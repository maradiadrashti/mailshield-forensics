import React from 'react';
import { X, ShieldAlert, Cpu, AlertCircle, CheckCircle, Link2, Paperclip } from 'lucide-react';
import { EmailMessage, AnalysisResult } from '../../types';
import { RiskScoreMeter } from './RiskScoreMeter';
import { UrlAnalysisCard } from './UrlAnalysisCard';
import { MisinformationCard } from './MisinformationCard';
import { Badge } from '../ui/Badge';
import { formatDate } from '../../utils/formatters';

interface ExplainableAiModalProps {
  email: EmailMessage | null;
  analysis: AnalysisResult | null;
  onClose: () => void;
}

export const ExplainableAiModal: React.FC<ExplainableAiModalProps> = ({
  email,
  analysis,
  onClose,
}) => {
  if (!email || !analysis) return null;

  const getThreatBadgeVariant = (threat: string) => {
    if (threat === 'Safe') return 'success';
    if (threat === 'Phishing' || threat === 'Scam') return 'danger';
    return 'warning';
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
            <div className="flex items-center space-x-2">
              <Badge variant="info" className="flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
                EXPLAINABLE AI THREAT ANALYSIS
              </Badge>
              <Badge variant={getThreatBadgeVariant(analysis.threat_type)} className="uppercase font-bold">
                {analysis.threat_type}
              </Badge>
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
          {/* Top Diagnostics Dashboard Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
            {/* Risk Gauge */}
            <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-slate-800 pb-4 md:pb-0 md:pr-4">
              <RiskScoreMeter score={analysis.risk_score} size="md" />
              <div className="mt-3 text-center">
                <span className="text-[11px] font-mono text-slate-400">AI Confidence Level</span>
                <p className="text-sm font-bold text-cyan-400 font-mono">{(analysis.confidence * 100).toFixed(0)}% Certainty</p>
              </div>
            </div>

            {/* Category Breakdown Progress Bars */}
            <div className="col-span-2 space-y-2.5 font-mono text-xs">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Threat Breakdown Spectrum
              </h4>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Phishing Indicator</span>
                  <span className="text-rose-400 font-bold">{analysis.breakdown.phishing_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-rose-500 rounded-full" style={{ width: `${analysis.breakdown.phishing_score}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Scam & Fraud Score</span>
                  <span className="text-amber-400 font-bold">{analysis.breakdown.scam_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-amber-500 rounded-full" style={{ width: `${analysis.breakdown.scam_score}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Suspicious URL Risk</span>
                  <span className="text-cyan-400 font-bold">{analysis.breakdown.url_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${analysis.breakdown.url_score}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Social Engineering</span>
                  <span className="text-purple-400 font-bold">{analysis.breakdown.social_engineering_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500 rounded-full" style={{ width: `${analysis.breakdown.social_engineering_score}%` }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* AI Misinformation & Fact Verification Panel */}
          {analysis.misinformation_detail && (
            <MisinformationCard detail={analysis.misinformation_detail} />
          )}

          {/* Deep 6-Vector URL Threat Inspection Panel */}
          {email.links.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Link2 className="w-4 h-4 text-cyan-400" />
                URL Threat Matrix ({email.links.length} Extracted Links)
              </h3>
              <div className="space-y-3">
                {email.links.map((link, i) => (
                  <UrlAnalysisCard key={i} url={link} />
                ))}
              </div>
            </div>
          )}

          {/* Explainable AI Evidentiary Reasons Panel */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Explainable AI Evidentiary Reasons ({analysis.reasons.length})
            </h3>
            <div className="space-y-2">
              {analysis.reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-200 flex items-start space-x-3"
                >
                  <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span className="leading-relaxed font-sans">{reason}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Actionable Safety Recommendations Panel */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              Actionable Security Recommendations
            </h3>
            <div className="space-y-2">
              {analysis.recommendations.map((rec, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-start space-x-3"
                >
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span className="leading-relaxed font-sans">{rec}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Attachments Summary */}
          {email.attachments.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs">
              <div className="flex items-center space-x-2 text-purple-400 font-semibold">
                <Paperclip className="w-4 h-4" />
                <span>Attachments ({email.attachments.length})</span>
              </div>
              <ul className="space-y-1 text-[11px] text-slate-400">
                {email.attachments.map((att, i) => (
                  <li key={i} className="p-1.5 bg-slate-950 rounded flex justify-between">
                    <span className="truncate">{att.filename}</span>
                    <span className="text-slate-500 font-mono">{(att.size / 1024).toFixed(0)} KB</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex justify-between items-center text-xs text-slate-400">
          <span className="font-mono">Analysis Timestamp: {formatDate(analysis.analyzed_at)}</span>
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors shadow-lg shadow-blue-600/30"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
