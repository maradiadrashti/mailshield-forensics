import React from 'react';
import { AlertTriangle, ShieldCheck, Newspaper, Highlighter } from 'lucide-react';
import { MisinformationDetail } from '../../types';
import { Badge } from '../ui/Badge';

interface MisinformationCardProps {
  detail?: MisinformationDetail;
}

export const MisinformationCard: React.FC<MisinformationCardProps> = ({ detail }) => {
  if (!detail) return null;

  const isLowCredibility = detail.credibility_score < 50;

  return (
    <div
      className={`p-5 rounded-2xl border transition-all duration-200 space-y-4 ${
        isLowCredibility
          ? 'bg-rose-500/10 border-rose-500/30 glow-rose'
          : detail.credibility_score < 80
          ? 'bg-amber-500/10 border-amber-500/30'
          : 'bg-slate-900/60 border-slate-800'
      }`}
    >
      {/* Header Bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Newspaper className={`w-5 h-5 ${isLowCredibility ? 'text-rose-400' : 'text-cyan-400'}`} />
          <h3 className="text-sm font-bold text-white">AI Misinformation & Fact Verification</h3>
        </div>

        <Badge
          variant={isLowCredibility ? 'danger' : detail.credibility_score < 80 ? 'warning' : 'success'}
          className="font-mono text-xs font-bold"
        >
          {detail.credibility_score}% CREDIBILITY SCORE
        </Badge>
      </div>

      {/* Credibility Progress Meter */}
      <div className="space-y-1 font-mono text-xs">
        <div className="flex justify-between text-[11px] text-slate-400">
          <span>Truth Credibility Level</span>
          <span className={isLowCredibility ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
            {detail.credibility_score}%
          </span>
        </div>
        <div className="h-2 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-700 ${
              isLowCredibility ? 'bg-rose-500' : detail.credibility_score < 80 ? 'bg-amber-500' : 'bg-emerald-500'
            }`}
            style={{ width: `${detail.credibility_score}%` }}
          ></div>
        </div>
      </div>

      {/* Flagged Suspicious Sentences Highlighting Panel */}
      {detail.suspicious_sentences.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-slate-800/80">
          <div className="flex items-center space-x-2 text-xs font-semibold text-amber-400">
            <Highlighter className="w-4 h-4" />
            <span>Flagged Suspicious Sentences ({detail.suspicious_sentences.length})</span>
          </div>

          <div className="space-y-2">
            {detail.suspicious_sentences.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-950/80 border border-amber-500/40 text-xs space-y-1 font-sans"
              >
                <p className="text-amber-200 bg-amber-500/20 px-2 py-1 rounded font-medium inline-block border border-amber-500/30">
                  "{item.sentence}"
                </p>
                <div className="flex items-center gap-1.5 text-[11px] text-amber-400 font-mono pt-1">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>{item.risk}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Evidentiary Explanations */}
      {detail.evidence.length > 0 && (
        <div className="space-y-1.5 text-xs text-slate-300 pt-1 font-sans">
          {detail.evidence.map((ev, i) => (
            <div key={i} className="flex items-start space-x-2 text-slate-300">
              {isLowCredibility ? (
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
              )}
              <span>{ev}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
