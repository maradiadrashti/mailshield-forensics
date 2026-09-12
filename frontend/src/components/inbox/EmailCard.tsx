import React from 'react';
import { Link2, Paperclip, Calendar, Search } from 'lucide-react';
import { EmailMessage } from '../../types';
import { Badge } from '../ui/Badge';
import { RiskScoreMeter } from '../analysis/RiskScoreMeter';
import { formatDate, getThreatTier } from '../../utils/formatters';

interface EmailCardProps {
  email: EmailMessage;
  onClick: (email: EmailMessage) => void;
  onInspect?: (email: EmailMessage) => void;
  onOpenInvestigation?: (id: string) => void;
}

export const EmailCard: React.FC<EmailCardProps> = ({ email, onClick, onInspect, onOpenInvestigation }) => {
  const getSenderInitials = (senderStr: string) => {
    const clean = senderStr.replace(/<.*>/, '').trim();
    return clean ? clean.slice(0, 2).toUpperCase() : 'GM';
  };

  const analysis = email.analysis;
  const threatTier = analysis ? getThreatTier(analysis.risk_score) : null;

  return (
    <div
      onClick={() => onClick(email)}
      className="glass-panel p-5 rounded-xl border border-slate-800/90 hover:border-blue-500/50 hover:bg-slate-900/80 transition-all duration-200 cursor-pointer space-y-3 group relative overflow-hidden"
    >
      {/* Header Info */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center space-x-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-blue-600/10 border border-blue-500/30 text-blue-400 font-mono font-bold text-xs flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform duration-200">
            {getSenderInitials(email.sender)}
          </div>
          <div className="min-w-0">
            <h4 className="text-sm font-semibold text-white truncate group-hover:text-blue-400 transition-colors duration-150">
              {email.sender}
            </h4>
            <p className="text-[11px] text-slate-400 truncate font-mono">To: {email.recipient}</p>
          </div>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          {analysis && <RiskScoreMeter score={analysis.risk_score} size="sm" />}
          <div className="flex items-center space-x-1.5 text-[11px] text-slate-400 font-mono">
            <Calendar className="w-3.5 h-3.5 text-slate-500" />
            <span>{formatDate(email.date)}</span>
          </div>
        </div>
      </div>

      {/* Subject line */}
      <h3 className="text-sm font-semibold text-slate-200 line-clamp-1 group-hover:text-white">
        {email.subject}
      </h3>

      {/* Snippet preview */}
      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed font-sans">
        {email.snippet || email.body_text?.slice(0, 140)}
      </p>

      {/* Footer Tags & Metadata */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
        <div className="flex items-center space-x-2">
          {analysis && analysis.is_trusted_sender && (
            <Badge variant="success" className="font-mono text-[10px] uppercase font-bold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              Trusted Sender
            </Badge>
          )}

          {threatTier && (
            <Badge
              variant={threatTier.variant}
              className="font-mono text-[10px] uppercase font-bold flex items-center gap-1"
            >
              <span className={`w-1.5 h-1.5 rounded-full ${
                threatTier.variant === 'success' ? 'bg-emerald-400' :
                threatTier.variant === 'warning' ? 'bg-amber-400' : 'bg-rose-400'
              }`}></span>
              {threatTier.label}
            </Badge>
          )}

          {email.links.length > 0 && (
            <Badge variant="warning" className="flex items-center gap-1 font-mono text-[10px]">
              <Link2 className="w-3 h-3" />
              {email.links.length} {email.links.length === 1 ? 'URL' : 'URLs'}
            </Badge>
          )}

          {email.attachments.length > 0 && (
            <Badge variant="info" className="flex items-center gap-1 font-mono text-[10px]">
              <Paperclip className="w-3 h-3" />
              {email.attachments.length} {email.attachments.length === 1 ? 'File' : 'Files'}
            </Badge>
          )}
        </div>

        <button
          onClick={(e) => {
            e.stopPropagation();
            if (onOpenInvestigation) {
              onOpenInvestigation(email.id);
            } else {
              onInspect?.(email);
            }
          }}
          className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 font-semibold group-hover:translate-x-0.5 transition-all duration-150 focus:outline-none"
        >
          <Search className="w-3.5 h-3.5" /> Open Investigation &rarr;
        </button>
      </div>
    </div>
  );
};
