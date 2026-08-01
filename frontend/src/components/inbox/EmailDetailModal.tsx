import React from 'react';
import { X, Link2, Paperclip, Calendar, User, FileText } from 'lucide-react';
import { EmailMessage } from '../../types';
import { Badge } from '../ui/Badge';
import { formatDate } from '../../utils/formatters';

interface EmailDetailModalProps {
  email: EmailMessage | null;
  onClose: () => void;
}

export const EmailDetailModal: React.FC<EmailDetailModalProps> = ({ email, onClose }) => {
  if (!email) return null;

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="glass-panel w-full max-w-3xl max-h-[90vh] rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-900/60">
          <div className="space-y-2 pr-6">
            <Badge variant="info">GMAIL MESSAGE INSPECTOR</Badge>
            <h2 className="text-xl font-bold text-white leading-snug">{email.subject}</h2>
            <div className="flex flex-wrap items-center gap-y-1 gap-x-4 text-xs text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <User className="w-3.5 h-3.5 text-blue-400" />
                <strong className="text-slate-200">From:</strong> {email.sender}
              </span>
              <span className="flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5 text-slate-500" />
                {formatDate(email.date)}
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors focus:outline-none shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Body Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          {/* Extracted Links Panel */}
          {email.links.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center space-x-2 text-xs font-semibold text-slate-400">
                <Link2 className="w-4 h-4 text-slate-400" />
                <span>Extracted Links ({email.links.length})</span>
              </div>
              <div className="flex flex-col gap-1.5 font-mono text-[11px] max-w-full overflow-hidden">
                {email.links.map((link, i) => (
                  <a
                    key={i}
                    href={link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 hover:underline truncate"
                  >
                    {link}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Attachment Metadata Panel */}
          {email.attachments.length > 0 && (
            <div className="p-4 rounded-xl bg-blue-500/10 border border-blue-500/30 space-y-2">
              <div className="flex items-center space-x-2 text-xs font-semibold text-blue-400">
                <Paperclip className="w-4 h-4" />
                <span>Attached Files ({email.attachments.length})</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-xs">
                {email.attachments.map((att, i) => (
                  <div key={i} className="p-2.5 rounded bg-slate-950/60 border border-slate-800 flex items-center space-x-3">
                    <FileText className="w-4 h-4 text-blue-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="font-semibold text-slate-200 truncate">{att.filename}</p>
                      <p className="text-[10px] text-slate-500">{att.mime_type} • {formatFileSize(att.size)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Email Body Text */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Email Content Body
            </h4>
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-200 text-sm font-sans leading-relaxed whitespace-pre-wrap select-text">
              {email.body_text || (
                <div dangerouslySetInnerHTML={{ __html: email.body_html || '<em>(Empty Body)</em>' }} />
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 flex justify-between items-center text-xs text-slate-400">
          <span className="font-mono">Message ID: {email.id}</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
