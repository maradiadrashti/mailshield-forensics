import React from 'react';
import { ShieldAlert, ArrowRight } from 'lucide-react';
import { EmailMessage } from '../../types';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { formatDate } from '../../utils/formatters';

interface RecentThreatsListProps {
  threats: EmailMessage[];
  onSelectThreat: (email: EmailMessage) => void;
}

export const RecentThreatsList: React.FC<RecentThreatsListProps> = ({
  threats,
  onSelectThreat,
}) => {
  return (
    <Card className="p-6 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-5 h-5 text-rose-500" />
          <h3 className="text-sm font-bold text-white">Recent Dangerous Email Threats</h3>
        </div>
        <Badge variant="danger">{threats.length} Flagged</Badge>
      </div>

      {threats.length === 0 ? (
        <div className="py-6 text-center text-xs text-slate-400 font-sans">
          No high-risk email threats detected in your inbox.
        </div>
      ) : (
        <div className="space-y-3">
          {threats.map((threat) => (
            <div
              key={threat.id}
              onClick={() => onSelectThreat(threat)}
              className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-rose-500/50 hover:bg-slate-900 transition-all duration-200 cursor-pointer flex items-center justify-between group"
            >
              <div className="space-y-1 min-w-0 pr-4">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-semibold text-white truncate">{threat.sender}</span>
                  {threat.analysis && (
                    <Badge variant="danger" className="text-[10px] uppercase font-mono">
                      {threat.analysis.threat_type} ({threat.analysis.risk_score})
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-slate-300 truncate">{threat.subject}</p>
                <p className="text-[10px] text-slate-500 font-mono">{formatDate(threat.date)}</p>
              </div>

              <div className="text-rose-400 group-hover:translate-x-1 transition-transform shrink-0">
                <ArrowRight className="w-4 h-4" />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
};
