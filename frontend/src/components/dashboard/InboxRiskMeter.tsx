import React from 'react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';

interface InboxRiskMeterProps {
  score: number; // 0 to 100
}

export const InboxRiskMeter: React.FC<InboxRiskMeterProps> = ({ score }) => {
  const getTheme = (val: number) => {
    if (val >= 80) {
      return { stroke: '#10b981', color: 'text-emerald-400', label: 'EXCELLENT', variant: 'success' as const };
    }
    if (val >= 50) {
      return { stroke: '#f59e0b', color: 'text-amber-400', label: 'MODERATE RISK', variant: 'warning' as const };
    }
    return { stroke: '#f43f5e', color: 'text-rose-500', label: 'HIGH RISK INBOX', variant: 'danger' as const };
  };

  const theme = getTheme(score);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <Card className="flex flex-col items-center justify-center text-center p-8 relative overflow-hidden">
      <div className="space-y-1 mb-4">
        <Badge variant={theme.variant} className="font-mono text-xs uppercase font-bold">
          {theme.label}
        </Badge>
        <h3 className="text-sm font-bold text-white">Inbox Security Health Rating</h3>
      </div>

      <div className="relative flex items-center justify-center my-2 font-mono">
        <svg className="w-36 h-36 transform -rotate-90">
          <circle cx="72" cy="72" r={radius} stroke="#1e293b" strokeWidth="10" fill="transparent" />
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke={theme.stroke}
            strokeWidth="10"
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-black ${theme.color}`}>{score}%</span>
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Security Score</span>
        </div>
      </div>

      <p className="text-xs text-slate-400 max-w-xs mt-2 leading-relaxed font-sans">
        Aggregated MailShield security rating evaluating phishing ratio, suspicious links, and unverified senders.
      </p>
    </Card>
  );
};
