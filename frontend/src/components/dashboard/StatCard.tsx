import React from 'react';
import { Card } from '../ui/Card';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  glow?: 'blue' | 'emerald' | 'rose' | 'amber' | 'none';
  trend?: 'up' | 'down' | 'neutral';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  glow = 'none',
}) => {
  return (
    <Card glow={glow} className="flex items-center justify-between p-6">
      <div className="space-y-1">
        <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">{title}</span>
        <div className="text-2xl md:text-3xl font-black text-white font-mono">{value}</div>
        {subtitle && <p className="text-xs text-slate-400 font-sans">{subtitle}</p>}
      </div>
      <div className="p-3 rounded-2xl bg-slate-900/80 border border-slate-800 text-blue-400 shrink-0">
        {icon}
      </div>
    </Card>
  );
};
