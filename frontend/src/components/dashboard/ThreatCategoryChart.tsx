import React from 'react';
import { Card } from '../ui/Card';
import { ThreatCategoriesBreakdown } from '../../types';

interface ThreatCategoryChartProps {
  categories: ThreatCategoriesBreakdown;
}

export const ThreatCategoryChart: React.FC<ThreatCategoryChartProps> = ({ categories }) => {
  const items = [
    { label: 'Phishing', count: categories.phishing, color: 'bg-rose-500', textColor: 'text-rose-400' },
    { label: 'Scam & Fraud', count: categories.scam, color: 'bg-amber-500', textColor: 'text-amber-400' },
    { label: 'Suspicious URLs', count: categories.suspicious_url, color: 'bg-cyan-500', textColor: 'text-cyan-400' },
    { label: 'Misinformation', count: categories.misinformation, color: 'bg-emerald-500', textColor: 'text-emerald-400' },
    { label: 'Social Engineering', count: categories.social_engineering, color: 'bg-purple-500', textColor: 'text-purple-400' },
  ];

  const total = items.reduce((acc, curr) => acc + curr.count, 0) || 1;

  return (
    <Card className="p-6 space-y-5">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <h3 className="text-sm font-bold text-white">Threat Category Spectrum</h3>
        <span className="text-xs font-mono text-slate-400">{total} Threat Detections</span>
      </div>

      {/* Visual Spectrum Bar */}
      <div className="h-3 w-full bg-slate-900 rounded-full overflow-hidden flex">
        {items.map(
          (item, idx) =>
            item.count > 0 && (
              <div
                key={idx}
                className={`h-full ${item.color} transition-all duration-500`}
                style={{ width: `${(item.count / total) * 100}%` }}
                title={`${item.label}: ${item.count}`}
              ></div>
            )
        )}
      </div>

      {/* Detailed Category Bars */}
      <div className="space-y-3 font-mono text-xs">
        {items.map((item, idx) => {
          const percentage = Math.round((item.count / total) * 100);
          return (
            <div key={idx} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300">{item.label}</span>
                <span className={`font-bold ${item.textColor}`}>
                  {item.count} ({percentage}%)
                </span>
              </div>
              <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden">
                <div
                  className={`h-full ${item.color} rounded-full transition-all duration-500`}
                  style={{ width: `${percentage}%` }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
};
