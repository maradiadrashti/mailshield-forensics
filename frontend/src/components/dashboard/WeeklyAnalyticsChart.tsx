import React from 'react';
import { Card } from '../ui/Card';
import { WeeklyDataPoint } from '../../types';

interface WeeklyAnalyticsChartProps {
  data: WeeklyDataPoint[];
}

export const WeeklyAnalyticsChart: React.FC<WeeklyAnalyticsChartProps> = ({ data }) => {
  const maxTotal = Math.max(...data.map((d) => d.total), 1);

  return (
    <Card className="p-6 space-y-5">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <h3 className="text-sm font-bold text-white">Weekly Threat Analytics Trend</h3>
        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center gap-1 text-slate-400">
            <span className="w-2.5 h-2.5 rounded bg-blue-500"></span> Total Volume
          </span>
          <span className="flex items-center gap-1 text-rose-400">
            <span className="w-2.5 h-2.5 rounded bg-rose-500"></span> Threats
          </span>
        </div>
      </div>

      {/* Bar Chart Container */}
      <div className="h-44 flex items-end justify-between gap-2 pt-4 px-2 font-mono">
        {data.map((point, idx) => {
          const totalHeight = (point.total / maxTotal) * 100;
          const threatHeight = (point.threats / maxTotal) * 100;

          return (
            <div key={idx} className="flex-1 flex flex-col items-center gap-2 group">
              <div className="w-full max-w-[28px] h-32 bg-slate-900 rounded-t-lg relative flex items-end justify-center overflow-hidden">
                {/* Total Volume Bar */}
                <div
                  className="w-full bg-blue-600/30 group-hover:bg-blue-600/50 transition-all rounded-t duration-300"
                  style={{ height: `${totalHeight}%` }}
                ></div>
                {/* Threat Bar */}
                {point.threats > 0 && (
                  <div
                    className="w-full bg-rose-500/80 group-hover:bg-rose-500 transition-all absolute bottom-0 rounded-t duration-300"
                    style={{ height: `${threatHeight}%` }}
                  ></div>
                )}
              </div>
              <span className="text-[11px] text-slate-400 font-semibold group-hover:text-white transition-colors">
                {point.day}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
};
