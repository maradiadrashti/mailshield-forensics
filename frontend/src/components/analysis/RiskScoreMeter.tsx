import React from 'react';

interface RiskScoreMeterProps {
  score: number; // 0 to 100
  size?: 'sm' | 'md' | 'lg';
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({ score, size = 'md' }) => {
  const getScoreTheme = (val: number) => {
    if (val >= 70) {
      return {
        color: 'text-rose-500',
        stroke: '#f43f5e',
        bg: 'bg-rose-500/10 border-rose-500/30',
        label: 'HIGH RISK',
      };
    }
    if (val >= 40) {
      return {
        color: 'text-amber-400',
        stroke: '#f59e0b',
        bg: 'bg-amber-500/10 border-amber-500/30',
        label: 'MODERATE THREAT',
      };
    }
    return {
      color: 'text-emerald-400',
      stroke: '#10b981',
      bg: 'bg-emerald-500/10 border-emerald-500/30',
      label: 'SAFE',
    };
  };

  const theme = getScoreTheme(score);

  if (size === 'sm') {
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded-md font-mono text-xs font-bold border ${theme.bg} ${theme.color}`}>
        {score} / 100
      </span>
    );
  }

  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative font-mono">
      <svg className="w-28 h-28 transform -rotate-90">
        {/* Background Circle */}
        <circle
          cx="56"
          cy="56"
          r={radius}
          stroke="#1e293b"
          strokeWidth="8"
          fill="transparent"
        />
        {/* Progress Arc */}
        <circle
          cx="56"
          cy="56"
          r={radius}
          stroke={theme.stroke}
          strokeWidth="8"
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`text-2xl font-black ${theme.color}`}>{score}</span>
        <span className="text-[9px] text-slate-400 tracking-wider uppercase font-semibold">Risk Score</span>
      </div>
    </div>
  );
};
