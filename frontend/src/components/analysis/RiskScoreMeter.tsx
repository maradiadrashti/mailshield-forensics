import React from 'react';

interface RiskScoreMeterProps {
  score: number; // 0 to 100
  size?: 'xs' | 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({
  score,
  size = 'md',
  showLabel = true,
}) => {
  const boundedScore = Math.min(100, Math.max(0, Math.round(score)));

  // Standardized 4-tier color palette matching the 3-Layer engine:
  // 0–24: SAFE
  // 25–49: LOW / SUSPICIOUS
  // 50–74: HIGH
  // 75–100: CRITICAL
  const getScoreTheme = (val: number) => {
    if (val >= 75) {
      return {
        color: 'text-rose-400',
        stroke: '#f43f5e',
        bg: 'bg-rose-500/10 border-rose-500/30',
        glow: 'shadow-rose-500/20',
        label: 'CRITICAL',
      };
    }
    if (val >= 50) {
      return {
        color: 'text-orange-400',
        stroke: '#fb923c',
        bg: 'bg-orange-500/10 border-orange-500/30',
        glow: 'shadow-orange-500/20',
        label: 'HIGH',
      };
    }
    if (val >= 25) {
      return {
        color: 'text-amber-400',
        stroke: '#f59e0b',
        bg: 'bg-amber-500/10 border-amber-500/30',
        glow: 'shadow-amber-500/20',
        label: 'SUSPICIOUS',
      };
    }
    return {
      color: 'text-emerald-400',
      stroke: '#10b981',
      bg: 'bg-emerald-500/10 border-emerald-500/30',
      glow: 'shadow-emerald-500/20',
      label: 'SAFE',
    };
  };

  const theme = getScoreTheme(boundedScore);

  // Configuration per size
  if (size === 'xs' || size === 'sm') {
    const dim = size === 'xs' ? 32 : 42;
    const strokeWidth = size === 'xs' ? 3.5 : 4;
    const radius = (dim - strokeWidth) / 2;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (boundedScore / 100) * circumference;

    return (
      <div
        className="relative inline-flex items-center justify-center font-mono select-none group/gauge"
        title={`Threat Score: ${boundedScore}/100 (${theme.label})`}
      >
        <svg width={dim} height={dim} className="transform -rotate-90">
          {/* Background Ring Track */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated Progress Arc */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Numeric Score in Center */}
        <div className="absolute inset-0 flex items-center justify-center text-center">
          <span className={`${size === 'xs' ? 'text-[10px]' : 'text-xs'} font-black ${theme.color}`}>
            {boundedScore}
          </span>
        </div>
      </div>
    );
  }

  // Medium (e.g. for modals and cards)
  const dim = size === 'lg' ? 140 : 88;
  const strokeWidth = size === 'lg' ? 10 : 7;
  const radius = (dim - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (boundedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center relative font-mono select-none">
      <div className="relative flex items-center justify-center" style={{ width: dim, height: dim }}>
        <svg width={dim} height={dim} className="transform -rotate-90">
          {/* Background Ring */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated Progress Arc */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`${size === 'lg' ? 'text-3xl' : 'text-xl'} font-black ${theme.color}`}>
            {boundedScore}
          </span>
          {showLabel && (
            <span className="text-[8px] text-slate-400 tracking-wider uppercase font-semibold">
              / 100
            </span>
          )}
        </div>
      </div>

      {showLabel && (
        <span className={`mt-1.5 text-[9px] uppercase tracking-wider font-bold ${theme.color}`}>
          {theme.label}
        </span>
      )}
    </div>
  );
};
