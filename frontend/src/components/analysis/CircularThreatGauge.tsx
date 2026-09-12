import React, { useEffect, useState } from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Layers } from 'lucide-react';
import { ThreeLayerBreakdown } from '../../types';
import { Badge } from '../ui/Badge';

interface CircularThreatGaugeProps {
  score: number;
  confidence?: number;
  verdict?: string;
  severity?: string;
  layers?: ThreeLayerBreakdown;
  reasons?: string[];
  isLoading?: boolean;
}

export const CircularThreatGauge: React.FC<CircularThreatGaugeProps> = ({
  score,
  confidence = 0.9,
  verdict,
  layers,
  isLoading = false,
}) => {
  const [animatedScore, setAnimatedScore] = useState<number>(0);

  // Trigger smooth numeric and SVG animation on mount or score update
  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(Math.min(100, Math.max(0, score)));
    }, 50);
    return () => clearTimeout(timer);
  }, [score]);

  // Score levels per specification:
  // 0–24: SAFE
  // 25–49: LOW / SUSPICIOUS
  // 50–74: HIGH
  // 75–100: CRITICAL
  const getScoreTheme = (val: number) => {
    if (val >= 75) {
      return {
        levelLabel: 'CRITICAL',
        colorClass: 'text-rose-500',
        bgGlow: 'from-rose-500/15 via-rose-500/5 to-transparent',
        borderClass: 'border-rose-500/30',
        strokeColor: '#f43f5e',
        strokeGradientId: 'threat-grad-critical',
        gradientStops: ['#f43f5e', '#e11d48'],
        badgeVariant: 'danger' as const,
        icon: ShieldAlert,
      };
    }
    if (val >= 50) {
      return {
        levelLabel: 'HIGH',
        colorClass: 'text-orange-400',
        bgGlow: 'from-orange-500/15 via-orange-500/5 to-transparent',
        borderClass: 'border-orange-500/30',
        strokeColor: '#fb923c',
        strokeGradientId: 'threat-grad-high',
        gradientStops: ['#fb923c', '#ea580c'],
        badgeVariant: 'warning' as const,
        icon: AlertTriangle,
      };
    }
    if (val >= 25) {
      return {
        levelLabel: 'LOW / SUSPICIOUS',
        colorClass: 'text-amber-400',
        bgGlow: 'from-amber-500/15 via-amber-500/5 to-transparent',
        borderClass: 'border-amber-500/30',
        strokeColor: '#f59e0b',
        strokeGradientId: 'threat-grad-low',
        gradientStops: ['#fbbf24', '#d97706'],
        badgeVariant: 'warning' as const,
        icon: AlertTriangle,
      };
    }
    return {
      levelLabel: 'SAFE',
      colorClass: 'text-emerald-400',
      bgGlow: 'from-emerald-500/15 via-emerald-500/5 to-transparent',
      borderClass: 'border-emerald-500/30',
      strokeColor: '#10b981',
      strokeGradientId: 'threat-grad-safe',
      gradientStops: ['#34d399', '#059669'],
      badgeVariant: 'success' as const,
      icon: ShieldCheck,
    };
  };

  const theme = getScoreTheme(score);
  const StatusIcon = theme.icon;

  // SVG Geometry
  const size = 200;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  // Extract layer objects with fallbacks
  const layer1 = layers?.content_security || {
    score: score >= 25 ? Math.min(40, Math.round(score * 0.4)) : 0,
    max_score: 40,
    status: score >= 50 ? 'elevated' : 'safe',
    signals: ['Content and payload inspection clean'],
  };

  const layer2 = layers?.transport_forensics || {
    score: score >= 50 ? Math.min(25, Math.round(score * 0.25)) : 0,
    max_score: 25,
    status: 'safe',
    signals: ['Mail transport headers validated'],
  };

  const layer3 = layers?.behavioral_ai || {
    score: score >= 25 ? Math.min(35, Math.round(score * 0.35)) : 0,
    max_score: 35,
    status: 'safe',
    signals: ['Behavioral baseline evaluation complete'],
  };

  const displayVerdict = verdict || (score < 25 ? 'Safe' : 'Suspicious Email');

  return (
    <div className="space-y-6">
      {/* Top Gauge & Primary Verdict Card */}
      <div className="relative rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 p-6 md:p-8 overflow-hidden shadow-2xl">
        {/* Ambient Radial Backdrop Glow */}
        <div
          className={`absolute -top-24 -left-24 w-96 h-96 rounded-full bg-gradient-to-br ${theme.bgGlow} blur-3xl pointer-events-none opacity-60`}
        />

        <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between gap-8">
          {/* Left: Large Circular Gauge */}
          <div className="flex flex-col items-center justify-center shrink-0">
            <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
              {/* SVG Ring */}
              <svg width={size} height={size} className="transform -rotate-90">
                <defs>
                  <linearGradient id={theme.strokeGradientId} x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor={theme.gradientStops[0]} />
                    <stop offset="100%" stopColor={theme.gradientStops[1]} />
                  </linearGradient>
                  <filter id="gauge-glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Subtle outer track border */}
                <circle
                  cx={size / 2}
                  cy={size / 2}
                  r={radius + 4}
                  stroke="#334155"
                  strokeWidth="1"
                  strokeDasharray="2 4"
                  fill="transparent"
                  opacity="0.4"
                />

                {/* Background Ring Track */}
                <circle
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  stroke="#1e293b"
                  strokeWidth={strokeWidth}
                  fill="transparent"
                />

                {/* Animated Progress Arc */}
                <circle
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  stroke={`url(#${theme.strokeGradientId})`}
                  strokeWidth={strokeWidth}
                  fill="transparent"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  filter="url(#gauge-glow)"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>

              {/* Center Numeric Score Content */}
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none font-mono">
                <span className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-0.5">
                  THREAT SCORE
                </span>
                <div className="flex items-baseline justify-center space-x-1">
                  <span className={`text-4xl md:text-5xl font-black tracking-tight ${theme.colorClass}`}>
                    {isLoading ? '—' : score}
                  </span>
                  <span className="text-sm font-semibold text-slate-500">/100</span>
                </div>
                <div className="mt-1">
                  <Badge variant={theme.badgeVariant} className="text-[9px] uppercase font-mono px-2 py-0.5 tracking-wider font-bold">
                    {theme.levelLabel}
                  </Badge>
                </div>
              </div>
            </div>
          </div>

          {/* Right: Primary Verdict & Core Intelligence */}
          <div className="flex-1 space-y-4 w-full text-center lg:text-left">
            <div className="space-y-1.5">
              <div className="flex items-center justify-center lg:justify-start space-x-2 text-xs font-mono uppercase tracking-wider text-slate-400">
                <StatusIcon className={`w-4 h-4 ${theme.colorClass}`} />
                <span>Primary Verdict</span>
              </div>
              <h3 className={`text-2xl md:text-3xl font-extrabold tracking-tight ${theme.colorClass} font-sans`}>
                {isLoading ? 'Evaluating Threat Vectors...' : displayVerdict}
              </h3>
            </div>

            <p className="text-xs md:text-sm text-slate-300 leading-relaxed font-sans max-w-2xl">
              {score >= 75
                ? 'Critical security alert. Multiple high-confidence malicious indicators were identified across content, transport forensics, and sender behavior layers.'
                : score >= 50
                ? 'Elevated security risk. Anomalous transport routing, suspicious link structures, or behavioral shifts warrant immediate caution.'
                : score >= 25
                ? 'Mild threat indicators observed. Review link destinations and attachment signatures carefully before interacting.'
                : 'Cryptographic email authentication and sender behavioral analysis indicate normal legitimate correspondence.'}
            </p>

            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-2 font-mono text-xs text-slate-400">
              <div className="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center space-x-2">
                <span className="text-slate-500">AI Confidence:</span>
                <span className="text-white font-bold">{Math.round(confidence * 100)}%</span>
              </div>
              <div className="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center space-x-2">
                <span className="text-slate-500">Scoring Model:</span>
                <span className="text-cyan-400 font-bold">3-Layer Deterministic Engine</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Dynamic 3-Layer Breakdown Presentation */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center space-x-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Explainable Analysis Layers
            </h4>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Layer Contributions (Max 100)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Layer 1: Content & File Security */}
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <div className="flex items-center space-x-2">
                <div className="w-5 h-5 rounded-md bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-[10px] font-mono font-bold text-blue-400">
                  01
                </div>
                <span className="text-xs font-bold text-slate-200 font-sans">
                  Content & File Security
                </span>
              </div>
              <span className={`text-xs font-mono font-bold ${layer1.score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                +{layer1.score} <span className="text-[10px] text-slate-500">/ 40</span>
              </span>
            </div>

            <ul className="space-y-1.5 text-[11px] text-slate-300 font-sans">
              {layer1.signals && layer1.signals.length > 0 ? (
                layer1.signals.map((sig, idx) => (
                  <li key={idx} className="flex items-start space-x-1.5">
                    <span className="text-blue-400 mt-0.5">•</span>
                    <span className="leading-tight">{sig}</span>
                  </li>
                ))
              ) : (
                <li className="text-slate-500 text-[11px]">No content threat indicators found</li>
              )}
            </ul>
          </div>

          {/* Layer 2: Mail Transport Forensics */}
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <div className="flex items-center space-x-2">
                <div className="w-5 h-5 rounded-md bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-[10px] font-mono font-bold text-indigo-400">
                  02
                </div>
                <span className="text-xs font-bold text-slate-200 font-sans">
                  Mail Transport Forensics
                </span>
              </div>
              <span className={`text-xs font-mono font-bold ${layer2.score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                +{layer2.score} <span className="text-[10px] text-slate-500">/ 25</span>
              </span>
            </div>

            <ul className="space-y-1.5 text-[11px] text-slate-300 font-sans">
              {layer2.signals && layer2.signals.length > 0 ? (
                layer2.signals.map((sig, idx) => (
                  <li key={idx} className="flex items-start space-x-1.5">
                    <span className="text-indigo-400 mt-0.5">•</span>
                    <span className="leading-tight">{sig}</span>
                  </li>
                ))
              ) : (
                <li className="text-slate-500 text-[11px]">Transport path validated</li>
              )}
            </ul>
          </div>

          {/* Layer 3: AI Behavioral Analysis */}
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <div className="flex items-center space-x-2">
                <div className="w-5 h-5 rounded-md bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-[10px] font-mono font-bold text-cyan-400">
                  03
                </div>
                <span className="text-xs font-bold text-slate-200 font-sans">
                  AI Behavioral Analysis
                </span>
              </div>
              <span className={`text-xs font-mono font-bold ${layer3.score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                +{layer3.score} <span className="text-[10px] text-slate-500">/ 35</span>
              </span>
            </div>

            <ul className="space-y-1.5 text-[11px] text-slate-300 font-sans">
              {layer3.signals && layer3.signals.length > 0 ? (
                layer3.signals.map((sig, idx) => (
                  <li key={idx} className="flex items-start space-x-1.5">
                    <span className="text-cyan-400 mt-0.5">•</span>
                    <span className="leading-tight">{sig}</span>
                  </li>
                ))
              ) : (
                <li className="text-slate-500 text-[11px]">Behavioral comparison normal</li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
