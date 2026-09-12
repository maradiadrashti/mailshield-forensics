import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  glow?: 'blue' | 'emerald' | 'rose' | 'amber' | 'none';
}

export const Card: React.FC<CardProps> = ({ children, className = '', glow = 'none' }) => {
  const glowStyles = {
    blue: 'glow-blue',
    emerald: 'glow-emerald',
    rose: 'glow-rose',
    amber: 'glow-amber',
    none: '',
  };

  return (
    <div
      className={`glass-panel rounded-xl p-6 transition-all duration-300 ${glowStyles[glow]} ${className}`}
    >
      {children}
    </div>
  );
};
