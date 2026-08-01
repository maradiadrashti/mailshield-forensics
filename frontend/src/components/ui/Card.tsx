import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  glow?: 'blue' | 'emerald' | 'rose' | 'none';
}

export const Card: React.FC<CardProps> = ({ children, className = '', glow = 'none' }) => {
  const glowStyles = {
    blue: 'glow-blue',
    emerald: 'glow-emerald',
    rose: 'glow-rose',
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
