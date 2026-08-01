import React from 'react';

export const InboxSkeleton: React.FC = () => {
  return (
    <div className="space-y-4 animate-pulse">
      {[1, 2, 3, 4, 5].map((idx) => (
        <div
          key={idx}
          className="p-5 rounded-xl bg-slate-900/60 border border-slate-800/80 space-y-3"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-lg bg-slate-800"></div>
              <div className="space-y-1.5">
                <div className="w-32 h-3.5 bg-slate-800 rounded"></div>
                <div className="w-48 h-2.5 bg-slate-800/60 rounded"></div>
              </div>
            </div>
            <div className="w-20 h-3 bg-slate-800 rounded"></div>
          </div>
          <div className="w-3/4 h-4 bg-slate-800 rounded"></div>
          <div className="w-full h-3 bg-slate-800/40 rounded"></div>
        </div>
      ))}
    </div>
  );
};
