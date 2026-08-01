import React from 'react';
import { ShieldOff, Home, ArrowLeft } from 'lucide-react';
import { Button } from '../components/ui/Button';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="glass-panel p-8 rounded-2xl border border-slate-800 max-w-md w-full text-center space-y-6 animate-in zoom-in-95 duration-200">
        <div className="w-16 h-16 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400 mx-auto flex items-center justify-center">
          <ShieldOff className="w-8 h-8" />
        </div>

        <div className="space-y-2">
          <span className="text-4xl font-black font-mono text-cyan-400">404</span>
          <h2 className="text-xl font-bold text-white tracking-tight">Security Route Not Found</h2>
          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            The requested MailShield security endpoint does not exist or has been relocated.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3 pt-2">
          <Button variant="primary" className="flex-1 font-mono text-xs" onClick={() => (window.location.href = '/')}>
            <Home className="w-4 h-4 mr-2" /> Go to Dashboard
          </Button>
          <Button variant="outline" className="flex-1 font-mono text-xs" onClick={() => window.history.back()}>
            <ArrowLeft className="w-4 h-4 mr-2" /> Go Back
          </Button>
        </div>
      </div>
    </div>
  );
};
