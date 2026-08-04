import React, { useState, useEffect } from 'react';
import { Shield, Lock, Cpu, Eye, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';

export const LoginPage: React.FC = () => {
  const { loginWithGoogle, handleAuthCallback, isAuthenticated } = useAuth();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const showDevDemo = import.meta.env.VITE_ENABLE_DEV_DEMO !== 'false';

  const handleDemoLogin = async () => {
    try {
      await handleAuthCallback("demo_google_auth_code");
      window.location.href = '/';
    } catch (err) {
      console.error('Demo login failed:', err);
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const err = params.get('error');
    if (err) {
      setErrorMsg(err);
    }
  }, []);

  if (isAuthenticated) {
    window.location.href = '/';
    return null;
  }

  return (
    <div className="min-h-screen bg-shield-bg text-slate-100 flex flex-col justify-center items-center px-4 relative overflow-hidden py-12">
      {/* Background Ambient Glow Effects */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-600/15 rounded-full blur-[140px] pointer-events-none"></div>
      <div className="absolute bottom-10 right-10 w-[350px] h-[350px] bg-cyan-600/10 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="max-w-md w-full space-y-8 relative z-10">
        {/* Brand Header */}
        <div className="text-center space-y-3">
          <div className="inline-flex p-4 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400 glow-blue mb-2">
            <Shield className="w-12 h-12 animate-pulse" />
          </div>
          <h1 className="text-3xl font-extrabold text-white tracking-tight flex items-center justify-center gap-2">
            MailShield <span className="text-blue-500 font-mono">AI</span>
          </h1>
          <p className="text-slate-400 text-sm">
            Production AI Email Security & Phishing Prevention Platform
          </p>
        </div>

        {/* Login Card */}
        <Card glow="blue" className="p-8 space-y-6">
          <div className="space-y-2 text-center">
            <Badge variant="info">OAUTH 2.0 SECURITY</Badge>
            <h2 className="text-xl font-bold text-white">Sign in to MailShield AI</h2>
            <p className="text-xs text-slate-400">
              Connect your Gmail account securely to scan inboxes for threats, scams, and misinformation.
            </p>
          </div>

          {errorMsg && (
            <div className="p-3.5 bg-red-950/40 border border-red-500/35 rounded-xl text-xs text-red-300 text-center animate-fade-in font-medium">
              {errorMsg}
            </div>
          )}

          <div className="space-y-4 pt-2">
            {/* Google OAuth Login Button */}
            <button
              onClick={loginWithGoogle}
              className="w-full flex items-center justify-center space-x-3 px-4 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm border border-blue-400/30 transition-all duration-200 shadow-xl focus:outline-none focus:ring-2 focus:ring-blue-400 group"
            >
              <svg className="w-5 h-5 shrink-0 bg-white rounded-full p-0.5" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>Sign in with Google Account</span>
              <ArrowRight className="w-4 h-4 text-blue-200 group-hover:translate-x-1 transition-transform duration-200" />
            </button>

            {/* Development Demo Login Button (hidden in production) */}
            {showDevDemo && (
              <>
                <div className="relative py-1 text-center text-xs text-slate-500">
                  <span className="bg-shield-card px-2 relative z-10 font-mono text-[10px] uppercase text-slate-500">Dev Testing Only</span>
                  <div className="absolute top-1/2 left-0 right-0 h-px bg-slate-800"></div>
                </div>

                <Button
                  variant="secondary"
                  size="md"
                  onClick={handleDemoLogin}
                  className="w-full text-xs font-mono py-2.5 text-blue-400 hover:text-blue-300 border border-blue-500/20"
                >
                  <Lock className="w-3.5 h-3.5 mr-2" />
                  Sign in as Demo Security Analyst
                </Button>
              </>
            )}
          </div>
        </Card>

        {/* Features Preview */}
        <div className="grid grid-cols-3 gap-3 text-center text-xs">
          <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800 space-y-1">
            <Lock className="w-4 h-4 text-blue-400 mx-auto" />
            <span className="text-slate-300 block font-medium">OAuth 2.0</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800 space-y-1">
            <Cpu className="w-4 h-4 text-emerald-400 mx-auto" />
            <span className="text-slate-300 block font-medium">AI Scoring</span>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-slate-800 space-y-1">
            <Eye className="w-4 h-4 text-cyan-400 mx-auto" />
            <span className="text-slate-300 block font-medium">Explainable AI</span>
          </div>
        </div>
      </div>
    </div>
  );

};
