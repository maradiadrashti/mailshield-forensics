import React, { useEffect, useState, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, RefreshCw, AlertTriangle } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

export const AuthCallbackPage: React.FC = () => {
  const { handleAuthCallback } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const processedRef = useRef(false);

  useEffect(() => {
    if (processedRef.current) return;
    processedRef.current = true;

    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const oauthError = urlParams.get('error');

    if (oauthError) {
      if (oauthError === 'access_denied') {
        setError('Access Blocked by Google (Test User Required): Your account has not been added as a Test User in Google Cloud Console. Go to Google Cloud Console > OAuth Consent Screen > Test Users and add your Gmail address.');
      } else {
        setError(`Google OAuth Error: ${oauthError}`);
      }
      return;
    }

    if (!code) {
      setError('No authorization code was returned from Google OAuth callback.');
      return;
    }

    handleAuthCallback(code)
      .then(() => {
        window.location.href = '/';
      })
      .catch((err: any) => {
        console.error('Google OAuth callback handler failed:', err);
        setError(err.response?.data?.detail || err.message || 'Authentication code exchange failed.');
      });
  }, [handleAuthCallback]);


  return (
    <div className="min-h-screen bg-shield-bg flex items-center justify-center px-4">
      <Card glow={error ? 'rose' : 'blue'} className="max-w-md w-full p-8 text-center space-y-6">
        <div className="inline-flex p-4 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400">
          <Shield className={`w-10 h-10 ${error ? 'text-rose-500' : 'animate-bounce text-blue-400'}`} />
        </div>

        {error ? (
          <div className="space-y-4">
            <div className="flex items-center justify-center space-x-2 text-rose-400">
              <AlertTriangle className="w-5 h-5" />
              <h2 className="text-lg font-bold">Authentication Failed</h2>
            </div>
            <p className="text-xs text-rose-300/80 bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg">
              {error}
            </p>
            <Button variant="primary" onClick={() => (window.location.href = '/login')}>
              Return to Login
            </Button>
          </div>
        ) : (
          <div className="space-y-3">
            <h2 className="text-xl font-bold text-white">Authenticating with Google...</h2>
            <div className="flex items-center justify-center space-x-2 text-xs text-slate-400 font-mono">
              <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
              <span>Exchanging authorization code for MailShield JWT session...</span>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
};
