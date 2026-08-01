import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { Shield, RefreshCw } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center space-y-4 text-slate-400">
        <div className="p-3 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400 glow-blue">
          <Shield className="w-10 h-10 animate-bounce" />
        </div>
        <div className="flex items-center space-x-2 text-sm font-mono">
          <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
          <span>Verifying MailShield Session & Google Identity...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    window.location.href = '/login';
    return null;
  }

  return <>{children}</>;
};
