import React, { useState, useRef, useEffect } from 'react';
import { Shield, LogOut, ChevronDown, CheckCircle2, LayoutDashboard, Mail, Scan } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../ui/Badge';

interface NavbarProps {
  currentTab?: 'dashboard' | 'inbox';
  onTabChange?: (tab: 'dashboard' | 'inbox') => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab = 'dashboard', onTabChange }) => {
  const { user, logout, isAuthenticated } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((part) => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <header className="border-b border-shield-border/60 bg-slate-950/85 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Identity & Main Tabs */}
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => onTabChange?.('dashboard')}>
            <div className="p-2 rounded-xl bg-blue-600/10 border border-blue-500/30 text-blue-400">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                MailShield <span className="text-blue-500 font-mono">AI</span>
              </h1>
            </div>
          </div>

          {isAuthenticated && (
            <nav className="hidden sm:flex items-center space-x-1 p-1 rounded-xl bg-slate-900 border border-slate-800 text-xs font-medium">
              <button
                onClick={() => onTabChange?.('dashboard')}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all ${
                  currentTab === 'dashboard'
                    ? 'bg-blue-600 text-white font-semibold shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </button>

              <button
                onClick={() => onTabChange?.('inbox')}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all ${
                  currentTab === 'inbox'
                    ? 'bg-blue-600 text-white font-semibold shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Mail className="w-3.5 h-3.5" />
                <span>Gmail Inbox</span>
              </button>
            </nav>
          )}
        </div>

        {/* Right Section / Profile Menu */}
        <div className="flex items-center space-x-4">
          <Badge variant="success" className="hidden md:flex items-center gap-1.5 py-1 px-3">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            SYSTEM ACTIVE
          </Badge>

          {isAuthenticated && user ? (
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="flex items-center space-x-3 p-1.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-blue-500/50 transition-all duration-200 focus:outline-none"
              >
                {user.avatar_url ? (
                  <img
                    src={user.avatar_url}
                    alt={user.name}
                    className="w-8 h-8 rounded-lg object-cover border border-blue-500/30"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-lg bg-blue-600/20 text-blue-400 font-mono font-bold text-xs flex items-center justify-center border border-blue-500/30">
                    {getInitials(user.name)}
                  </div>
                )}
                <div className="hidden md:block text-left text-xs">
                  <p className="font-semibold text-slate-100 leading-tight">{user.name}</p>
                  <p className="text-[10px] text-slate-400 truncate max-w-[120px]">{user.email}</p>
                </div>
                <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Dropdown Menu */}
              {dropdownOpen && (
                <div className="absolute right-0 mt-2 w-72 rounded-xl glass-panel border border-slate-700/80 shadow-2xl py-2 z-50 animate-in fade-in slide-in-from-top-2">
                  <div className="px-4 py-3 border-b border-slate-800 space-y-1">
                    <p className="text-sm font-semibold text-white truncate">{user.name}</p>
                    <p className="text-xs text-slate-400 truncate">{user.email}</p>
                    <div className="pt-1 flex items-center gap-1.5 text-[10px] text-emerald-400 font-mono">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      Connected via Google OAuth
                    </div>
                  </div>

                  <div className="px-4 py-2 border-b border-slate-800 text-[11px] text-slate-400 space-y-1 font-mono">
                    <div className="flex justify-between">
                      <span>Google ID:</span>
                      <span className="text-slate-200 truncate max-w-[120px]">{user.google_id}</span>
                    </div>
                  </div>

                  <div className="p-1">
                    <button
                      onClick={logout}
                      className="w-full flex items-center space-x-2 px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors duration-150"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => (window.location.href = '/login')}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-all duration-200 shadow-lg shadow-blue-600/30"
            >
              Sign In
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
