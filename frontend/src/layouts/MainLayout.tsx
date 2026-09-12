import React from 'react';
import { Navbar } from '../components/layout/Navbar';

interface MainLayoutProps {
  children: React.ReactNode;
  currentTab?: 'dashboard' | 'inbox' | 'forensics' | 'trusted';
  onTabChange?: (tab: 'dashboard' | 'inbox' | 'forensics' | 'trusted') => void;
}

export const MainLayout: React.FC<MainLayoutProps> = ({ children, currentTab, onTabChange }) => {
  return (
    <div className="min-h-screen bg-shield-bg flex flex-col font-sans">
      <Navbar currentTab={currentTab} onTabChange={onTabChange} />
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        {children}
      </main>
      <footer className="border-t border-shield-border/60 py-6 text-center text-xs text-slate-500">
        <p>MailShield Forensics &copy; {new Date().getFullYear()} - AI-Powered Email Threat Detection & Forensic Intelligence</p>
      </footer>
    </div>
  );
};
