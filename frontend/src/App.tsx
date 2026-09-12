import { useState, useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { AppProvider } from './context/AppContext';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { MainLayout } from './layouts/MainLayout';
import { DashboardPage } from './pages/DashboardPage';
import { InboxPage } from './pages/InboxPage';
import { ForensicsPage } from './pages/ForensicsPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { LoginPage } from './pages/LoginPage';
import { AuthCallbackPage } from './pages/AuthCallbackPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { TrustedSendersPage } from './pages/TrustedSendersPage';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { forensicsApi } from './services/forensicsApi';

export function App() {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'inbox' | 'forensics' | 'trusted'>('dashboard');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string | null>(null);

  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname;
      setCurrentPath(path);
      if (path.startsWith('/forensics/investigation/')) {
        const id = path.replace('/forensics/investigation/', '');
        setSelectedInvestigationId(id || null);
        setActiveTab('forensics');
      } else if (path === '/forensics') {
        setSelectedInvestigationId(null);
        setActiveTab('forensics');
      } else if (path === '/inbox') {
        setSelectedInvestigationId(null);
        setActiveTab('inbox');
      } else if (path === '/trusted') {
        setSelectedInvestigationId(null);
        setActiveTab('trusted');
      } else if (path === '/' || path === '/dashboard') {
        setSelectedInvestigationId(null);
        setActiveTab('dashboard');
      }
    };

    handlePopState();

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleTabChange = (tab: 'dashboard' | 'inbox' | 'forensics' | 'trusted') => {
    setActiveTab(tab);
    setSelectedInvestigationId(null);
    const newPath = tab === 'dashboard' ? '/' : `/${tab}`;
    window.history.pushState({}, '', newPath);
    setCurrentPath(newPath);
  };

  const handleOpenInvestigation = async (id: string) => {
    try {
      const inv = await forensicsApi.openInvestigation(id);
      const targetId = inv.id || id;
      setSelectedInvestigationId(targetId);
      setActiveTab('forensics');
      const newPath = `/forensics/investigation/${targetId}`;
      window.history.pushState({}, '', newPath);
      setCurrentPath(newPath);
    } catch (err) {
      console.error('Failed to register investigation case:', err);
      setSelectedInvestigationId(id);
      setActiveTab('forensics');
      const newPath = `/forensics/investigation/${id}`;
      window.history.pushState({}, '', newPath);
      setCurrentPath(newPath);
    }
  };

  const validPaths = ['/', '/login', '/auth/callback', '/dashboard', '/inbox', '/forensics', '/trusted'];
  const isKnownPath =
    validPaths.some((p) => currentPath === p || currentPath.startsWith('/auth/callback')) ||
    currentPath.startsWith('/forensics/investigation/');

  let content;
  if (!isKnownPath) {
    content = <NotFoundPage />;
  } else if (currentPath === '/login') {
    content = <LoginPage />;
  } else if (currentPath.startsWith('/auth/callback')) {
    content = <AuthCallbackPage />;
  } else {
    content = (
      <ProtectedRoute>
        <MainLayout currentTab={activeTab} onTabChange={handleTabChange}>
          {activeTab === 'dashboard' ? (
            <DashboardPage />
          ) : activeTab === 'inbox' ? (
            <InboxPage onOpenInvestigation={handleOpenInvestigation} />
          ) : activeTab === 'forensics' ? (
            selectedInvestigationId || currentPath.startsWith('/forensics/investigation/') ? (
              <InvestigationDetailPage
                investigationId={selectedInvestigationId || currentPath.split('/forensics/investigation/')[1] || ''}
                onBack={() => handleTabChange('forensics')}
              />
            ) : (
              <ForensicsPage
                onOpenInvestigation={handleOpenInvestigation}
                onGoToInbox={() => handleTabChange('inbox')}
              />
            )
          ) : (
            <TrustedSendersPage />
          )}
        </MainLayout>
      </ProtectedRoute>
    );
  }

  return (
    <ErrorBoundary>
      <AuthProvider>
        <AppProvider>
          {content}
        </AppProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
