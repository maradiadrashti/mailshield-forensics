import { useState, useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { AppProvider } from './context/AppContext';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { MainLayout } from './layouts/MainLayout';
import { DashboardPage } from './pages/DashboardPage';
import { InboxPage } from './pages/InboxPage';
import { LoginPage } from './pages/LoginPage';
import { AuthCallbackPage } from './pages/AuthCallbackPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ProtectedRoute } from './components/auth/ProtectedRoute';

export function App() {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'inbox'>('dashboard');

  useEffect(() => {
    const handlePopState = () => setCurrentPath(window.location.pathname);
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const validPaths = ['/', '/login', '/auth/callback'];
  const isKnownPath = validPaths.some((p) => currentPath === p || currentPath.startsWith('/auth/callback'));

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
        <MainLayout currentTab={activeTab} onTabChange={setActiveTab}>
          {activeTab === 'dashboard' ? (
            <DashboardPage />
          ) : (
            <InboxPage />
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
