import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { User, TokenResponse } from '../types';
import { authApi } from '../services/authApi';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  loginWithGoogle: () => Promise<void>;
  handleAuthCallback: (code: string) => Promise<TokenResponse>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(
    localStorage.getItem('mailshield_access_token')
  );
  const [, setRefreshToken] = useState<string | null>(
    localStorage.getItem('mailshield_refresh_token')
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Validate session on app launch
  const checkAuthStatus = useCallback(async () => {
    const existingToken = localStorage.getItem('mailshield_access_token');
    const existingRefreshToken = localStorage.getItem('mailshield_refresh_token');

    if (!existingToken) {
      setIsLoading(false);
      return;
    }

    try {
      const userData = await authApi.getMe();
      setUser(userData);
      setToken(existingToken);
    } catch (error) {
      console.warn('Access token expired or invalid. Attempting refresh...', error);
      if (existingRefreshToken) {
        try {
          const tokenRes = await authApi.refreshToken(existingRefreshToken);
          saveSession(tokenRes);
        } catch (refreshErr) {
          console.error('Session refresh failed:', refreshErr);
          clearSession();
        }
      } else {
        clearSession();
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  const saveSession = (authData: TokenResponse) => {
    localStorage.setItem('mailshield_access_token', authData.access_token);
    localStorage.setItem('mailshield_refresh_token', authData.refresh_token);
    setToken(authData.access_token);
    setRefreshToken(authData.refresh_token);
    setUser(authData.user);
  };

  const clearSession = () => {
    localStorage.removeItem('mailshield_access_token');
    localStorage.removeItem('mailshield_refresh_token');
    setToken(null);
    setRefreshToken(null);
    setUser(null);
  };

  const loginWithGoogle = async () => {
    try {
      const { url } = await authApi.getGoogleLoginUrl();
      window.location.href = url;
    } catch (err: any) {
      console.error('Failed to retrieve Google OAuth authorization URL:', err);
      alert('Unable to connect to Google OAuth server. Please ensure backend server is running and check network settings.');
    }
  };

  const handleAuthCallback = async (code: string): Promise<TokenResponse> => {
    setIsLoading(true);
    try {
      const tokenRes = await authApi.handleGoogleCallback(code);
      saveSession(tokenRes);
      // Trigger automatic Gmail API synchronization right after successful authentication
      try {
        const { gmailApi } = await import('../services/gmailApi');
        await gmailApi.syncMessages(20);
      } catch (syncErr) {
        console.warn('Initial Gmail sync encountered warning:', syncErr);
      }
      return tokenRes;
    } finally {
      setIsLoading(false);
    }
  };


  const logout = async () => {
    try {
      await authApi.logout();
    } catch (err) {
      console.warn('Backend logout request failed or timed out:', err);
    } finally {
      clearSession();
      window.location.href = '/login';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        loginWithGoogle,
        handleAuthCallback,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
