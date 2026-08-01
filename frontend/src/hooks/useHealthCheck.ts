import { useState, useEffect, useCallback } from 'react';
import { healthApi } from '../services/api';
import { HealthCheckStatus } from '../types';

export const useHealthCheck = () => {
  const [health, setHealth] = useState<HealthCheckStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const checkHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await healthApi.checkHealth();
      setHealth(data);
    } catch (err: any) {
      setError(err.message || 'Health check request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  return { health, loading, error, refetch: checkHealth };
};
