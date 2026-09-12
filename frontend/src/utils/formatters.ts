export const formatDate = (dateString: string): string => {
  try {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(date);
  } catch {
    return dateString;
  }
};

export interface ThreatTier {
  label: 'Safe' | 'Suspicious' | 'Dangerous';
  variant: 'success' | 'warning' | 'danger';
}

/**
 * Buckets an email numeric risk score (0-100) into 3 client-side tiers:
 * - 0-30  -> "Safe" (green)
 * - 31-69 -> "Suspicious" (amber)
 * - 70-100 -> "Dangerous" (red)
 */
export const getThreatTier = (score: number = 0): ThreatTier => {
  const normalized = Math.max(0, Math.min(100, Math.round(score)));
  if (normalized <= 30) {
    return { label: 'Safe', variant: 'success' };
  }
  if (normalized < 70) {
    return { label: 'Suspicious', variant: 'warning' };
  }
  return { label: 'Dangerous', variant: 'danger' };
};

