import React, { useState, useEffect } from 'react';
import { ShieldAlert, ExternalLink, Check, AlertTriangle, ShieldCheck, Lock, Link2, Globe } from 'lucide-react';
import { URLSingleAnalysis } from '../../types';
import { urlAnalysisApi } from '../../services/urlAnalysisApi';
import { Badge } from '../ui/Badge';

interface UrlAnalysisCardProps {
  url: string;
}

export const UrlAnalysisCard: React.FC<UrlAnalysisCardProps> = ({ url }) => {
  const [analysis, setAnalysis] = useState<URLSingleAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let isMounted = true;
    urlAnalysisApi
      .scanUrl(url)
      .then((res) => {
        if (isMounted) setAnalysis(res);
      })
      .catch((err) => {
        console.error('URL scan failed:', err);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [url]);

  if (loading) {
    return (
      <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 animate-pulse flex items-center justify-between text-xs text-slate-500">
        <div className="flex items-center space-x-2">
          <Globe className="w-4 h-4 text-blue-400" />
          <span className="truncate max-w-[200px]">{url}</span>
        </div>
        <span>Scanning 6 threat vectors...</span>
      </div>
    );
  }

  if (!analysis) return null;

  const isHighRisk = analysis.risk_score >= 60;

  return (
    <div
      className={`p-4 rounded-xl border transition-all duration-200 space-y-3 ${
        isHighRisk
          ? 'bg-rose-500/10 border-rose-500/30'
          : analysis.risk_score >= 30
          ? 'bg-amber-500/10 border-amber-500/30'
          : 'bg-slate-950/70 border-slate-800'
      }`}
    >
      {/* Top Header: URL & Risk Pill */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center space-x-2 min-w-0 font-mono text-xs">
          <Link2 className={`w-4 h-4 shrink-0 ${isHighRisk ? 'text-rose-400' : 'text-cyan-400'}`} />
          <a
            href={analysis.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-slate-200 hover:text-blue-400 truncate hover:underline flex items-center gap-1 font-semibold"
          >
            {analysis.url} <ExternalLink className="w-3 h-3 shrink-0 text-slate-500" />
          </a>
        </div>

        <Badge
          variant={isHighRisk ? 'danger' : analysis.risk_score >= 30 ? 'warning' : 'success'}
          className="font-mono text-[10px] font-bold shrink-0"
        >
          {analysis.risk_score} / 100 RISK
        </Badge>
      </div>

      {/* 6 Threat Vectors Badge Matrix */}
      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
        {/* Vector 1: HTTPS */}
        <Badge variant={analysis.is_https ? 'success' : 'danger'} className="flex items-center gap-1">
          <Lock className="w-3 h-3" />
          {analysis.is_https ? 'HTTPS Encrypted' : 'HTTP Unencrypted'}
        </Badge>

        {/* Vector 2: Typosquatting */}
        {analysis.is_typosquatting && (
          <Badge variant="danger" className="flex items-center gap-1 font-bold">
            <AlertTriangle className="w-3 h-3" />
            Spoofing {analysis.spoofed_brand || 'Brand'}
          </Badge>
        )}

        {/* Vector 3: Shortened URL */}
        {analysis.is_shortened && (
          <Badge variant="warning" className="flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" />
            URL Shortener
          </Badge>
        )}

        {/* Vector 4: Domain Length */}
        {analysis.is_excessive_length && (
          <Badge variant="warning" className="flex items-center gap-1">
            📏 Obfuscated Domain Length
          </Badge>
        )}

        {/* Vector 5: Special Characters / @ Trick */}
        {analysis.has_special_chars && (
          <Badge variant="danger" className="flex items-center gap-1 font-bold">
            ⚠️ Suspicious Special Chars (@/--)
          </Badge>
        )}

        {/* Vector 6: IP Address Hostname */}
        {analysis.is_ip_address && (
          <Badge variant="danger" className="flex items-center gap-1 font-bold">
            🌐 IP Address Hostname
          </Badge>
        )}

        {!analysis.is_typosquatting && !analysis.is_shortened && !analysis.is_ip_address && (
          <Badge variant="neutral" className="flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            Clean Domain Matrix
          </Badge>
        )}
      </div>

      {/* Specific Evidentiary Reasons & Recommendations */}
      {analysis.reasons.length > 0 && (
        <div className="pt-2 border-t border-slate-800/80 space-y-1.5 text-[11px] text-slate-300 font-sans">
          {analysis.reasons.map((reason, i) => (
            <p key={i} className="flex items-start gap-1.5 text-slate-300">
              <span className="text-rose-400 font-bold shrink-0">•</span>
              <span>{reason}</span>
            </p>
          ))}
          {analysis.recommendations.map((rec, i) => (
            <p key={i} className="flex items-start gap-1.5 text-emerald-400 font-medium">
              <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{rec}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
};
