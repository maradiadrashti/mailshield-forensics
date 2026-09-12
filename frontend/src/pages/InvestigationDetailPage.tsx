import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  ArrowLeft,
  ArrowRight,
  FileText,
  Server,
  Globe,
  Radio,
  Network,
  Lock,
  Layers,
  KeyRound,
  FileSearch,
  X,
  MapPin,
  Cpu,
  Link2,
  Paperclip,
  Hash,
  RefreshCw,
  AlertTriangle,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { forensicsApi } from '../services/forensicsApi';
import { gmailApi } from '../services/gmailApi';
import { analysisApi } from '../services/analysisApi';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { ForensicHeaderResponse, EmailMessage, AnalysisResult } from '../types';
import { CircularThreatGauge } from '../components/analysis/CircularThreatGauge';

// Custom DIV icon generator for Green Map Markers
const createGreenMarkerIcon = (hopNum: number, isOrigin: boolean, isDestination: boolean) => {
  const label = isOrigin ? 'Origin' : isDestination ? 'Ingress MX' : `Relay H${hopNum}`;
  return L.divIcon({
    className: 'custom-gps-marker-green',
    html: `
      <div class="relative flex flex-col items-center justify-center -translate-y-2">
        ${isOrigin ? '<div class="absolute w-8 h-8 rounded-full bg-emerald-500/25 animate-ping"></div>' : ''}
        <div class="relative w-6 h-6 rounded-full bg-slate-950 border-2 border-emerald-400 flex items-center justify-center shadow-lg shadow-emerald-500/40">
          <span class="text-[10px] font-bold font-mono text-emerald-400 leading-none">H${hopNum}</span>
        </div>
        <div class="mt-0.5 px-1.5 py-0.2 rounded bg-slate-900/95 border border-emerald-500/40 text-[8px] font-mono text-emerald-300 whitespace-nowrap shadow">
          ${label}
        </div>
      </div>
    `,
    iconSize: [30, 38],
    iconAnchor: [15, 19],
  });
};

// Helper component to auto-zoom & fit bounds dynamically
const MapBoundsController: React.FC<{ hops: any[] }> = ({ hops }) => {
  const map = useMap();
  useEffect(() => {
    const validCoords = hops
      .filter((h) => h.latitude !== null && h.longitude !== null && h.latitude !== undefined && h.longitude !== undefined)
      .map((h) => [h.latitude!, h.longitude!] as [number, number]);

    if (validCoords.length === 1) {
      map.setView(validCoords[0], 4);
    } else if (validCoords.length > 1) {
      const bounds = L.latLngBounds(validCoords);
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
    }
  }, [hops, map]);
  return null;
};


interface InvestigationDetailPageProps {
  investigationId: string;
  onBack: () => void;
}

export const InvestigationDetailPage: React.FC<InvestigationDetailPageProps> = ({
  investigationId,
  onBack,
}) => {
  const [showReportModal, setShowReportModal] = useState(false);
  const [showRawAuth, setShowRawAuth] = useState(false);

  // Forensic header data state
  const [forensicData, setForensicData] = useState<ForensicHeaderResponse | null>(null);
  const [forensicLoading, setForensicLoading] = useState<boolean>(true);
  const [forensicError, setForensicError] = useState<string | null>(null);

  // Associated email & AI analysis state
  const [emailMeta, setEmailMeta] = useState<EmailMessage | null>(null);
  const [analysisMeta, setAnalysisMeta] = useState<AnalysisResult | null>(null);

  const fetchForensicData = useCallback(async () => {
    if (!investigationId) return;

    setForensicLoading(true);
    setForensicError(null);

    try {
      // 1. Fetch forensic header intelligence
      const headersPromise = forensicsApi.getForensicHeaders(investigationId);

      // 2. Concurrently attempt to load email and threat analysis metadata
      const emailPromise = gmailApi.getMessage(investigationId).catch(() => null);
      const analysisPromise = analysisApi.getAnalysis(investigationId).catch(() => null);

      const [headerRes, emailRes, analysisRes] = await Promise.all([
        headersPromise,
        emailPromise,
        analysisPromise,
      ]);

      setForensicData(headerRes);
      if (emailRes) setEmailMeta(emailRes);
      if (analysisRes) setAnalysisMeta(analysisRes);
    } catch (err: any) {
      console.error('Failed to fetch forensic header data:', err);
      const detail = err.response?.data?.detail || 'Unable to retrieve forensic header data from backend.';
      setForensicError(detail);
    } finally {
      setForensicLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchForensicData();
  }, [fetchForensicData]);

  const handleGenerateReport = async () => {
    try {
      const token = localStorage.getItem('mailshield_access_token');
      const response = await axios.get(
        `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'}/investigations/${investigationId}/report`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          },
          responseType: 'blob'
        }
      );
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `MailShield_Forensic_Report_${investigationId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (err) {
      console.error('Failed to download PDF report:', err);
      alert('Failed to generate forensic report. Please make sure backend is running.');
    }
  };

  // Helper for auth badge styling
  const renderAuthBadge = (status?: string | null) => {
    const norm = (status || 'unknown').toLowerCase();
    switch (norm) {
      case 'pass':
        return <Badge variant="success" className="font-mono text-[10px] uppercase font-bold">PASS</Badge>;
      case 'fail':
        return <Badge variant="danger" className="font-mono text-[10px] uppercase font-bold">FAIL</Badge>;
      case 'neutral':
        return <Badge variant="warning" className="font-mono text-[10px] uppercase font-bold">NEUTRAL</Badge>;
      default:
        return <Badge variant="neutral" className="font-mono text-[10px] uppercase font-bold">UNKNOWN</Badge>;
    }
  };

  // Helper for IP classification badge
  const renderIpBadge = (classification?: string | null) => {
    if (!classification) return null;
    const norm = classification.toLowerCase();
    const variant = norm === 'public' ? 'info' : norm === 'private' ? 'warning' : 'neutral';
    return (
      <Badge variant={variant} className="font-mono text-[9px] uppercase tracking-wider">
        {classification}
      </Badge>
    );
  };

  const routeHops = forensicData?.route_hops || [];
  const mapHops = routeHops.filter(
    (hop) => hop.latitude !== null && hop.longitude !== null && hop.latitude !== undefined && hop.longitude !== undefined
  );
  const polylineCoordinates = [...mapHops]
    .sort((a, b) => b.hop - a.hop)
    .map((hop) => [hop.latitude!, hop.longitude!] as [number, number]);

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Top Breadcrumb & Actions Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-6 rounded-2xl border border-slate-700/70">
        <div className="space-y-2 min-w-0">
          <button
            onClick={onBack}
            className="inline-flex items-center space-x-1.5 text-xs text-blue-400 hover:text-blue-300 font-mono transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Investigations</span>
          </button>
          <div className="flex items-center space-x-3 flex-wrap gap-y-1">
            <h2 className="text-xl md:text-2xl font-bold text-white font-mono truncate">
              Investigation <span className="text-blue-400">#{investigationId ? investigationId.slice(0, 16) : '—'}</span>
            </h2>
            <Badge
              variant={
                forensicLoading ? 'neutral' :
                forensicError ? 'danger' :
                forensicData?.analysis_status === 'complete' ? 'success' : 'info'
              }
              className="font-mono text-[10px] uppercase"
            >
              {forensicLoading
                ? 'LOADING FORENSICS...'
                : forensicError
                ? 'HEADER FETCH FAILED'
                : `STATUS: ${(forensicData?.analysis_status || 'COMPLETE').toUpperCase()}`}
            </Badge>
          </div>
        </div>

        <div>
          <Button
            size="md"
            variant="primary"
            onClick={handleGenerateReport}
            className="text-xs font-mono shadow-lg shadow-blue-600/20"
          >
            <FileText className="w-4 h-4 mr-2" />
            Generate Forensic Report
          </Button>
        </div>
      </div>

      {/* 1. Threat Assessment (Large Circular Threat Score Gauge & 3 Real Analysis Layers) */}
      <CircularThreatGauge
        score={analysisMeta ? analysisMeta.risk_score : 0}
        confidence={analysisMeta ? analysisMeta.confidence : 0.92}
        verdict={analysisMeta?.verdict || analysisMeta?.threat_type || (forensicLoading ? 'Analyzing...' : 'Safe')}
        severity={analysisMeta?.severity}
        layers={analysisMeta?.layers || analysisMeta?.breakdown?.layers}
        reasons={analysisMeta?.reasons || []}
        isLoading={forensicLoading && !analysisMeta}
      />


      {/* 2. Why Was This Email Flagged? (Explainable Threat Signals) */}
      <Card className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Why Was This Email Flagged?</h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Explainable Signals</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-1">
          {[
            {
              label: 'AI Analysis',
              icon: Cpu,
              value: analysisMeta ? `${analysisMeta.risk_score}/100 Risk` : '—',
            },
            {
              label: 'Authentication',
              icon: Lock,
              value: forensicData
                ? `SPF: ${forensicData.authentication.spf} | DKIM: ${forensicData.authentication.dkim}`
                : '—',
            },
            {
              label: 'URL Analysis',
              icon: Link2,
              value: emailMeta ? `${emailMeta.links.length} URLs` : '—',
            },
            {
              label: 'Header Anomalies',
              icon: FileSearch,
              value: forensicData
                ? `${forensicData.received_chain.length} Received Hops`
                : '—',
            },
            {
              label: 'Network Intelligence',
              icon: Network,
              value: forensicData?.origin_ip_candidate
                ? `IP: ${forensicData.origin_ip_candidate}`
                : '—',
            },
          ].map((cat, idx) => {
            const Icon = cat.icon;
            return (
              <div key={idx} className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                <div className="flex items-center space-x-2 text-slate-400">
                  <Icon className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-xs font-semibold text-slate-200">{cat.label}</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono truncate">{cat.value}</div>
              </div>
            );
          })}
        </div>

        {analysisMeta && analysisMeta.reasons && analysisMeta.reasons.length > 0 ? (
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
            <span className="text-xs font-bold text-slate-300 font-mono uppercase tracking-wider block">
              Observed Indicators:
            </span>
            <ul className="list-disc list-inside space-y-1 text-xs text-slate-300">
              {analysisMeta.reasons.map((reason, rIdx) => (
                <li key={rIdx}>{reason}</li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-800/80 text-center text-xs text-slate-400 font-sans">
            {/* TODO: backend integration required */}
            Detailed behavioral signal breakdown will appear here as additional modules are activated.
          </div>
        )}
      </Card>

      {/* 3. Main Grid: Email Auth & Header Forensics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Email Authentication */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <KeyRound className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Email Authentication</h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">RFC 7208 / 6376 / 7489</span>
          </div>

          {forensicLoading ? (
            <div className="py-8 text-center space-y-2">
              <RefreshCw className="w-5 h-5 text-blue-400 animate-spin mx-auto" />
              <p className="text-xs text-slate-400 font-mono">Loading authentication records...</p>
            </div>
          ) : (
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-300 font-medium">SPF (Sender Policy Framework)</span>
                {renderAuthBadge(forensicData?.authentication.spf)}
              </div>

              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-300 font-medium">DKIM (DomainKeys Identified Mail)</span>
                {renderAuthBadge(forensicData?.authentication.dkim)}
              </div>

              <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-300 font-medium">DMARC (Domain-based Auth)</span>
                {renderAuthBadge(forensicData?.authentication.dmarc)}
              </div>

              {forensicData?.authentication.raw_auth_results && (
                <div className="pt-2 border-t border-slate-800/80">
                  <button
                    onClick={() => setShowRawAuth(!showRawAuth)}
                    className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 font-mono transition-colors"
                  >
                    <span>Raw Authentication-Results</span>
                    {showRawAuth ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>

                  {showRawAuth && (
                    <pre className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/90 text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all leading-relaxed max-h-36 overflow-y-auto">
                      {forensicData.authentication.raw_auth_results}
                    </pre>
                  )}
                </div>
              )}
            </div>
          )}

          <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
            Authentication validation evaluates cryptographic signature integrity and SPF sender domain authorization.
          </p>
        </Card>

        {/* Header Forensics */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <FileSearch className="w-5 h-5 text-indigo-400" />
              <h3 className="text-sm font-bold text-white">Header Forensics</h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">Header Inspection</span>
          </div>

          {forensicLoading ? (
            <div className="py-8 text-center space-y-2">
              <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin mx-auto" />
              <p className="text-xs text-slate-400 font-mono">Loading forensic header analysis...</p>
            </div>
          ) : forensicError ? (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-center space-y-2">
              <AlertTriangle className="w-5 h-5 text-rose-400 mx-auto" />
              <p className="text-xs text-rose-300 font-sans">Unable to retrieve forensic header data.</p>
              <Button size="sm" variant="secondary" onClick={fetchForensicData} className="text-xs font-mono">
                <RefreshCw className="w-3.5 h-3.5 mr-1" /> Retry
              </Button>
            </div>
          ) : (
            <div className="space-y-2.5 font-mono text-xs">
              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">From:</span>
                <span className="text-slate-200 font-semibold truncate sm:text-right break-all">
                  {forensicData?.headers.from || emailMeta?.sender || '—'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">Reply-To:</span>
                <span className="text-slate-200 font-semibold truncate sm:text-right break-all">
                  {forensicData?.headers.reply_to || '—'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">Return-Path:</span>
                <span className="text-slate-200 font-semibold truncate sm:text-right break-all">
                  {forensicData?.headers.return_path || '—'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">Message-ID:</span>
                <span className="text-slate-300 text-[11px] truncate sm:text-right break-all">
                  {forensicData?.headers.message_id || '—'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">Subject:</span>
                <span className="text-slate-200 font-semibold truncate sm:text-right">
                  {forensicData?.headers.subject || emailMeta?.subject || '—'}
                </span>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">Date:</span>
                <span className="text-slate-300 text-[11px] truncate sm:text-right">
                  {forensicData?.headers.date || emailMeta?.date || '—'}
                </span>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* 4. Received Chain (Hop-by-hop MTA Breakdown) */}
      <Card className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Network className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-white">Received Chain Analysis</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {forensicData ? `${forensicData.received_chain.length} Hops Recorded` : 'Transport Trace'}
          </span>
        </div>

        {forensicLoading ? (
          <div className="py-8 text-center space-y-2">
            <RefreshCw className="w-5 h-5 text-indigo-400 animate-spin mx-auto" />
            <p className="text-xs text-slate-400 font-mono">Parsing transport Received headers...</p>
          </div>
        ) : !forensicData || forensicData.received_chain.length === 0 ? (
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-center text-xs text-slate-400 font-sans">
            No Received hops recorded in headers.
          </div>
        ) : (
          <div className="max-h-[360px] overflow-y-auto space-y-3 pr-1">
            {forensicData.received_chain.map((hop) => (
              <div
                key={hop.hop}
                className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 font-mono text-xs hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded bg-blue-600/20 text-blue-400 font-bold text-[10px]">
                      Hop {hop.hop}
                    </span>
                    {hop.source_ip && (
                      <span className="text-slate-200 font-bold text-xs">{hop.source_ip}</span>
                    )}
                  </div>
                  {renderIpBadge(hop.ip_classification)}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-400 pt-1">
                  <div>
                    <span className="text-slate-500">From: </span>
                    <span className="text-slate-300 break-all">{hop.from_host || '—'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">By: </span>
                    <span className="text-slate-300 break-all">{hop.by_host || '—'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Protocol: </span>
                    <span className="text-slate-300">{hop.protocol || '—'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Timestamp: </span>
                    <span className="text-slate-300">{hop.timestamp || '—'}</span>
                  </div>
                </div>

                {hop.raw && (
                  <div className="pt-1.5 border-t border-slate-800/60">
                    <p className="text-[10px] text-slate-500 break-all font-mono leading-relaxed line-clamp-2 hover:line-clamp-none transition-all">
                      {hop.raw}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 5. Network Intelligence & Mail Route Visualization */}
      <Card className="p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Network className="w-5 h-5 text-blue-400" />
            <h3 className="text-sm font-bold text-white">Network Intelligence</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">Autonomous System & IP Telemetry</span>
        </div>

        {/* Telemetry Data Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 font-mono text-xs">
          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">
              Origin IP Candidate
            </span>
            <div className="text-xs font-bold text-blue-400 truncate">
              {forensicData?.origin_ip_candidate || '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">Country</span>
            <div className="text-xs font-bold text-slate-300 truncate" title={forensicData?.network_intelligence?.country || '—'}>
              {forensicData?.network_intelligence?.country || '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">City</span>
            <div className="text-xs font-bold text-slate-300 truncate" title={forensicData?.network_intelligence?.city || '—'}>
              {forensicData?.network_intelligence?.city || '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">ISP / Org</span>
            <div className="text-xs font-bold text-slate-300 truncate" title={forensicData?.network_intelligence?.isp || '—'}>
              {forensicData?.network_intelligence?.isp || '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">ASN</span>
            <div className="text-xs font-bold text-slate-300 truncate" title={forensicData?.network_intelligence?.asn || '—'}>
              {forensicData?.network_intelligence?.asn || '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">VPN/Proxy/Tor</span>
            <div className="pt-0.5">
              {forensicData?.network_intelligence?.vpn_proxy_tor ? (
                (() => {
                  const val = forensicData.network_intelligence.vpn_proxy_tor;
                  const variant = val === 'VPN Detected' ? 'danger' : val === 'Hosting Provider' ? 'info' : val === 'No' ? 'success' : 'neutral';
                  return <Badge variant={variant} className="font-mono text-[9px] uppercase tracking-wider">{val}</Badge>;
                })()
              ) : '—'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block truncate">Risk Indicator</span>
            <div className="pt-0.5">
              {forensicData?.network_intelligence?.risk_indicator ? (
                (() => {
                  const val = forensicData.network_intelligence.risk_indicator;
                  const variant = val === 'High Risk' ? 'danger' : val === 'Medium Risk' ? 'warning' : val === 'Low Risk' || val === 'Safe (Local)' ? 'success' : 'neutral';
                  return <Badge variant={variant} className="font-mono text-[9px] uppercase tracking-wider">{val}</Badge>;
                })()
              ) : '—'}
            </div>
          </div>
        </div>

        {/* Mail Route / Hop Visualization Path */}
        <div className="p-4 rounded-2xl bg-slate-950/60 border border-slate-800/80 space-y-3">
          <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider text-left pl-2">Mail Transport Path Trace</h4>
          {(!forensicData || routeHops.length === 0) ? (
            <div className="p-6 text-center space-y-3">
              <div className="w-10 h-10 rounded-xl bg-blue-600/10 border border-blue-500/30 text-blue-400 flex items-center justify-center mx-auto">
                <Radio className="w-5 h-5 animate-pulse" />
              </div>
              <div className="space-y-1">
                <p className="text-xs text-slate-400 font-sans max-w-md mx-auto">
                  Network route visualization will appear after IP and Received-header analysis.
                </p>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2 p-3 overflow-x-auto select-none">
              {[...routeHops]
                .sort((a, b) => b.hop - a.hop) // chronological flow: origin first, destination last
                .map((hop, idx, arr) => (
                  <React.Fragment key={hop.hop}>
                    <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center space-x-2 text-xs font-mono">
                      <span className="w-4 h-4 rounded bg-blue-500/10 border border-blue-500/30 text-[9px] text-blue-400 flex items-center justify-center font-bold">
                        H{hop.hop}
                      </span>
                      <div className="flex flex-col text-left">
                        <span className="text-white font-bold text-[11px] truncate max-w-[120px]" title={hop.ip || 'Internal Gateway'}>
                          {hop.ip || 'Internal Gateway'}
                        </span>
                        <span className="text-[10px] text-slate-500 truncate max-w-[120px]" title={hop.city && hop.city !== 'Unknown' ? `${hop.city}, ${hop.country}` : hop.country || 'Local Network'}>
                          {hop.city && hop.city !== 'Unknown' ? `${hop.city}, ${hop.country}` : (hop.country && hop.country !== 'Unknown' ? hop.country : 'Local Network')}
                        </span>
                      </div>
                    </div>
                    {idx < arr.length - 1 && (
                      <ArrowRight className="w-4 h-4 text-slate-600 animate-pulse shrink-0" />
                    )}
                  </React.Fragment>
                ))}
            </div>
          )}
        </div>
      </Card>

      {/* 6. Geographic Mail Route (Geolocation Map) */}
      <Card className="p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Geographic Mail Route</h3>
            </div>
            <p className="text-xs text-slate-400">
              Origin and relay locations extracted from the email&rsquo;s Received headers.
            </p>
          </div>
          <Badge variant="info" className="font-mono text-[10px]">GEO FORENSICS</Badge>
        </div>

        {/* Leaflet Interactive Map Container */}
        <div className="relative rounded-2xl bg-slate-950 border border-slate-800/90 overflow-hidden h-[380px] w-full z-0">
          {mapHops.length === 0 ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-8 text-center z-10">
              <div className="w-12 h-12 rounded-2xl bg-cyan-600/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto shadow-inner mb-3">
                <MapPin className="w-6 h-6 text-slate-500" />
              </div>
              <h4 className="text-sm font-bold text-white">No Geographic Hops Extracted</h4>
              <p className="text-xs text-slate-400 max-w-md mt-1">
                Geographic coordinates could not be resolved for any IP addresses in the mail path.
              </p>
            </div>
          ) : (
            <MapContainer
              center={[0, 0]}
              zoom={2}
              scrollWheelZoom={true}
              className="w-full h-full"
              minZoom={2}
              maxBounds={[[-90, -180], [90, 180]]}
              maxBoundsViscosity={1.0}
            >
              <TileLayer
                attribution='Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ'
                url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
                noWrap={true}
              />
              <MapBoundsController hops={routeHops} />
              
              {/* Draw polylines connecting hops chronologically with emerald dotted line */}
              <Polyline
                positions={polylineCoordinates}
                color="#10b981"
                weight={3}
                opacity={0.9}
                dashArray="6, 8"
              />

              {/* Draw hop marker pins with all-green sleek design */}
              {mapHops.map((hop) => {
                const maxHopSeq = Math.max(...routeHops.map((h) => h.hop));
                const minHopSeq = Math.min(...routeHops.map((h) => h.hop));
                const isOrigin = hop.hop === maxHopSeq;
                const isDestination = hop.hop === minHopSeq;
                return (
                  <Marker
                    key={hop.hop}
                    position={[hop.latitude!, hop.longitude!]}
                    icon={createGreenMarkerIcon(hop.hop, isOrigin, isDestination)}
                  >
                    <Popup>
                      <div className="space-y-1.5 text-xs p-1">
                        <div className="font-mono text-emerald-400 font-bold border-b border-slate-800 pb-1 flex items-center justify-between">
                          <span>Hop {hop.hop}</span>
                          <span className="text-[10px] text-emerald-300 font-normal">
                            {isOrigin ? '(Origin MTA)' : isDestination ? '(Ingress MX)' : '(Intermediate Relay)'}
                          </span>
                        </div>
                        <div><span className="text-slate-400">IP Address:</span> <span className="font-mono text-white font-semibold">{hop.ip || '—'}</span></div>
                        <div><span className="text-slate-400">Location:</span> <span className="text-slate-200">{hop.city && hop.city !== 'Unknown' ? `${hop.city}, ${hop.country}` : hop.country}</span></div>
                        <div><span className="text-slate-400">ISP:</span> <span className="text-slate-200">{hop.isp}</span></div>
                        <div><span className="text-slate-400">ASN:</span> <span className="font-mono text-slate-200">{hop.asn}</span></div>
                      </div>
                    </Popup>
                  </Marker>
                );
              })}
            </MapContainer>
          )}
        </div>
      </Card>


      {/* 7. Indicators of Compromise (IOC) & Forensic Evidence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Indicators of Compromise */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Layers className="w-5 h-5 text-amber-400" />
              <h3 className="text-sm font-bold text-white">Indicators of Compromise</h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">IOC Inventory</span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            {[
              {
                label: 'IP Addresses',
                icon: Globe,
                count: forensicData ? (forensicData.origin_ip_candidate ? 1 : 0) : 0,
              },
              { label: 'Domains', icon: Server, count: 0 },
              { label: 'URLs', icon: Link2, count: emailMeta ? emailMeta.links.length : 0 },
              { label: 'Attachment Names', icon: Paperclip, count: emailMeta ? emailMeta.attachments.length : 0 },
              { label: 'File Hashes', icon: Hash, count: 0 },
            ].map((ioc, idx) => {
              const Icon = ioc.icon;
              return (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-1.5 text-slate-400">
                    <Icon className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-[11px] text-slate-300">{ioc.label}</span>
                  </div>
                  <span className="text-slate-400 font-bold">{ioc.count > 0 ? ioc.count : '—'}</span>
                </div>
              );
            })}
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-800/80 text-center text-xs text-slate-400 font-sans">
            {forensicData?.origin_ip_candidate || (emailMeta && emailMeta.links.length > 0)
              ? `Observed IOC items from headers and body metadata.`
              : 'No indicators of compromise recorded yet.'}
          </div>
        </Card>

        {/* Forensic Evidence Integrity */}
        <Card className="p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Evidence Integrity</h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">Chain of Custody</span>
          </div>

          <div className="space-y-2.5 font-mono text-xs">
            {[
              { label: 'Evidence ID', value: forensicData?.evidence_integrity?.evidence_id || '—' },
              { label: 'Evidence SHA-256', value: forensicData?.evidence_integrity?.evidence_sha256 || '—' },
              { label: 'Captured At', value: forensicData?.evidence_integrity?.captured_at || '—' },
              { label: 'Chain-of-Custody Status', value: forensicData?.evidence_integrity?.chain_of_custody_status || '—' },
              { label: 'Last Audit Event', value: forensicData?.evidence_integrity?.last_audit_event || '—' },
            ].map((item, idx) => (
              <div key={idx} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-slate-400 text-[11px] shrink-0">{item.label}:</span>
                <span className="text-slate-300 font-semibold truncate max-w-full sm:text-right font-mono text-[10px] break-all" title={item.value}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>

          <p className="text-[11px] text-slate-500 font-sans">
            Evidence cryptographic blocks are chained sequentially in a local tamper-evident SQLite blockchain.
          </p>
        </Card>
      </div>

      {/* Forensic Report Modal Notice */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-md rounded-2xl border border-slate-700/80 p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-cyan-400">
                <FileText className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Forensic Report Generator</h3>
              </div>
              <button
                onClick={() => setShowReportModal(false)}
                className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="py-2 space-y-2 text-center">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto mb-3">
                <FileText className="w-6 h-6 animate-pulse" />
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                Forensic report generation will be available after backend report generation is connected.
              </p>
              <p className="text-[11px] text-slate-500 font-mono">
                {/* TODO: backend integration required */}
                Status: Pending backend integration
              </p>
            </div>

            <Button
              variant="secondary"
              onClick={() => setShowReportModal(false)}
              className="w-full text-xs font-mono"
            >
              Close
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
