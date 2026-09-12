export interface HealthCheckStatus {
  status: string;
  app_name: string;
  environment: string;
  timestamp: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatar_url?: string | null;
  google_id: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface AttachmentMeta {
  filename: string;
  mime_type: string;
  size: number;
}

export interface URLVectorScores {
  https_score: number;
  typosquatting_score: number;
  shortener_score: number;
  domain_length_score: number;
  special_chars_score: number;
  ip_address_score: number;
}

export interface URLSingleAnalysis {
  url: string;
  hostname: string;
  scheme: string;
  is_https: boolean;
  is_typosquatting: boolean;
  spoofed_brand?: string | null;
  is_shortened: boolean;
  is_excessive_length: boolean;
  has_special_chars: boolean;
  is_ip_address: boolean;
  has_executable: boolean;
  vector_scores: URLVectorScores;
  risk_score: number;
  reasons: string[];
  recommendations: string[];
}

export interface LayerBreakdown {
  score: number;
  max_score: number;
  status: 'safe' | 'suspicious' | 'elevated' | 'critical' | string;
  signals: string[];
  has_history?: boolean;
  history_count?: number;
  details?: Record<string, any>;
}

export interface ThreeLayerBreakdown {
  content_security: LayerBreakdown;
  transport_forensics: LayerBreakdown;
  behavioral_ai: LayerBreakdown;
}

export interface ThreatBreakdown {
  phishing_score?: number;
  scam_score?: number;
  url_score?: number;
  misinformation_score?: number;
  social_engineering_score?: number;
  layers?: ThreeLayerBreakdown;
  verdict?: string;
  severity?: string;
}

export interface SuspiciousSentence {
  sentence: string;
  risk: string;
}

export interface MisinformationDetail {
  credibility_score: number;
  confidence: number;
  suspicious_sentences: SuspiciousSentence[];
  evidence: string[];
}

export interface AnalysisResult {
  id: string;
  email_id: string;
  user_id: string;
  risk_score: number;
  confidence: number;
  threat_type: string;
  verdict?: string;
  severity?: 'safe' | 'low' | 'high' | 'critical' | string;
  is_trusted_sender: boolean;
  reasons: string[];
  recommendations: string[];
  breakdown: ThreatBreakdown;
  layers?: ThreeLayerBreakdown;
  misinformation_detail?: MisinformationDetail;
  analyzed_at: string;
}

export interface BatchAnalysisResponse {
  analyzed_count: number;
  high_risk_count: number;
  results: AnalysisResult[];
}

export interface EmailMessage {
  id: string;
  thread_id?: string | null;
  sender: string;
  recipient: string;
  subject: string;
  date: string;
  snippet?: string | null;
  body_text?: string | null;
  body_html?: string | null;
  links: string[];
  attachments: AttachmentMeta[];
  fetched_at: string;
  analysis?: AnalysisResult;
}

export interface PaginatedEmailResponse {
  items: EmailMessage[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface ThreatCategoriesBreakdown {
  phishing: number;
  scam: number;
  suspicious_url: number;
  misinformation: number;
  social_engineering: number;
}

export interface WeeklyDataPoint {
  day: string;
  total: number;
  threats: number;
}

export interface DashboardStats {
  inbox_security_score: number;
  total_emails: number;
  safe_emails: number;
  dangerous_emails: number;
  threat_detection_rate: number;
  threat_categories: ThreatCategoriesBreakdown;
  weekly_analytics: WeeklyDataPoint[];
  recent_threats: EmailMessage[];
  security_recommendations: string[];
}

export interface OCRAnalysisResponse {
  filename: string;
  extracted_text: string;
  extracted_urls: string[];
  risk_score: number;
  confidence: number;
  threat_type: string;
  reasons: string[];
  recommendations: string[];
  breakdown: ThreatBreakdown;
  scanned_at: string;
}

export interface EmailAuthenticationResult {
  spf: 'pass' | 'fail' | 'neutral' | 'unknown';
  dkim: 'pass' | 'fail' | 'neutral' | 'unknown';
  dmarc: 'pass' | 'fail' | 'neutral' | 'unknown';
  raw_auth_results?: string | null;
}

export interface NormalizedHeaders {
  from?: string | null;
  to?: string | null;
  reply_to?: string | null;
  return_path?: string | null;
  message_id?: string | null;
  subject?: string | null;
  date?: string | null;
}

export interface ReceivedHop {
  hop: number;
  raw: string;
  source_ip?: string | null;
  ip_classification?: 'public' | 'private' | 'loopback' | 'link-local' | 'reserved' | 'unspecified' | null;
  from_host?: string | null;
  by_host?: string | null;
  timestamp?: string | null;
  protocol?: string | null;
}

export interface NetworkIntelligence {
  ip?: string | null;
  country: string;
  city: string;
  isp: string;
  asn: string;
  vpn_proxy_tor: string;
  risk_indicator: string;
  latitude?: number | null;
  longitude?: number | null;
}

export interface RouteHop {
  hop: number;
  ip?: string | null;
  country: string;
  city: string;
  isp: string;
  asn: string;
  latitude?: number | null;
  longitude?: number | null;
}

export interface EvidenceIntegrity {
  evidence_id: string;
  evidence_sha256: string;
  captured_at: string;
  chain_of_custody_status: string;
  last_audit_event: string;
}

export interface ForensicHeaderResponse {
  email_id: string;
  headers: NormalizedHeaders;
  authentication: EmailAuthenticationResult;
  received_chain: ReceivedHop[];
  origin_ip_candidate?: string | null;
  network_intelligence?: NetworkIntelligence | null;
  route_hops: RouteHop[];
  evidence_integrity?: EvidenceIntegrity | null;
  analysis_status: string;
}

export interface Investigation {
  id: string;
  email_id: string;
  gmail_message_id?: string | null;
  sender: string;
  recipient: string;
  subject: string;
  date: string;
  snippet?: string | null;
  score: number;
  risk_score: number;
  verdict: string;
  threat_level: 'safe' | 'suspicious' | 'high' | 'critical' | string;
  severity: 'safe' | 'low' | 'high' | 'critical' | string;
  status: 'open' | 'in_progress' | 'closed' | string;
  report_generated: boolean;
  notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface InvestigationMetrics {
  total_investigations: number;
  dangerous_count: number;
  suspicious_count: number;
  reports_generated_count: number;
}

export interface InvestigationListResponse {
  metrics: InvestigationMetrics;
  investigations: Investigation[];
  total: number;
}

export interface OpenInvestigationRequest {
  email_id: string;
  notes?: string;
}


