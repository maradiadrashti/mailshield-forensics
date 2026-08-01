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

export interface ThreatBreakdown {
  phishing_score: number;
  scam_score: number;
  url_score: number;
  misinformation_score: number;
  social_engineering_score: number;
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
  reasons: string[];
  recommendations: string[];
  breakdown: ThreatBreakdown;
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
