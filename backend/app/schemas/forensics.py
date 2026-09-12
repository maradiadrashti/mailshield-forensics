from typing import Optional, List, Literal
from pydantic import BaseModel, Field, ConfigDict


class EmailAuthenticationResult(BaseModel):
    spf: Literal["pass", "fail", "neutral", "unknown"] = Field(
        default="unknown", description="SPF verification result"
    )
    dkim: Literal["pass", "fail", "neutral", "unknown"] = Field(
        default="unknown", description="DKIM verification result"
    )
    dmarc: Literal["pass", "fail", "neutral", "unknown"] = Field(
        default="unknown", description="DMARC verification result"
    )
    raw_auth_results: Optional[str] = Field(
        default=None, description="Raw Authentication-Results header"
    )


class NormalizedHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: Optional[str] = Field(default=None, alias="from", description="From header")
    reply_to: Optional[str] = Field(default=None, description="Reply-To header")
    return_path: Optional[str] = Field(default=None, description="Return-Path header")
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    subject: Optional[str] = Field(default=None, description="Subject header")
    date: Optional[str] = Field(default=None, description="Date header")
    to: Optional[str] = Field(default=None, description="To / Recipient header")


class ReceivedHop(BaseModel):
    hop: int = Field(..., description="1-based hop sequence number in the header chain")
    raw: str = Field(..., description="Raw Received header line")
    source_ip: Optional[str] = Field(default=None, description="Extracted IPv4 or IPv6 address")
    ip_classification: Optional[str] = Field(
        default=None,
        description="Classification: public, private, loopback, link-local, reserved, unspecified",
    )
    from_host: Optional[str] = Field(default=None, description="Transmitting host/domain reported in 'from'")
    by_host: Optional[str] = Field(default=None, description="Receiving MTA server reported in 'by'")
    timestamp: Optional[str] = Field(default=None, description="Timestamp extracted from header if present")
    protocol: Optional[str] = Field(default=None, description="Transport protocol e.g. ESMTPS, SMTP, HTTP")


class NetworkIntelligence(BaseModel):
    ip: Optional[str] = Field(default=None, description="IP address analyzed")
    country: str = Field(default="Unknown", description="Resolved country")
    city: str = Field(default="Unknown", description="Resolved city")
    isp: str = Field(default="Unknown", description="Resolved ISP or Organization")
    asn: str = Field(default="Unknown", description="Resolved Autonomous System Number")
    vpn_proxy_tor: str = Field(default="No", description="Indicators of VPN/Proxy/Tor/Hosting usage")
    risk_indicator: str = Field(default="Low Risk", description="Evaluated IP risk level")
    latitude: Optional[float] = Field(default=None, description="Latitude coordinates")
    longitude: Optional[float] = Field(default=None, description="Longitude coordinates")


class RouteHop(BaseModel):
    hop: int = Field(..., description="MTA hop sequence number")
    ip: Optional[str] = Field(default=None, description="Transmitting hop IP address")
    country: str = Field(default="Unknown", description="Resolved country")
    city: str = Field(default="Unknown", description="Resolved city")
    isp: str = Field(default="Unknown", description="Resolved ISP")
    asn: str = Field(default="Unknown", description="Resolved ASN")
    latitude: Optional[float] = Field(default=None, description="Latitude coordinates")
    longitude: Optional[float] = Field(default=None, description="Longitude coordinates")


class EvidenceIntegrity(BaseModel):
    evidence_id: str = Field(..., description="Evidence ID generated from hash")
    evidence_sha256: str = Field(..., description="SHA-256 hash of the evidence payload")
    captured_at: str = Field(..., description="ISO timestamp when block was signed")
    chain_of_custody_status: str = Field(
        default="Cryptographically Sealed (SHA-256 Chain)", description="Cryptographic state label"
    )
    last_audit_event: str = Field(..., description="Last audited block descriptor")


class ForensicHeaderResponse(BaseModel):
    email_id: str = Field(..., description="Gmail message ID")
    headers: NormalizedHeaders = Field(..., description="Normalized key RFC headers")
    authentication: EmailAuthenticationResult = Field(
        ..., description="Extracted SPF, DKIM, and DMARC status"
    )
    received_chain: List[ReceivedHop] = Field(
        default_factory=list, description="Ordered list of parsed Received hops"
    )
    origin_ip_candidate: Optional[str] = Field(
        default=None,
        description="Earliest verified public IP in the Received hop chain for GeoLocation",
    )
    network_intelligence: Optional[NetworkIntelligence] = Field(
        default=None, description="Network intelligence telemetry details for origin IP"
    )
    route_hops: List[RouteHop] = Field(
        default_factory=list, description="Geo-routing hops trace derived from Received headers"
    )
    evidence_integrity: Optional[EvidenceIntegrity] = Field(
        default=None, description="Evidence integrity and chain of custody audit metrics"
    )
    analysis_status: str = Field(
        default="complete", description="Header parsing status: complete, partial, or missing_headers"
    )


class InvestigationItem(BaseModel):
    id: str = Field(..., description="Investigation UUID")
    email_id: str = Field(..., description="Associated Gmail / EmailMessage ID")
    gmail_message_id: Optional[str] = Field(default=None, description="Gmail message ID")
    sender: str = Field(..., description="Sender email address")
    recipient: str = Field(..., description="Recipient email address")
    subject: str = Field(..., description="Email subject")
    date: str = Field(..., description="Email date in ISO format")
    snippet: Optional[str] = Field(default=None, description="Short snippet of email text")
    score: int = Field(..., description="Authoritative 3-layer threat score (0-100)")
    risk_score: int = Field(..., description="Alias for score")
    verdict: str = Field(..., description="Evidence-based primary threat verdict")
    threat_level: str = Field(..., description="Severity string (safe, low, elevated, high, critical)")
    severity: str = Field(..., description="Severity string (safe, low, high, critical)")
    status: str = Field(default="open", description="Investigation status: open, in_progress, closed")
    report_generated: bool = Field(default=False, description="Whether a PDF report has been generated")
    notes: Optional[str] = Field(default=None, description="Investigator notes")
    created_at: str = Field(..., description="Creation timestamp in ISO format")
    updated_at: str = Field(..., description="Last update timestamp in ISO format")


class InvestigationMetrics(BaseModel):
    total_investigations: int = Field(..., description="Total active forensic cases for user")
    dangerous_count: int = Field(..., description="Confirmed dangerous / critical threats")
    suspicious_count: int = Field(..., description="Suspicious / elevated risk cases")
    reports_generated_count: int = Field(..., description="Exported audit reports generated")


class InvestigationListResponse(BaseModel):
    metrics: InvestigationMetrics
    investigations: List[InvestigationItem]
    total: int


class OpenInvestigationRequest(BaseModel):
    email_id: str = Field(..., description="Email ID to open or retrieve an investigation for")
    notes: Optional[str] = Field(default=None, description="Optional investigator notes")


