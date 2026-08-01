from pydantic import BaseModel, Field


class URLVectorScores(BaseModel):
    https_score: int
    typosquatting_score: int
    shortener_score: int
    domain_length_score: int
    special_chars_score: int
    ip_address_score: int


class URLSingleAnalysisResponse(BaseModel):
    url: str
    hostname: str
    scheme: str
    is_https: bool
    is_typosquatting: bool
    spoofed_brand: str | None = None
    is_shortened: bool
    is_excessive_length: bool
    has_special_chars: bool
    is_ip_address: bool
    has_executable: bool
    vector_scores: URLVectorScores
    risk_score: int = Field(..., ge=0, le=100)
    reasons: list[str]
    recommendations: list[str]


class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL string to scan")
