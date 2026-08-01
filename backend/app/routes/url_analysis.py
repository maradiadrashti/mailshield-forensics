from fastapi import APIRouter, Depends, status
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.url_analysis import URLScanRequest, URLSingleAnalysisResponse
from app.ai.url_analyzer import URLAnalyzer

router = APIRouter(prefix="/analysis/url", tags=["URL Threat Engine"])


@router.post(
    "/scan",
    response_model=URLSingleAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan an individual URL across 6 cybersecurity threat vectors"
)
async def scan_single_url(
    payload: URLScanRequest,
    current_user: User = Depends(get_current_user)
):
    report = URLAnalyzer.analyze_single_url(payload.url)
    return URLSingleAnalysisResponse.model_validate(report)
