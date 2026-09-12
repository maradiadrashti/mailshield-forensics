from typing import Optional
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.models.email import EmailMessage
from app.models.analysis_result import AnalysisResult
from app.models.investigation import Investigation
from app.schemas.forensics import (
    ForensicHeaderResponse,
    InvestigationItem,
    InvestigationListResponse,
    OpenInvestigationRequest,
)
from app.controllers.forensics_controller import ForensicsController
from app.services.report_service import ReportService
from app.services.investigation_service import InvestigationService

router = APIRouter(tags=["Email Header Forensics & Investigations"])


# ---------------------------------------------------------------------------
# Investigation Case Management Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/forensics/investigations",
    response_model=InvestigationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all persistent forensic investigations and metrics for the current user"
)
async def list_investigations(
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns authentic forensic cases belonging to the current user along with
    real database metrics (total, dangerous, suspicious, and reports generated).
    """
    return ForensicsController.list_investigations(
        db=db, user=current_user, status_filter=status_filter, search=search
    )


@router.post(
    "/forensics/investigations",
    response_model=InvestigationItem,
    status_code=status.HTTP_200_OK,
    summary="Open or retrieve a forensic investigation case for a real email message"
)
async def open_investigation(
    req: OpenInvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Creates a new persistent investigation or returns the existing case for an email.
    Guarantees duplicate prevention and triggers deterministic 3-layer threat analysis.
    """
    return ForensicsController.open_investigation(
        db=db, user=current_user, req=req
    )


@router.get(
    "/forensics/investigations/{investigation_id}",
    response_model=InvestigationItem,
    status_code=status.HTTP_200_OK,
    summary="Get single investigation case details by investigation ID or email ID"
)
async def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves detailed case information for a specific investigation with verified user ownership.
    """
    return ForensicsController.get_investigation_detail(
        db=db, user=current_user, investigation_id_or_email_id=investigation_id
    )


# ---------------------------------------------------------------------------
# Header Forensics Intelligence Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/forensics/emails/{email_id}/headers",
    response_model=ForensicHeaderResponse,
    status_code=status.HTTP_200_OK,
    summary="Get parsed forensic headers, Received hops, and origin IP candidate for an email"
)
async def get_email_forensic_headers(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Parses and normalizes email headers, authentication results (SPF, DKIM, DMARC),
    multi-hop Received chain, and extracts the earliest verified public origin IP.
    """
    return ForensicsController.get_email_forensic_headers(db, current_user, email_id)


@router.get(
    "/emails/{email_id}/forensics/headers",
    response_model=ForensicHeaderResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def get_email_forensic_headers_alias(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return ForensicsController.get_email_forensic_headers(db, current_user, email_id)


# ---------------------------------------------------------------------------
# PDF Report Generation Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/investigations/{email_id}/report",
    status_code=status.HTTP_200_OK,
    summary="Generate and download a PDF forensic investigation report"
)
async def get_forensic_report(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates a PDF incident report including executive summary, email authentication matrix,
    hop transport routing trail, and cryptographic Chain of Custody certificate.
    """
    # 1. Verify email exists and belongs to user (or resolve investigation ID)
    email = db.query(EmailMessage).filter(
        EmailMessage.id == email_id, EmailMessage.user_id == current_user.id
    ).first()

    if not email:
        inv = db.query(Investigation).filter(
            Investigation.id == email_id, Investigation.user_id == current_user.id
        ).first()
        if inv:
            email = db.query(EmailMessage).filter(
                EmailMessage.id == inv.email_id, EmailMessage.user_id == current_user.id
            ).first()

    if not email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email message with ID '{email_id}' was not found in your mailbox."
        )

    # 2. Get forensic header details
    forensic_data = ForensicsController.get_email_forensic_headers(db, current_user, email.id)

    # 3. Get AI analysis details
    analysis = db.query(AnalysisResult).filter(
        AnalysisResult.email_id == email.id,
        AnalysisResult.user_id == current_user.id
    ).first()

    # 4. Mark report generated on the investigation
    InvestigationService.mark_report_generated(db, current_user, email.id)

    # 5. Generate report PDF stream
    pdf_buffer = ReportService.generate_pdf_report(forensic_data, email, analysis)

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=MailShield_Forensic_Report_{email.id[:8]}.pdf"
        }
    )
