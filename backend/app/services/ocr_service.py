from datetime import datetime, timezone
from fastapi import UploadFile, HTTPException, status
from app.ai.ocr_engine import OCREngine
from app.ai.scoring_engine import ScoringEngine
from app.schemas.ocr import OCRAnalysisResponse
from app.schemas.analysis import ThreatBreakdown


class OCRService:
    @classmethod
    async def process_image_upload(cls, file: UploadFile) -> OCRAnalysisResponse:
        if not file.content_type.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file must be a valid image format (.png, .jpg, .jpeg, .webp)"
            )

        image_bytes = await file.read()
        if not image_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded image file is empty"
            )

        # 1. OCR Character Recognition & URL Extraction
        extracted_text, extracted_urls = OCREngine.extract_text_from_image(image_bytes)

        # 2. Run AI Threat Pipeline (Phishing, Scam, URL, Misinformation)
        ai_data = ScoringEngine.analyze_email(
            sender="OCR Extracted Sender",
            recipient="User Inbox",
            subject="OCR Screenshot Threat Scan",
            body_text=extracted_text,
            links=extracted_urls,
            attachments=[]
        )

        return OCRAnalysisResponse(
            filename=file.filename or "screenshot.png",
            extracted_text=extracted_text,
            extracted_urls=extracted_urls,
            risk_score=ai_data["risk_score"],
            confidence=ai_data["confidence"],
            threat_type=ai_data["threat_type"],
            reasons=ai_data["reasons"],
            recommendations=ai_data["recommendations"],
            breakdown=ThreatBreakdown(**ai_data["breakdown"]),
            scanned_at=datetime.now(timezone.utc)
        )
