from fastapi import APIRouter, Depends, UploadFile, File, status
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.ocr import OCRAnalysisResponse
from app.controllers.ocr_controller import OCRController

router = APIRouter(prefix="/ocr", tags=["OCR Screenshot Threat Scanner"])


@router.post(
    "/scan",
    response_model=OCRAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload image screenshot for OCR character recognition and AI threat scanning"
)
async def scan_screenshot(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    return await OCRController.scan_image(file)
