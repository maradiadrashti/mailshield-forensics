from fastapi import UploadFile
from app.schemas.ocr import OCRAnalysisResponse
from app.services.ocr_service import OCRService


class OCRController:
    @staticmethod
    async def scan_image(file: UploadFile) -> OCRAnalysisResponse:
        return await OCRService.process_image_upload(file)
