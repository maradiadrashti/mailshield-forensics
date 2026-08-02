from fastapi import APIRouter
from app.routes.health import router as health_router
from app.routes.auth import router as auth_router
from app.routes.gmail import router as gmail_router
from app.routes.analysis import router as analysis_router
from app.routes.url_analysis import router as url_analysis_router
from app.routes.dashboard import router as dashboard_router
from app.routes.ocr import router as ocr_router
from app.routes.trusted_sender import router as trusted_sender_router

router = APIRouter()
router.include_router(health_router)
router.include_router(auth_router)
router.include_router(gmail_router)
router.include_router(analysis_router)
router.include_router(url_analysis_router)
router.include_router(dashboard_router)
router.include_router(ocr_router)
router.include_router(trusted_sender_router)
