import os
import sys

# Ensure backend directory is in sys.path when running `python app/main.py` directly
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Fix UnicodeEncodeError for logging in Windows (e.g. Rupee symbol)
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.routes import router as api_routes
from app.middleware import setup_cors, LoggingMiddleware, RateLimitMiddleware
from app.core.security import SecurityHeadersMiddleware
import asyncio
from app.database.session import init_db
from app.services.gmail_sync_worker import periodic_gmail_sync_loop


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database tables
    try:
        init_db()
    except Exception as e:
        print(f"Warning: Database initialization error: {e}")

    # Start background Gmail sync worker (polls every 30 seconds)
    sync_worker_task = asyncio.create_task(periodic_gmail_sync_loop(interval_seconds=30))

    yield

    # Graceful shutdown
    sync_worker_task.cancel()
    try:
        await sync_worker_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="MailShield AI - Production-grade AI Cybersecurity Platform for Gmail Analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# Apply Security Headers & Middleware
app.add_middleware(SecurityHeadersMiddleware)
setup_cors(app)
app.add_middleware(LoggingMiddleware)
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException

app.add_middleware(RateLimitMiddleware, requests_per_minute=600)


@app.exception_handler(FastAPIHTTPException)
async def fastapi_http_exception_handler(request: Request, exc: FastAPIHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers
    )


@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"Global Exception caught: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected security system error occurred. Internal security logged."}
    )


# Mount API routes
app.include_router(api_routes, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
