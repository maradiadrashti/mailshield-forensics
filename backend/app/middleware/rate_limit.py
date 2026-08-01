import time
from collections import defaultdict
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory token bucket rate limiter protecting API endpoints against brute force & DoS.
    Enforces a maximum of 600 requests per minute per IP address.
    """
    def __init__(self, app, requests_per_minute: int = 600):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.client_requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Exclude static docs from rate limiting
        if request.url.path in ["/docs", "/redoc", "/openapi.json", "/"]:
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()

        # Clean timestamps older than 60 seconds
        request_times = self.client_requests[client_ip]
        self.client_requests[client_ip] = [t for t in request_times if now - t < 60]

        if len(self.client_requests[client_ip]) >= self.requests_per_minute:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Maximum 600 requests per minute allowed."},
                headers={"Retry-After": "60"}
            )

        self.client_requests[client_ip].append(now)
        return await call_next(request)
