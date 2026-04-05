import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time

from .config import BACKEND_HOST, BACKEND_PORT, ACTIVE_THREAT_PROVIDER
from .database import init_db
from .routers import url_router, file_router, history_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Zenith Threat Detection Engine",
    description="Enterprise-grade hybrid URL and file analysis API.",
    version="2.0.0",
    lifespan=lifespan
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start_time = time.time()
    response: Response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Critical system error occurred.", "code": "INTERNAL_ERROR"}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=[BACKEND_HOST, "localhost", "127.0.0.1"])



# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Returns the system status and active provider."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "provider": ACTIVE_THREAT_PROVIDER
    }

from fastapi import FastAPI, HTTPException, Request, Response, Security, Depends
from fastapi.security import APIKeyHeader
from .config import BACKEND_API_KEY, BACKEND_HOST, BACKEND_PORT, ACTIVE_THREAT_PROVIDER
import json
import logging
import sys
from datetime import datetime

# Structured SOC Logging Configuration
def setup_logging():
    logger = logging.getLogger("zenith")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s') # JSON format
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

# SOC-Ready JSON Logging Middleware
@app.middleware("http")
async def soc_logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "client_ip": request.client.host if request.client else "unknown",
        "duration_ms": round(duration * 1000, 2)
    }
    logger.info(json.dumps(log_entry))
    return response

# Security: Mandatory API Key Verification
API_KEY_NAME = "X-Zenith-Auth"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid Zenith Authentication Key")
    return api_key

# Update routers to require authentication
app.include_router(url_router.router, dependencies=[Depends(get_api_key)])
app.include_router(file_router.router, dependencies=[Depends(get_api_key)])
app.include_router(history_router.router, dependencies=[Depends(get_api_key)])

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=BACKEND_HOST, port=BACKEND_PORT, reload=True)
