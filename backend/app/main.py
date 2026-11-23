from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.api.routes.analysis import router as analysis_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables on startup when ENABLE_HISTORY is true
    init_db()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="PhishGuard AI - Autonomous Phishing Detection & Threat Intelligence Platform",
    version=settings.VERSION,
    lifespan=lifespan
)

# Cross-Origin Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root backwards-compatible health endpoints
@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION
    }


@app.get("/health")
def read_health():
    return {"status": "ok"}


# Mount API routes at /api (matching PRD contract)
app.include_router(analysis_router, prefix="/api")
