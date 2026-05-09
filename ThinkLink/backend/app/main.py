from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import analysis

app = FastAPI(
    title="ThinkLink Link Analysis API",
    description="Real-time link safety analysis for browser extension",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis.router, prefix="/api/v1", tags=["analysis"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "ThinkLink API"}
