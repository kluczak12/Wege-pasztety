import asyncio
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from app.models.schemas import (
    BatchAnalysisRequest,
    BatchAnalysisResult,
    LinkAnalysisRequest,
    LinkAnalysisResult,
)
from app.services.analyzer import analyze_link

router = APIRouter()


@router.post("/analyze", response_model=BatchAnalysisResult)
async def analyze_links(request: BatchAnalysisRequest):
    if not request.links:
        raise HTTPException(status_code=400, detail="No links provided")

    if len(request.links) > 50:
        raise HTTPException(status_code=400, detail="Max 50 links per batch")

    tasks = [analyze_link(link) for link in request.links]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    processed = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed.append(
                LinkAnalysisResult(
                    url=request.links[i].url,
                    risk_level="unknown",
                    risk_score=0.0,
                    is_safe=False,
                    indicators=[],
                    ai_assessment=f"Analysis error: {str(result)}",
                )
            )
        else:
            processed.append(result)

    dangerous = sum(1 for r in processed if r.risk_level == "dangerous")
    suspicious = sum(1 for r in processed if r.risk_level == "suspicious")

    return BatchAnalysisResult(
        results=processed,
        analyzed_count=len(processed),
        dangerous_count=dangerous,
        suspicious_count=suspicious,
    )


@router.post("/analyze/single", response_model=LinkAnalysisResult)
async def analyze_single_link(request: LinkAnalysisRequest):
    return await analyze_link(request)


@router.get("/sandbox/video")
async def get_sandbox_video(url: str = Query(..., description="URL to simulate")):
    return JSONResponse(
        {
            "status": "ready",
            "url": url,
            "video_url": "https://example.com/sandbox/mock_recording.mp4",
            "thumbnail_url": "https://example.com/sandbox/mock_thumb.jpg",
            "duration_seconds": 12,
            "events_detected": [
                {"time": 1.2, "event": "Page load initiated"},
                {"time": 2.5, "event": "JavaScript executed — attempted cookie access"},
                {"time": 4.1, "event": "Redirect to third-party domain detected"},
                {"time": 6.8, "event": "Form field auto-fill attempted"},
                {"time": 9.3, "event": "Network request to known malware C&C server blocked"},
            ],
            "verdict": "DANGEROUS — multiple malicious behaviors detected in sandbox",
        }
    )
