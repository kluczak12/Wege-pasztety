import asyncio
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from app.models.schemas import (
    BatchAnalysisRequest,
    BatchAnalysisResult,
    LinkAnalysisRequest,
    LinkAnalysisResult,
    TextPhishingAnalysisResponse,
    TextPhishingRequest,
)
from app.services.analyzer import analyze_link, analyze_text_phishing, sandbox_simulation_for_url

router = APIRouter()


@router.post("/analyze", response_model=BatchAnalysisResult)
async def analyze_links(request: BatchAnalysisRequest):
    if not request.links:
        raise HTTPException(status_code=400, detail="Nie przekazano żadnych linków")

    if len(request.links) > 50:
        raise HTTPException(status_code=400, detail="Maksymalnie 50 linków na żądanie")

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
                    ai_assessment=f"Błąd analizy: {str(result)}",
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


@router.post("/analyze/text-phishing", response_model=TextPhishingAnalysisResponse)
async def analyze_text_phishing_endpoint(request: TextPhishingRequest):
    try:
        data = await analyze_text_phishing(request.text)
        return TextPhishingAnalysisResponse(**data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/sandbox/video")
async def get_sandbox_video(url: str = Query(..., description="URL do symulacji")):
    try:
        payload = await sandbox_simulation_for_url(url)
        return JSONResponse(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
