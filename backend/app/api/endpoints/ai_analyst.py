from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.core.errors import SentinelException
from backend.app.schemas.ai_analyst import (
    AlertExplanationRequest,
    AlertExplanationResponse,
    AnalystChatRequest,
    AnalystChatResponse,
    AIAnalystStatusResponse
)
from backend.app.services.ai_analyst import (
    explain_alert_with_ai,
    chat_with_ai_analyst
)

router = APIRouter()

@router.get("/explain/{alert_id}", response_model=AlertExplanationResponse, summary="Explain Security Alert via GET")
def explain_alert_get(
    alert_id: int,
    include_raw_logs: bool = Query(True, description="Include contributing raw event logs"),
    db: Session = Depends(get_db)
):
    try:
        return explain_alert_with_ai(db, alert_id=alert_id, include_raw_logs=include_raw_logs)
    except ValueError as e:
        raise SentinelException(
            message=str(e),
            code="ALERT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )

@router.post("/explain", response_model=AlertExplanationResponse, summary="Explain Security Alert via POST")
def explain_alert_post(
    payload: AlertExplanationRequest,
    db: Session = Depends(get_db)
):
    try:
        return explain_alert_with_ai(db, alert_id=payload.alert_id, include_raw_logs=payload.include_raw_logs)
    except ValueError as e:
        raise SentinelException(
            message=str(e),
            code="ALERT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )

@router.post("/chat", response_model=AnalystChatResponse, summary="Chat with AI Security Analyst")
def chat_with_analyst_endpoint(
    payload: AnalystChatRequest,
    db: Session = Depends(get_db)
):
    if not payload.message.strip():
        raise SentinelException(
            message="Message content cannot be empty.",
            code="EMPTY_MESSAGE",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    return chat_with_ai_analyst(db, payload)

@router.get("/status", response_model=AIAnalystStatusResponse, summary="AI Analyst Integration Status")
def get_ai_analyst_status():
    has_gemini = bool(settings.GEMINI_API_KEY.strip())
    return AIAnalystStatusResponse(
        gemini_configured=has_gemini,
        model="gemini-2.5-flash" if has_gemini else "grounded-deterministic-engine",
        capabilities=[
            "Plain-language threat explanation",
            "What Happened / Why Suspicious / Potential Impact narrative generation",
            "Actionable tactical mitigation recommendations",
            "MITRE ATT&CK framework correlation",
            "Interactive follow-up security Q&A chat",
            "Strict evidence grounding without hallucination"
        ]
    )
