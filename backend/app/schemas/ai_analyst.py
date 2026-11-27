from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AlertExplanationRequest(BaseModel):
    alert_id: int = Field(..., description="ID of the SecurityAlert to explain")
    include_raw_logs: bool = Field(True, description="Whether to include contributing raw logs in context")

class AlertExplanationResponse(BaseModel):
    alert_id: int
    alert_title: str
    severity: str
    rule_name: str
    what_happened: str
    why_suspicious: str
    potential_impact: str
    defensive_recommendations: List[str]
    mitre_attack_mapping: Optional[Dict[str, str]] = None
    disclaimer: str
    provider: str # "GEMINI_2_5_FLASH" or "GROUNDED_SOC_ENGINE"
    generated_at: datetime

class ChatMessage(BaseModel):
    role: str = Field(..., description="'user' or 'assistant'")
    content: str

class AnalystChatRequest(BaseModel):
    message: str = Field(..., description="User query to the AI Security Analyst")
    alert_id: Optional[int] = Field(None, description="Optional active alert ID for context")
    chat_history: Optional[List[ChatMessage]] = Field(default=[], description="Previous conversation turns")

class AnalystChatResponse(BaseModel):
    reply: str
    referenced_alert_id: Optional[int] = None
    provider: str
    suggested_followups: List[str] = []

class AIAnalystStatusResponse(BaseModel):
    gemini_configured: bool
    model: str
    capabilities: List[str]
