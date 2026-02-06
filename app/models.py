from pydantic import BaseModel, Field
from typing import Optional, List, Dict

class HoneypotRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    sender: Optional[str] = None
    language: Optional[str] = None

class ExtractedIntelligence(BaseModel):
    upi_ids: List[str] = []
    bank_accounts: List[str] = []
    phone_numbers: List[str] = []
    urls: List[str] = []

class SessionState(BaseModel):
    session_id: str
    turn: int
    stage: str

class HoneypotResponse(BaseModel):
    is_scam: bool
    scam_type: str
    confidence: float
    persona_used: str
    next_message: str
    extracted_intelligence: ExtractedIntelligence
    session_state: SessionState
