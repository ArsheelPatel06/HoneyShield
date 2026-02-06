from fastapi import FastAPI, Depends, Request, status
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.responses import JSONResponse
from app.auth import verify_api_key
from app.models import HoneypotRequest, HoneypotResponse, ExtractedIntelligence, SessionState

app = FastAPI(title="Honey-Pot API")

# Global Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "ValidationError", "message": "Invalid request parameters", "details": exc.errors()},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "HTTPException", "message": exc.detail, "details": None},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "InternalServerError", "message": "An unexpected error occurred", "details": str(exc)},
    )

@app.get("/health")
def health_check():
    return {"status": "ok"}

from app.extractor import extract_upi_ids, extract_urls, extract_phone_numbers, extract_bank_accounts

@app.post("/honeypot", response_model=HoneypotResponse, dependencies=[Depends(verify_api_key)])
def honeypot_entry(request: HoneypotRequest):
    # Validate body size
    if len(request.message) > 5000:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Message too long (max 5000 chars)")
        
    # Detect scam
    from app.detector import detect_scam
    detection_result = detect_scam(request.message)
    
    # Session Management
    from app.memory import get_or_create_session, save_session
    session_id, session_data = get_or_create_session(request.session_id)
    
    # Update logic
    current_turn = session_data.get("turn", 0) + 1
    
    # Update scam type if detected (priority to new detection, else keep old)
    # If detection is "unknown" but we had a previous type, keep previous?
    # Strategy: If we detect a specific scam now, overwrite. If unknown now, keep history.
    current_scam_type = detection_result["scam_type"]
    if current_scam_type == "unknown" and session_data.get("scam_type") != "unknown":
        current_scam_type = session_data.get("scam_type", "unknown")

    # Determine Stage
    stage = "hook"
    if current_turn == 1:
        stage = "hook"
    elif current_turn == 2:
        stage = "trust_building"
    elif 3 <= current_turn <= 5:
        stage = "extraction"
    else:
        stage = "exit"
        
    # Generate Response & Extraction
    if current_scam_type != "unknown":
        from app.agent import generate_response
        persona, next_msg = generate_response(
            current_scam_type, 
            stage, 
            session_id, 
            current_turn
        )
        extracted_data = ExtractedIntelligence(
            upi_ids=extract_upi_ids(request.message),
            bank_accounts=extract_bank_accounts(request.message),
            phone_numbers=extract_phone_numbers(request.message),
            urls=extract_urls(request.message)
        )
    else:
        persona = "none"
        next_msg = ""
        extracted_data = ExtractedIntelligence() # Defaults to empty lists

    # Save State
    new_state = {
        "turn": current_turn,
        "stage": stage,
        "scam_type": current_scam_type,
        "session_id": session_id
    }
    save_session(session_id, new_state)

    return HoneypotResponse(
        is_scam=(current_scam_type != "unknown"), # Return contextual is_scam
        scam_type=current_scam_type,
        confidence=detection_result["confidence"],
        persona_used=persona,
        next_message=next_msg,
        extracted_intelligence=extracted_data,
        session_state=SessionState(
            session_id=session_id,
            turn=current_turn,
            stage=stage
        )
    )
