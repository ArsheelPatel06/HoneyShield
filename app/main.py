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

from fastapi import Body

# No change to imports above...

from app.limiter import check_rate_limit

@app.post("/honeypot", response_model=HoneypotResponse, dependencies=[Depends(verify_api_key), Depends(check_rate_limit)])
def honeypot_entry(request_data: dict = Body(default={})):
    # 1. Flexible Message Extraction
    # Keys to check in order of priority
    possible_keys = ["message", "text", "input", "query", "prompt"]
    message = ""
    
    for key in possible_keys:
        if key in request_data and isinstance(request_data[key], str):
            message = request_data[key]
            break
            
    # Session ID extraction (optional)
    session_id_in = request_data.get("session_id")
    
    # 2. Handle Empty/Missing Message -> Return Benign Response immediately
    # We must generate session state even for benign to keep contract valid
    from app.memory import get_or_create_session
    
    # If using existing session, we might want to increment turn?
    # Requirement: "return ... next_message="" ... explanation 'No message provided'"
    # If no message, we shouldn't really advance the scam state logic much, but we need valid objects.
    
    if not message.strip():
        # Get or create valid session ID
        real_session_id, _ = get_or_create_session(session_id_in)
        
        return HoneypotResponse(
            is_scam=False,
            scam_type="unknown",
            confidence=0.0,
            persona_used="none",
            next_message="",
            extracted_intelligence=ExtractedIntelligence(),
            session_state=SessionState(
                session_id=real_session_id,
                turn=0, # Or keep as is? Let's say 0 or 1.
                stage="hook"
            )
        )

    # 3. Validate body size (only if message exists)
    if len(message) > 5000:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Message too long (max 5000 chars)")
        
    # 4. Detect scam
    from app.detector import detect_scam
    detection_result = detect_scam(message)
    
    # 5. Session Management
    from app.memory import get_or_create_session, save_session
    session_id, session_data = get_or_create_session(session_id_in)
    
    # Update logic
    current_turn = session_data.get("turn", 0) + 1
    
    # Update scam type if detected
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
            upi_ids=extract_upi_ids(message),
            bank_accounts=extract_bank_accounts(message),
            phone_numbers=extract_phone_numbers(message),
            urls=extract_urls(message)
        )
    else:
        persona = "none"
        next_msg = ""
        extracted_data = ExtractedIntelligence()
        
    # Generate Explanation
    # If benign (is_scam=False), signals=[] summary="No scam indicators detected."
    # If scam, signals=detection_result["signals"], summary="Detected {scam_type} with confidence {confidence}"
    
    from app.models import Explanation
    if current_scam_type != "unknown":
        expl_summary = f"Detected {current_scam_type} pattern with {detection_result['confidence']} confidence."
        expl_signals = detection_result.get("signals", [])
    else:
        expl_summary = "No scam indicators detected."
        expl_signals = []
        
    explanation_obj = Explanation(signals=expl_signals, summary=expl_summary)

    # Save State
    new_state = {
        "turn": current_turn,
        "stage": stage,
        "scam_type": current_scam_type,
        "session_id": session_id
    }
    save_session(session_id, new_state)

    return HoneypotResponse(
        is_scam=(current_scam_type != "unknown"),
        scam_type=current_scam_type,
        confidence=detection_result["confidence"],
        persona_used=persona,
        next_message=next_msg,
        extracted_intelligence=extracted_data,
        session_state=SessionState(
            session_id=session_id,
            turn=current_turn,
            stage=stage
        ),
        explanation=explanation_obj
    )
