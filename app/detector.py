import re

def detect_scam(message: str) -> dict:
    """
    Detects if a message is a scam and classifies it.
    Returns: {
        "is_scam": bool,
        "scam_type": str,
        "confidence": float,
        "signals": list[str]
    }
    """
    message_lower = message.lower()
    signals = []
    scores = {
        "phishing": 0,
        "otp_fraud": 0,
        "upi_refund": 0,
        "loan_scam": 0,
        "job_scam": 0,
        "impersonation": 0
    }
    
    # helper for checking keywords
    def check(keywords, type_key, points=1):
        for kw in keywords:
            if kw in message_lower:
                scores[type_key] += points
                signals.append(f"{type_key}:{kw}")
    
    # Phishing Rules
    # Link detection is a strong signal for phishing when combined with urgency
    has_link = "http" in message_lower or "www." in message_lower or ".com" in message_lower
    if has_link:
        scores["phishing"] += 0.5 
    
    check(["verify", "kyc", "login", "update", "expire", "suspend"], "phishing", 1)
    
    # OTP Fraud
    check(["otp", "code", "verification", "share code", "4 digit"], "otp_fraud", 1.5)
    
    # UPI Refund
    check(["refund", "cashback", "upi", "collect request", "scan", "qr code", "bhim", "gpay", "phonepe"], "upi_refund", 1.2)
    
    # Loan Scam
    check(["instant loan", "no cibil", "processing fee", "low interest", "approve", "disburse"], "loan_scam", 1.2)
    
    # Job Scam
    check(["job offer", "part time", "work from home", "registration fee", "telegram", "hr manager", "hiring"], "job_scam", 1.2)
    
    # Impersonation
    check(["police", "cbi", "customs", "bank officer", "manager", "arrest", "parcel"], "impersonation", 1.5)
    
    # Determine winner
    max_score = 0
    winner = "unknown"
    
    for st, score in scores.items():
        if score > max_score:
            max_score = score
            winner = st
            
    # Calculate confidence
    # Requirements:
    # < 0.3: Benign (Score < 1.0)
    # 0.4 - 0.7: Medium (Score 1.0 - 2.5)
    # > 0.9: High (Score >= 3.0, implying ~3 signals)
    
    if max_score < 0.5:
        # Basically nothing found or just a weak link
        confidence = 0.0
        is_scam = False
    elif max_score < 1.0:
        # Weak match
        confidence = 0.25 # < 0.3
        is_scam = False # Treat as not scam enough to trigger honeypot? 
        # Requirement says "If benign, confidence < 0.3". 
        # But if is_scam is False, persona is "none".
        # Let's say if score > 0.5 we flag as potential scam (is_scam=True) but low confidence?
        # User said "The honeypot agent must only generate bait messages when is_scam is true."
        # If confidence is 0.25, maybe we shouldn't bait.
        # Let's set is_scam=True only if confidence > 0.5?
        # Actually, let's stick to: is_scam = max_score > 0.8 (at least one strong keyword)
        is_scam = False
    else:
        is_scam = True
        # Linear mapping for medium range
        # 1.0 -> 0.4
        # 2.5 -> 0.7
        # 3.0 -> 0.9
        # 5.0 -> 0.99
        
        if max_score < 2.5:
            # Range 1.0 to 2.5 -> Map to 0.4 to 0.7
            # Slope = (0.7 - 0.4) / (2.5 - 1.0) = 0.3 / 1.5 = 0.2
            confidence = 0.4 + (max_score - 1.0) * 0.2
        elif max_score < 4.5:
            # Range 2.5 to 4.5 -> Map to 0.7 to 0.95
            confidence = 0.7 + (max_score - 2.5) * 0.125
        else:
            confidence = 0.99
            
    return {
        "is_scam": is_scam,
        "scam_type": winner if is_scam else "unknown",
        "confidence": round(confidence, 2),
        "signals": signals
    }
