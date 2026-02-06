from fastapi import Header, HTTPException, status
from app.config import settings

def verify_api_key(x_api_key: str | None = Header(None)):
    """
    Validates the x-api-key header.
    Returns True if valid.
    Raises 401 if missing.
    Raises 403 if invalid.
    """
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key"
        )
    
    if x_api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key"
        )
        
    return True
