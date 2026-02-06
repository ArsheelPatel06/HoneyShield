import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from app.config import settings

class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.limit = requests_per_minute
        self.window = 60  # seconds
        # Dictionary to store request timestamps: {ip: [timestamp1, timestamp2, ...]}
        self.requests = defaultdict(list)

    def check_rate_limit(self, request: Request):
        if not settings.RATE_LIMIT_ENABLED:
            return

        client_ip = request.client.host
        current_time = time.time()
        
        # Get history for this IP
        history = self.requests[client_ip]
        
        # Filter out requests older than the window
        valid_requests = [t for t in history if current_time - t < self.window]
        self.requests[client_ip] = valid_requests
        
        # Check limit
        if len(valid_requests) >= self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later."
            )
            
        # Add current request
        self.requests[client_ip].append(current_time)

# Global instance
limiter = RateLimiter(requests_per_minute=60)

async def check_rate_limit(request: Request):
    limiter.check_rate_limit(request)
