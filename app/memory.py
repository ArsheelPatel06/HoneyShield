import os
import json
import uuid
from typing import Dict, Any

# Optional Redis support
try:
    import redis
except ImportError:
    redis = None

class SessionManager:
    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self.redis_client = None
        self.local_storage = {}
        
        if self.redis_url and redis:
            try:
                self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
                print(f"Connected to Redis at {self.redis_url}")
            except Exception as e:
                print(f"Failed to connect to Redis: {e}. Using in-memory storage.")

    def get_session(self, session_id: str) -> Dict[str, Any]:
        if not session_id:
            # Should not happen if caller generates ID, but safe handling
            return {}
            
        if self.redis_client:
            data = self.redis_client.get(f"session:{session_id}")
            if data:
                return json.loads(data)
            return {}
        else:
            return self.local_storage.get(session_id, {})

    def update_session(self, session_id: str, data: Dict[str, Any]):
        if self.redis_client:
            self.redis_client.set(f"session:{session_id}", json.dumps(data), ex=3600*24) # 24h expiry
        else:
            self.local_storage[session_id] = data

session_manager = SessionManager()

def get_or_create_session(session_id: str | None) -> tuple[str, Dict[str, Any]]:
    """
    Returns (session_id, session_data).
    If session_id is None, generates a new one.
    If session exists, loads it.
    If new, initializes default state.
    """
    if not session_id:
        session_id = str(uuid.uuid4())
        session_data = {"turn": 0, "stage": "hook", "scam_type": "unknown"}
    else:
        session_data = session_manager.get_session(session_id)
        if not session_data:
            # Session ID provided but not found (expired/new)
            session_data = {"turn": 0, "stage": "hook", "scam_type": "unknown"}
            
    return session_id, session_data

def save_session(session_id: str, data: Dict[str, Any]):
    session_manager.update_session(session_id, data)
