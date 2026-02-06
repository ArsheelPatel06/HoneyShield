import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    API_KEY = os.getenv("API_KEY", None)

settings = Settings()
print(f"DEBUG: Loaded API_KEY: {settings.API_KEY}")
