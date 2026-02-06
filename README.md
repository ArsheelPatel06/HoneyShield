# Honey-Pot API

Backend for the Agentic Honey-Pot Scam Detection & Intelligence Extraction system.

## Setup

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   uvicorn app.main:app --reload --port 8003
   ```

## Deployment (Docker)

### Build the Image
```bash
docker build -t honeypot-api .
```

### Run the Container
```bash
docker run -d -p 8000:8000 \
  -e API_KEY=your_secret_key \
  -e REDIS_URL=redis://host:port/0 \
  --name honeypot-container \
  honeypot-api
```
*Note: `REDIS_URL` is optional. If omitted, in-memory storage is used.*
