from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.logs import router as log_router
from app.api.anomalies import router as anomaly_router



app = FastAPI(
    title="AI Investigation Intelligence Layer",
    version="1.0.0"
)

# Enable CORS so the frontend (port 8080) can access the backend (port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(anomaly_router)

# Register API routes
app.include_router(log_router)

@app.get("/")
def home():
    return {
        "project": "AI Investigation Intelligence Layer",
        "status": "Running",
        "version": "1.0.0"
    }