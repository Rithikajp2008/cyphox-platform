"""
SIH26149 - Person 1 Secure Erasure API Application Entry Point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router

app = FastAPI(
    title="SIH26149 — Person 1: Secure Erasure Engine API",
    description=(
        "Standardized REST API for Secure Data Erasure, Sanitization, Multi-Pass Overwriting, "
        "Safety Validation, and Erasure Verification. Complies strictly with the SIH26149 Common Team Contract."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Enable CORS for cross-origin UI or integration client calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)
