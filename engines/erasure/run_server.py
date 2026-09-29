"""
SIH26149 - Person 1 Secure Erasure API Server Runner
"""

import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("SIH26149 — PERSON 1: SECURE ERASURE ENGINE & REST API")
    print("=" * 70)
    print("Starting server at http://127.0.0.1:8765")
    print("Interactive Swagger Documentation: http://127.0.0.1:8765/docs")
    print("ReDoc Documentation: http://127.0.0.1:8765/redoc")
    print("=" * 70)
    uvicorn.run("api.main:app", host="127.0.0.1", port=8765, reload=True)
