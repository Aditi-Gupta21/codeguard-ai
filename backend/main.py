from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scanner import scan_code

app = FastAPI(
    title="CodeGuard AI",
    description="AI-powered code analysis and security assistant",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="Source code to scan. Maximum 50,000 characters.",
    )


@app.get("/")
def home():
    return {"message": "CodeGuard AI backend is running!"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/scan")
def scan_endpoint(request: ScanRequest):
    try:
        findings = scan_code(request.code)
        return {
            "findings": findings,
            "total_findings": len(findings),
        }
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc