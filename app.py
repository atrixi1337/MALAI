"""
MALAI - Malware Analysis AI Agent
FastAPI web application for file upload and analysis.
"""

import shutil
import uuid
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config import UPLOAD_DIR, MAX_FILE_SIZE_BYTES
from agents.analyzer import AnalysisEngine

app = FastAPI(
    title="MALAI - Malware Analysis AI Agent",
    description="AI-powered malware analysis and forensic reporting",
    version="1.0.0",
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

# Initialize analysis engine
engine = AnalysisEngine()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main web interface."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Upload and analyze a file."""
    # Validate file size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE_BYTES // (1024*1024)}MB",
        )

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Save to upload directory
    file_id = str(uuid.uuid4())[:8]
    safe_name = file.filename.replace("/", "_").replace("\\", "_")
    save_path = UPLOAD_DIR / f"{file_id}_{safe_name}"

    try:
        save_path.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    # Run analysis
    try:
        result = await engine.analyze_file(save_path, file.filename)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    finally:
        # Clean up uploaded file
        try:
            save_path.unlink()
        except Exception:
            pass


@app.post("/api/report")
async def generate_report(file: UploadFile = File(...)):
    """Upload file and generate a full forensic report."""
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    file_id = str(uuid.uuid4())[:8]
    safe_name = file.filename.replace("/", "_").replace("\\", "_")
    save_path = UPLOAD_DIR / f"{file_id}_{safe_name}"

    try:
        save_path.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    try:
        result = await engine.analyze_file(save_path, file.filename)

        # Generate AI report
        report = await engine.ai_engine.generate_report(
            result, result.get("ai_analysis", {})
        )

        return JSONResponse(content={
            "analysis": result,
            "report": report,
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
    finally:
        try:
            save_path.unlink()
        except Exception:
            pass


@app.get("/api/health")
async def health_check():
    """Check API health and AI availability."""
    return {
        "status": "healthy",
        "ai_engine": "orcarouter",
        "yara_rules": len(engine.yara_analyzer.get_rules_info()),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
