"""
MALAI - Malware Analysis AI Agent
FastAPI web application for file upload and analysis.
"""

import shutil
import uuid
import zipfile
import zlib
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
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
    response = templates.TemplateResponse("index.html", {"request": request})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


async def _extract_zip(zip_path: Path, password: str = None) -> list[Path]:
    """Extract ZIP file contents, optionally with password.

    Returns list of extracted file paths. Handles plain, ZipCrypto-encrypted,
    and AES-encrypted (WinZip/7-Zip) ZIPs. Falls back to stdlib zipfile when
    pyzipper is unavailable.
    """
    extracted = []
    pwd = password.encode('utf-8') if password else None

    zf = _open_zip(zip_path)
    try:
        for info in zf.infolist():
            # Skip directories and macOS metadata
            if info.is_dir() or info.filename.startswith('__MACOSX'):
                continue
            # Skip files that are too large
            if info.file_size > MAX_FILE_SIZE_BYTES:
                continue
            try:
                data = zf.read(info.filename, pwd=pwd)
            except RuntimeError as e:
                msg = str(e).lower()
                # Encrypted but no password supplied
                if 'password' in msg or 'encrypted' in msg:
                    if not password:
                        raise HTTPException(
                            status_code=400,
                            detail="ZIP is password-protected. Provide the password.",
                        )
                    raise HTTPException(status_code=400, detail="Wrong ZIP password")
                # Unsupported compression (e.g. AES without pyzipper) or other issue
                if 'compression method' in msg or 'not supported' in msg or 'aes' in msg:
                    raise HTTPException(
                        status_code=400,
                        detail="ZIP uses an unsupported encryption/compression method.",
                    )
                # Other runtime error — skip this entry
                continue
            except (zipfile.BadZipFile, zlib.error, OSError):
                # Corrupt entry — skip
                continue
            # Save extracted file
            file_id = str(uuid.uuid4())[:8]
            safe_name = Path(info.filename).name.replace("/", "_").replace("\\", "_")
            if not safe_name:
                safe_name = f"{file_id}_entry"
            out_path = UPLOAD_DIR / f"{file_id}_{safe_name}"
            out_path.write_bytes(data)
            extracted.append(out_path)
    finally:
        zf.close()

    return extracted


def _open_zip(zip_path: Path):
    """Open a ZIP, preferring pyzipper (handles AES) and falling back to stdlib.

    Raises HTTPException(400) for a non-ZIP file.
    """
    try:
        # pyzipper is API-compatible with stdlib zipfile and adds AES support.
        from pyzipper import AESZipFile  # type: ignore
        return AESZipFile(zip_path, 'r')
    except ImportError:
        pass
    try:
        return zipfile.ZipFile(zip_path, 'r')
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...), zip_password: str = Form(None)):
    """Upload and analyze a file. For ZIPs, extracts and analyzes contents."""
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

    # Check if it's a ZIP file
    is_zip = zipfile.is_zipfile(save_path)

    try:
        if is_zip:
            # Extract and analyze each file inside
            extracted_paths = await _extract_zip(save_path, zip_password)
            if not extracted_paths:
                raise HTTPException(status_code=400, detail="ZIP file contains no analyzable files")

            results = []
            for ep in extracted_paths:
                try:
                    result = await engine.analyze_file(ep, ep.name)
                    results.append(result)
                except Exception as e:
                    results.append({"file_name": ep.name, "error": str(e)})
                finally:
                    try:
                        ep.unlink()
                    except Exception:
                        pass

            return JSONResponse(content={
                "file_name": file.filename,
                "is_zip": True,
                "file_count": len(results),
                "files": results,
            })
        else:
            # Analyze single file
            result = await engine.analyze_file(save_path, file.filename)
            return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")
    finally:
        try:
            save_path.unlink()
        except Exception:
            pass


@app.post("/api/report")
async def generate_report(file: UploadFile = File(...), zip_password: str = Form(None)):
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

    is_zip = zipfile.is_zipfile(save_path)

    try:
        if is_zip:
            extracted_paths = await _extract_zip(save_path, zip_password)
            if not extracted_paths:
                raise HTTPException(status_code=400, detail="ZIP file contains no analyzable files")

            all_results = []
            all_reports = []
            for ep in extracted_paths:
                try:
                    result = await engine.analyze_file(ep, ep.name)
                    report = await engine.ai_engine.generate_report(
                        result, result.get("ai_analysis", {})
                    )
                    all_results.append(result)
                    all_reports.append(report)
                except Exception as e:
                    all_results.append({"file_name": ep.name, "error": str(e)})
                    all_reports.append(f"Report generation failed for {ep.name}: {e}")
                finally:
                    try:
                        ep.unlink()
                    except Exception:
                        pass

            return JSONResponse(content={
                "file_name": file.filename,
                "is_zip": True,
                "file_count": len(all_results),
                "files": all_results,
                "reports": all_reports,
            })
        else:
            result = await engine.analyze_file(save_path, file.filename)
            report = await engine.ai_engine.generate_report(
                result, result.get("ai_analysis", {})
            )
            return JSONResponse(content={
                "analysis": result,
                "report": report,
            })
    except HTTPException:
        raise
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
