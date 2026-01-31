from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
import shutil
import os
import uuid
import httpx
from datetime import datetime, timezone
from pathlib import Path

# Imports assuming we run from inside backend/ directory
try:
    from utils import secure_hash
    from crypto import sign_hash
    from qr_service import generate_qr, stamp_document
except ImportError:
    # Fallback for when running from root or if backend is a package
    from backend.utils import secure_hash
    from backend.crypto import sign_hash
    from backend.qr_service import generate_qr, stamp_document

app = FastAPI(title="Nagpur DPI Portal Document Verification")

# Create a temporary directory for file processing
TEMP_DIR = Path("temp_files")
TEMP_DIR.mkdir(exist_ok=True)

def cleanup_files(*files):
    for file in files:
        if isinstance(file, (str, Path)) and os.path.exists(file):
            try:
                os.remove(file)
            except Exception:
                pass

def process_background_tasks(input_path: Path, output_path: Path, doc_hash: str):
    """
    Handles background tasks: logging to audit trail and cleaning up temp files.
    """
    log_audit_event(doc_hash)
    cleanup_files(input_path, output_path)

def log_audit_event(doc_hash: str):
    """
    Logs the document hash to Supabase audit_logs table.
    """
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not supabase_url or not supabase_key:
        print("WARNING: Supabase credentials not found. Skipping audit log.")
        return

    try:
        url = f"{supabase_url}/rest/v1/audit_logs"
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }
        data = {
            "document_hash": doc_hash,
            "issuance_date": datetime.now(timezone.utc).isoformat()
        }

        # Using synchronous post as we are in a sync function
        response = httpx.post(url, headers=headers, json=data)
        if response.status_code >= 400:
            print(f"Error logging to Supabase: {response.text}")
    except Exception as e:
        print(f"Exception logging to Supabase: {e}")

@app.post("/issue/document")
def issue_document(file: UploadFile = File(...)):
    """
    Takes a file, runs the hash->sign->qr->stamp pipeline, and returns the 'stamped' PDF for download.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    file_id = str(uuid.uuid4())
    input_path = TEMP_DIR / f"{file_id}_original.pdf"
    output_path = TEMP_DIR / f"{file_id}_stamped.pdf"

    try:
        # Save the uploaded file
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 1. Calculate Hash
        doc_hash = secure_hash(input_path)

        # 2. Sign Hash
        signature = sign_hash(doc_hash)

        # 3. Generate QR Payload
        payload = {
            'hash': doc_hash,
            'sig': signature,
            'issuer': 'Nagpur_DPI_Portal'
        }

        # 4. Generate QR Image
        qr_img = generate_qr(payload)

        # 5. Stamp Document
        stamp_document(str(input_path), str(output_path), qr_img)

        return FileResponse(
            path=output_path,
            filename=f"stamped_{file.filename}",
            media_type='application/pdf',
            background=BackgroundTask(process_background_tasks, input_path, output_path, doc_hash)
        )

    except Exception as e:
        # Cleanup on error
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=500, detail=str(e))
