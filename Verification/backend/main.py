from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil
import uuid
import logging

from detector import analyze_image

app = FastAPI(title="CertiTrust Verification API")

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(level=logging.INFO)

@app.post("/verify-document")
async def verify_document(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are allowed")

    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # ---- STEP 1: QR CHECK ----
        qr_verified = True  # Always true for now

        # ---- STEP 2: AI CHECK ----
        logging.info(f"Analyzing file: {file_path}")
        ai_result = analyze_image(file_path)
        logging.info(f"AI Analysis Result: {ai_result}")

        # Calculate Trust Score as a percentage
        trust_score = round((ai_result["scores"]["human"]) * 100, 2) # ai result is actually anomaly score so we need to flip it
        return {
            "status": "verified",
            "qr_verified": qr_verified,
            "ai_check": {
                "ai_manipulation_likely": ai_result["ai_manipulation_likely"],
                "trust_score": trust_score,
            },
        }

    finally:
        # ---- Cleanup ----
        if os.path.exists(file_path):
            os.remove(file_path)