"""
QR Code Service for CertiTrust
==============================
Generates and stamps QR codes following W3C Verifiable Credentials standards.

Features:
- W3C VC compliant QR payload format
- High-speed PDF stamping with PyMuPDF
- Memory-efficient processing
- Configurable QR placement
"""

import qrcode
import json
import fitz  # PyMuPDF
from PIL import Image
import io
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class QRPosition(Enum):
    """QR code placement positions."""
    TOP_LEFT = "top_left"
    TOP_RIGHT = "top_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_RIGHT = "bottom_right"
    CENTER = "center"


@dataclass
class QRConfig:
    """Configuration for QR code generation and placement."""
    size: int = 100  # QR code size in PDF points
    margin: int = 36  # Margin from page edge (36pt = 0.5 inch)
    position: QRPosition = QRPosition.TOP_RIGHT
    # Level H provides 30% error correction - essential for printed documents
    # that may be folded, smudged, or partially damaged
    error_correction: int = qrcode.constants.ERROR_CORRECT_H
    box_size: int = 10
    border: int = 4
    fill_color: str = "black"
    back_color: str = "white"


def generate_qr(data: Dict[str, Any], config: Optional[QRConfig] = None) -> Image.Image:
    """
    Generates a QR code image from a dictionary payload.
    
    Args:
        data: Dictionary to encode in QR code
        config: Optional QR configuration
        
    Returns:
        PIL Image of the QR code
    """
    if config is None:
        config = QRConfig()
    
    json_payload = json.dumps(data, separators=(',', ':'))  # Compact JSON
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=config.error_correction,
        box_size=config.box_size,
        border=config.border,
    )
    qr.add_data(json_payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color=config.fill_color, back_color=config.back_color)
    return img


def generate_w3c_qr_payload(
    document_id: str,
    document_hash: str,
    issuer_id: str,
    signature: str,
    issuer_name: Optional[str] = None,
    merkle_root: Optional[str] = None,
    credential_type: str = "VerifiableCredential"
) -> Dict[str, Any]:
    """
    Generates a W3C Verifiable Credentials compliant QR payload.
    
    The payload follows the VC Data Model 2.0 specification for
    embedded proofs.
    
    Args:
        document_id: Unique document identifier
        document_hash: SHA-256 hash of the document
        issuer_id: Institution identifier
        signature: Ed25519 signature (base64)
        issuer_name: Optional issuer display name
        merkle_root: Optional Merkle root for multi-page docs
        credential_type: Type of credential
        
    Returns:
        W3C VC compliant payload dictionary
    """
    payload = {
        "@context": "https://www.w3.org/ns/credentials/v2",
        "type": ["VerifiablePresentation", credential_type],
        "id": f"urn:certitrust:{document_id}",
        "holder": f"did:certitrust:{issuer_id}",
        "proof": {
            "type": "Ed25519Signature2020",
            "verificationMethod": f"did:certitrust:{issuer_id}#key-1",
            "proofValue": signature,
            "documentHash": document_hash
        }
    }
    
    if issuer_name:
        payload["holder"] = {
            "id": f"did:certitrust:{issuer_id}",
            "name": issuer_name
        }
    
    if merkle_root:
        payload["proof"]["merkleRoot"] = merkle_root
    
    return payload


def calculate_qr_position(
    page_width: float,
    page_height: float,
    qr_size: int,
    margin: int,
    position: QRPosition
) -> Tuple[float, float, float, float]:
    """
    Calculates QR code position on page.
    
    Args:
        page_width: Page width in points
        page_height: Page height in points
        qr_size: QR code size in points
        margin: Margin from edge in points
        position: Desired position
        
    Returns:
        Tuple of (x0, y0, x1, y1) coordinates
    """
    if position == QRPosition.TOP_RIGHT:
        x0 = page_width - margin - qr_size
        y0 = margin
    elif position == QRPosition.TOP_LEFT:
        x0 = margin
        y0 = margin
    elif position == QRPosition.BOTTOM_RIGHT:
        x0 = page_width - margin - qr_size
        y0 = page_height - margin - qr_size
    elif position == QRPosition.BOTTOM_LEFT:
        x0 = margin
        y0 = page_height - margin - qr_size
    else:  # CENTER
        x0 = (page_width - qr_size) / 2
        y0 = (page_height - qr_size) / 2
    
    return x0, y0, x0 + qr_size, y0 + qr_size


def stamp_document(
    input_pdf_path: str,
    output_pdf_path: str,
    qr_image: Image.Image,
    config: Optional[QRConfig] = None,
    pages: Optional[list] = None
):
    """
    Stamps QR code onto PDF pages using PyMuPDF (high-speed).

    Args:
        input_pdf_path: Path to the source PDF.
        output_pdf_path: Path where the stamped PDF will be saved.
        qr_image: PIL Image of the QR code.
        config: Optional QR configuration.
        pages: Optional list of page indices to stamp (0-indexed). 
               If None, stamps only the first page.
    """
    if config is None:
        config = QRConfig()
    
    doc = fitz.open(input_pdf_path)

    try:
        # Determine which pages to stamp
        if pages is None:
            pages_to_stamp = [0] if len(doc) > 0 else []
        else:
            pages_to_stamp = [p for p in pages if 0 <= p < len(doc)]
        
        # Convert PIL image to bytes once
        img_byte_arr = io.BytesIO()
        qr_image.save(img_byte_arr, format='PNG')
        img_bytes = img_byte_arr.getvalue()
        
        for page_idx in pages_to_stamp:
            page = doc[page_idx]
            
            # Calculate position
            x0, y0, x1, y1 = calculate_qr_position(
                page.rect.width,
                page.rect.height,
                config.size,
                config.margin,
                config.position
            )
            
            rect = fitz.Rect(x0, y0, x1, y1)
            page.insert_image(rect, stream=img_bytes)
        
        doc.save(output_pdf_path)
        
    finally:
        doc.close()


def stamp_document_all_pages(
    input_pdf_path: str,
    output_pdf_path: str,
    qr_image: Image.Image,
    config: Optional[QRConfig] = None
):
    """
    Stamps QR code onto all pages of a PDF.
    
    Args:
        input_pdf_path: Path to the source PDF
        output_pdf_path: Path for stamped PDF
        qr_image: PIL Image of the QR code
        config: Optional QR configuration
    """
    doc = fitz.open(input_pdf_path)
    pages = list(range(len(doc)))
    doc.close()
    
    stamp_document(input_pdf_path, output_pdf_path, qr_image, config, pages)


def add_verification_watermark(
    input_pdf_path: str,
    output_pdf_path: str,
    text: str = "VERIFIED",
    opacity: float = 0.1
):
    """
    Adds a subtle verification watermark to all pages.
    
    Memory-efficient implementation using PyMuPDF.
    
    Args:
        input_pdf_path: Path to source PDF
        output_pdf_path: Path for output PDF
        text: Watermark text
        opacity: Watermark opacity (0-1)
    """
    doc = fitz.open(input_pdf_path)
    
    try:
        for page in doc:
            # Add diagonal watermark text
            text_point = fitz.Point(page.rect.width / 4, page.rect.height / 2)
            page.insert_text(
                text_point,
                text,
                fontsize=72,
                rotate=45,
                color=(0.7, 0.7, 0.7),
                overlay=True
            )
        
        doc.save(output_pdf_path)
        
    finally:
        doc.close()


def extract_qr_from_pdf(pdf_path: str, page_num: int = 0) -> Optional[Dict[str, Any]]:
    """
    Extracts and decodes QR code from a PDF page.
    
    Uses OpenCV for QR detection.
    
    Args:
        pdf_path: Path to the PDF
        page_num: Page number to scan (0-indexed)
        
    Returns:
        Decoded QR data as dictionary, or None if not found
    """
    try:
        import cv2
        import numpy as np
        
        doc = fitz.open(pdf_path)
        
        if page_num >= len(doc):
            doc.close()
            return None
        
        page = doc[page_num]
        
        # Render page to image
        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # 2x zoom for better QR detection
        img_data = pix.tobytes("png")
        doc.close()
        
        # Convert to OpenCV format
        nparr = np.frombuffer(img_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Detect QR code
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        
        if data:
            return json.loads(data)
        
        return None
        
    except Exception as e:
        print(f"Error extracting QR: {e}")
        return None


# Legacy compatibility - keeping original function signatures
def generate_qr_legacy(data: Dict[str, Any]) -> Image.Image:
    """
    Legacy function for backward compatibility.
    """
    return generate_qr(data)
