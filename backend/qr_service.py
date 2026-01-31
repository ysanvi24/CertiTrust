import qrcode
import json
import fitz  # PyMuPDF
from PIL import Image
import io
from typing import Dict, Any

def generate_qr(data: Dict[str, Any]) -> Image.Image:
    """
    Generates a QR code image from a dictionary payload.
    """
    json_payload = json.dumps(data)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(json_payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    return img

def stamp_document(input_pdf_path: str, output_pdf_path: str, qr_image: Image.Image):
    """
    Pastes the QR code onto the top-right corner of the first page of the PDF.

    Args:
        input_pdf_path: Path to the source PDF.
        output_pdf_path: Path where the stamped PDF will be saved.
        qr_image: PIL Image of the QR code.
    """
    doc = fitz.open(input_pdf_path)

    if len(doc) > 0:
        page = doc[0]  # Stamp the first page

        # Define the size of the QR code on the PDF (e.g., 100x100 units)
        qr_width = 100
        qr_height = 100
        margin = 36  # 0.5 inch (36pt)

        # Calculate position: top-right corner
        # x0 = page_width - margin - qr_width
        # y0 = margin
        x0 = page.rect.width - margin - qr_width
        y0 = margin
        x1 = x0 + qr_width
        y1 = y0 + qr_height

        rect = fitz.Rect(x0, y0, x1, y1)

        # Convert PIL image to bytes
        img_byte_arr = io.BytesIO()
        qr_image.save(img_byte_arr, format='PNG')
        img_bytes = img_byte_arr.getvalue()

        page.insert_image(rect, stream=img_bytes)

    doc.save(output_pdf_path)
    doc.close()
