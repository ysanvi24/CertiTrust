import fitz
import os
import sys
from fastapi.testclient import TestClient

# Ensure we can import from the current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import app

client = TestClient(app)

def create_dummy_pdf(filename="test.pdf"):
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "Hello, World! This is a test document.")
    doc.save(filename)
    doc.close()
    return filename

def test_pipeline():
    print("Starting pipeline test...")
    # 1. Create a dummy PDF
    pdf_path = "test_original.pdf"
    create_dummy_pdf(pdf_path)

    output_path = "test_stamped.pdf"

    try:
        # 2. Test the API endpoint
        with open(pdf_path, "rb") as f:
            print("Sending request to /issue/document...")
            response = client.post(
                "/issue/document",
                files={"file": ("test_original.pdf", f, "application/pdf")}
            )

        if response.status_code != 200:
            print(f"Failed with status {response.status_code}: {response.text}")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"

        # Save the result
        with open(output_path, "wb") as f:
            f.write(response.content)

        print(f"Saved stamped PDF to {output_path}")

        # 3. Verify the output PDF has an image (the QR code)
        doc = fitz.open(output_path)
        page = doc[0]
        images = page.get_images()

        # We expect at least one image (the QR code)
        print(f"Found {len(images)} images in the stamped PDF.")
        assert len(images) >= 1, "Stamped PDF should contain at least one image (QR code)"

        doc.close()

        print("Pipeline test passed successfully!")

    except Exception as e:
        print(f"Test failed with error: {e}")
        raise

    finally:
        # Cleanup
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        if os.path.exists(output_path):
            os.remove(output_path)

if __name__ == "__main__":
    test_pipeline()
