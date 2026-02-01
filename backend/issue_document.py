#!/usr/bin/env python3
"""
Document Issuance Script for CertiTrust
=======================================
Multi-tenant document issuance with Ed25519 signing, QR stamping, and audit logging.

Usage:
    python issue_document.py <input_pdf_path> [output_pdf_path] [--institution-id <id>]
    
Examples:
    python issue_document.py my_document.pdf
    python issue_document.py input.pdf stamped_output.pdf
    python issue_document.py degree.pdf --institution-id abc-123-def
"""

import sys
import os
import argparse
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

# Set default environment variables (can be overridden externally)
os.environ['ISSUER_PRIVATE_KEY'] = os.environ.get(
    'ISSUER_PRIVATE_KEY',
    'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSU9scUVkK0dCMHIzTjBuZi9hWUNYMFhhZjJVL29UUnRrRkR0RjNvbUlCWU0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ=='
)
os.environ['SUPABASE_URL'] = os.environ.get(
    'SUPABASE_URL',
    'https://jruxbqdfcdyemwpihmxx.supabase.co'
)
os.environ['SUPABASE_SERVICE_ROLE_KEY'] = os.environ.get(
    'SUPABASE_SERVICE_ROLE_KEY',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpydXhicWRmY2R5ZW13cGlobXh4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2OTg0MzY3OSwiZXhwIjoyMDg1NDE5Njc5fQ.L25zeZDibbQsuMDAVmCxk_HIcC17gA-VuCItSXaLFfA'
)

from fastapi.testclient import TestClient
from main import app


def print_banner():
    """Print CertiTrust banner."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║             CertiTrust Document Issuance v2.0                 ║
║         Multi-Tenant Document Verification Platform          ║
╚═══════════════════════════════════════════════════════════════╝
    """)


def issue_document(
    input_path: str,
    output_path: str = None,
    institution_id: str = None,
    document_type: str = "generic"
) -> bool:
    """
    Issue a document by processing it through the CertiTrust pipeline.

    Args:
        input_path: Path to the input PDF file
        output_path: Path to save the stamped PDF (optional)
        institution_id: UUID of the issuing institution (optional)
        document_type: Type of document (generic, academic, permit)

    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(input_path):
        print(f"❌ Error: Input file '{input_path}' not found")
        return False

    if not input_path.lower().endswith('.pdf'):
        print("❌ Error: Only PDF files are supported")
        return False

    if output_path is None:
        input_name = Path(input_path).stem
        output_path = f"{input_name}_stamped.pdf"

    print(f"\n📄 Processing document: {input_path}")
    
    if institution_id:
        print(f"🏛️  Institution ID: {institution_id}")
    else:
        print("⚠️  No institution ID provided, using legacy mode")
    
    print(f"📋 Document type: {document_type}")
    print()
    print("🔐 Loading issuer private key...")
    print("📊 Calculating document hash (SHA-256, chunked)...")
    print("🌳 Building Merkle tree for tamper localization...")
    print("✍️  Generating Ed25519 digital signature...")
    print("📱 Creating W3C VC compliant QR code...")
    print("🏷️  Stamping document with verification QR...")
    print("📝 Logging to hash-chain audit trail...")
    print()

    client = TestClient(app)

    try:
        with open(input_path, "rb") as f:
            # Prepare request data
            files = {"file": (os.path.basename(input_path), f, "application/pdf")}
            data = {"document_type": document_type}
            
            if institution_id:
                data["institution_id"] = institution_id
            
            response = client.post(
                "/issue/document",
                files=files,
                data=data
            )

        if response.status_code != 200:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return False

        # Save the stamped document
        with open(output_path, "wb") as f:
            f.write(response.content)

        print("=" * 60)
        print("✅ Document issued successfully!")
        print("=" * 60)
        print()
        print(f"📁 Stamped document saved to: {output_path}")
        print()
        print("🔍 The document now contains:")
        print("   • Cryptographic SHA-256 hash for integrity verification")
        print("   • Ed25519 digital signature from institutional key")
        print("   • Merkle tree root for multi-page tamper detection")
        print("   • W3C Verifiable Credentials compliant QR code")
        print("   • Hash-chain audit trail entry in Supabase")
        print()
        
        # Show file sizes
        input_size = os.path.getsize(input_path)
        output_size = os.path.getsize(output_path)
        print(f"📊 Original size: {input_size:,} bytes")
        print(f"📊 Stamped size:  {output_size:,} bytes")
        print(f"📊 Overhead:      {output_size - input_size:,} bytes ({(output_size/input_size - 1)*100:.1f}%)")
        
        return True

    except Exception as e:
        print(f"❌ Error processing document: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CertiTrust Document Issuance - Multi-Tenant Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Issue a document (legacy mode):
    python issue_document.py certificate.pdf
    
  Issue with specific output path:
    python issue_document.py input.pdf stamped_certificate.pdf
    
  Issue for a specific institution:
    python issue_document.py degree.pdf --institution-id abc-123-def
    
  Issue as academic credential:
    python issue_document.py transcript.pdf -t academic -i inst-123
        """
    )
    
    parser.add_argument(
        "input_path",
        help="Path to the input PDF file"
    )
    
    parser.add_argument(
        "output_path",
        nargs="?",
        default=None,
        help="Path to save the stamped PDF (optional)"
    )
    
    parser.add_argument(
        "-i", "--institution-id",
        dest="institution_id",
        default=None,
        help="UUID of the issuing institution (for multi-tenant mode)"
    )
    
    parser.add_argument(
        "-t", "--type",
        dest="document_type",
        choices=["generic", "academic", "permit", "aadhaar"],
        default="generic",
        help="Type of document (default: generic)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    success = issue_document(
        input_path=args.input_path,
        output_path=args.output_path,
        institution_id=args.institution_id,
        document_type=args.document_type
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()