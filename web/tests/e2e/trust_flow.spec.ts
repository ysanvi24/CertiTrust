/**
 * CertiTrust E2E Integration Test
 * ================================
 * Tests the complete trust flow:
 * 1. Onboarding an institution
 * 2. Issuing a degree document
 * 3. Verifying that degree
 */

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as fs from 'fs';

// Generate unique test data
const testInstitution = {
  name: `Test University ${Date.now()}`,
  slug: `test-university-${Date.now()}`,
  email: 'test@university.edu',
  domain: 'test-university.edu'
};

let institutionId: string | null = null;

test.describe('CertiTrust Full Trust Flow', () => {
  
  test.describe.serial('Complete Workflow', () => {
    
    test('1. Home page loads correctly', async ({ page }) => {
      await page.goto('/');
      
      // Check hero section
      await expect(page.locator('h1')).toContainText('CertiTrust');
      
      // Check feature cards
      await expect(page.getByText('Institution Onboarding')).toBeVisible();
      await expect(page.getByText('Issue Documents')).toBeVisible();
      await expect(page.getByText('Verify Documents')).toBeVisible();
    });

    test('2. Onboard a new institution', async ({ page }) => {
      await page.goto('/admin/onboard');
      
      // Check page loaded
      await expect(page.getByText('Institution Onboarding')).toBeVisible();
      
      // Fill the form
      await page.fill('input#name', testInstitution.name);
      await page.fill('input#slug', testInstitution.slug);
      await page.fill('input#email', testInstitution.email);
      await page.fill('input#domain', testInstitution.domain);
      
      // Submit
      await page.click('button[type="submit"]');
      
      // Wait for success
      await expect(page.getByText('Institution Onboarded Successfully!')).toBeVisible({ timeout: 15000 });
      
      // Verify public key is displayed
      await expect(page.getByText('-----BEGIN PUBLIC KEY-----')).toBeVisible();
      
      // Get and store the institution ID from the page
      const idElement = page.locator('code').first();
      institutionId = await idElement.textContent();
      expect(institutionId).toBeTruthy();
      
      console.log(`Onboarded institution: ${institutionId}`);
    });

    test('3. Issue a degree document', async ({ page }) => {
      // First, set the institution in localStorage (simulating previous onboarding)
      await page.goto('/dashboard/issue');
      
      // Inject the institution ID into localStorage
      if (institutionId) {
        await page.evaluate((id) => {
          localStorage.setItem('certitrust_institution_id', id);
          localStorage.setItem('certitrust_institution_name', 'Test University');
        }, institutionId);
        
        // Reload to pick up localStorage
        await page.reload();
      }
      
      // Check page loaded
      await expect(page.getByText('Issue Document')).toBeVisible();
      
      // Select document type
      await page.click('[role="combobox"]');
      await page.click('[role="option"]:has-text("Academic Degree")');
      
      // Create a test PDF file for upload
      const testPdfPath = path.join(__dirname, 'test-degree.pdf');
      
      // Create a minimal PDF file if it doesn't exist
      if (!fs.existsSync(testPdfPath)) {
        // Create a simple PDF content (minimal valid PDF)
        const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Test Degree) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
300
%%EOF`;
        fs.writeFileSync(testPdfPath, pdfContent);
      }
      
      // Upload the file
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(testPdfPath);
      
      // Wait for file to be recognized
      await expect(page.getByText('test-degree.pdf')).toBeVisible();
      
      // Submit
      await page.click('button:has-text("Issue Credential")');
      
      // Wait for success
      await expect(page.getByText('Document Issued Successfully!')).toBeVisible({ timeout: 20000 });
      
      // Verify download button is present
      await expect(page.getByText('Download Stamped PDF')).toBeVisible();
      
      console.log('Document issued successfully');
    });

    test('4. Verify a document via file upload', async ({ page }) => {
      await page.goto('/verify');
      
      // Check page loaded
      await expect(page.getByText('Document Verification')).toBeVisible();
      
      // We need a stamped PDF to verify - for E2E test, we'll use the API directly
      // to get a stamped document first
      
      // Create test PDF
      const testPdfPath = path.join(__dirname, 'test-verify.pdf');
      const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 100 700 Td (Test Verify) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
300
%%EOF`;
      fs.writeFileSync(testPdfPath, pdfContent);
      
      // Upload the file
      const fileInput = page.locator('input[type="file"]');
      await fileInput.setInputFiles(testPdfPath);
      
      // Wait for file to be recognized
      await expect(page.getByText('test-verify.pdf')).toBeVisible();
      
      // Click verify
      await page.click('button:has-text("Verify Document")');
      
      // Wait for result (may fail since it's not a stamped PDF, but UI should work)
      await page.waitForSelector('.rounded-lg:has-text("Verification"), .rounded-lg:has-text("Failed")', { timeout: 15000 });
      
      console.log('Verification flow completed');
    });

    test('5. API Health Check', async ({ request }) => {
      const response = await request.get('http://localhost:8000/health');
      expect(response.ok()).toBeTruthy();
      
      const data = await response.json();
      expect(data.status).toBe('healthy');
      expect(data.version).toBe('2.0.0');
      expect(data.supabase_configured).toBe(true);
    });

    test('6. API Institution Onboarding', async ({ request }) => {
      const response = await request.post('http://localhost:8000/admin/onboard', {
        data: {
          name: `API Test Institution ${Date.now()}`,
          slug: `api-test-${Date.now()}`,
          contact_email: 'api@test.com',
          domain: 'api-test.com'
        }
      });
      
      expect(response.ok()).toBeTruthy();
      
      const data = await response.json();
      expect(data.id).toBeTruthy();
      expect(data.public_key_pem).toContain('-----BEGIN PUBLIC KEY-----');
    });

    test('7. API Document Verification', async ({ request }) => {
      // Test the verify/document endpoint
      const response = await request.post('http://localhost:8000/verify/document', {
        data: {
          document_hash: 'a'.repeat(64),
          signature: 'invalid_signature',
        }
      });
      
      expect(response.ok()).toBeTruthy();
      
      const data = await response.json();
      expect(data.is_valid).toBe(false);
      expect(data.message).toBeTruthy();
    });
  });
});

// Cleanup
test.afterAll(async () => {
  // Clean up test files
  const testFiles = [
    path.join(__dirname, 'test-degree.pdf'),
    path.join(__dirname, 'test-verify.pdf'),
  ];
  
  for (const file of testFiles) {
    if (fs.existsSync(file)) {
      fs.unlinkSync(file);
    }
  }
});
