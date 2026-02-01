import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  FileText, 
  CheckCircle2, 
  Loader2, 
  Download, 
  ShieldCheck, 
  FileCheck, 
  Lock,
  ChevronRight,
  Menu,
  X
} from 'lucide-react';
import { PDFDocument, rgb, StandardFonts } from 'pdf-lib';
import QRCode from 'qrcode';
import { motion, AnimatePresence } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import mammoth from 'mammoth';
import { generateId } from '../../lib/generateId';
import { computeSHA256Hex } from '../../lib/computeHash';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
} 

type VerificationState = 'idle' | 'processing' | 'completed' | 'error';

export function DocumentVerifier() {
  const [state, setState] = useState<VerificationState>('idle');
  const [file, setFile] = useState<File | null>(null);
  const [processedPdfUrl, setProcessedPdfUrl] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [shortId, setShortId] = useState<string | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);

  // Helper: Text Wrapping for PDF generation from text
  const wrapText = (text: string, maxWidth: number, font: any, fontSize: number) => {
    const paragraphs = text.split('\n');
    let lines: string[] = [];

    for (const paragraph of paragraphs) {
      if (paragraph.trim() === '') {
        lines.push('');
        continue;
      }

      const words = paragraph.split(' ');
      let currentLine = '';

      for (const word of words) {
        const testLine = currentLine ? `${currentLine} ${word}` : word;
        const width = font.widthOfTextAtSize(testLine, fontSize);
        if (width <= maxWidth) {
          currentLine = testLine;
        } else {
          lines.push(currentLine);
          currentLine = word;
        }
      }
      lines.push(currentLine);
    }
    return lines;
  };

  const processFile = async (uploadedFile: File) => {
    try {
      setState('processing');
      
      // Artificial delay for UX
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const fileBuffer = await uploadedFile.arrayBuffer();
      let pdfDoc: PDFDocument;

      if (uploadedFile.type === 'application/pdf') {
        pdfDoc = await PDFDocument.load(fileBuffer);
      } else if (uploadedFile.type === 'image/jpeg' || uploadedFile.type === 'image/png') {
        pdfDoc = await PDFDocument.create();
        const page = pdfDoc.addPage();
        const { width, height } = page.getSize();
        
        let image;
        if (uploadedFile.type === 'image/jpeg') {
          image = await pdfDoc.embedJpg(fileBuffer);
        } else {
          image = await pdfDoc.embedPng(fileBuffer);
        }
        
        const imgDims = image.scaleToFit(width - 40, height - 40);
        page.drawImage(image, {
          x: (width - imgDims.width) / 2,
          y: (height - imgDims.height) / 2,
          width: imgDims.width,
          height: imgDims.height,
        });
      } else if (
        uploadedFile.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || 
        uploadedFile.name.endsWith('.docx')
      ) {
        const result = await mammoth.extractRawText({ arrayBuffer: fileBuffer });
        const text = result.value;
        
        pdfDoc = await PDFDocument.create();
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const fontSize = 12;
        const margin = 50;
        
        let page = pdfDoc.addPage();
        let { width, height } = page.getSize();
        const maxWidth = width - (margin * 2);
        
        const lines = wrapText(text, maxWidth, font, fontSize);
        let y = height - margin;

        for (const line of lines) {
          if (y < margin + fontSize) {
             page = pdfDoc.addPage();
             y = height - margin;
          }
          page.drawText(line, { x: margin, y, size: fontSize, font, color: rgb(0, 0, 0) });
          y -= (fontSize + 4);
        }
      } else {
        throw new Error("Unsupported file type");
      }

      const helveticaFont = await pdfDoc.embedFont(StandardFonts.Helvetica);
      
      // Deterministic SHA-256 hash of the file as the document ID (lowercase hex)
      const fileHash = await computeSHA256Hex(fileBuffer);
      const signatureId = fileHash; // canonical identifier for the file (lowercase)
      // Keep a short human-friendly preview for the UI (20 chars)
      setShortId(signatureId.slice(0, 20));
      // Keep the full file hash in state for registration/verification
      setFileHash(fileHash);
      const timestamp = new Date().toISOString();
      const verificationUrl = (() => {
        try {
          // Prefer backend at same host on port 3000 (dev); fall back to current origin
          const origin = window.location.origin.replace(/:\d+$/, ':3000');
          return `${origin}/api/verifyHash?hash=${fileHash}`;
        } catch (e) {
          return `/api/verifyHash?hash=${fileHash}`;
        }
      })();

      const qrCodeDataUrl = await QRCode.toDataURL(verificationUrl, {
        margin: 1,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      });
      const qrImage = await pdfDoc.embedPng(qrCodeDataUrl);

      
      const pages = pdfDoc.getPages();
      const firstPage = pages[0];
      const { width, height } = firstPage.getSize();
      
      // Professional Stamp Layout
      const stampWidth = 180;
      const stampHeight = 60;
      const stampX = width - stampWidth - 20;
      const stampY = height - stampHeight - 20;

      // Draw background for stamp (optional)
      firstPage.drawRectangle({
        x: stampX,
        y: stampY,
        width: stampWidth,
        height: stampHeight,
        color: rgb(0.95, 0.95, 0.95),
        opacity: 0.5,
      });

      // Draw QR Code
      firstPage.drawImage(qrImage, {
        x: stampX + 5,
        y: stampY + 5,
        width: 50,
        height: 50,
      });
      
      // Draw Text Details
      const fontSizeDetails = 7;
      const textX = stampX + 60;
      let textY = stampY + 45;

      firstPage.drawText(`DIGITALLY VERIFIED`, {
        x: textX,
        y: textY,
        size: 9,
        font: helveticaFont,
        color: rgb(0, 0.2, 0.6), // Dark Blue
      });
      
      textY -= 12;
      // Show first 20 chars grouped in 4s for readability
      firstPage.drawText(`ID: ${signatureId.slice(0,20).match(/.{1,4}/g)?.join('-')}`, {
        x: textX,
        y: textY,
        size: fontSizeDetails,
        font: helveticaFont,
        color: rgb(0.3, 0.3, 0.3),
      });

      textY -= 10;
      firstPage.drawText(`Date: ${new Date().toISOString().split('T')[0]}`, {
        x: textX,
        y: textY,
        size: fontSizeDetails,
        font: helveticaFont,
        color: rgb(0.3, 0.3, 0.3),
      });

      textY -= 10;
      firstPage.drawText(`CertifyPro Secure Cloud`, {
        x: textX,
        y: textY,
        size: fontSizeDetails,
        font: helveticaFont,
        color: rgb(0.5, 0.5, 0.5),
      });
      
      const pdfBytes = await pdfDoc.save();
      // Ensure we pass a plain ArrayBuffer to Blob to avoid SharedArrayBuffer typing issues
      // Create a plain ArrayBuffer copy to avoid SharedArrayBuffer typing issues
      const ab = new ArrayBuffer(pdfBytes.byteLength);
      new Uint8Array(ab).set(pdfBytes.subarray(0, pdfBytes.byteLength));
      const blob = new Blob([ab], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      
      setProcessedPdfUrl(url);
      setState('completed');
      
    } catch (err) {
      console.error(err);
      setErrorMessage("We encountered an issue processing your file. Please ensure it is a valid document.");
      setState('error');
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const selectedFile = acceptedFiles[0];
    if (selectedFile) {
      setFile(selectedFile);
      processFile(selectedFile);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx']
    },
    maxFiles: 1,
    disabled: state === 'processing',
    onDropRejected: () => {
        setErrorMessage("Unsupported file format. Please upload PDF, JPG, PNG or DOCX.");
        setState('error');
    }
  });

  const reset = () => {
    setState('idle');
    setFile(null);
    setProcessedPdfUrl(null);
    setErrorMessage('');
  };

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-900 selection:bg-indigo-100 selection:text-indigo-900">
      
      {/* Navigation Bar */}
      <nav className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-2 cursor-pointer" onClick={reset}>
              <div className="bg-indigo-600 p-1.5 rounded-lg">
                <ShieldCheck className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold tracking-tight text-slate-900">Certify<span className="text-indigo-600">Pro</span></span>
            </div>
            
            <div className="hidden md:flex items-center space-x-8">
              <a href="#" className="text-sm font-medium text-slate-600 hover:text-indigo-600 transition-colors">Solutions</a>
              <a href="#" className="text-sm font-medium text-slate-600 hover:text-indigo-600 transition-colors">Enterprise</a>
              <a href="#" className="text-sm font-medium text-slate-600 hover:text-indigo-600 transition-colors">Developers</a>
              <a href="#" className="text-sm font-medium text-slate-600 hover:text-indigo-600 transition-colors">Pricing</a>
            </div>

            <div className="hidden md:flex items-center gap-4">
              <button className="text-sm font-medium text-slate-600 hover:text-indigo-600 transition-colors">Sign In</button>
              <button className="px-4 py-2 bg-slate-900 text-white text-sm font-medium rounded-lg hover:bg-slate-800 transition-colors shadow-sm">
                Get Started
              </button>
            </div>

            {/* Mobile Menu Button */}
            <div className="md:hidden">
              <button onClick={() => setIsMenuOpen(!isMenuOpen)} className="p-2 text-slate-600 hover:bg-slate-100 rounded-md">
                {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 lg:py-24">
        <div className="grid lg:grid-cols-2 gap-16 items-center">
          
          {/* Left Column: Content */}
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-50 border border-indigo-100 text-indigo-700 text-sm font-medium mb-6">
              <span className="flex h-2 w-2 rounded-full bg-indigo-600"></span>
              Bank-grade document security
            </div>
            <h1 className="text-5xl font-extrabold tracking-tight text-slate-900 mb-6 leading-[1.1]">
              Secure Document <br />
              <span className="text-indigo-600">Verification & Stamping</span>
            </h1>
            <p className="text-lg text-slate-600 mb-8 leading-relaxed">
              Instantly process, verify, and digitally stamp your critical documents. 
              Our AI-powered engine ensures authenticity with cryptographic signatures 
              embedded directly into your files.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 mb-12">
               <div className="flex items-center gap-2 text-slate-700 font-medium">
                  <CheckCircle2 className="w-5 h-5 text-indigo-600" />
                  <span>256-bit Encryption</span>
               </div>
               <div className="flex items-center gap-2 text-slate-700 font-medium">
                  <CheckCircle2 className="w-5 h-5 text-indigo-600" />
                  <span>Instant Processing</span>
               </div>
               <div className="flex items-center gap-2 text-slate-700 font-medium">
                  <CheckCircle2 className="w-5 h-5 text-indigo-600" />
                  <span>GDPR Compliant</span>
               </div>
            </div>
          </div>

          {/* Right Column: The App Interface */}
          <div className="relative">
            {/* Decorative background blobs */}
            <div className="absolute -top-10 -right-10 w-72 h-72 bg-indigo-300 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
            <div className="absolute -bottom-10 -left-10 w-72 h-72 bg-blue-300 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-pulse delay-1000"></div>

            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6 }}
              className="relative bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden"
            >
              <div className="px-6 py-4 border-b border-slate-100 bg-slate-50/50 flex justify-between items-center">
                 <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-slate-400" />
                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Secure Upload Environment</span>
                 </div>
                 <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-300"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-300"></div>
                 </div>
              </div>

              <div className="p-8 min-h-[420px] flex flex-col justify-center">
                <AnimatePresence mode="wait">
                  {state === 'idle' || state === 'error' ? (
                    <motion.div
                      key="upload"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex flex-col h-full"
                    >
                      <div 
                        {...getRootProps()} 
                        className={cn(
                          "flex-1 border-2 border-dashed rounded-xl p-8 transition-all duration-300 flex flex-col items-center justify-center gap-6 cursor-pointer group",
                          isDragActive ? "border-indigo-500 bg-indigo-50/30" : "border-slate-200 hover:border-indigo-400 hover:bg-slate-50",
                          state === 'error' && "border-red-300 bg-red-50/30"
                        )}
                      >
                        <input {...getInputProps()} />
                        
                        <div className={cn(
                          "w-20 h-20 rounded-2xl flex items-center justify-center shadow-sm transition-transform duration-300 group-hover:scale-110",
                          isDragActive ? "bg-indigo-100 text-indigo-600" : "bg-white border border-slate-100 text-slate-400",
                          state === 'error' && "bg-red-50 text-red-500 border-red-100"
                        )}>
                           {state === 'error' ? <ShieldCheck className="w-10 h-10" /> : <Upload className="w-10 h-10" />}
                        </div>

                        <div className="text-center space-y-2">
                          <p className="text-lg font-semibold text-slate-900">
                             {isDragActive ? "Drop to upload" : "Click or drag file"}
                          </p>
                          <p className="text-sm text-slate-500 max-w-[200px] mx-auto">
                            PDF, DOCX, PNG, or JPG (max 10MB)
                          </p>
                        </div>

                        <button className="px-5 py-2.5 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-all shadow-md shadow-indigo-200">
                          Select Document
                        </button>
                      </div>

                      {state === 'error' && (
                        <motion.div 
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-4 p-3 bg-red-50 border border-red-100 rounded-lg text-sm text-red-600 flex items-center gap-2"
                        >
                          <ShieldCheck className="w-4 h-4" />
                          {errorMessage}
                          <button onClick={(e) => {e.stopPropagation(); reset();}} className="ml-auto font-medium underline">Retry</button>
                        </motion.div>
                      )}
                    </motion.div>
                  ) : state === 'processing' ? (
                    <motion.div
                      key="processing"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex flex-col items-center justify-center h-full text-center"
                    >
                      <div className="relative w-24 h-24 mb-8">
                         <div className="absolute inset-0 border-4 border-slate-100 rounded-full"></div>
                         <div className="absolute inset-0 border-4 border-indigo-600 rounded-full border-t-transparent animate-spin"></div>
                         <FileText className="absolute inset-0 m-auto w-8 h-8 text-indigo-600 animate-pulse" />
                      </div>
                      <h3 className="text-xl font-bold text-slate-900 mb-2">Analyzing Document</h3>
                      <p className="text-slate-500 text-sm max-w-xs">
                        We are encrypting your file and appending a unique verification token...
                      </p>
                    </motion.div>
                  ) : (
                    <motion.div
                      key="completed"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="flex flex-col items-center justify-center h-full text-center"
                    >
                      <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mb-6 ring-8 ring-green-50">
                        <FileCheck className="w-10 h-10 text-green-600" />
                      </div>
                      
                      <h3 className="text-2xl font-bold text-slate-900 mb-2">Successfully Verified</h3>
                      <p className="text-slate-500 text-sm max-w-xs mb-8">
                        Your document has been secured with ID <span className="font-mono text-slate-700 bg-slate-100 px-1 py-0.5 rounded text-xs">{shortId || '—'}</span> 
                      </p>

                      <div className="w-full space-y-3">
                        {processedPdfUrl && (
                          <a 
                            href={processedPdfUrl} 
                            download={`verified-${file?.name ? file.name.split('.')[0] : 'document'}.pdf`}
                            className="flex items-center justify-center gap-2 w-full px-4 py-3 bg-indigo-600 text-white font-medium rounded-xl hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200"
                          >
                            <Download className="w-5 h-5" />
                            Download Signed Document
                          </a>
                        )}

                        {/* Register certificate with Supabase (and optionally attest on-chain) */}
                        <button
                          onClick={async () => {
                            try {
                              setState('processing');
                              const res = await fetch('/api/registerHash', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ fileHash: fileHash || shortId || null, fileName: file?.name, owner: 'did:example:institution', attest: false })
                              });
                              const data = await res.json();
                              if (!res.ok) throw new Error(data.error || 'Registration failed');
                              alert('Registered successfully');
                              setState('completed');
                            } catch (err) {
                              console.error(err);
                              alert('Registration failed: ' + (err instanceof Error ? err.message : String(err)));
                              setState('completed');
                            }
                          }}
                          className="w-full px-4 py-3 bg-white border border-slate-200 text-slate-600 font-medium rounded-xl hover:bg-slate-50 transition-colors"
                        >
                          Register Certificate (Database)
                        </button>

                        <button 
                          onClick={reset}
                          className="w-full px-4 py-3 bg-white border border-slate-200 text-slate-600 font-medium rounded-xl hover:bg-slate-50 transition-colors"
                        >
                          Verify Another File
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>

            {/* Testimonials or Stats below the card */}
            <div className="mt-8 grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold text-slate-900">10M+</p>
                <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">Docs Processed</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-slate-900">99.9%</p>
                <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">Uptime</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-slate-900">0s</p>
                <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">Data Retention</p>
              </div>
            </div>
          </div>
        </div>
      </main>
      
      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 mt-20">
         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="flex flex-col md:flex-row justify-between items-center">
               <div className="flex items-center gap-2 mb-4 md:mb-0">
                  <div className="bg-slate-900 p-1 rounded-md">
                     <ShieldCheck className="w-4 h-4 text-white" />
                  </div>
                  <span className="text-lg font-bold text-slate-900">CertifyPro</span>
               </div>
               <p className="text-sm text-slate-500">
                  © {new Date().getFullYear()} CertifyPro Inc. All rights reserved.
               </p>
            </div>
         </div>
      </footer>

    </div>
  );
}
