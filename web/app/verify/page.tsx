"use client"

import { useState, useCallback } from 'react'
import Link from 'next/link'
import { 
  Shield, ArrowLeft, Upload, CheckCircle, XCircle, 
  AlertTriangle, FileText, Link2, Clock, Building2, Loader2,
  AlertCircle, Info
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

// Error codes from backend
type ErrorCode = 
  | 'SUCCESS'
  | 'QR_NOT_FOUND'
  | 'QR_DECODE_FAIL'
  | 'PAYLOAD_READ_FAIL'
  | 'HASH_MISMATCH'
  | 'SIGNATURE_MISMATCH'
  | 'INSTITUTION_NOT_FOUND'
  | 'DOCUMENT_REVOKED'
  | 'INTERNAL_ERROR';

interface VerificationResult {
  valid: boolean
  error_code?: ErrorCode
  message: string
  file_name?: string
  document_id?: string
  issuer_id?: string
  institution_name?: string
  institution_active?: boolean
  original_hash?: string
  current_file_hash?: string
  signature?: string
  signature_valid?: boolean
  merkle_root?: string
  credential_type?: string
  hash_note?: string
  signature_verified_with?: string
  // Legacy fields
  is_valid?: boolean
  institution_id?: string | null
  issued_at?: string | null
  document_type?: string | null
  qr_data?: Record<string, unknown>
}

// Friendly error messages for each error code
const ERROR_MESSAGES: Record<ErrorCode, { title: string; description: string; icon: typeof AlertCircle }> = {
  SUCCESS: { 
    title: 'Document Verified', 
    description: 'The document signature is valid and authentic.',
    icon: CheckCircle
  },
  QR_NOT_FOUND: { 
    title: 'QR Code Not Found', 
    description: 'No verification QR code was detected in this PDF. Is this a CertiTrust stamped document?',
    icon: AlertTriangle
  },
  QR_DECODE_FAIL: { 
    title: 'QR Decode Failed', 
    description: 'A QR code was found but could not be decoded. The image may be damaged or low resolution.',
    icon: AlertTriangle
  },
  PAYLOAD_READ_FAIL: { 
    title: 'Invalid QR Payload', 
    description: 'The QR code does not contain valid verification data.',
    icon: AlertCircle
  },
  HASH_MISMATCH: { 
    title: 'Document Modified', 
    description: 'The document content has been modified after signing.',
    icon: XCircle
  },
  SIGNATURE_MISMATCH: { 
    title: 'Signature Invalid', 
    description: 'The cryptographic signature could not be verified. The document may have been tampered with or signed by an unknown issuer.',
    icon: XCircle
  },
  INSTITUTION_NOT_FOUND: { 
    title: 'Issuer Not Found', 
    description: 'The issuing institution is not registered in the CertiTrust network.',
    icon: AlertCircle
  },
  DOCUMENT_REVOKED: { 
    title: 'Document Revoked', 
    description: 'This document has been revoked by the issuing institution.',
    icon: XCircle
  },
  INTERNAL_ERROR: { 
    title: 'Verification Error', 
    description: 'An internal error occurred during verification. Please try again.',
    icon: AlertCircle
  }
};

export default function VerifyPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragActive, setDragActive] = useState(false)

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true)
    } else if (e.type === "dragleave") {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0]
      if (droppedFile.type === 'application/pdf') {
        setFile(droppedFile)
        setError(null)
        setResult(null)
      } else {
        setError('Please upload a PDF file')
      }
    }
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0]
      if (selectedFile.type === 'application/pdf') {
        setFile(selectedFile)
        setError(null)
        setResult(null)
      } else {
        setError('Please upload a PDF file')
      }
    }
  }

  const handleVerify = async () => {
    if (!file) {
      setError('Please select a PDF file')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(`${apiUrl}/verify/file`, {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.detail || 'Verification failed')
      }

      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const resetVerification = () => {
    setFile(null)
    setResult(null)
    setError(null)
  }

  return (
    <main className="container mx-auto px-4 py-8 max-w-2xl">
      <div className="mb-8">
        <Link href="/" className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Home
        </Link>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded-full bg-purple-100 flex items-center justify-center">
              <Shield className="h-6 w-6 text-purple-600" />
            </div>
            <div>
              <CardTitle>Document Verification</CardTitle>
              <CardDescription>
                Upload a CertiTrust stamped PDF to verify its authenticity
              </CardDescription>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
              <XCircle className="h-4 w-4 flex-shrink-0" />
              {error}
            </div>
          )}

          {/* File Upload Zone */}
          {!result && (
            <div
              className={`
                relative border-2 border-dashed rounded-lg p-8 text-center transition-colors
                ${dragActive ? 'border-purple-500 bg-purple-50' : 'border-gray-300 hover:border-gray-400'}
                ${file ? 'bg-blue-50 border-blue-300' : ''}
              `}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              <input
                type="file"
                accept=".pdf,application/pdf"
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              
              {file ? (
                <div>
                  <FileText className="h-12 w-12 text-blue-600 mx-auto mb-2" />
                  <p className="font-medium text-blue-800">{file.name}</p>
                  <p className="text-sm text-blue-600">
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
              ) : (
                <div>
                  <Upload className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                  <p className="font-medium text-gray-700">
                    Drag & drop a stamped PDF here
                  </p>
                  <p className="text-sm text-gray-500">
                    or click to browse
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Verify Button */}
          {file && !result && (
            <Button 
              onClick={handleVerify} 
              className="w-full" 
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Verify Document
                </>
              )}
            </Button>
          )}

          {/* Verification Result */}
          {result && (
            <div className="space-y-4">
              {/* Main Status */}
              {(() => {
                const isValid = result.valid || result.is_valid
                const errorCode = result.error_code || (isValid ? 'SUCCESS' : 'SIGNATURE_MISMATCH')
                const errorInfo = ERROR_MESSAGES[errorCode as ErrorCode] || ERROR_MESSAGES.INTERNAL_ERROR
                const StatusIcon = errorInfo.icon
                
                return (
                  <>
                    <div className={`
                      p-6 rounded-lg text-center
                      ${isValid ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}
                    `}>
                      <StatusIcon className={`h-16 w-16 mx-auto mb-3 ${isValid ? 'text-green-600' : 'text-red-600'}`} />
                      <h3 className={`text-xl font-bold mb-2 ${isValid ? 'text-green-800' : 'text-red-800'}`}>
                        {errorInfo.title} {isValid ? '✓' : '✗'}
                      </h3>
                      <p className={isValid ? 'text-green-600' : 'text-red-600'}>{result.message}</p>
                      
                      {/* Error Code Badge */}
                      {errorCode && errorCode !== 'SUCCESS' && (
                        <Badge variant="outline" className="mt-3">
                          Error Code: {errorCode}
                        </Badge>
                      )}
                    </div>

                    {/* Trust Summary Dashboard */}
                    <div className="space-y-3">
                      <h4 className="font-semibold text-gray-900 flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Trust Summary
                      </h4>

                      <div className="grid gap-3">
                        {/* Signature Validity */}
                        <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center gap-2">
                            {result.signature_valid || isValid ? (
                              <CheckCircle className="h-5 w-5 text-green-600" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600" />
                            )}
                            <span className="font-medium">Ed25519 Signature</span>
                          </div>
                          <Badge variant={result.signature_valid || isValid ? "success" : "destructive"}>
                            {result.signature_valid || isValid ? 'Valid' : 'Invalid'}
                          </Badge>
                        </div>

                        {/* Institution */}
                        {(result.institution_name || result.issuer_id) && (
                          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center gap-2">
                              <Building2 className="h-5 w-5 text-blue-600" />
                              <span className="font-medium">Issuing Institution</span>
                            </div>
                            <div className="text-right">
                              <span className="text-sm font-medium">
                                {result.institution_name || result.issuer_id}
                              </span>
                              {result.institution_active !== undefined && (
                                <Badge variant={result.institution_active ? "success" : "secondary"} className="ml-2">
                                  {result.institution_active ? 'Active' : 'Inactive'}
                                </Badge>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Document ID */}
                        {result.document_id && (
                          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center gap-2">
                              <FileText className="h-5 w-5 text-gray-600" />
                              <span className="font-medium">Document ID</span>
                            </div>
                            <code className="text-xs bg-gray-200 px-2 py-1 rounded">
                              {result.document_id.slice(0, 16)}...
                            </code>
                          </div>
                        )}

                        {/* Merkle Root */}
                        {result.merkle_root && (
                          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center gap-2">
                              <Link2 className="h-5 w-5 text-purple-600" />
                              <span className="font-medium">Merkle Root</span>
                            </div>
                            <Badge variant="outline">
                              {result.merkle_root.slice(0, 12)}...
                            </Badge>
                          </div>
                        )}

                        {/* Credential Type */}
                        {(result.credential_type || result.document_type) && (
                          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center gap-2">
                              <FileText className="h-5 w-5 text-gray-600" />
                              <span className="font-medium">Document Type</span>
                            </div>
                            <Badge variant="secondary">
                              {(result.credential_type || result.document_type || 'generic').toString().charAt(0).toUpperCase() + 
                               (result.credential_type || result.document_type || 'generic').toString().slice(1)}
                            </Badge>
                          </div>
                        )}

                        {/* Verification Method */}
                        {result.signature_verified_with && (
                          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center gap-2">
                              <Shield className="h-5 w-5 text-green-600" />
                              <span className="font-medium">Verified With</span>
                            </div>
                            <Badge variant="outline">
                              {result.signature_verified_with === 'institution_key' ? 'Institution Key' : 'Legacy Key'}
                            </Badge>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Hash Information (collapsible for technical users) */}
                    {(result.original_hash || result.current_file_hash) && (
                      <details className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                        <summary className="font-semibold text-blue-900 cursor-pointer flex items-center gap-2">
                          <Info className="h-4 w-4" />
                          Technical Details
                        </summary>
                        <div className="mt-3 space-y-2 text-xs">
                          {result.original_hash && (
                            <div>
                              <span className="font-medium">Original Hash (from QR):</span>
                              <code className="block bg-white p-2 rounded mt-1 break-all">
                                {result.original_hash}
                              </code>
                            </div>
                          )}
                          {result.current_file_hash && (
                            <div>
                              <span className="font-medium">Current File Hash:</span>
                              <code className="block bg-white p-2 rounded mt-1 break-all">
                                {result.current_file_hash}
                              </code>
                            </div>
                          )}
                          {result.hash_note && (
                            <p className="text-blue-700 italic">{result.hash_note}</p>
                          )}
                        </div>
                      </details>
                    )}
                  </>
                )
              })()}

              {/* Reset Button */}
              <Button 
                onClick={resetVerification} 
                variant="outline" 
                className="w-full"
              >
                Verify Another Document
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  )
}
