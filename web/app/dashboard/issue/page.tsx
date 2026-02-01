"use client"

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import { 
  FileCheck, ArrowLeft, Upload, Download, AlertCircle, 
  CheckCircle, FileText, Building2, Loader2 
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

type DocumentType = 'academic' | 'aadhaar' | 'permit' | 'generic'

export default function IssuePage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null)
  const [fileName, setFileName] = useState<string>('')
  
  const [institutionId, setInstitutionId] = useState<string | null>(null)
  const [institutionName, setInstitutionName] = useState<string | null>(null)
  
  const [documentType, setDocumentType] = useState<DocumentType>('academic')
  const [file, setFile] = useState<File | null>(null)
  const [dragActive, setDragActive] = useState(false)

  useEffect(() => {
    // Load institution from localStorage
    const id = localStorage.getItem('certitrust_institution_id')
    const name = localStorage.getItem('certitrust_institution_name')
    setInstitutionId(id)
    setInstitutionName(name)
  }, [])

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
      } else {
        setError('Please upload a PDF file')
      }
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) {
      setError('Please select a PDF file')
      return
    }

    setLoading(true)
    setError(null)
    setSuccess(false)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      const formData = new FormData()
      formData.append('file', file)
      
      // Build URL with query parameters
      const params = new URLSearchParams()
      params.append('document_type', documentType)
      if (institutionId) {
        params.append('institution_id', institutionId)
      }

      const response = await fetch(`${apiUrl}/issue/document?${params.toString()}`, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Issuance failed' }))
        throw new Error(errorData.detail || 'Issuance failed')
      }

      // Get the stamped PDF as a blob
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      setDownloadUrl(url)
      setFileName(`stamped_${file.name}`)
      setSuccess(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    if (downloadUrl) {
      const a = document.createElement('a')
      a.href = downloadUrl
      a.download = fileName
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    }
  }

  const resetForm = () => {
    setFile(null)
    setSuccess(false)
    setDownloadUrl(null)
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

      {/* Institution Status */}
      {institutionId ? (
        <div className="mb-6 p-4 rounded-lg bg-blue-50 border border-blue-200 flex items-center gap-3">
          <Building2 className="h-5 w-5 text-blue-600" />
          <div className="flex-1">
            <p className="text-sm font-medium text-blue-900">
              Issuing as: {institutionName || 'Institution'}
            </p>
            <p className="text-xs text-blue-600 font-mono">{institutionId}</p>
          </div>
          <Badge variant="success">Connected</Badge>
        </div>
      ) : (
        <div className="mb-6 p-4 rounded-lg bg-yellow-50 border border-yellow-200 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-yellow-600" />
          <div className="flex-1">
            <p className="text-sm font-medium text-yellow-900">
              No institution connected
            </p>
            <p className="text-xs text-yellow-600">
              Using legacy signing mode. <Link href="/admin/onboard" className="underline">Onboard an institution</Link> for full features.
            </p>
          </div>
        </div>
      )}

      {success ? (
        <Card className="border-green-200 bg-green-50">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-green-600" />
              </div>
              <div>
                <CardTitle className="text-green-800">Document Issued Successfully!</CardTitle>
                <CardDescription className="text-green-600">
                  Your document has been signed and stamped with a QR code
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="bg-white rounded-lg p-6 border text-center">
              <FileText className="h-16 w-16 text-green-600 mx-auto mb-4" />
              <p className="font-medium text-lg mb-2">{fileName}</p>
              <p className="text-sm text-gray-500 mb-4">
                Ed25519 signed • QR stamped • W3C VC compliant
              </p>
              <Button onClick={handleDownload} className="gap-2">
                <Download className="h-4 w-4" />
                Download Stamped PDF
              </Button>
            </div>
          </CardContent>
          <CardFooter className="flex gap-4">
            <Button onClick={resetForm} variant="outline" className="flex-1">
              Issue Another Document
            </Button>
            <Link href="/verify">
              <Button variant="secondary">
                Verify Documents
              </Button>
            </Link>
          </CardFooter>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                <FileCheck className="h-6 w-6 text-green-600" />
              </div>
              <div>
                <CardTitle>Issue Document</CardTitle>
                <CardDescription>
                  Upload a PDF and create a cryptographically signed credential
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <form onSubmit={handleSubmit}>
            <CardContent className="space-y-6">
              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  {error}
                </div>
              )}

              {/* Document Type Selection */}
              <div className="space-y-2">
                <Label>Document Type</Label>
                <Select value={documentType} onValueChange={(v) => setDocumentType(v as DocumentType)}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select document type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="academic">🎓 Academic Degree</SelectItem>
                    <SelectItem value="aadhaar">🪪 Aadhaar Card</SelectItem>
                    <SelectItem value="permit">📋 Permit / License</SelectItem>
                    <SelectItem value="generic">📄 Generic Document</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* File Upload Zone */}
              <div className="space-y-2">
                <Label>Document (PDF)</Label>
                <div
                  className={`
                    relative border-2 border-dashed rounded-lg p-8 text-center transition-colors
                    ${dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'}
                    ${file ? 'bg-green-50 border-green-300' : ''}
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
                      <FileText className="h-12 w-12 text-green-600 mx-auto mb-2" />
                      <p className="font-medium text-green-800">{file.name}</p>
                      <p className="text-sm text-green-600">
                        {(file.size / 1024).toFixed(1)} KB
                      </p>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="mt-2"
                        onClick={(e) => {
                          e.preventDefault()
                          setFile(null)
                        }}
                      >
                        Remove
                      </Button>
                    </div>
                  ) : (
                    <div>
                      <Upload className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                      <p className="font-medium text-gray-700">
                        Drag & drop your PDF here
                      </p>
                      <p className="text-sm text-gray-500">
                        or click to browse
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>

            <CardFooter>
              <Button 
                type="submit" 
                className="w-full" 
                disabled={loading || !file}
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Signing & Stamping...
                  </>
                ) : (
                  <>
                    <FileCheck className="mr-2 h-4 w-4" />
                    Issue Credential
                  </>
                )}
              </Button>
            </CardFooter>
          </form>
        </Card>
      )}
    </main>
  )
}
