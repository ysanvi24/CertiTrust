"use client"

import { useState } from 'react'
import Link from 'next/link'
import { Building2, ArrowLeft, Copy, Check, Key, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

interface OnboardingResult {
  id: string
  name: string
  slug: string
  public_key_pem: string
  created_at: string
  is_active: boolean
}

export default function AdminOnboardPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<OnboardingResult | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    contact_email: '',
    domain: ''
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
      const response = await fetch(`${apiUrl}/admin/onboard`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Onboarding failed')
      }

      const data = await response.json()
      setResult(data)
      
      // Store institution ID in localStorage for subsequent actions
      localStorage.setItem('certitrust_institution_id', data.id)
      localStorage.setItem('certitrust_institution_name', data.name)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopied(field)
    setTimeout(() => setCopied(null), 2000)
  }

  const generateSlug = (name: string) => {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
  }

  if (result) {
    return (
      <main className="container mx-auto px-4 py-8 max-w-2xl">
        <div className="mb-8">
          <Link href="/" className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Home
          </Link>
        </div>

        <Card className="border-green-200 bg-green-50">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                <Check className="h-6 w-6 text-green-600" />
              </div>
              <div>
                <CardTitle className="text-green-800">Institution Onboarded Successfully!</CardTitle>
                <CardDescription className="text-green-600">
                  Your Ed25519 keypair has been generated securely
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Institution ID */}
            <div className="bg-white rounded-lg p-4 border">
              <div className="flex items-center justify-between mb-2">
                <Label className="text-sm text-gray-500">Institution ID</Label>
                <Badge variant="success">Active</Badge>
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-sm bg-gray-100 px-3 py-2 rounded font-mono">
                  {result.id}
                </code>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={() => copyToClipboard(result.id, 'id')}
                >
                  {copied === 'id' ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            {/* Public Key */}
            <div className="bg-white rounded-lg p-4 border">
              <div className="flex items-center gap-2 mb-2">
                <Key className="h-4 w-4 text-blue-600" />
                <Label className="text-sm text-gray-500">Ed25519 Public Key (PEM)</Label>
              </div>
              <div className="relative">
                <pre className="text-xs bg-gray-100 p-3 rounded font-mono overflow-x-auto whitespace-pre-wrap break-all">
                  {result.public_key_pem}
                </pre>
                <Button
                  size="sm"
                  variant="ghost"
                  className="absolute top-2 right-2"
                  onClick={() => copyToClipboard(result.public_key_pem, 'key')}
                >
                  {copied === 'key' ? <Check className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-white rounded-lg p-4 border">
                <Label className="text-sm text-gray-500">Institution Name</Label>
                <p className="font-medium mt-1">{result.name}</p>
              </div>
              <div className="bg-white rounded-lg p-4 border">
                <Label className="text-sm text-gray-500">Slug</Label>
                <p className="font-medium font-mono mt-1">{result.slug}</p>
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex gap-4">
            <Link href="/dashboard/issue" className="flex-1">
              <Button className="w-full">
                Start Issuing Documents
              </Button>
            </Link>
            <Link href="/">
              <Button variant="outline">
                Home
              </Button>
            </Link>
          </CardFooter>
        </Card>
      </main>
    )
  }

  return (
    <main className="container mx-auto px-4 py-8 max-w-xl">
      <div className="mb-8">
        <Link href="/" className="inline-flex items-center text-sm text-gray-600 hover:text-gray-900">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Home
        </Link>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded-full bg-blue-100 flex items-center justify-center">
              <Building2 className="h-6 w-6 text-blue-600" />
            </div>
            <div>
              <CardTitle>Institution Onboarding</CardTitle>
              <CardDescription>
                Register your institution to start issuing verified documents
              </CardDescription>
            </div>
          </div>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">
            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="name">Institution Name *</Label>
              <Input
                id="name"
                placeholder="e.g., Nagpur University"
                value={formData.name}
                onChange={(e) => {
                  setFormData({
                    ...formData,
                    name: e.target.value,
                    slug: formData.slug || generateSlug(e.target.value)
                  })
                }}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="slug">URL Slug *</Label>
              <Input
                id="slug"
                placeholder="e.g., nagpur-university"
                value={formData.slug}
                onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
                pattern="^[a-z0-9-]+$"
                required
              />
              <p className="text-xs text-gray-500">Only lowercase letters, numbers, and hyphens</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Contact Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@university.edu"
                value={formData.contact_email}
                onChange={(e) => setFormData({ ...formData, contact_email: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="domain">Institution Domain</Label>
              <Input
                id="domain"
                placeholder="university.edu"
                value={formData.domain}
                onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
              />
            </div>
          </CardContent>

          <CardFooter>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? (
                <>
                  <span className="animate-spin mr-2">⏳</span>
                  Generating Keypair...
                </>
              ) : (
                <>
                  <Key className="mr-2 h-4 w-4" />
                  Generate Ed25519 Keypair & Register
                </>
              )}
            </Button>
          </CardFooter>
        </form>
      </Card>
    </main>
  )
}
