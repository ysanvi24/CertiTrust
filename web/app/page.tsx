import Link from 'next/link'
import { Shield, FileCheck, Building2, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'

export default function Home() {
  return (
    <main className="container mx-auto px-4 py-16">
      {/* Hero Section */}
      <div className="text-center mb-16">
        <div className="flex justify-center mb-6">
          <Shield className="h-20 w-20 text-blue-600" />
        </div>
        <h1 className="text-5xl font-bold text-gray-900 mb-4">
          CertiTrust
        </h1>
        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
          DPI-3 Multi-Tenant Document Verification & Trust Layer.
          Secure, cryptographically verifiable credentials for institutions.
        </p>
      </div>

      {/* Feature Cards */}
      <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto mb-16">
        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <Building2 className="h-10 w-10 text-blue-600 mb-2" />
            <CardTitle>Institution Onboarding</CardTitle>
            <CardDescription>
              Register your institution with Ed25519 keypair generation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/admin/onboard">
              <Button className="w-full" variant="outline">
                Onboard <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <FileCheck className="h-10 w-10 text-green-600 mb-2" />
            <CardTitle>Issue Documents</CardTitle>
            <CardDescription>
              Create W3C Verifiable Credentials with QR stamps
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/dashboard/issue">
              <Button className="w-full" variant="outline">
                Issue <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        <Card className="hover:shadow-lg transition-shadow">
          <CardHeader>
            <Shield className="h-10 w-10 text-purple-600 mb-2" />
            <CardTitle>Verify Documents</CardTitle>
            <CardDescription>
              Instantly verify any CertiTrust stamped document
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/verify">
              <Button className="w-full" variant="outline">
                Verify <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>

      {/* Trust Indicators */}
      <div className="text-center">
        <div className="inline-flex items-center gap-8 text-sm text-gray-500">
          <span className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-green-500"></span>
            Ed25519 Signatures
          </span>
          <span className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-blue-500"></span>
            W3C VC Standard
          </span>
          <span className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-purple-500"></span>
            Hash-Chain Audit
          </span>
        </div>
      </div>
    </main>
  )
}
