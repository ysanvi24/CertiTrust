/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable React strict mode for development
  reactStrictMode: true,
  
  // Enable standalone output for Docker
  output: 'standalone',
  
  // Configure external API rewrites (optional, for proxying)
  async rewrites() {
    return [
      {
        source: '/api/backend/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/:path*`
      }
    ]
  },
  
  // Optimize images
  images: {
    unoptimized: true
  },
  
  // Reduce memory usage during build
  experimental: {
    optimizePackageImports: ['lucide-react']
  }
}

module.exports = nextConfig
