import { issueCredential } from './routes/issueCredential.js';
import { verifyCredential } from './routes/verifyCredential.js';
import { getCredential } from './routes/getCredential.js';

const PORT = process.env.PORT || 3000;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization'
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
}

async function attachCors(res) {
  // Read the original response body and re-wrap with CORS headers
  const text = await res.text();
  const headers = Object.fromEntries(res.headers.entries());
  return new Response(text, { status: res.status, headers: { ...headers, ...corsHeaders } });
}

Bun.serve({
  port: Number(PORT),
  fetch: async (req) => {
    const url = new URL(req.url);
    const pathname = url.pathname;

    // CORS preflight
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

    // Serve demo frontend static files under /frontend
    if (req.method === 'GET' && pathname.startsWith('/frontend')) {
      const relPath = pathname === '/frontend' || pathname === '/frontend/' ? '/index.html' : pathname.replace('/frontend', '');
      const filePath = `frontend${relPath}`;
      try {
        const contentType = filePath.endsWith('.js') ? 'application/javascript' : filePath.endsWith('.css') ? 'text/css' : 'text/html';
        return new Response(Bun.file(filePath), { status: 200, headers: { 'Content-Type': contentType, ...corsHeaders } });
      } catch (err) {
        return jsonResponse({ ok: false, error: 'Not found' }, 404);
      }
    }

    // Serve root index.html
    if (req.method === 'GET' && pathname === '/') {
      try {
        return new Response(Bun.file('frontend/index.html'), { headers: { 'Content-Type': 'text/html', ...corsHeaders } });
      } catch (err) {
        return jsonResponse({ ok: false, error: 'Not found' }, 404);
      }
    }

    // Simple routing
    if (req.method === 'POST' && pathname === '/api/issueCredential') return attachCors(await issueCredential(req));
    if (req.method === 'POST' && pathname === '/api/verifyCredential') return attachCors(await verifyCredential(req));
    if ((req.method === 'GET' || req.method === 'POST') && pathname === '/api/verifyHash') {
      const { verifyHash } = await import('./routes/verifyHash.js');
      return attachCors(await verifyHash(req));
    }
    if (req.method === 'GET' && pathname === '/api/getCredential') return attachCors(await getCredential(req));

    return jsonResponse({ ok: true, message: 'DPI-03 backend running' });
  }
});

console.log(`Server running on http://localhost:${PORT}`);
