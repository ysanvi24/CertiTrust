import { createClient } from '@supabase/supabase-js';
import { sha256Bytes32 } from '../utils/hash.js';
import { checkAttested } from '../utils/blockchain.js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

export async function verifyHash(req) {
  try {
    const url = new URL(req.url);
    const hash = (url.searchParams.get('hash') || (req.method === 'POST' ? (await req.json()).hash : null));
    if (!hash) return new Response(JSON.stringify({ error: 'hash required' }), { status: 400 });

    const normalized = hash.startsWith('0x') ? hash : '0x' + hash;

    // Check on-chain
    const rpcUrl = process.env.RPC_URL;
    const contractAddress = process.env.CONTRACT_ADDRESS;
    const onChain = await checkAttested({ rpcUrl, contractAddress, docHash: normalized });

    // Lookup document metadata in Supabase by file_hash (no 0x)
    let doc = null;
    try {
      const fileHash = hash.startsWith('0x') ? hash.slice(2) : hash;
      const { data, error } = await supabase.from('documents').select('*').eq('file_hash', fileHash).maybeSingle();
      if (!error) doc = data;
    } catch (e) {
      // ignore supabase lookup errors
    }

    return new Response(JSON.stringify({ ok: true, attested: onChain.attested, attestor: onChain.attestor, blockNumber: onChain.blockNumber, document: doc }), { status: 200 });
  } catch (err) {
    console.error('verifyHash error', err);
    return new Response(JSON.stringify({ error: err.message || String(err) }), { status: 500 });
  }
}
