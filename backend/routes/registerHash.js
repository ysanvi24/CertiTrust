import { createClient } from '@supabase/supabase-js';
import { sha256Bytes32 } from '../utils/hash.js';
import { attestHash } from '../utils/blockchain.js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

export async function registerHash(req) {
  try {
    const body = req.method === 'POST' ? await req.json() : {};
    const fileHash = body.fileHash || body.hash;
    const owner = body.owner || body.issuer || 'did:example:institution';
    const fileName = body.fileName || null;
    const metadata = body.metadata || null;
    const attest = Boolean(body.attest);

    if (!fileHash) return new Response(JSON.stringify({ error: 'fileHash required' }), { status: 400 });

    // store document metadata in Supabase
    const insertObj = { file_hash: fileHash, owner, file_name: fileName, metadata };
    const { data: docData, error: docErr } = await supabase.from('documents').insert([insertObj]).select().single();
    if (docErr) throw docErr;

    let attestation = null;
    if (attest) {
      const rpcUrl = process.env.RPC_URL;
      const contractAddress = process.env.CONTRACT_ADDRESS;
      const deployerPrivateKey = process.env.DEPLOYER_PRIVATE_KEY;
      // use bytes32 form (0x...)
      const docHashBytes32 = sha256Bytes32(Buffer.from(fileHash, 'hex'));
      attestation = await attestHash({ rpcUrl, contractAddress, privateKey: deployerPrivateKey, docHash: docHashBytes32 });
      // store attestation record
      const { error: attErr } = await supabase.from('attestations').insert([{ document_id: docData.id, tx_hash: attestation.txHash, block_number: attestation.blockNumber, contract_address: contractAddress }]);
      if (attErr) throw attErr;
    }

    return new Response(JSON.stringify({ ok: true, document: docData, attestation }), { status: 200 });
  } catch (err) {
    console.error('registerHash error', err);
    return new Response(JSON.stringify({ error: err.message || String(err) }), { status: 500 });
  }
}
