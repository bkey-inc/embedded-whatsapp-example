// Throwaway mocks: KMS (:4998), Kapso Graph proxy + BMoni proxy (:4999).
import http from 'node:http';
import { secp256k1 } from '@noble/curves/secp256k1';
import { type Address, type Hex, bytesToHex, keccak256, recoverAddress, toHex, verifyMessage } from 'viem';

const keys = new Map<string, Uint8Array>();
const SPKI_PREFIX = Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex');

const read = (req: http.IncomingMessage) =>
  new Promise<string>((r) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => r(b));
  });

http
  .createServer(async (req, res) => {
    const target = String(req.headers['x-amz-target'] ?? '');
    const body = JSON.parse((await read(req)) || '{}');
    const send = (o: unknown) => {
      res.setHeader('content-type', 'application/x-amz-json-1.1');
      res.end(JSON.stringify(o));
    };
    if (target.endsWith('CreateKey')) {
      const id = `key-${keys.size + 1}`;
      keys.set(id, secp256k1.utils.randomPrivateKey());
      return send({ KeyMetadata: { KeyId: id, Arn: `arn:aws:kms:us-east-1:0:key/${id}` } });
    }
    if (target.endsWith('GetPublicKey')) {
      const pub = secp256k1.getPublicKey(keys.get(body.KeyId)!, false);
      return send({ KeyId: body.KeyId, PublicKey: Buffer.concat([SPKI_PREFIX, pub]).toString('base64') });
    }
    if (target.endsWith('Sign')) {
      const digest = Buffer.from(body.Message, 'base64');
      const sig = secp256k1.sign(digest, keys.get(body.KeyId)!, { lowS: false });
      return send({ KeyId: body.KeyId, Signature: Buffer.from(sig.toDERRawBytes()).toString('base64'), SigningAlgorithm: 'ECDSA_SHA_256' });
    }
    res.statusCode = 400;
    send({ __type: 'UnsupportedOperation', target });
  })
  .listen(4998);

export const outbound: Array<{ path: string; body: any }> = [];
export const calls: string[] = [];
let owner: Address | undefined;
let challengeMsg = '';
let signPayloadCalls = 0;
let proposalPolls = 0;
const HASH: Hex = keccak256(toHex('card proposal p1'));
let proposalStatus = 'PENDING_SIGNATURES';

http
  .createServer(async (req, res) => {
    const raw = await read(req);
    const body = raw ? JSON.parse(raw) : undefined;
    const url = req.url ?? '';
    const json = (code: number, o: unknown) => {
      res.statusCode = code;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(o));
    };
    if (url.endsWith('/messages')) {
      outbound.push({ path: url, body });
      return json(200, { messaging_product: 'whatsapp', contacts: [{ input: body.to, wa_id: body.to }], messages: [{ id: `wamid.out${outbound.length}` }] });
    }
    if (!url.startsWith('/v1/')) return json(404, { url });
    if (req.headers['x-api-key'] !== 'test-key') return json(401, { message: 'bad key' });
    calls.push(`${req.method} ${url}`);
    const m = req.method;

    if (m === 'POST' && url === '/v1/users') {
      if (body.bvn === '00000000000') return json(400, { statusCode: 400, message: 'Invalid BVN' });
      return json(201, { user: { bmoniUserId: 'u1' } });
    }
    if (m === 'POST' && url.endsWith('/owner-proof-challenges')) {
      owner = body.userOwnerAddress;
      challengeMsg = `BMoni owner proof for ${owner} nonce ${Date.now()}`;
      return json(201, { challengeId: 'c1', groupId: 'g1', message: challengeMsg, expiresAt: new Date(Date.now() + 6e5).toISOString() });
    }
    if (m === 'POST' && url.endsWith('/create-managed')) {
      const ok = await verifyMessage({ address: body.userOwnerAddress, message: challengeMsg, signature: body.ownerProofSignature });
      if (!ok || body.ownerProofChallengeId !== 'c1') return json(400, { message: 'Owner proof signature invalid' });
      return json(201, { id: 'w1', walletAddress: '0x000000000000000000000000000000000000dEaD' });
    }
    if (m === 'POST' && url === '/v1/users/u1/cards') {
      return json(200, { flow: 'group', proposalId: 'p1', feeAmount: '1000', feeCurrency: 'NGN', proposalStatus: 'PENDING_APPROVALS', signPayloadPending: true });
    }
    if (m === 'GET' && url.endsWith('/proposals/p1/sign-payload')) {
      signPayloadCalls++;
      if (signPayloadCalls === 1) return json(404, { message: 'not ready' });
      return json(200, { success: true, data: { method: 'evm', walletIndex: 0, workflowId: 'wf', hashToSign: HASH, payload: HASH, deadline: new Date(Date.now() + 6e5).toISOString() } });
    }
    if (m === 'POST' && url.endsWith('/proposals/p1/sign')) {
      const signer = await recoverAddress({ hash: HASH, signature: body.signature });
      if (signer.toLowerCase() !== owner?.toLowerCase()) return json(400, { message: 'signer not authorised' });
      proposalStatus = 'EXECUTING';
      return json(200, { success: true, data: { proposal: { id: 'p1', status: proposalStatus } } });
    }
    if (m === 'GET' && url.endsWith('/proposals/p1')) {
      if (proposalStatus === 'EXECUTING' && ++proposalPolls >= 2) proposalStatus = 'COMPLETED';
      return json(200, { success: true, data: { proposal: { id: 'p1', status: proposalStatus } } });
    }
    if (m === 'GET' && url.endsWith('/smart-wallets/w1/cards')) {
      return json(200, { cards: proposalStatus === 'COMPLETED' ? [{ id: 'card1', type: 'virtual', status: 'ACTIVE' }] : [] });
    }
    if (m === 'POST' && url.endsWith('/cards/sensitive-data')) {
      return json(200, { success: true, message: 'OK', data: { cardNumber: '5399123412341234', cvv: '123', expiryDate: '12/29' } });
    }
    json(404, { message: `mock: no route ${m} ${url}` });
  })
  .listen(4999);

export const hashHex = bytesToHex;
