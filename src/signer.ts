import {
  CreateKeyCommand,
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import {
  type Address,
  type Hex,
  bytesToBigInt,
  bytesToHex,
  hashMessage,
  hexToBytes,
  numberToHex,
  recoverAddress,
  serializeSignature,
} from 'viem';
import { publicKeyToAddress } from 'viem/accounts';

// Private keys never leave KMS: one secp256k1 key per WhatsApp user, KMS signs digests.
const kms = new KMSClient({});
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export async function createUserKey(
  label: string,
): Promise<{ keyId: string; address: Address }> {
  const { KeyMetadata } = await kms.send(
    new CreateKeyCommand({
      KeySpec: 'ECC_SECG_P256K1',
      KeyUsage: 'SIGN_VERIFY',
      Description: `useAzza wallet owner key: ${label}`,
    }),
  );
  if (!KeyMetadata?.KeyId) throw new Error('KMS did not return a key id');
  return { keyId: KeyMetadata.KeyId, address: await addressOf(KeyMetadata.KeyId) };
}

const addresses = new Map<string, Address>();

export async function addressOf(keyId: string): Promise<Address> {
  const cached = addresses.get(keyId);
  if (cached) return cached;
  const { PublicKey } = await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));
  if (!PublicKey) throw new Error(`KMS key ${keyId} has no public key`);
  // SPKI DER ends with the 65-byte uncompressed point (0x04 || X || Y).
  const address = publicKeyToAddress(bytesToHex(PublicKey.slice(-65)));
  addresses.set(keyId, address);
  return address;
}

/** EIP-191 personal_sign — used for the owner-proof challenge. */
export function signMessage(keyId: string, message: string): Promise<Hex> {
  return signDigest(keyId, hashMessage(message));
}

/** Raw ECDSA over a 32-byte hash (no prefix) — used for proposal hashes. */
export async function signDigest(keyId: string, digest: Hex): Promise<Hex> {
  const { Signature } = await kms.send(
    new SignCommand({
      KeyId: keyId,
      Message: hexToBytes(digest),
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    }),
  );
  if (!Signature) throw new Error(`KMS returned no signature for ${keyId}`);
  return derToEthSignature(Signature, digest, await addressOf(keyId));
}

/** KMS returns DER (r, s) with no recovery id; Ethereum wants low-s r||s||v. */
export async function derToEthSignature(
  der: Uint8Array,
  digest: Hex,
  expected: Address,
): Promise<Hex> {
  const { r, s: rawS } = parseDer(der);
  const s = rawS > SECP256K1_N / 2n ? SECP256K1_N - rawS : rawS;
  for (const yParity of [0, 1]) {
    const signature = serializeSignature({
      r: numberToHex(r, { size: 32 }),
      s: numberToHex(s, { size: 32 }),
      yParity,
    });
    const signer = await recoverAddress({ hash: digest, signature });
    if (signer.toLowerCase() === expected.toLowerCase()) return signature;
  }
  throw new Error('KMS signature does not recover to the expected address');
}

function parseDer(der: Uint8Array): { r: bigint; s: bigint } {
  // SEQUENCE { INTEGER r, INTEGER s } — secp256k1 sigs are ≤72 bytes, so lengths are single-byte.
  if (der[0] !== 0x30 || der[2] !== 0x02) throw new Error('Malformed DER signature');
  const rLen = der[3];
  const sTag = 4 + rLen;
  if (der[sTag] !== 0x02) throw new Error('Malformed DER signature');
  const sLen = der[sTag + 1];
  return {
    r: bytesToBigInt(der.slice(4, 4 + rLen)),
    s: bytesToBigInt(der.slice(sTag + 2, sTag + 2 + sLen)),
  };
}
