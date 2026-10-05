// Self-check for the KMS DER → Ethereum signature conversion. Run: npm run check
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';
import { type Hex, hashMessage, hexToBytes, keccak256, toHex } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { derToEthSignature } from './signer.js';

for (let i = 0; i < 25; i++) {
  const pk = generatePrivateKey();
  const account = privateKeyToAccount(pk);

  // EIP-191 path (owner-proof challenge) must match a normal wallet signature byte-for-byte.
  const message = `BMoni owner proof ${i}`;
  const digest = hashMessage(message);
  const sig = secp256k1.sign(hexToBytes(digest), hexToBytes(pk));
  assert.equal(
    await derToEthSignature(sig.toDERRawBytes(), digest, account.address),
    await account.signMessage({ message }),
  );

  // KMS may return high-s; the result must still be the canonical low-s signature.
  const highS = new secp256k1.Signature(sig.r, secp256k1.CURVE.n - sig.s);
  assert.equal(
    await derToEthSignature(highS.toDERRawBytes(), digest, account.address),
    await account.signMessage({ message }),
  );

  // Raw-hash path (proposal hashes): no prefix, recovers to the owner.
  const raw: Hex = keccak256(toHex(`proposal ${i}`));
  const rawSig = secp256k1.sign(hexToBytes(raw), hexToBytes(pk));
  assert.equal(
    await derToEthSignature(rawSig.toDERRawBytes(), raw, account.address),
    await account.sign({ hash: raw }),
  );

  // A signature from a different key must be rejected, not silently accepted.
  const other = privateKeyToAccount(generatePrivateKey());
  await assert.rejects(derToEthSignature(sig.toDERRawBytes(), digest, other.address));
}
console.log('signer check: ok');
