import type { Address, Hex } from 'viem';
import { env } from './env.js';

export class BmoniError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`BMoni proxy responded ${status}: ${JSON.stringify(body)}`);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${env.BMONI_PROXY_URL}/v1${path}`, {
    method,
    headers: { 'x-api-key': env.BMONI_API_KEY, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  const json: unknown = text ? JSON.parse(text) : null;
  if (!res.ok) throw new BmoniError(res.status, json);
  return json as T;
}

const u = (userId: string) => `/users/${encodeURIComponent(userId)}`;

export type SignRequest = { hashToSign: Hex; deadline: string };
export type Proposal = { id: string; status?: string };

export const bmoni = {
  createUser: (input: { firstName: string; email: string; phoneNumber: string; bvn: string; identityId: string }) =>
    call<{ user: { bmoniUserId: string } }>('POST', '/users', input),

  createOwnerProofChallenge: (userId: string, input: { currency: string; userOwnerAddress: Address }) =>
    call<{ challengeId: string; message: string; expiresAt: string }>(
      'POST', `${u(userId)}/smart-wallets/owner-proof-challenges`, input,
    ),

  createManagedWallet: (
    userId: string,
    input: { currency: string; userOwnerAddress: Address; ownerProofChallengeId: string; ownerProofSignature: Hex },
  ) => call<{ id: string; walletAddress: string | null }>('POST', `${u(userId)}/smart-wallets/create-managed`, input),

  createCard: (
    userId: string,
    input: { cardName: string; cardColor: string; currency: 'NGN' | 'USD'; type: 'virtual'; smartWalletId: string },
  ) =>
    call<{ flow: 'personal' | 'group'; proposalId?: string }>(
      'POST', `${u(userId)}/cards`, input,
    ),

  getProposalSignPayload: (userId: string, proposalId: string) =>
    call<{ data: SignRequest }>('GET', `${u(userId)}/smart-wallets/proposals/${proposalId}/sign-payload`),

  signProposal: (userId: string, proposalId: string, signature: Hex) =>
    call<unknown>('POST', `${u(userId)}/smart-wallets/proposals/${proposalId}/sign`, { signature }),

  getProposal: (userId: string, proposalId: string) =>
    call<{ data: { proposal: Proposal } }>('GET', `${u(userId)}/smart-wallets/proposals/${proposalId}`),

  listWalletCards: (userId: string, smartWalletId: string) =>
    call<{ cards: Array<{ id: string; type: string; status: string }> }>(
      'GET', `${u(userId)}/smart-wallets/${smartWalletId}/cards`,
    ),

  // Returns raw PAN + CVV. Whoever calls this is in PCI scope — never log, cache or persist the result.
  getSensitiveCardData: (userId: string, input: { identityId: string; cardId: string }) =>
    call<{ data: { cardNumber: string; cvv: string; expiryDate: string; cardholderName?: string } }>(
      'POST', `${u(userId)}/cards/sensitive-data`, input,
    ),
};
