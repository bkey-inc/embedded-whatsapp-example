import { randomBytes } from 'node:crypto';

// ponytail: in-memory maps keep the example runnable; production needs Postgres/Redis.
// keyId is the one field you must never lose: it is the only link to the user's KMS key.

export type Step = 'ask_name' | 'ask_email' | 'ask_bvn' | 'creating' | 'ready';

export interface Session {
  phone: string; // WhatsApp number, digits only
  step: Step;
  firstName?: string;
  email?: string;
  bmoniUserId?: string;
  identityId?: string;
  keyId?: string;
  smartWalletId?: string;
  cardId?: string;
  pendingCardProposalId?: string;
  cardProposalSigned?: boolean;
  pinHash?: string; // scrypt "salt:hash", never the PIN itself
}

export const sessions = new Map<string, Session>();

export const findByBmoniUserId = (bmoniUserId: string) =>
  [...sessions.values()].find((s) => s.bmoniUserId === bmoniUserId);

export interface LinkToken {
  phone: string;
  purpose: 'set_pin' | 'reveal';
  expiresAt: number;
  attempts: number;
}

const tokens = new Map<string, LinkToken>();
const TOKEN_TTL_MS = 10 * 60 * 1000;
export const MAX_PIN_ATTEMPTS = 5;

export function issueToken(phone: string, purpose: LinkToken['purpose']): string {
  const token = randomBytes(32).toString('base64url');
  tokens.set(token, { phone, purpose, expiresAt: Date.now() + TOKEN_TTL_MS, attempts: 0 });
  return token;
}

export function getToken(token: string): LinkToken | undefined {
  const entry = tokens.get(token);
  if (entry && entry.expiresAt > Date.now() && entry.attempts < MAX_PIN_ATTEMPTS) return entry;
  tokens.delete(token);
  return undefined;
}

export const burnToken = (token: string) => tokens.delete(token);

// Kapso and BMoni both retry deliveries; remember what we've already handled.
const seen = new Map<string, number>();
export function firstTime(id: string): boolean {
  const now = Date.now();
  for (const [key, at] of seen) if (now - at > 24 * 3600_000) seen.delete(key);
  if (seen.has(id)) return false;
  seen.set(id, now);
  return true;
}
