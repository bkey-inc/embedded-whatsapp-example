import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { WhatsAppClient } from '@kapso/whatsapp-cloud-api';
import { BmoniError, type SignRequest, bmoni } from './bmoni.js';
import { env } from './env.js';
import { addressOf, createUserKey, signDigest, signMessage } from './signer.js';
import { type Session, issueToken, sessions } from './store.js';

const wa = new WhatsAppClient({
  baseUrl: env.KAPSO_BASE_URL,
  kapsoApiKey: env.KAPSO_API_KEY,
});
const phoneNumberId = env.KAPSO_PHONE_NUMBER_ID;

const say = (to: string, body: string) => wa.messages.sendText({ phoneNumberId, to, body });

const showMenu = (to: string) =>
  wa.messages.sendInteractiveButtons({
    phoneNumberId,
    to,
    bodyText: 'What would you like to do?',
    buttons: [
      { id: 'get_card', title: 'Get a card' },
      { id: 'show_card', title: 'Show card details' },
    ],
  });

const sendLink = (to: string, bodyText: string, displayText: string, path: string) =>
  wa.messages.sendInteractiveCtaUrl({
    phoneNumberId,
    to,
    bodyText,
    parameters: { displayText, url: `${env.PUBLIC_URL}${path}` },
  });

export const sendPinSetupLink = (phone: string) =>
  sendLink(
    phone,
    'Set a 6-digit PIN. You will need it to view your card details.',
    'Set PIN',
    `/pin/${issueToken(phone, 'set_pin')}`,
  );

// One message at a time per user: WhatsApp users double-tap, Kapso retries.
const queues = new Map<string, Promise<unknown>>();
export function enqueue(phone: string, job: () => Promise<unknown>): void {
  const next = (queues.get(phone) ?? Promise.resolve())
    .then(job)
    .catch(async (err) => {
      console.error(`[bot] ${phone}:`, err);
      await say(phone, friendlyError(err)).catch(() => undefined);
    })
    .finally(() => {
      if (queues.get(phone) === next) queues.delete(phone);
    });
  queues.set(phone, next);
}

export async function handleMessage(phone: string, input: { text?: string; buttonId?: string }) {
  const text = input.text?.trim() ?? '';
  let s = sessions.get(phone);
  if (!s) {
    s = { phone, step: 'ask_name' };
    sessions.set(phone, s);
    return say(phone, "Welcome to useAzza! Let's set up your wallet. What's your first name?");
  }

  switch (s.step) {
    case 'ask_name':
      if (!text) return say(phone, 'Please type your first name.');
      s.firstName = text;
      s.step = 'ask_email';
      return say(phone, `Thanks ${s.firstName}. What's your email address?`);

    case 'ask_email':
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return say(phone, "That email doesn't look right. Try again?");
      s.email = text;
      s.step = 'ask_bvn';
      // ponytail: BVN collected in chat for brevity; a WhatsApp Flow keeps it out of chat history.
      return say(phone, 'Last step: reply with your 11-digit BVN so we can verify your identity.');

    case 'ask_bvn':
      if (!/^\d{11}$/.test(text)) return say(phone, 'A BVN is exactly 11 digits. Please try again.');
      s.step = 'creating';
      await say(phone, 'Setting up your wallet, this takes a few seconds...');
      try {
        await onboard(s, text);
      } catch (err) {
        s.step = 'ask_bvn'; // let them retry with a corrected BVN
        throw err;
      }
      await say(phone, 'Your wallet is ready.');
      await sendPinSetupLink(phone);
      return showMenu(phone);

    case 'creating':
      return say(phone, 'Still setting things up, one moment...');

    case 'ready':
      if (input.buttonId === 'get_card') return requestCard(s);
      if (input.buttonId === 'show_card') return revealCard(s);
      return showMenu(phone);
  }
}

async function onboard(s: Session, bvn: string) {
  if (!s.bmoniUserId) {
    s.identityId = randomUUID();
    const { user } = await bmoni.createUser({
      firstName: s.firstName!,
      email: s.email!,
      phoneNumber: `+${s.phone}`,
      bvn, // proxy prefills name, DOB and address from the BVN record
      identityId: s.identityId,
    });
    s.bmoniUserId = user.bmoniUserId;
  }

  // useAzza holds the wallet owner key in KMS and signs on the user's behalf.
  // Persist keyId BEFORE using it, so a crash here never orphans a key.
  if (!s.keyId) s.keyId = (await createUserKey(s.bmoniUserId)).keyId;

  if (!s.smartWalletId) {
    const userOwnerAddress = await addressOf(s.keyId);
    const challenge = await bmoni.createOwnerProofChallenge(s.bmoniUserId, {
      currency: env.WALLET_CURRENCY,
      userOwnerAddress,
    });
    const wallet = await bmoni.createManagedWallet(s.bmoniUserId, {
      currency: env.WALLET_CURRENCY,
      userOwnerAddress,
      ownerProofChallengeId: challenge.challengeId,
      ownerProofSignature: await signMessage(s.keyId, challenge.message),
    });
    s.smartWalletId = wallet.id;
  }
  s.step = 'ready';
}

async function requestCard(s: Session) {
  if (s.cardId) return say(s.phone, 'You already have a card. Tap "Show card details" to see it.');

  // A card proposal carries a fee. Reuse the pending one on every retry so a
  // double tap or a crash mid-flow can never charge the user twice.
  if (!s.pendingCardProposalId) {
    // BVN is already on file from user creation, so the proxy's card KYC check passes without it.
    const created = await bmoni.createCard(s.bmoniUserId!, {
      cardName: `${s.firstName} useAzza`,
      cardColor: '#0B6E4F',
      currency: 'NGN',
      type: 'virtual',
      smartWalletId: s.smartWalletId!,
    });
    if (created.flow !== 'group' || !created.proposalId) {
      throw new Error(`Unexpected card flow ${created.flow}`);
    }
    s.pendingCardProposalId = created.proposalId;
  }
  const proposalId = s.pendingCardProposalId;

  if (!s.cardProposalSigned) {
    const payload = await waitForSignPayload(s.bmoniUserId!, proposalId);
    await bmoni.signProposal(s.bmoniUserId!, proposalId, await signDigest(s.keyId!, payload.hashToSign));
    s.cardProposalSigned = true;
  }

  await say(s.phone, "Your virtual card is being issued. I'll message you as soon as it's ready.");
  void watchCardIssuance(s, proposalId);
}

async function waitForSignPayload(userId: string, proposalId: string): Promise<SignRequest> {
  for (let i = 0; i < 20; i++) {
    try {
      return (await bmoni.getProposalSignPayload(userId, proposalId)).data;
    } catch (err) {
      if (!(err instanceof BmoniError && err.status === 404)) throw err; // 404 = not prepared yet
    }
    await sleep(3_000);
  }
  throw new Error(`Sign payload for proposal ${proposalId} never became ready`);
}

// Anything not COMPLETED or explicitly failed counts as still in flight, so an
// unfamiliar status can never unlock a second (paid) card request.
const PROPOSAL_FAILED = new Set(['FAILED', 'REJECTED', 'CANCELLED', 'EXPIRED']);
const watching = new Set<string>();

async function watchCardIssuance(s: Session, proposalId: string) {
  if (watching.has(proposalId)) return;
  watching.add(proposalId);
  try {
    // ponytail: in-process poll; a job queue survives restarts if issuance runs long.
    for (let i = 0; i < 60; i++) {
      await sleep(5_000);
      let status: string | undefined;
      try {
        status = (await bmoni.getProposal(s.bmoniUserId!, proposalId)).data.proposal.status;
      } catch (err) {
        console.warn(`[card] poll ${proposalId} failed, retrying:`, err);
        continue;
      }
      if (status !== 'COMPLETED' && !PROPOSAL_FAILED.has(status ?? '')) continue;

      // Terminal either way: only now is it safe to allow a fresh card request.
      s.pendingCardProposalId = undefined;
      s.cardProposalSigned = undefined;
      if (status !== 'COMPLETED') {
        console.error(`[card] proposal ${proposalId} ended ${status}`);
        return say(s.phone, "We couldn't issue your card. Please contact support before trying again.");
      }
      const { cards } = await bmoni.listWalletCards(s.bmoniUserId!, s.smartWalletId!);
      s.cardId = cards.find((c) => c.type === 'virtual')?.id;
      if (!s.cardId) {
        console.error(`[card] proposal ${proposalId} completed but no virtual card is listed`);
        return say(s.phone, 'Your card is almost ready. We will message you once it shows up.');
      }
      await say(s.phone, 'Your virtual card is ready!');
      return showMenu(s.phone);
    }
    // Still pending: keep the proposal so tapping "Get a card" resumes it instead of paying again.
    await say(s.phone, "Your card is taking longer than usual. Tap \"Get a card\" later to check on it.");
  } finally {
    watching.delete(proposalId);
  }
}

async function revealCard(s: Session) {
  if (!s.cardId) return say(s.phone, 'You don\'t have a card yet. Tap "Get a card" first.');
  if (!s.pinHash) return sendPinSetupLink(s.phone);
  // Card data never goes into the chat: the user gets a one-time, PIN-gated link instead.
  return sendLink(
    s.phone,
    'Tap below and enter your PIN to view your card. The link works once and expires in 10 minutes.',
    'View card',
    `/card/${issueToken(s.phone, 'reveal')}`,
  );
}

export function friendlyError(err: unknown): string {
  if (err instanceof BmoniError) {
    const detail = JSON.stringify(err.body).toLowerCase();
    if (err.status === 409) return 'An account already exists for this number. Please contact support.';
    if (err.status === 400 && detail.includes('bvn')) return "We couldn't verify that BVN. Please check it and send it again.";
    if (err.status === 400 && detail.includes('city')) return 'Your address on file is incomplete. Please contact support.';
    if (err.status === 429) return "You're going a bit fast. Please wait a minute and try again.";
  }
  return 'Something went wrong on our side. Please try again in a few minutes.';
}

export const sendCardAlert = (to: string, amount: string, merchant: string) =>
  // Card alerts can land outside the 24h service window, so they must be an approved template.
  wa.messages.sendTemplate({
    phoneNumberId,
    to,
    template: {
      name: 'card_transaction_alert',
      language: { code: 'en', policy: 'deterministic' },
      components: [{ type: 'body', parameters: [{ type: 'text', text: amount }, { type: 'text', text: merchant }] }],
    },
  });
