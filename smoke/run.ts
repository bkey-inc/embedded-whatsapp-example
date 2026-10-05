import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

Object.assign(process.env, {
  PORT: '4997',
  PUBLIC_URL: 'http://localhost:4997',
  BMONI_PROXY_URL: 'http://localhost:4999',
  BMONI_API_KEY: 'test-key',
  BMONI_WEBHOOK_SECRET: 'bmoni-secret',
  KAPSO_API_KEY: 'kapso-key',
  KAPSO_BASE_URL: 'http://localhost:4999/',
  KAPSO_PHONE_NUMBER_ID: '123456',
  KAPSO_WEBHOOK_SECRET: 'kapso-secret',
  AWS_REGION: 'us-east-1',
  AWS_ACCESS_KEY_ID: 'test',
  AWS_SECRET_ACCESS_KEY: 'test',
  AWS_ENDPOINT_URL_KMS: 'http://localhost:4998',
});

const { outbound, calls } = await import('./mocks.js');
await import('../src/server.js');
await sleep(300);

const APP = 'http://localhost:4997';
const PHONE = '2348012345678';
const sign = (body: string, secret: string) => createHmac('sha256', secret).update(body).digest('hex');

async function kapso(message: object, opts: { key?: string; badSig?: boolean } = {}) {
  const body = JSON.stringify({ message: { id: `wamid.${randomUUID()}`, from: PHONE, ...message }, conversation: { phone_number: PHONE }, phone_number_id: '123456' });
  return fetch(`${APP}/webhooks/kapso`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-webhook-event': 'whatsapp.message.received',
      'x-idempotency-key': opts.key ?? randomUUID(),
      'x-webhook-signature': opts.badSig ? 'deadbeef' : sign(body, 'kapso-secret'),
    },
    body,
  });
}
const text = (t: string, key?: string) => kapso({ type: 'text', text: { body: t } }, { key });
const button = (id: string) => kapso({ type: 'interactive', interactive: { type: 'button_reply', button_reply: { id, title: id } } });

async function waitFor(n: number, ms = 20_000) {
  const end = Date.now() + ms;
  while (outbound.length < n) {
    if (Date.now() > end) throw new Error(`Timed out waiting for ${n} outbound, have ${outbound.length}: ${JSON.stringify(outbound.slice(-3))}`);
    await sleep(50);
  }
}
const last = () => outbound[outbound.length - 1].body;
const lastText = () => JSON.stringify(last());
const linkPath = () => new URL(last().interactive.action.parameters.url).pathname;
const form = (o: Record<string, string>) => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o) });

// signature + dedupe
assert.equal((await kapso({ type: 'text', text: { body: 'hi' } }, { badSig: true })).status, 401);
await text('hi', 'dup-1'); await waitFor(1);
assert.match(lastText(), /first name/);
await text('hi', 'dup-1'); await sleep(300);
assert.equal(outbound.length, 1, 'duplicate Kapso delivery must be ignored');

// onboarding questions + validation
await text('Ada'); await waitFor(2); assert.match(lastText(), /email/);
await text('not-an-email'); await waitFor(3); assert.match(lastText(), /doesn't look right/);
await text('ada@example.com'); await waitFor(4); assert.match(lastText(), /BVN/);
await text('123'); await waitFor(5); assert.match(lastText(), /exactly 11 digits/);
await text('00000000000'); await waitFor(7); assert.match(lastText(), /couldn't verify that BVN/);

// real onboarding: user → KMS key → owner proof → managed wallet
await text('22345678901'); await waitFor(11, 30_000);
const texts = outbound.slice(7).map((o) => JSON.stringify(o.body));
assert.ok(texts.some((t) => /Your wallet is ready/.test(t)), 'wallet ready message');
const pinMsg = outbound.find((o) => o.body.type === 'interactive' && o.body.interactive.type === 'cta_url');
assert.ok(pinMsg, 'PIN setup link sent');
const pinPath = new URL(pinMsg!.body.interactive.action.parameters.url).pathname;
assert.equal(last().interactive.type, 'button', 'menu shown');

// PIN page
assert.equal((await fetch(`${APP}${pinPath}`)).status, 200);
assert.equal((await fetch(`${APP}${pinPath}`, form({ pin: '123456', confirm: '654321' }))).status, 400);
const pinSet = await fetch(`${APP}${pinPath}`, form({ pin: '123456', confirm: '123456' }));
assert.equal(pinSet.status, 200);
assert.equal(pinSet.headers.get('cache-control'), 'no-store');
assert.equal((await fetch(`${APP}${pinPath}`)).status, 410, 'PIN link is single use');

// card issuance — double tap must create exactly one card
const before = outbound.length;
await button('get_card'); await button('get_card');
await waitFor(before + 2, 30_000);
assert.equal(calls.filter((c) => c === 'POST /v1/users/u1/cards').length, 1, 'card created once despite double tap');
assert.equal(calls.filter((c) => c.endsWith('/proposals/p1/sign')).length, 1, 'proposal signed once');
await waitFor(before + 4, 40_000); // "ready" + menu
assert.ok(outbound.slice(before).some((o) => /virtual card is ready/.test(JSON.stringify(o.body))));

// reveal
await button('show_card'); await waitFor(before + 5);
const cardPath = linkPath();
assert.equal((await fetch(`${APP}${cardPath}`)).status, 200);
const wrong = await fetch(`${APP}${cardPath}`, form({ pin: '000000' }));
assert.equal(wrong.status, 401); assert.match(await wrong.text(), /4 tries left/);
const shown = await fetch(`${APP}${cardPath}`, form({ pin: '123456' }));
const html = await shown.text();
assert.equal(shown.status, 200); assert.match(html, /5399 1234 1234 1234/); assert.match(html, /12\/29/);
assert.equal((await fetch(`${APP}${cardPath}`, form({ pin: '123456' }))).status, 410, 'reveal link is single use');
assert.ok(!outbound.some((o) => JSON.stringify(o.body).includes('5399')), 'PAN never sent to WhatsApp');

// BMoni webhook → template alert
const evt = JSON.stringify({ id: 'evt-1', eventType: 'card.transaction.created', payload: { userId: 'u1', cardId: 'card1', direction: 'debit', amount: '2500.00', currency: 'NGN', merchant: 'SHOPRITE' }, timestamp: new Date().toISOString() });
const post = (sig: string) => fetch(`${APP}/webhooks/bmoni`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-webhook-signature': sig, 'x-webhook-id': 'evt-1' }, body: evt });
assert.equal((await post('nope')).status, 401);
const n = outbound.length;
assert.equal((await post(sign(evt, 'bmoni-secret'))).status, 200); await waitFor(n + 1);
assert.equal(last().type, 'template'); assert.match(lastText(), /SHOPRITE/);
await post(sign(evt, 'bmoni-secret')); await sleep(300);
assert.equal(outbound.length, n + 1, 'duplicate BMoni event ignored');

console.log(`smoke: ok (${outbound.length} WhatsApp messages, ${calls.length} BMoni calls)`);
process.exit(0);
