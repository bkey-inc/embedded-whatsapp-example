import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import express, { type Request, type Response } from 'express';
import { bmoni } from './bmoni.js';
import { enqueue, handleMessage, sendCardAlert } from './bot.js';
import { env } from './env.js';
import { MAX_PIN_ATTEMPTS, burnToken, findByBmoniUserId, firstTime, getToken, sessions } from './store.js';

const scryptAsync = promisify(scrypt) as (pin: string, salt: Buffer, len: number) => Promise<Buffer>;
const app = express();

function validSignature(rawBody: unknown, header: unknown, secret: string): rawBody is Buffer {
  if (!Buffer.isBuffer(rawBody) || typeof header !== 'string') return false;
  const expected = Buffer.from(createHmac('sha256', secret).update(rawBody).digest('hex'));
  const given = Buffer.from(header);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

// ── Kapso: inbound WhatsApp messages ────────────────────────────────────────
type KapsoMessageEvent = {
  message?: {
    id?: string;
    from?: string;
    text?: { body?: string };
    interactive?: { button_reply?: { id?: string } };
  };
  conversation?: { phone_number?: string };
};

app.post('/webhooks/kapso', express.raw({ type: 'application/json' }), (req: Request, res: Response) => {
  if (!validSignature(req.body, req.header('x-webhook-signature'), env.KAPSO_WEBHOOK_SECRET)) {
    return res.sendStatus(401);
  }
  // Ack fast: Kapso retries after 10s, and the bot's work (KMS, BMoni) takes longer than that.
  res.sendStatus(200);

  const key = req.header('x-idempotency-key');
  if (key && !firstTime(`kapso:${key}`)) return;
  if (req.header('x-webhook-event') !== 'whatsapp.message.received') return;

  const body = JSON.parse(req.body.toString('utf8'));
  const events: KapsoMessageEvent[] = body.batch === true ? body.data : [body];
  for (const event of events) {
    const phone = event.conversation?.phone_number ?? event.message?.from;
    // Users who hide their number arrive with only a BSUID; BMoni needs a phone number to onboard.
    if (!phone || (event.message?.id && !firstTime(`msg:${event.message.id}`))) continue;
    enqueue(phone, () =>
      handleMessage(phone, {
        text: event.message?.text?.body,
        buttonId: event.message?.interactive?.button_reply?.id,
      }),
    );
  }
});

// ── BMoni proxy: card events (partner configs only receive card.* and employee.*) ─
app.post('/webhooks/bmoni', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
  if (!validSignature(req.body, req.header('x-webhook-signature'), env.BMONI_WEBHOOK_SECRET)) {
    return res.sendStatus(401);
  }
  res.sendStatus(200);

  const id = req.header('x-webhook-id');
  if (id && !firstTime(`bmoni:${id}`)) return;
  const event = JSON.parse(req.body.toString('utf8')) as {
    eventType: string;
    payload: { userId?: string; amount?: string; currency?: string; merchant?: string; direction?: string };
  };
  const session = event.payload.userId ? findByBmoniUserId(event.payload.userId) : undefined;
  if (!session) return;

  if (event.eventType === 'card.transaction.created' && event.payload.direction === 'debit') {
    await sendCardAlert(
      session.phone,
      `${event.payload.currency ?? ''} ${event.payload.amount ?? ''}`.trim(),
      event.payload.merchant ?? 'a merchant',
    ).catch((err) => console.error('[bmoni-webhook] alert failed:', err));
  }
});

// ── PIN-gated pages: card data is only ever shown here, never in WhatsApp ────
const pageHeaders = (res: Response) =>
  res.set({
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
  });

const escape = (value: string) =>
  value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const page = (title: string, inner: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)}</title>
<style>
  body{font-family:system-ui,sans-serif;margin:0;padding:32px 20px;background:#f4f7f5;color:#10241b}
  main{max-width:380px;margin:0 auto}
  h1{font-size:1.4rem;margin:0 0 16px}
  input{font-size:1.4rem;letter-spacing:.4em;width:100%;padding:12px;border:1px solid #9bb5a8;border-radius:8px;box-sizing:border-box;margin:8px 0}
  button{font-size:1rem;width:100%;padding:14px;border:0;border-radius:8px;background:#0b6e4f;color:#fff;margin-top:8px}
  dl{background:#fff;border-radius:12px;padding:16px 20px}
  dt{font-size:.8rem;color:#4a6b5c;margin-top:12px} dd{margin:2px 0 0;font-size:1.2rem;font-variant-numeric:tabular-nums}
  .note{font-size:.85rem;color:#4a6b5c}
</style></head><body><main>${inner}</main></body></html>`;

const pinForm = (title: string, extra = '', error = '') =>
  page(title, `<h1>${escape(title)}</h1>${error ? `<p role="alert">${escape(error)}</p>` : ''}
<form method="post">
  <label>PIN<input name="pin" type="password" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="off" required></label>
  ${extra}
  <button type="submit">Continue</button>
</form>`);

const confirmField =
  '<label>Confirm PIN<input name="confirm" type="password" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="off" required></label>';
const expired = page('Link expired', '<h1>This link has expired</h1><p>Go back to WhatsApp and ask for a new one.</p>');

async function hashPin(pin: string): Promise<string> {
  const salt = randomBytes(16);
  return `${salt.toString('hex')}:${(await scryptAsync(pin, salt, 32)).toString('hex')}`;
}

async function pinMatches(pin: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  const candidate = await scryptAsync(pin, Buffer.from(salt, 'hex'), 32);
  return timingSafeEqual(candidate, Buffer.from(hash, 'hex'));
}

app.use(['/pin', '/card'], express.urlencoded({ extended: false }), (_req, res, next) => {
  pageHeaders(res);
  next();
});

app.get('/pin/:token', (req, res) => {
  const link = getToken(req.params.token);
  if (link?.purpose !== 'set_pin') return res.status(410).send(expired);
  res.send(pinForm('Set your card PIN', confirmField));
});

app.post('/pin/:token', async (req, res) => {
  const link = getToken(req.params.token);
  const session = link && sessions.get(link.phone);
  if (link?.purpose !== 'set_pin' || !session) return res.status(410).send(expired);

  const { pin, confirm } = req.body as { pin?: string; confirm?: string };
  if (!pin || !/^\d{6}$/.test(pin) || pin !== confirm) {
    return res.status(400).send(pinForm('Set your card PIN', confirmField, 'PINs must be 6 digits and match.'));
  }
  session.pinHash = await hashPin(pin);
  burnToken(req.params.token);
  res.send(page('PIN set', '<h1>PIN saved</h1><p>You can close this page and return to WhatsApp.</p>'));
});

app.get('/card/:token', (req, res) => {
  const link = getToken(req.params.token);
  if (link?.purpose !== 'reveal') return res.status(410).send(expired);
  res.send(pinForm('Enter your PIN to view your card'));
});

app.post('/card/:token', async (req, res) => {
  const link = getToken(req.params.token);
  const session = link && sessions.get(link.phone);
  if (link?.purpose !== 'reveal' || !session?.pinHash || !session.cardId) return res.status(410).send(expired);

  const pin = String((req.body as { pin?: string }).pin ?? '');
  if (!(await pinMatches(pin, session.pinHash))) {
    link.attempts += 1;
    const left = MAX_PIN_ATTEMPTS - link.attempts;
    if (left <= 0) {
      burnToken(req.params.token);
      return res.status(403).send(expired);
    }
    return res.status(401).send(pinForm('Enter your PIN to view your card', '', `Wrong PIN. ${left} tries left.`));
  }
  burnToken(req.params.token); // one view per link

  try {
    // Fetched fresh for this one response and never stored or logged (PCI: no CVV at rest).
    const { data } = await bmoni.getSensitiveCardData(session.bmoniUserId!, {
      identityId: session.identityId!,
      cardId: session.cardId,
    });
    res.send(
      page(
        'Your card',
        `<h1>Your virtual card</h1><dl>
          <dt>Card number</dt><dd>${escape(data.cardNumber.replace(/(\d{4})(?=\d)/g, '$1 '))}</dd>
          <dt>Expiry</dt><dd>${escape(data.expiryDate)}</dd>
          <dt>CVV</dt><dd>${escape(data.cvv)}</dd>
        </dl><p class="note">Close this page when you're done. This link won't work again.</p>`,
      ),
    );
  } catch (err) {
    console.error('[reveal] sensitive-data failed with status', (err as { status?: number }).status);
    res.status(502).send(page('Try again', '<h1>Could not load your card</h1><p>Ask for a new link in WhatsApp.</p>'));
  }
});

app.listen(env.PORT, () => console.log(`useAzza bot listening on :${env.PORT}`));
