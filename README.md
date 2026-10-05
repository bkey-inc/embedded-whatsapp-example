# BMoni Embedded × Kapso: WhatsApp wallet + card bot (example)

A TypeScript reference for running BMoni wallets and virtual cards entirely over WhatsApp.
Kapso carries the messages. useAzza's backend holds each user's wallet key in AWS KMS and
signs for them. The BMoni proxy API is used as-is, with no changes.

```
WhatsApp user ⇄ Kapso ⇄ this server ⇄ BMoni proxy (/v1)
                             │
                             └─ AWS KMS (one secp256k1 key per user, never exported)
```

## What it does

| Step | WhatsApp | Server | BMoni proxy call |
| --- | --- | --- | --- |
| Onboard | name → email → BVN | creates a KMS key, signs the owner proof | `POST /users`, `POST …/smart-wallets/owner-proof-challenges`, `POST …/smart-wallets/create-managed` |
| PIN | "Set PIN" link | stores a scrypt hash of a 6-digit PIN | none |
| Get a card | button | creates the card proposal once, signs it, polls until `COMPLETED` | `POST …/cards`, `GET …/proposals/:id/sign-payload`, `POST …/proposals/:id/sign`, `GET …/proposals/:id`, `GET …/smart-wallets/:id/cards` |
| Show card | one-time link + PIN | shows PAN/CVV on a no-store web page, never in chat | `POST …/cards/sensitive-data` |
| Card alerts | template message | verifies the BMoni webhook HMAC | inbound `card.transaction.created` |

Files: `src/server.ts` (webhooks + PIN pages), `src/bot.ts` (conversation), `src/bmoni.ts`
(proxy client), `src/signer.ts` (KMS signing), `src/store.ts` (in-memory state).

## Run it offline first

No accounts needed. Mock KMS, Kapso and BMoni run locally and the whole flow is exercised:

```bash
npm install
npm run smoke   # full flow against mocks
npm run check   # KMS DER → Ethereum signature conversion
npm run typecheck
```

## Run it for real

1. **AWS KMS.** The server's IAM role needs `kms:CreateKey`, `kms:GetPublicKey` and `kms:Sign`.
   Set `AWS_REGION`.
2. **Kapso.** Connect the WhatsApp number. Add a webhook to `https://<PUBLIC_URL>/webhooks/kapso`
   for `whatsapp.message.received`, and copy its secret into `KAPSO_WEBHOOK_SECRET`.
3. **WhatsApp template.** Get `card_transaction_alert` approved with two body variables
   (amount, merchant). Alerts can arrive outside the 24-hour window, so they must be templates.
4. **BMoni.** Get a partner API key, then register the callback:
   ```bash
   curl -X POST "$BMONI_PROXY_URL/v1/webhooks/config" -H "x-api-key: $BMONI_API_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"callbackUrl":"https://<PUBLIC_URL>/webhooks/bmoni","events":["card.transaction.created","card.fulfillment.updated"]}'
   ```
   Put the `secretKey` from the response in `BMONI_WEBHOOK_SECRET`.
5. `cp .env.example .env`, fill it in, export it, then `npm start`.

## Before production

- **Replace `src/store.ts`** with Postgres or Redis. `keyId` is the only link to a user's KMS key.
  If it's lost, recovery means rotating the wallet owner through BMoni, which is manual today.
- **Move the in-process card poll to a job queue** so issuance survives restarts. The bot already
  resumes a pending card when the user taps "Get a card" again, so nobody pays twice.
- **PCI-DSS.** This server receives raw PAN and CVV. It never stores or logs them, and the pages
  send `Cache-Control: no-store`. You're still in PCI scope, so plan for that.
- **Collect the BVN in a WhatsApp Flow** instead of chat, so it doesn't stay in chat history.
- **Add a lockout per user, not just per link.** Each reveal link allows 5 PIN tries, but a user
  can ask for new links.

## Confirm with BMoni

These are best readings of the proxy code, not tested against staging:

1. `POST /cards/sensitive-data` takes `identityId` + `cardId`. This example passes the
   `identityId` it set when creating the user, plus the platform card id. Confirm those are the
   right ids for smart-wallet cards.
2. Proposal `hashToSign` is signed as a raw ECDSA signature over the hash, with no EIP-191 prefix.
3. A virtual card ends at proposal status `COMPLETED`. This example treats `FAILED`, `REJECTED`,
   `CANCELLED` and `EXPIRED` as failed, and any other status as still in progress.
