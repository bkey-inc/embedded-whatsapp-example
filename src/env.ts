function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var ${name}`);
  return value;
}

export const env = {
  PORT: Number(process.env.PORT ?? 3000),
  PUBLIC_URL: required('PUBLIC_URL'), // https URL of this server, used in reveal links
  BMONI_PROXY_URL: required('BMONI_PROXY_URL'), // e.g. https://embedded.bmoni.example
  BMONI_API_KEY: required('BMONI_API_KEY'),
  BMONI_WEBHOOK_SECRET: required('BMONI_WEBHOOK_SECRET'), // from POST /v1/webhooks/config
  KAPSO_API_KEY: required('KAPSO_API_KEY'),
  KAPSO_BASE_URL: process.env.KAPSO_BASE_URL ?? 'https://app.kapso.ai/api/meta/',
  KAPSO_PHONE_NUMBER_ID: required('KAPSO_PHONE_NUMBER_ID'),
  KAPSO_WEBHOOK_SECRET: required('KAPSO_WEBHOOK_SECRET'),
  WALLET_CURRENCY: process.env.WALLET_CURRENCY ?? 'CNGN',
};
