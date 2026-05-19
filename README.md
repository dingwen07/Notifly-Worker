# Notifly Worker

Cloudflare Worker backend for Notifly. This repository is intentionally rooted like a Worker project so it can be connected directly to Cloudflare Workers Git integration.

## Local development

```bash
npm install
npm run dev -- --ip 0.0.0.0 --port 8787
```

Local-only values belong in `.dev.vars`; that file is ignored by git.

For local development, the Worker also accepts `GOOGLE_SERVICE_ACCOUNT_KEY_JSON_BASE64` when storing multiline JSON directly is inconvenient. Production should use the raw JSON secret below.

## Cloudflare setup

Create KV namespaces:

```bash
npx wrangler kv namespace create NOTIFLY_KV
npx wrangler kv namespace create NOTIFLY_KV --preview
```

Put the returned IDs in `wrangler.toml`.

Set the production service-account secret in Cloudflare:

```bash
npx wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON
```

Then deploy manually:

```bash
npm run deploy
```

For Git integration, connect this repository in Cloudflare Workers and use:

- Build command: `npm install`
- Deploy command: `npm run deploy`
- Root directory: repository root

Do not deploy `DEV_SKIP_INTEGRITY` or `DEV_SKIP_FCM` in production.
