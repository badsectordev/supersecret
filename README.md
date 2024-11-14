# SuperSecret

A secure, self-destructing message service built on Cloudflare Workers. Share sensitive information with one-time viewable links that expire after 24 hours.

## Features

- End-to-end encryption using AES-GCM
- One-time viewing (messages self-destruct after being read)
- 24-hour automatic expiration
- Zero server-side key storage
- Hybrid key system (master key + per-message key)

## Deployment

1. Install Wrangler CLI:
```bash
npm install -g wrangler
```

2. Create KV namespace:
```bash
wrangler kv:namespace create SUPER_SECRETS
```

3. Update wrangler.toml with your KV namespace ID:
```toml
name = "supersecret"
main = "src/worker.js"
compatibility_date = "2024-01-01"


[[kv_namespaces]]
binding = "SUPER_SECRETS"
id = "your-kv-namespace-id"
```

4. Set your master key:
```bash
wrangler secret put MASTER_KEY
```

5. Deploy:
```bash
wrangler deploy
```

## Security

- Messages are encrypted using AES-GCM with a hybrid key system
- Master key never leaves the server
- Dynamic key per message passed via URL fragment
- Keys are derived using HKDF
- All secrets expire after 24 hours
- Messages are deleted immediately after viewing

## Development

```bash
# Run locally
wrangler dev

# Test
wrangler dev --test

# Deploy
wrangler deploy
```

## License

MIT
