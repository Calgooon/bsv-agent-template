<p align="center">
  <img src="https://img.shields.io/badge/BSV-Agent_Template-blue?style=for-the-badge&logo=bitcoin-sv" alt="BSV Agent Template" />
</p>

<h1 align="center">bsv-agent-template</h1>

<p align="center">
  <strong>Ship a paid API in 15 minutes.</strong><br/>
  A Rust + Cloudflare Worker starter kit with BRC-31 authentication and BRC-29 micropayments baked in.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#endpoints">Endpoints</a> &middot;
  <a href="#how-payment-works">How Payment Works</a> &middot;
  <a href="#build-your-own">Build Your Own</a> &middot;
  <a href="#testing">Testing</a>
</p>

---

## What is this?

This template gives you a working Cloudflare Worker that:

1. **Authenticates every request** using [BRC-31](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0031.md) mutual authentication — both client and server prove their identity with cryptographic signatures on every message.

2. **Accepts micropayments** using [BRC-29](https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0029.md) — paid endpoints return HTTP 402 with a payment request, the client creates a BSV transaction, and retries with payment. The server verifies and internalizes the funds automatically.

Fork it. Replace the hello-world logic with your service. Deploy. You now have a paid API.

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/Calgooon/bsv-agent-template.git
cd bsv-agent-template
npm install

# 2. Configure
cp .dev.vars.example .dev.vars
# Edit .dev.vars — set a 64-char hex private key (or generate one)

# 3. Run
npm run dev
# Server is live at http://localhost:8787
```

> **Note:** This project depends on `bsv-auth-cloudflare` and `bsv-sdk`, which are private crates. Contact [@Calgooon](https://github.com/Calgooon) for access.

---

## Endpoints

| Route | Method | Auth | Payment | What it does |
|:------|:------:|:----:|:-------:|:-------------|
| `/` | `GET` | — | — | Health check. Returns `{"status": "ok"}` |
| `/.well-known/x402-info` | `GET` | — | — | API discovery manifest (endpoints, pricing, server identity) |
| `/.well-known/auth` | `POST` | — | — | BRC-31 handshake (handled automatically by middleware) |
| `/free` | `POST` | Yes | — | Returns a greeting with the caller's identity key |
| `/paid` | `POST` | Yes | 10 sats | Returns a confirmation message + payment receipt |

---

## How Payment Works

```
  Client                                Server
    │                                     │
    │  POST /paid                         │
    │  (no payment header)                │
    │────────────────────────────────────>│
    │                                     │
    │  HTTP 402                           │
    │  x-bsv-payment-satoshis-required: 10│
    │  x-bsv-payment-derivation-prefix: … │
    │<────────────────────────────────────│
    │                                     │
    │  ┌─────────────────────────┐        │
    │  │ Client wallet creates   │        │
    │  │ a 10-sat BSV transaction│        │
    │  │ to server's derived key │        │
    │  └─────────────────────────┘        │
    │                                     │
    │  POST /paid                         │
    │  x-bsv-payment: {tx, prefix, suffix}│
    │────────────────────────────────────>│
    │                                     │
    │                    Verify nonce ✓    │
    │                    Decode BEEF tx ✓  │
    │                    Internalize via   │
    │                    storage server ✓  │
    │                                     │
    │  HTTP 200                           │
    │  {"message": "Payment received!",   │
    │   "payment": {"accepted": true,     │
    │               "txid": "464dec..."}} │
    │<────────────────────────────────────│
```

The full flow happens in **two HTTP round-trips**. The client library ([x402-client](https://github.com/Calgooon/x402)) handles this automatically.

---

## Build Your Own

The template is designed to be extended. Here's how to add a new paid endpoint:

### 1. Set your price

At the top of `src/lib.rs`:

```rust
const PAID_ENDPOINT_PRICE: u64 = 10;  // Change this
```

Or define per-endpoint constants:

```rust
const PRICE_BASIC: u64 = 10;
const PRICE_PREMIUM: u64 = 1000;
```

### 2. Write a handler

**Auth only** (no payment) — copy `handle_free`:

```rust
fn handle_my_endpoint(
    auth_context: &bsv_auth_cloudflare::types::AuthContext,
    session: &bsv_auth_cloudflare::middleware::AuthSession,
) -> Result<Response> {
    // auth_context.identity_key has the caller's public key
    let body = serde_json::json!({
        "result": "your data here"
    });
    sign_json_response(&body, 200, &[], session)
        .map_err(|e| Error::from(e.to_string()))
}
```

**Auth + payment** — copy `handle_paid` and put your business logic in the "Payment accepted!" section (search for that comment in `src/lib.rs`).

### 3. Add a route

In the `match path.as_str()` block:

```rust
"/my-endpoint" => handle_my_endpoint(&auth_context, &session),
```

### 4. Update the discovery manifest

Add your endpoint to the `handle_x402_info` function so clients can discover it programmatically.

---

## Testing

Use the [x402-client](https://github.com/Calgooon/x402) to test against your running server:

```bash
# Discover all endpoints
python3 brc31_helpers.py discover "http://localhost:8787"

# Test authentication
python3 brc31_helpers.py auth POST "http://localhost:8787/free"

# Test payment (auto-handles 402 → pay → retry)
python3 brc31_helpers.py pay POST "http://localhost:8787/paid"
```

Or test the health check with curl:

```bash
curl http://localhost:8787/
# {"status":"ok","service":"bsv-agent-template"}
```

---

## Project Structure

```
bsv-agent-template/
├── src/
│   └── lib.rs              # Worker entry point, routing, handlers
├── Cargo.toml              # Rust dependencies
├── wrangler.toml           # Cloudflare Worker config
├── package.json            # npm scripts (dev, build)
├── .dev.vars.example       # Template for local secrets
└── .gitignore
```

### Key dependencies

| Crate | Source | Purpose |
|:------|:------:|:--------|
| `bsv-auth-cloudflare` | Private | BRC-31 auth middleware, CORS, response signing, storage client |
| `bsv-sdk` | Private | Key derivation, nonce creation/verification, transaction parsing |
| `worker` | crates.io | Cloudflare Workers runtime |
| `serde` / `serde_json` | crates.io | JSON serialization |

---

## Deploy to Cloudflare

```bash
# 1. Set your account_id in wrangler.toml

# 2. Create a KV namespace for auth sessions
npx wrangler kv namespace create AUTH_SESSIONS
# Copy the id into wrangler.toml

# 3. Set the server private key as a secret
npx wrangler secret put SERVER_PRIVATE_KEY

# 4. Deploy
npx wrangler deploy
```

Your agent is now live at `https://bsv-agent-template.<your-subdomain>.workers.dev`.

---

## Related Projects

- **[x402-client](https://github.com/Calgooon/x402)** — Python client library for BRC-31 auth + BRC-29 payment. Use this to test your agent.
- **[bsv-auth-cloudflare](https://github.com/Calgooon)** — The Rust middleware that powers authentication and payment verification.
- **[banana-agent](https://github.com/Calgooon/banana-agent)** — A real-world agent built from this template: AI image generation with dynamic pricing.

---

## License

MIT
