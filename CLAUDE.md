# bsv-agent-template

Rust Cloudflare Worker template with BRC-31 mutual authentication and BRC-29 micropayments. Fork and add your own paid endpoints.

## Project Structure

```
bsv-agent-template/
├── src/
│   └── lib.rs              # All worker logic: routing, auth, payment, handlers
├── Cargo.toml              # Rust deps (bsv-auth-cloudflare + bsv-sdk are PRIVATE)
├── wrangler.toml            # CF Worker config (placeholder account_id and KV id)
├── package.json             # npm run dev / npm run build
├── .dev.vars.example        # Template for SERVER_PRIVATE_KEY
├── .dev.vars                # Actual secrets (gitignored)
└── .gitignore
```

## How to Run

```bash
# Local development
npm run dev
# → http://localhost:8787

# Build only (no server)
npm run build

# Compile check
cargo check --target wasm32-unknown-unknown

# Deploy to Cloudflare
npx wrangler deploy
```

## Dependencies

- **bsv-auth-cloudflare** (private, `path = "../rust-middleware/bsv-auth-cloudflare"`) — BRC-31 auth middleware: handshake, session management, request/response signing, CORS, payment header constants, `WorkerStorageClient` for internalizing payments via `storage.babbage.systems`.
- **bsv-sdk** (private, `path = "../rust-sdk"`) — BSV primitives: `PrivateKey`, `ProtoWallet`, `create_nonce`/`verify_nonce`, `from_base64`, `Transaction::from_beef`.
- **worker** (crates.io) — Cloudflare Workers Rust runtime.
- **serde** / **serde_json** (crates.io) — JSON serialization.

Contact [@Calgooon](https://github.com/Calgooon) for access to private crates.

## Architecture

### Endpoints

| Route | Method | Auth | Payment | Handler |
|:------|:------:|:----:|:-------:|:--------|
| `/` | GET | No | No | Inline in `main()` |
| `/.well-known/x402-info` | GET | No | No | `handle_x402_info()` |
| `/.well-known/auth` | POST | — | — | `process_auth()` (middleware) |
| `/free` | POST | Yes | No | `handle_free()` |
| `/paid` | POST | Yes | 10 sats | `handle_paid()` |

### Request Flow

1. `main()` → CORS preflight check → public endpoints → auth middleware → routing
2. Auth middleware (`process_auth`) handles BRC-31 handshake (returns `AuthResult::Response`) or verifies signatures (returns `AuthResult::Authenticated`)
3. Authenticated requests are routed by path to handler functions
4. All authenticated responses are signed via `sign_json_response()`

### Payment Flow (`handle_paid`)

1. Check `x-bsv-payment` header
2. **No header** → `create_nonce()` → return 402 with payment headers (version, satoshis-required, derivation-prefix)
3. **Header present** → parse `BsvPayment` JSON → `verify_nonce()` → `from_base64()` decode tx → `Transaction::from_beef()` extract txid → `WorkerStorageClient` internalize via storage.babbage.systems → return 200 with receipt

### Key Constants

```rust
const AGENT_NAME: &str = "bsv-agent-template";  // Nonce originator + manifest name
const PAID_ENDPOINT_PRICE: u64 = 10;             // Satoshis for /paid endpoint
```

## Adding New Endpoints

1. Write handler fn — follow `handle_free` (no payment) or `handle_paid` (with payment)
2. Add match arm in `main()` routing section
3. Add entry in `handle_x402_info()` manifest
4. Set price via constant at top of file

## Testing

Requires [MetaNet Client](https://projectbabbage.com) running locally (wallet at `localhost:3321`).

```bash
# x402-client scripts (from ~/bsv/calgooon-skills/skills/x402/scripts/)
python3 brc31_helpers.py discover "http://localhost:8787"
python3 brc31_helpers.py auth POST "http://localhost:8787/free"
python3 brc31_helpers.py pay POST "http://localhost:8787/paid"  # spends 10 real sats
```

Or basic health check:

```bash
curl http://localhost:8787/
# {"status":"ok","service":"bsv-agent-template"}
```

## Configuration

- **SERVER_PRIVATE_KEY** — 64-char hex private key. Set in `.dev.vars` (local) or `npx wrangler secret put` (production).
- **AUTH_SESSIONS** — KV namespace binding for session storage. Create with `npx wrangler kv namespace create AUTH_SESSIONS`.
- **account_id** — Your Cloudflare account ID in `wrangler.toml`.

## Critical Notes

- `bsv-auth-cloudflare` and `bsv-sdk` are private path dependencies. The repo won't compile without them cloned as siblings.
- Payment internalization goes through `storage.babbage.systems` (mainnet). Test payments spend real sats.
- The nonce originator (`AGENT_NAME`) must match between `create_nonce` and `verify_nonce` — changing it after issuing 402s will break in-flight payments.
- `.dev.vars` is gitignored. Only `.dev.vars.example` is committed. Never commit real keys.
- The KV id in `wrangler.toml` is a placeholder — must be replaced before `wrangler dev` will work with KV persistence.
