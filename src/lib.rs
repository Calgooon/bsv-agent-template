//! BSV Agent Template: Cloudflare Worker with BRC-31 Auth + BRC-29 Micropayment
//!
//! This is a starter template for building paid API agents on the BSV blockchain.
//! It demonstrates the full authentication and payment flow:
//!
//! 1. **BRC-31 Mutual Authentication** — Client and server exchange identity keys
//!    and sign every request/response. Handled by the `bsv-auth-cloudflare` middleware.
//!
//! 2. **BRC-29 Micropayment** — Paid endpoints return HTTP 402 with a payment request.
//!    The client creates a BSV transaction and retries with the payment in a header.
//!    The server verifies and internalizes the payment via `storage.babbage.systems`.
//!
//! ## Endpoints
//!
//! - `GET  /`                      → Health check (public, no auth)
//! - `GET  /.well-known/x402-info` → API discovery manifest (public, no auth)
//! - `POST /.well-known/auth`      → BRC-31 handshake (handled by middleware)
//! - `POST /free`                  → Authenticated greeting (auth only, no payment)
//! - `POST /paid`                  → Paid hello world (auth + payment)
//!
//! ## How to add your own endpoints
//!
//! 1. Add a new match arm in the routing section (search for "Route authenticated requests")
//! 2. Write a handler function following `handle_free` (no payment) or `handle_paid` (with payment)
//! 3. Update the `handle_x402_info` manifest so clients can discover your endpoint
//! 4. If paid, set your price — either use the `PAID_ENDPOINT_PRICE` constant or
//!    calculate dynamic pricing like banana-agent does

#[allow(unused_imports)]
use bsv_auth_cloudflare::{
    add_cors_headers,
    client::WorkerStorageClient,
    init_panic_hook,
    middleware::{
        auth::handle_cors_preflight,
        payment::payment_headers,
        process_auth, sign_json_response,
        AuthMiddlewareOptions, AuthResult,
    },
    refund::issue_refund,
    types::BsvPayment,
};
use bsv_sdk::auth::utils::{create_nonce, verify_nonce};
use bsv_sdk::primitives::{from_base64, PrivateKey};
use bsv_sdk::wallet::ProtoWallet;
use worker::*;

// ─── Configuration ──────────────────────────────────────────────────
//
// Change these constants to customize your agent.

/// Your agent's name. Used in the x402-info manifest.
const AGENT_NAME: &str = "bsv-agent-template";

/// Nonce originator — must match between create_nonce and verify_nonce.
/// All production agents use ORIGINATOR for this constant.
const ORIGINATOR: &str = "bsv-agent-template";

/// Price in satoshis for the /paid endpoint.
/// 10 sats ≈ $0.000005 at $50/BSV — a trivial amount for testing.
/// Change this to whatever your service is worth.
const PAID_ENDPOINT_PRICE: u64 = 10;

// ─── Entry point ────────────────────────────────────────────────────

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    init_panic_hook();

    // Handle CORS preflight (OPTIONS requests).
    // This is required for browser-based clients.
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    // ── Public endpoints (no auth required) ─────────────────────────

    // Health check — useful for uptime monitoring
    if req.path() == "/" && req.method() == Method::Get {
        let response = Response::from_json(&serde_json::json!({
            "status": "ok",
            "service": AGENT_NAME
        }))?;
        return Ok(add_cors_headers(response));
    }

    // API discovery manifest — tells clients what endpoints exist,
    // what they cost, and how to authenticate
    if req.path() == "/.well-known/x402-info" && req.method() == Method::Get {
        return handle_x402_info(&env);
    }

    // ── Auth middleware ──────────────────────────────────────────────
    //
    // Everything below this point requires BRC-31 authentication.
    // The middleware handles:
    //   - POST /.well-known/auth  → handshake (returns AuthResult::Response)
    //   - All other POST requests → signature verification (returns AuthResult::Authenticated)

    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| Error::from(format!("SERVER_PRIVATE_KEY not set: {}", e)))?
        .to_string();

    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key.clone(),
        allow_unauthenticated: false,
        session_ttl_seconds: 3600, // Sessions last 1 hour
        ..Default::default()
    };

    // process_auth returns either:
    //   - AuthResult::Response — for handshake responses (send directly to client)
    //   - AuthResult::Authenticated — for verified requests (continue to routing)
    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

    let (auth_context, req, session, request_body) = match auth_result {
        AuthResult::Authenticated {
            context,
            request,
            session,
            body,
        } => (context, request, session, body),
        // Handshake response — send it back to the client
        AuthResult::Response(response) => return Ok(response),
    };

    // We need a session to sign responses. This should always exist
    // after successful authentication, but check just in case.
    let session = match session {
        Some(s) => s,
        None => {
            let resp = Response::from_json(&serde_json::json!({
                "status": "error",
                "code": "ERR_NO_SESSION",
                "description": "Authentication required"
            }))?
            .with_status(401);
            return Ok(add_cors_headers(resp));
        }
    };

    // ── Route authenticated requests ────────────────────────────────
    //
    // Add your own endpoints here! Follow the pattern:
    //   - Auth-only: call a handler like handle_free
    //   - Auth + payment: call a handler like handle_paid

    let path = req.path();
    match path.as_str() {
        "/free" => handle_free(&auth_context, &session),
        "/paid" => {
            match handle_paid(
                &req,
                &auth_context,
                &session,
                &server_key,
                &request_body,
                &env,
            )
            .await
            {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "code": "ERR_PAID_HANDLER",
                        "description": format!("{}", e)
                    });
                    let resp = Response::from_json(&body)?.with_status(500);
                    Ok(add_cors_headers(resp))
                }
            }
        }
        _ => {
            let body = serde_json::json!({
                "status": "error",
                "code": "NOT_FOUND",
                "description": "Unknown endpoint"
            });
            sign_json_response(&body, 404, &[], &session)
                .map_err(|e| Error::from(e.to_string()))
        }
    }
}

// ─── /free ──────────────────────────────────────────────────────────
//
// Example: authenticated endpoint with no payment.
// The client's identity key is available in auth_context.identity_key.

fn handle_free(
    auth_context: &bsv_auth_cloudflare::types::AuthContext,
    session: &bsv_auth_cloudflare::middleware::AuthSession,
) -> Result<Response> {
    let body = serde_json::json!({
        "message": "Hello! You are authenticated.",
        "your_identity": auth_context.identity_key,
        "authenticated": true
    });

    // sign_json_response signs the response body so the client can verify
    // the server's identity. This is the "mutual" part of mutual auth.
    sign_json_response(&body, 200, &[], session).map_err(|e| Error::from(e.to_string()))
}

// ─── /paid ──────────────────────────────────────────────────────────
//
// Example: authenticated endpoint with BRC-29 micropayment.
//
// The payment flow works in two round-trips:
//
// 1. Client sends POST /paid (no payment header)
//    → Server returns 402 with:
//      - x-bsv-payment-satoshis-required: 10
//      - x-bsv-payment-derivation-prefix: <nonce>
//
// 2. Client creates a BSV transaction paying 10 sats to the server's
//    derived key, then retries with:
//      - x-bsv-payment: {"derivationPrefix":"...","derivationSuffix":"...","transaction":"<base64>"}
//    → Server verifies the nonce, decodes the transaction, and internalizes
//      it via storage.babbage.systems
//    → Server returns 200 with payment receipt

async fn handle_paid(
    req: &Request,
    auth_context: &bsv_auth_cloudflare::types::AuthContext,
    session: &bsv_auth_cloudflare::middleware::AuthSession,
    server_key: &str,
    request_body: &[u8],
    env: &Env,
) -> Result<Response> {
    let private_key = PrivateKey::from_hex(server_key)
        .map_err(|e| Error::from(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));

    // Check for payment header. Two modes:
    //   - Header mode: x-bsv-payment contains the JSON directly
    //   - Body mode:   x-bsv-payment is "body", payment JSON is in request body
    let payment_header = req
        .headers()
        .get(payment_headers::PAYMENT)
        .ok()
        .flatten();

    let payment_json: Option<String> = match payment_header.as_deref() {
        Some("body") => {
            // Body mode — payment JSON is in the request body
            if request_body.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(request_body).into_owned())
            }
        }
        Some(json) => Some(json.to_string()),
        None => None,
    };

    match payment_json {
        None => {
            // ── No payment → return 402 ─────────────────────────────
            //
            // Create a nonce (derivation prefix) that the client will use
            // to derive the payment key. The server can later verify this
            // nonce to confirm it issued the payment request.

            let derivation_prefix = create_nonce(&wallet, None, ORIGINATOR)
                .await
                .map_err(|e| Error::from(e.to_string()))?;

            // Bind this nonce to the quoted price in KV (5-min TTL).
            // On payment, we verify the nonce exists and delete it.
            // This prevents:
            //   1. Nonce reuse (replay attacks) — each nonce is deleted after one use
            //   2. Price manipulation — if you add dynamic pricing, store the
            //      request parameters here and verify them on payment
            let kv = env.kv("AUTH_SESSIONS")?;
            let binding = serde_json::json!({
                "price_sats": PAID_ENDPOINT_PRICE,
            });
            kv.put(
                &format!("price:{}", derivation_prefix),
                &binding.to_string(),
            )?
            .expiration_ttl(300) // 5 minutes
            .execute()
            .await?;

            let body = serde_json::json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": PAID_ENDPOINT_PRICE,
                "description": format!(
                    "Payment of {} satoshis required to access this endpoint.",
                    PAID_ENDPOINT_PRICE
                )
            });

            // These headers tell the client how to construct the payment:
            //   - VERSION: protocol version
            //   - SATOSHIS_REQUIRED: how much to pay
            //   - DERIVATION_PREFIX: nonce for BRC-42 key derivation
            let payment_hdrs = vec![
                (payment_headers::VERSION.to_string(), "1.0".to_string()),
                (
                    payment_headers::SATOSHIS_REQUIRED.to_string(),
                    PAID_ENDPOINT_PRICE.to_string(),
                ),
                (
                    payment_headers::DERIVATION_PREFIX.to_string(),
                    derivation_prefix,
                ),
            ];

            sign_json_response(&body, 402, &payment_hdrs, session)
                .map_err(|e| Error::from(e.to_string()))
        }
        Some(payment_json_str) => {
            // ── Payment provided → verify and internalize ───────────

            // Parse the payment JSON from the client
            let payment: BsvPayment = serde_json::from_str(&payment_json_str)
                .map_err(|e| Error::from(format!("Invalid payment JSON: {}", e)))?;

            // Verify the derivation prefix is a nonce we issued.
            // This prevents replay attacks — only nonces created by our
            // server with our private key will pass verification.
            let nonce_valid =
                verify_nonce(&payment.derivation_prefix, &wallet, None, ORIGINATOR)
                    .await
                    .unwrap_or(false);

            if !nonce_valid {
                let body = serde_json::json!({
                    "status": "error",
                    "code": "ERR_INVALID_DERIVATION_PREFIX",
                    "description": "The derivation prefix nonce is not valid."
                });
                return sign_json_response(&body, 400, &[], session)
                    .map_err(|e| Error::from(e.to_string()));
            }

            // Verify the nonce exists in KV (proves it's unused) and delete it.
            // This makes each nonce single-use — prevents replay attacks.
            let kv = env.kv("AUTH_SESSIONS")?;
            let kv_key = format!("price:{}", payment.derivation_prefix);
            let stored = kv.get(&kv_key).text().await?;
            if stored.is_none() {
                let body = serde_json::json!({
                    "status": "error",
                    "code": "ERR_NONCE_EXPIRED_OR_USED",
                    "description": "Payment nonce has expired or was already used."
                });
                return sign_json_response(&body, 400, &[], session)
                    .map_err(|e| Error::from(e.to_string()));
            }
            // Delete to prevent reuse (one-time nonce)
            kv.delete(&kv_key).await?;

            // Decode the BSV transaction from base64
            let tx_bytes = from_base64(&payment.transaction)
                .map_err(|e| Error::from(format!("Invalid base64 transaction: {}", e)))?;

            // Extract the transaction ID from the BEEF-encoded transaction.
            // This is included in the response receipt for the client's records.
            let txid = match bsv_sdk::transaction::Transaction::from_beef(&tx_bytes, None) {
                Ok(tx) => Some(tx.id()),
                Err(e) => {
                    console_log!("[paid] BEEF parse warning (txID unavailable): {}", e);
                    None
                }
            };

            // ── Internalize payment via storage.babbage.systems ─────
            //
            // The storage server is the BSV wallet backend. We:
            // 1. Authenticate with it (BRC-31 handshake)
            // 2. Register our server identity
            // 3. Send the transaction for internalization
            //
            // This is how the server "receives" the payment — the storage
            // server records the output as belonging to our wallet.

            let storage_wallet = ProtoWallet::new(Some(
                PrivateKey::from_hex(server_key)
                    .map_err(|e| Error::from(format!("Invalid server key: {}", e)))?,
            ));
            let mut storage_client = WorkerStorageClient::mainnet(storage_wallet);

            storage_client
                .make_available()
                .await
                .map_err(|e| Error::from(format!("Storage makeAvailable failed: {}", e)))?;

            let server_identity = wallet.identity_key().to_hex();
            let user_result: serde_json::Value = storage_client
                .find_or_insert_user(&server_identity)
                .await
                .map_err(|e| {
                    Error::from(format!("Storage findOrInsertUser failed: {}", e))
                })?;
            let user_id = user_result.get("userId").and_then(|v| v.as_i64());

            // The internalizeAction call tells the storage server about the
            // transaction output that pays us. It needs:
            //   - tx: raw transaction bytes
            //   - outputs: which output index, derivation info, and sender identity
            //   - description: human-readable label
            let auth_json = serde_json::json!({
                "identityKey": server_identity,
                "userId": user_id
            });
            let args_json = serde_json::json!({
                "tx": tx_bytes,
                "outputs": [{
                    "outputIndex": 0,
                    "protocol": "wallet payment",
                    "paymentRemittance": {
                        "derivationPrefix": payment.derivation_prefix,
                        "derivationSuffix": payment.derivation_suffix,
                        "senderIdentityKey": auth_context.identity_key
                    }
                }],
                // Sender label enables counterparty tracking in wallet dashboards.
                // All production agents MUST include this.
                "labels": [format!("sender:{}", auth_context.identity_key)],
                "description": "Payment for API request"
            });

            let internalize_result: std::result::Result<serde_json::Value, _> =
                storage_client
                    .internalize_action(auth_json, args_json)
                    .await;

            match internalize_result {
                Ok(result) => {
                    let accepted = result
                        .get("accepted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    // ── Payment accepted! Return your service response here ──
                    //
                    // This is where you put your actual business logic.
                    // The client has paid — give them what they paid for.
                    //
                    // If your business logic can fail (e.g., calling an
                    // external API), wrap it like this:
                    //
                    //   let service_result = call_my_service().await;
                    //   match service_result {
                    //       Ok(data) => { /* build success response */ }
                    //       Err(e) => {
                    //           // Service failed after payment — issue refund
                    //           match issue_refund(
                    //               server_key,
                    //               &auth_context.identity_key,
                    //               PAID_ENDPOINT_PRICE,
                    //               &format!("Service failed: {}", e),
                    //               ORIGINATOR,
                    //           ).await {
                    //               Ok(refund) => {
                    //                   let body = serde_json::json!({
                    //                       "status": "error",
                    //                       "code": "ERR_SERVICE_FAILED_REFUND_ISSUED",
                    //                       "refund": { ... refund fields ... }
                    //                   });
                    //                   return sign_json_response(&body, 500, &[], session);
                    //               }
                    //               Err(_) => { /* refund failed — log and return error */ }
                    //           }
                    //       }
                    //   }

                    let body = serde_json::json!({
                        "message": "Payment received! Hello from bsv-agent-template.",
                        "your_identity": auth_context.identity_key,
                        "payment": {
                            "satoshis_paid": PAID_ENDPOINT_PRICE,
                            "accepted": accepted,
                            "txid": txid
                        }
                    });

                    // Include payment receipt headers so the client can
                    // programmatically confirm the payment was accepted
                    let mut extra_hdrs = vec![(
                        payment_headers::SATOSHIS_PAID.to_string(),
                        PAID_ENDPOINT_PRICE.to_string(),
                    )];
                    if let Some(ref txid_str) = txid {
                        extra_hdrs
                            .push((payment_headers::TXID.to_string(), txid_str.clone()));
                    }

                    sign_json_response(&body, 200, &extra_hdrs, session)
                        .map_err(|e| Error::from(e.to_string()))
                }
                Err(e) => {
                    let body = serde_json::json!({
                        "status": "error",
                        "code": "ERR_PAYMENT_FAILED",
                        "description": e.to_string()
                    });
                    sign_json_response(&body, 400, &[], session)
                        .map_err(|e| Error::from(e.to_string()))
                }
            }
        }
    }
}

// ─── /.well-known/x402-info ─────────────────────────────────────────
//
// API discovery manifest. Clients fetch this to learn:
//   - What endpoints exist and what they do
//   - Which require auth and/or payment
//   - How much each endpoint costs
//   - The server's identity key (for verifying signatures)
//
// This follows the x402 discovery convention. Update this whenever
// you add, remove, or change endpoints.

fn handle_x402_info(env: &Env) -> Result<Response> {
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| Error::from(format!("SERVER_PRIVATE_KEY not set: {}", e)))?
        .to_string();
    let private_key = PrivateKey::from_hex(&server_key)
        .map_err(|e| Error::from(format!("Invalid server key: {}", e)))?;
    let wallet = ProtoWallet::new(Some(private_key));
    let server_identity = wallet.identity_key().to_hex();

    let body = serde_json::json!({
        "name": AGENT_NAME,
        "description": "BSV agent template with BRC-31 authentication and BRC-29 micropayments. Fork this to build your own paid API agent.",
        "serverIdentityKey": server_identity,
        "authProtocol": "brc-31",
        "authEndpoint": "/.well-known/auth",
        "capabilities": {
            "auth": "brc-31",
            "payment": "brc-29",
            "refunds": true,
            "refundProtocol": "brc-29",
            "refundFormat": {
                "transaction": "string (base64 AtomicBEEF)",
                "derivationPrefix": "string (base64, HMAC-derived nonce)",
                "derivationSuffix": "string (base64, random 32 bytes)",
                "senderIdentityKey": "string (66-char hex compressed pubkey)",
                "satoshis": "integer (amount refunded)",
                "txid": "string (64-char hex transaction ID)"
            },
            "refundInternalization": {
                "protocol": "wallet payment",
                "outputIndex": 0,
                "method": "internalizeAction",
                "note": "Client decodes base64 AtomicBEEF, calls wallet internalizeAction with paymentRemittance."
            }
        },
        "endpoints": [
            {
                "path": "/",
                "method": "GET",
                "auth": false,
                "payment": null,
                "description": "Health check. Returns server status.",
                "input": null,
                "output": {
                    "contentType": "application/json",
                    "schema": { "status": "string", "service": "string" }
                },
                "delivery": "instant"
            },
            {
                "path": "/free",
                "method": "POST",
                "auth": true,
                "payment": null,
                "description": "Authenticated endpoint that echoes back your identity. No payment required. Use this to verify your BRC-31 authentication is working.",
                "input": {
                    "contentType": "application/json",
                    "schema": null,
                    "description": "Any JSON body or empty. The body content is not used."
                },
                "output": {
                    "contentType": "application/json",
                    "schema": {
                        "authenticated": "boolean (always true)",
                        "message": "string",
                        "your_identity": "string (66-char hex compressed public key)"
                    },
                    "description": "Confirms BRC-31 authentication succeeded and echoes the client's identity key."
                },
                "delivery": "instant"
            },
            {
                "path": "/paid",
                "method": "POST",
                "auth": true,
                "payment": {
                    "satoshis": PAID_ENDPOINT_PRICE,
                    "protocol": "brc-29",
                    "description": format!(
                        "Requires a {} satoshi BSV payment per request. Payment is sent via x-bsv-payment header.",
                        PAID_ENDPOINT_PRICE
                    )
                },
                "refund": {
                    "supported": true,
                    "trigger": "service_failure",
                    "delivery": "inline",
                    "description": "If the server fails to deliver after accepting payment, the error response includes a 'refund' object with AtomicBEEF and derivation info. Client should auto-internalize.",
                    "errorCodes": ["ERR_SERVICE_FAILED_REFUND_ISSUED"],
                    "responseField": "refund"
                },
                "description": format!(
                    "Paid endpoint requiring BRC-31 auth + {} satoshi BRC-29 payment. The server verifies the payment transaction and returns a receipt. Supports refunds on service failure.",
                    PAID_ENDPOINT_PRICE
                ),
                "input": {
                    "contentType": "application/json",
                    "schema": null,
                    "description": "Any JSON body or empty. When payment is in body mode (x-bsv-payment: body), the body contains the payment JSON."
                },
                "output": {
                    "contentType": "application/json",
                    "schema": {
                        "message": "string",
                        "your_identity": "string (66-char hex compressed public key)",
                        "payment": {
                            "satoshis_paid": "integer",
                            "accepted": "boolean",
                            "txid": "string (64-char hex transaction ID)"
                        }
                    },
                    "description": "Confirms payment was accepted. Includes the transaction ID and amount paid."
                },
                "delivery": "instant"
            }
        ]
    });

    let response = Response::from_json(&body)?;
    Ok(add_cors_headers(response))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_originator_matches_agent_name() {
        // ORIGINATOR is used for nonce creation/verification.
        // It must be consistent — changing it breaks in-flight payments.
        assert_eq!(ORIGINATOR, AGENT_NAME);
    }

    #[test]
    fn test_agent_name() {
        assert_eq!(AGENT_NAME, "bsv-agent-template");
    }

    #[test]
    fn test_price_is_set() {
        assert!(PAID_ENDPOINT_PRICE > 0, "Price must be at least 1 satoshi");
    }

    #[tokio::test]
    async fn test_nonce_roundtrip() {
        // Verify that create_nonce + verify_nonce work with our ORIGINATOR
        let pk = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let wallet = ProtoWallet::new(Some(pk));

        let nonce = create_nonce(&wallet, None, ORIGINATOR).await.unwrap();
        // Nonce must be valid base64 (used as derivation prefix for BRC-42)
        assert!(from_base64(&nonce).is_ok(), "Nonce must be valid base64");

        let valid = verify_nonce(&nonce, &wallet, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(valid, "Nonce should verify with same wallet and originator");
    }

    #[tokio::test]
    async fn test_nonce_wrong_wallet_fails() {
        let pk1 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let pk2 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let wallet1 = ProtoWallet::new(Some(pk1));
        let wallet2 = ProtoWallet::new(Some(pk2));

        let nonce = create_nonce(&wallet1, None, ORIGINATOR).await.unwrap();
        let valid = verify_nonce(&nonce, &wallet2, None, ORIGINATOR)
            .await
            .unwrap();
        assert!(!valid, "Nonce should fail with different wallet key");
    }
}
