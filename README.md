# tiny-webhook

> Production webhook handler in one file. Stdlib only · MIT · HMAC verification + idempotency + DLQ + retry.

```bash
pip install tiny-webhook
# or: copy tiny_webhook.py into your project
```

## Features

- **HMAC signature verification** — GitHub, Stripe, Slack, Discord, Telegram, SendGrid, + generic
- **Idempotency guards** — File-backed deduplication with TTL sliding window
- **Dead-letter queue** — Persist failed deliveries for inspection and replay
- **Async retry** — Exponential backoff with jitter
- **Structured logging** — Correlation IDs, JSON-ready
- **Health + metrics endpoints** — `/health`, `/dlq`, `/routes`, `/metrics`
- **Async handlers** — Use `async def` for I/O-heavy processing

## Quick Start

```python
from tiny_webhook import WebhookApp, HMACVerifier

app = WebhookApp()

@app.on("push", "/webhooks/github", verify=HMACVerifier.github(secret="mysecret"))
async def handle_push(payload, ctx):
    print(f"Push to {payload['repository']['name']}")
    return {"ok": True, "stars": payload['repository']['stargazers_count']}

@app.on("payment", "/webhooks/stripe", verify=HMACVerifier.stripe("whsec_..."))
async def handle_payment(payload, ctx):
    return {"received": True}

app.run(port=8080)
```

## Supported Providers

| Provider | Header | Verifier |
|----------|--------|----------|
| GitHub | `X-Hub-Signature-256` | `HMACVerifier.github(secret)` |
| Stripe | `Stripe-Signature` | `HMACVerifier.stripe(signing_secret)` |
| Slack | `X-Slack-Signature` | `HMACVerifier.slack(signing_secret)` |
| Discord | `X-Signature-Ed25519` | `HMACVerifier.discord(public_key)` |
| Telegram | `secret_token` (body) | `HMACVerifier.telegram(bot_token)` |
| SendGrid | `X-Webhook-Signature` | `HMACVerifier.sendgrid(verification_key)` |
| Custom | Any header | `HMACVerifier.hmac_sha256(secret)` |

## Production Features

### Idempotency

```python
from tiny_webhook import WebhookApp, IdempotencyGuard

guard = IdempotencyGuard(
    store_path="/var/lib/webhook-idempotency.json",
    ttl_seconds=3600,
)

@app.on("payment", "/webhooks/stripe", guard=guard)
async def handle(payload, ctx):
    # Duplicate deliveries (same X-Webhook-ID within TTL) return 200
    # without re-running the handler
    return {"ok": True}
```

### Dead-Letter Queue

```python
from tiny_webhook import WebhookApp, DeadLetterQueue

dlq = DeadLetterQueue(path="/var/lib/webhook-dlq.jsonl", max_size=10000)

@app.on("push", "/webhooks/github", dlq=dlq)
async def handle(payload, ctx):
    if ctx.verifier_name == "github":
        raise ValueError("DB connection failed")
    return {"ok": True}

# Later: inspect DLQ
entries = dlq.entries(limit=100)
for entry in entries:
    print(entry["error"], entry["event"])
```

### Retry with Exponential Backoff

```python
from tiny_webhook import WebhookApp, RetryPolicy, DeadLetterQueue

retry = RetryPolicy(max_attempts=5, base_delay=1.0, exponential_base=2.0, jitter=True)
dlq = DeadLetterQueue()

@app.on("sync", "/webhooks/sync", retry=retry, dlq=dlq)
async def handle(payload, ctx):
    # Retried up to 5 times with backoff; then DLQ'd
    return {"ok": True}
```

## CLI

```bash
# Quick test server
python tiny_webhook.py --secret mysecret --port 8080

# With debug logging
python tiny_webhook.py --secret mysecret --log-level DEBUG
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check + route count |
| `GET` | `/dlq` | Dead-letter queue entries |
| `GET` | `/routes` | All registered routes |
| `GET` | `/metrics` | Idempotency guard stats |
| `POST` | `/{path}` | Webhook handler |

## Why?

Every webhook library is either a toy (no verification) or a framework (full Celery stack for a single `if event == "push"`). `tiny-webhook` is the middle ground — production-ready, one file, zero dependencies.

## Part of the tiny-* Ecosystem

```
tiny-webhook    — Webhook handler  (you are here)
tiny-router     — HTTP routing
tiny-log        — Structured logging
tiny-validator  — Input validation
tiny-rate       — Rate limiting
tiny-retry      — Retry + circuit breaker
fast-cache      — LRU+TTL cache
```

See all 35+ repos at: [github.com/hussain-alsaibai](https://github.com/hussain-alsaibai)

## License

MIT — do anything with it. Built by [OpenClaw 🦞](https://github.com/hussain-alsaibai)
