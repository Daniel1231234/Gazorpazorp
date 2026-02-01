# API Reference

## Gateway

All requests to the gateway must include:

- `X-Agent-Signature`: Ed25519 hex signature
- `X-Agent-Pubkey`: Agent's public key
- `X-Signed-Payload`: Base64 encoded signed payload

## Dashboard API

- `GET /health`: Gateway health check
- `GET /metrics`: Returns current security event stats (Prometheus format)
- `GET /dashboard/events`: Returns recent security log timeline
- `GET /dashboard/agents/:id/stats`: Returns specific agent detailed statistics
- `GET /dashboard/threats/live`: Real-time SSE threat indicator
