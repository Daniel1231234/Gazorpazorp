<div align="center">

# 🛡️ GAZORPAZORP

### Zero-Trust Security Gateway for Autonomous AI Agents

<img src="https://static.wikia.nocookie.net/rickandmorty/images/8/8e/Gazorpazorp.png/revision/latest?cb=20160919085452" alt="Gazorpazorp Planet" width="400"/>

*"Where Gazorpians come from" - Named after the planet from Rick and Morty,*
*because securing AI agents requires thinking from another dimension.*

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green?logo=node.js)](https://nodejs.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-red?logo=redis)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

[Getting Started](#-quick-start) •
[Architecture](#-architecture) •
[API Reference](#-api-reference) •
[Examples](#-examples) •
[Contributing](#-contributing)

</div>

---

## 🎯 The Problem

As AI agents become autonomous, traditional security models are **fundamentally broken**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     WHY TRADITIONAL AUTH FAILS FOR AI AGENTS                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ❌ API Key Stolen?        → Attacker has FULL access                       │
│  ❌ JWT Compromised?       → No way to detect hijacked session              │
│  ❌ Prompt Injection?      → Legitimate agent becomes malicious             │
│  ❌ Data Exfiltration?     → Looks like normal requests                     │
│                                                                             │
│  Traditional auth answers: "WHO is this?"                                   │
│  But never asks: "WHAT are they trying to do?" or "IS THIS NORMAL?"        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Gazorpazorp** is a security gateway that doesn't just verify identity—it understands **intent**.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔐 **Ed25519 Signatures** | Every request cryptographically signed. No shared secrets. Perfect non-repudiation. |
| 🧠 **Semantic Analysis** | Local LLM analyzes request intent in real-time. Detects prompt injection, data exfiltration, privilege escalation. |
| 📊 **Behavioral Profiling** | Learns each agent's normal patterns. Flags anomalies when hijacked agents deviate. |
| ⚡ **Dynamic Policies** | Rules engine evaluates reputation, risk score, and permissions for every request. |
| 🎯 **Challenge System** | Suspicious requests get challenged (proof-of-work, signature refresh) instead of blocked. |
| 🔄 **Fail-Safe Design** | Graceful degradation when LLM unavailable. Reputation-based fallback decisions. |

---

## 🏗️ Architecture

```
                              ┌─────────────────────────────────────────┐
                              │            GAZORPAZORP GATEWAY           │
                              └─────────────────────────────────────────┘
                                                  │
        ┌─────────────────────────────────────────┼─────────────────────────────────────────┐
        │                                         │                                         │
        ▼                                         ▼                                         ▼
┌───────────────────┐                 ┌───────────────────┐                 ┌───────────────────┐
│   LAYER 1: CRYPTO │                 │  LAYER 2: SEMANTIC │                │  LAYER 3: POLICY  │
│                   │                 │                    │                │                   │
│  ┌─────────────┐  │                 │  ┌──────────────┐  │                │  ┌─────────────┐  │
│  │  Ed25519    │  │                 │  │    Regex     │  │                │  │   Rules     │  │
│  │  Verify     │  │                 │  │  Pre-screen  │  │                │  │   Engine    │  │
│  └─────────────┘  │                 │  └──────────────┘  │                │  └─────────────┘  │
│         │         │                 │         │          │                │         │         │
│  ┌─────────────┐  │                 │  ┌──────────────┐  │                │  ┌─────────────┐  │
│  │   Nonce     │  │                 │  │   Ollama     │  │                │  │  Rate       │  │
│  │   Check     │  │                 │  │   LLM        │  │                │  │  Limiter    │  │
│  └─────────────┘  │                 │  └──────────────┘  │                │  └─────────────┘  │
│         │         │                 │         │          │                │         │         │
│  ┌─────────────┐  │                 │  ┌──────────────┐  │                │  ┌─────────────┐  │
│  │  Timestamp  │  │                 │  │   Anomaly    │  │                │  │  Challenge  │  │
│  │  Validate   │  │                 │  │   Detector   │  │                │  │  Service    │  │
│  └─────────────┘  │                 │  └──────────────┘  │                │  └─────────────┘  │
│                   │                 │                    │                │                   │
│  "Is this really  │                 │  "What is the      │                │  "Should this be  │
│   from agent X?"  │                 │   intent here?"    │                │   allowed now?"   │
└───────────────────┘                 └───────────────────┘                └───────────────────┘
        │                                         │                                         │
        │ ✓ Valid Signature                       │ ✓ Risk Score: 15                        │ ✓ ALLOW
        │ ✓ Fresh Timestamp                       │ ✓ Not Malicious                         │
        │ ✓ Unique Nonce                          │ ✓ Normal Behavior                       │
        │                                         │                                         │
        └─────────────────────────────────────────┴─────────────────────────────────────────┘
                                                  │
                                                  ▼
                                    ┌───────────────────────┐
                                    │    YOUR BACKEND API   │
                                    │                       │
                                    │  Headers added:       │
                                    │  • X-Agent-Id         │
                                    │  • X-Risk-Score       │
                                    │  • X-Verified: true   │
                                    └───────────────────────┘
```

---

## 🔄 Request Flow

```typescript
// What happens when an AI agent makes a request:

Agent Request
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 1️⃣  CRYPTOGRAPHIC VERIFICATION                                     │
│                                                                    │
│    ┌─────────────────────────────────────────────────────────────┐ │
│    │ const result = await cryptoVerifier.verifyRequest(          │ │
│    │   signedPayload,  // { method, path, body, timestamp, nonce }│
│    │   signature,      // Ed25519 signature                      │ │
│    │   publicKey       // Agent's registered public key          │ │
│    │ );                                                          │ │
│    │                                                             │ │
│    │ // Checks:                                                  │ │
│    │ // ✓ Signature mathematically valid                         │ │
│    │ // ✓ Timestamp within ±30 seconds                           │ │
│    │ // ✓ Nonce never used before (replay protection)            │ │
│    │ // ✓ Agent exists in registry                               │ │
│    └─────────────────────────────────────────────────────────────┘ │
│                                                                    │
│    ❌ FAIL → 403 "Invalid signature" / "Timestamp expired"         │
│    ✅ PASS → Continue to Layer 2                                   │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 2️⃣  SEMANTIC INTENT ANALYSIS                                       │
│                                                                    │
│    ┌─────────────────────────────────────────────────────────────┐ │
│    │ // TIER A: Trusted agents skip analysis                     │ │
│    │ if (agent.reputation > 95 && !hasSuspiciousPatterns) {      │ │
│    │   return { riskScore: 5, isMalicious: false };              │ │
│    │ }                                                           │ │
│    │                                                             │ │
│    │ // TIER B: Regex pre-screening                              │ │
│    │ const patterns = detectPatterns(requestBody);               │ │
│    │ // Checks for: prompt injection, SQL injection,             │ │
│    │ // data exfiltration, privilege escalation                  │ │
│    │                                                             │ │
│    │ // TIER C: Deep LLM analysis                                │ │
│    │ const analysis = await ollama.analyze({                     │ │
│    │   model: 'llama3:8b',                                       │ │
│    │   prompt: buildSecurityPrompt(request, agentContext)        │ │
│    │ });                                                         │ │
│    └─────────────────────────────────────────────────────────────┘ │
│                                                                    │
│    Returns: { riskScore: 0-100, isMalicious: bool, threatType }    │
│                                                                    │
│    ❌ Malicious + High Confidence → 403 "Request blocked"          │
│    ✅ PASS → Continue to Layer 3                                   │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 3️⃣  POLICY EVALUATION                                              │
│                                                                    │
│    ┌─────────────────────────────────────────────────────────────┐ │
│    │ const decision = await policyEngine.evaluate({              │ │
│    │   agent: { id, reputation, permissions },                   │ │
│    │   request: { method, path, body },                          │ │
│    │   analysis: { riskScore, threatType }                       │ │
│    │ });                                                         │ │
│    │                                                             │ │
│    │ // Rules evaluated by priority:                             │ │
│    │ // 1. Block if riskScore > 90                               │ │
│    │ // 2. Rate limit if reputation < 30                         │ │
│    │ // 3. Deny admin paths without sensitiveDataAccess          │ │
│    │ // 4. Challenge if 50 < riskScore < 90                      │ │
│    └─────────────────────────────────────────────────────────────┘ │
│                                                                    │
│    DENY      → 403 "Access denied by policy"                       │
│    RATE_LIMIT → 429 "Rate limit exceeded"                          │
│    CHALLENGE → 401 { challenge: { type, id, instructions } }       │
│    ALLOW    → Proxy to backend                                     │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
  Backend
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 20+
- **Redis** 7+
- **Ollama** with Llama 3 model

### Installation

**Option 1: Docker Compose (Recommended)**

The easiest way to get started is using Docker Compose, which starts all required services:

```bash
# Clone the repository
git clone https://github.com/yourusername/gazorpazorp
cd gazorpazorp

# Start all services (Gateway + Redis + Ollama + Prometheus + Grafana)
docker-compose up -d

# Pull LLM models into Ollama
docker exec -it gazorpazorp-ollama-1 ollama pull llama3:8b
docker exec -it gazorpazorp-ollama-1 ollama pull tinyllama

# View logs
docker-compose logs -f gazorpazorp
```

**Services Started:**
- `gazorpazorp` - Security gateway (port 3000)
- `redis` - Data store (port 6379)
- `ollama` - LLM inference (port 11434)
- `prometheus` - Metrics collection (port 9091)
- `grafana` - Monitoring dashboard (port 3001)
- `backend` - Your backend service (port 8080)

**Option 2: Local Development**

For development with hot-reload:

```bash
# Install dependencies
npm install

# Start infrastructure only
docker-compose up -d redis ollama

# Pull the LLM model
ollama pull llama3:8b

# Start the gateway in dev mode
npm run dev
```

**Docker Compose Commands:**

```bash
# Start all services
docker-compose up -d

# Start specific services
docker-compose up -d redis ollama

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and remove volumes (clears data)
docker-compose down -v

# Restart a specific service
docker-compose restart gazorpazorp

# View service status
docker-compose ps

# Execute commands in a running container
docker exec -it gazorpazorp-redis-1 redis-cli
```

### Verify Installation

```bash
# Health check
curl http://localhost:3000/health
# → {"status":"healthy"}

# Metrics endpoint
curl http://localhost:3000/metrics
# → Prometheus-format metrics
```

---

## 📖 API Reference

### Agent Registration

Before an agent can make requests, it must register its public key:

```typescript
import { AgentKeyGenerator } from 'gazorpazorp';

// Generate Ed25519 key pair
const { publicKey, privateKey } = AgentKeyGenerator.generate();

// Register with the gateway (store publicKey server-side)
const agent = await cryptoVerifier.registerAgent(publicKey, {
  allowedEndpoints: ['/api/read/*', '/api/write/*'],
  deniedEndpoints: ['/api/admin/*'],
  maxRequestsPerMinute: 100,
  sensitiveDataAccess: false
});

// Save privateKey securely - never share it!
```

### Making Authenticated Requests

```typescript
import { AgentKeyGenerator } from 'gazorpazorp';

// Sign the request
const request = {
  method: 'POST',
  path: '/api/data/query',
  body: { query: 'SELECT * FROM users WHERE id = 123' },
  timestamp: Date.now()
};

const { signedPayload, signature } = AgentKeyGenerator.signRequest(
  request,
  privateKey
);

// Send to gateway
const response = await fetch('http://gateway:3000/api/data/query', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Agent-Signature': signature,
    'X-Agent-Pubkey': publicKey,
    'X-Signed-Payload': Buffer.from(JSON.stringify(signedPayload)).toString('base64')
  },
  body: JSON.stringify(request.body)
});
```

### Challenge Response Flow

When the gateway issues a challenge:

```typescript
// Gateway returns 401 with challenge
{
  "status": "challenge_required",
  "challenge": {
    "id": "ch_abc123...",
    "type": "proof_of_work",
    "difficulty": 4,
    "instructions": "Find nonce where SHA256(ch_abc123... + nonce) has 4 leading zero bits"
  },
  "verifyUrl": "http://gateway:3000/api/challenge/verify"
}

// Solve the challenge (example for proof-of-work)
function solveChallenge(challengeId: string, difficulty: number): string {
  let nonce = 0;
  while (true) {
    const hash = sha256(challengeId + nonce.toString());
    if (hash.startsWith('0'.repeat(difficulty))) {
      return nonce.toString();
    }
    nonce++;
  }
}

// Submit solution
await fetch('http://gateway:3000/api/challenge/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    challengeId: 'ch_abc123...',
    solution: solveChallenge('ch_abc123...', 4)
  })
});

// Retry original request with challenge ID
await fetch('http://gateway:3000/api/data/query', {
  headers: {
    ...originalHeaders,
    'X-Challenge-Id': 'ch_abc123...'
  },
  // ... rest of request
});
```

---

## 📁 Project Structure

```
gazorpazorp/
├── src/
│   ├── index.ts                 # Entry point, ProductionGateway setup
│   │
│   ├── gateway/
│   │   └── sentinel.ts          # Core gateway, middleware orchestration
│   │
│   ├── crypto/
│   │   ├── agent-identity.ts    # Ed25519 verification, key generation
│   │   └── key-store.ts         # Redis-backed identity storage (Lua scripts)
│   │
│   ├── semantic/
│   │   ├── intent-analyzer.ts   # Tiered analysis (regex → LLM)
│   │   ├── patterns.ts          # Threat detection regexes
│   │   └── prompts/
│   │       └── analysis.ts      # LLM system prompt
│   │
│   ├── policy/
│   │   ├── engine.ts            # Rules evaluation engine
│   │   └── rules/
│   │       └── defaults.ts      # Default security rules
│   │
│   ├── behavioral/
│   │   └── anomaly-detector.ts  # Agent profiling & anomaly scoring
│   │
│   ├── challenge/
│   │   └── challenge-service.ts # PoW, signature refresh, rate delay
│   │
│   ├── cache/
│   │   └── analysis-cache.ts    # LLM result caching (reputation-segmented)
│   │
│   ├── dashboard/
│   │   └── api.ts               # Security events API, SSE streaming
│   │
│   └── observability/
│       └── metrics.ts           # Prometheus metrics
│
├── tests/
│   ├── crypto.test.ts           # Cryptographic verification tests
│   ├── semantic.test.ts         # Intent analysis tests
│   └── integration.test.ts      # End-to-end tests
│
├── examples/
│   ├── legit_agent.ts           # Legitimate request example
│   ├── malicious_agent.ts       # Prompt injection example
│   └── hijacked_agent.ts        # Credential theft scenario
│
├── docs/
│   ├── ARCHITECTURE.md          # Detailed architecture docs
│   ├── API.md                   # Full API reference
│   └── THREAT_MODEL.md          # Security threat model
│
├── docker-compose.yml           # Full stack orchestration
├── vitest.config.ts             # Test configuration
└── package.json
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Gateway port |
| `BACKEND_URL` | `http://localhost:8080` | Your API backend |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `LLM_DEEP_MODEL` | `llama3:8b` | Model for deep analysis |
| `LLM_FAST_MODEL` | `tinyllama` | Model for fast screening |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |

### Custom Policy Rules

```typescript
// Add custom rules to the policy engine
policyEngine.addRule({
  id: 'block_weekends',
  name: 'Block Weekend Access',
  priority: 5,
  conditions: [
    { field: 'request.timestamp', operator: 'matches', value: '^(Sat|Sun)' },
    { field: 'agent.permissions.sensitiveDataAccess', operator: 'eq', value: true }
  ],
  action: { type: 'deny', params: { reason: 'No sensitive access on weekends' } },
  enabled: true
});
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npm test -- tests/crypto.test.ts

# Watch mode
npm test -- --watch
```

### Test Coverage

| Module | Coverage |
|--------|----------|
| Crypto (signatures, keys) | ✅ Comprehensive |
| Semantic (patterns, LLM) | ✅ Comprehensive |
| Policy (rules, conditions) | ✅ Comprehensive |
| Behavioral (anomalies) | ✅ Comprehensive |
| Cache (segmentation) | ✅ Comprehensive |

---

## 📊 Monitoring

### Prometheus Metrics

Available at `GET /metrics`:

```prometheus
# Request counters
sentinel_requests_total{decision="allow",threat_type="none"} 1523

# Blocked requests
sentinel_blocked_requests_total{threat_type="prompt_injection",rule_id="block_high_risk"} 12

# Latency histograms
sentinel_request_duration_seconds_bucket{layer="crypto",le="0.01"} 1400
sentinel_llm_latency_seconds_bucket{model="llama3",tier="deep",le="1"} 89

# Risk score distribution
sentinel_risk_score_bucket{le="10"} 1200
sentinel_risk_score_bucket{le="50"} 1450

# Agent reputation gauges
sentinel_agent_reputation{agent_id="agent_abc123"} 85
```

### Dashboard API

```bash
# Get recent security events
curl http://localhost:3000/dashboard/events

# Get agent statistics
curl http://localhost:3000/dashboard/agents/agent_123/stats

# Stream live threats (Server-Sent Events)
curl http://localhost:3000/dashboard/threats/live
```

---

## 🆚 Comparison with Traditional Solutions

| Aspect | API Gateway (Kong, etc.) | WAF (Cloudflare, etc.) | **Gazorpazorp** |
|--------|--------------------------|------------------------|-----------------|
| **Auth Model** | API Keys, JWT | N/A | Ed25519 Signatures |
| **Threat Detection** | Rate limiting | Regex patterns | Semantic LLM Analysis |
| **Agent Context** | None | None | Reputation + Behavior |
| **Replay Protection** | None/Basic | None | Cryptographic Nonce |
| **Hijack Detection** | ❌ | ❌ | ✅ Behavioral Anomaly |
| **Prompt Injection** | ❌ | ❌ | ✅ LLM Detection |
| **Challenge System** | ❌ | CAPTCHA | ✅ PoW/Signature |

---

## 📚 Examples

### Load Testing

Perform load testing with realistic agent behavior:

```bash
# Run load test with default settings (10 agents, 100 requests each)
npx tsx examples/load_test.ts

# Custom configuration
GATEWAY_URL=http://localhost:3000 \
NUM_AGENTS=50 \
REQUESTS_PER_AGENT=200 \
THINK_TIME_MS=50 \
npx tsx examples/load_test.ts
```

**Sample Output:**
```
🛡️  Gazorpazorp Load Test

Configuration:
  Gateway URL: http://localhost:3000
  Agents: 10
  Requests per agent: 100
  Think time: 100ms
  Total requests: 1000

🔑 Generating 10 test agents...
✅ Generated 10 agents

🏥 Checking gateway health...
✅ Gateway is healthy

🚀 Starting load test...
[████████████████████████████████████████] 100.0% (1000/1000)

📊 Load Test Results

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Duration:        12.34s
Throughput:      81.04 req/s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Requests:  1000
✅ Successful:    847 (84.70%)
⚠️  Challenged:    98 (9.80%)
🚫 Rate Limited:  32 (3.20%)
❌ Failed:        23
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Latency (ms):
  Min:  45.00ms
  Avg:  128.50ms
  P50:  115.00ms
  P95:  256.00ms
  P99:  412.00ms
  Max:  1024.00ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

The load tester:
- Generates Ed25519 key pairs for each agent
- Signs all requests cryptographically
- Tracks success/failure/challenge/rate-limit rates
- Calculates latency percentiles (P50, P95, P99)
- Provides recommendations based on results

**See [examples/load_test.ts](examples/load_test.ts) for full implementation.**

### Client Integration Example

Coming soon: Full example of integrating Gazorpazorp into an AI agent client.

---

## 🗺️ Roadmap

- [x] Ed25519 cryptographic verification
- [x] Semantic intent analysis with LLM
- [x] Behavioral anomaly detection
- [x] Challenge-response mechanism
- [x] Comprehensive test suite
- [ ] **HSM Support** - Hardware security modules for key storage
- [ ] **Multi-Model Voting** - Consensus across multiple LLMs
- [ ] **Agent-to-Agent Protocol** - Secure inter-agent communication
- [ ] **Reputation Marketplace** - Decentralized trust scores
- [ ] **Web Dashboard** - Real-time monitoring UI

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Fork the repo, then:
git checkout -b feature/amazing-feature
npm test  # Make sure tests pass
git commit -m 'Add amazing feature'
git push origin feature/amazing-feature
# Open a Pull Request
```

---

## 📄 License

MIT © 2026 Gazorpazorp Security Project

---

<div align="center">

**Built for the age of autonomous AI agents** 🤖

*"Nobody exists on purpose. Nobody belongs anywhere. Everybody's gonna die.*
*Come watch TV."* - Morty Smith

*But at least your AI agents will be secure.* 🛡️

</div>
