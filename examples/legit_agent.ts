// examples/legit_agent.ts
import { AgentKeyGenerator } from "../src/crypto/agent-identity.js";

const GATEWAY_URL = "http://localhost:3000";

async function runLegitAgent() {
  // In real scenario, keys would be pre-registered
  const { privateKey, publicKey } = AgentKeyGenerator.generate();

  // Create a normal request
  const request = {
    method: "GET",
    path: "/api/accounts/123/balance",
    body: { includeHistory: true },
    timestamp: Date.now()
  };

  const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);

  const response = await fetch(`${GATEWAY_URL}${request.path}`, {
    method: request.method,
    headers: {
      "Content-Type": "application/json",
      "X-Agent-Signature": signature,
      "X-Agent-Pubkey": publicKey,
      "X-Signed-Payload": Buffer.from(JSON.stringify(signedPayload)).toString("base64")
    },
    body: JSON.stringify(request.body)
  });

  console.log("✅ Legitimate Agent Response:", response.status, await response.json());
}

runLegitAgent();
