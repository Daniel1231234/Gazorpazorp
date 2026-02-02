// src/crypto/agent-identity.ts
import { createPrivateKey, createPublicKey, sign, verify, randomBytes, createHash, generateKeyPairSync } from "crypto";
import { KeyStore } from "./key-store.js";
import { Redis } from "ioredis";

interface RateLimitConfig {}

export interface AgentIdentity {
  id: string; // Unique agent identifier
  publicKey: string; // PEM format
  fingerprint: string; // SHA256 of public key
  registeredAt: Date;
  lastSeen: Date;
  reputation: number; // 0-100 score
  permissions: AgentPermissions;
  rateLimit: RateLimitConfig;
  metadata: Record<string, unknown>;
}

export interface AgentPermissions {
  allowedEndpoints: string[]; // Glob patterns: ["/api/read/*", "/api/write/balance"]
  deniedEndpoints: string[];
  maxRequestsPerMinute: number;
  maxPayloadSize: number;
  allowedMethods: ("GET" | "POST" | "PUT" | "DELETE")[];
  sensitiveDataAccess: boolean;
}

export interface SignedRequest {
  method: string;
  path: string;
  body: unknown;
  timestamp: number;
  nonce: string; // Prevents replay even within timestamp window
}

export class CryptoVerifier {
  private keyStore: KeyStore;
  private redis: Redis;
  private readonly TIMESTAMP_TOLERANCE_MS = 30_000; // 30 seconds
  private readonly NONCE_EXPIRY_S = 60; // 60 seconds

  constructor(redis: Redis) {
    this.redis = redis;
    this.keyStore = new KeyStore(redis);
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  private constantTimeCompare(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  /**
   * Generate fingerprint from public key
   */
  public getFingerprint(publicKeyPem: string): string {
    return createHash("sha256").update(publicKeyPem).digest("hex");
  }

  /**
   * Register a new agent
   */
  public async registerAgent(publicKeyPem: string, permissions: Partial<AgentPermissions> = {}): Promise<AgentIdentity> {
    const fingerprint = this.getFingerprint(publicKeyPem);

    // Validate key format
    try {
      createPublicKey(publicKeyPem);
    } catch (e) {
      throw new Error("Invalid public key format");
    }

    const agent: AgentIdentity = {
      id: `agent_${randomBytes(16).toString("hex")}`,
      publicKey: publicKeyPem,
      fingerprint,
      registeredAt: new Date(),
      lastSeen: new Date(),
      reputation: 50, // Start neutral
      permissions: {
        allowedEndpoints: ["*"],
        deniedEndpoints: [],
        maxRequestsPerMinute: 60,
        maxPayloadSize: 1024 * 1024, // 1MB
        allowedMethods: ["GET", "POST"],
        sensitiveDataAccess: false,
        ...permissions
      },
      rateLimit: {
        windowMs: 60000,
        maxRequests: 60
      },
      metadata: {}
    };

    await this.keyStore.saveIdentity(agent);
    return agent;
  }

  /**
   * Verify a signed request
   */
  public async verifyRequest(
    signedPayload: SignedRequest,
    signatureHex: string,
    publicKeyPem: string
  ): Promise<{ valid: boolean; agent?: AgentIdentity; error?: string }> {
    // 1. Check timestamp freshness
    const now = Date.now();
    if (Math.abs(now - signedPayload.timestamp) > this.TIMESTAMP_TOLERANCE_MS) {
      return { valid: false, error: "Request expired or clock skew detected" };
    }

    // 2. Check nonce hasn't been used (replay protection)
    const fingerprint = this.getFingerprint(publicKeyPem);
    const nonceKey = `nonce:${fingerprint}:${signedPayload.nonce}`;

    // Use SET NX to atomically check and set the nonce
    const isNew = await this.redis.set(nonceKey, "used", "EX", this.NONCE_EXPIRY_S, "NX");
    if (!isNew) {
      return { valid: false, error: "Nonce already used - potential replay attack" };
    }

    // 3. Lookup agent by fingerprint
    const agent = await this.keyStore.getIdentity(fingerprint);
    if (!agent) {
      return { valid: false, error: "Unknown agent - not registered" };
    }

    // 4. Verify cryptographic signature
    try {
      const payloadString = JSON.stringify(signedPayload);
      const publicKey = createPublicKey(publicKeyPem);

      const isValid = verify(null, Buffer.from(payloadString), publicKey, Buffer.from(signatureHex, "hex"));

      if (!isValid) {
        // Decrease reputation for failed signature
        await this.keyStore.updateReputation(fingerprint, -5);
        return { valid: false, error: "Invalid signature" };
      }
    } catch (e) {
      return { valid: false, error: "Signature verification failed" };
    }

    // 5. Update agent metadata
    agent.lastSeen = new Date();
    await this.keyStore.updateReputation(fingerprint, 0.1); // Slowly build trust

    return { valid: true, agent };
  }
}

// Key generation utility for agents
export class AgentKeyGenerator {
  static generate(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" }
    });

    return { privateKey, publicKey };
  }

  static signRequest(request: Omit<SignedRequest, "nonce">, privateKeyPem: string): { signedPayload: SignedRequest; signature: string } {
    const signedPayload: SignedRequest = {
      ...request,
      nonce: randomBytes(16).toString("hex")
    };

    const privateKey = createPrivateKey(privateKeyPem);
    const signature = sign(null, Buffer.from(JSON.stringify(signedPayload)), privateKey).toString("hex");

    return { signedPayload, signature };
  }
}
