// tests/crypto.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { CryptoVerifier, AgentKeyGenerator, AgentIdentity, SignedRequest } from "../src/crypto/agent-identity.js";
import { KeyStore } from "../src/crypto/key-store.js";

// Mock Redis with Lua script support
const createMockRedis = () => {
  const store = new Map<string, string>();
  const expiry = new Map<string, number>();
  const lists = new Map<string, string[]>();

  const redisMock = {
    get: vi.fn(async (key: string) => store.get(key) || null),
    set: vi.fn(async (key: string, value: string, ex?: string, ttl?: number, nx?: string) => {
      if (nx === "NX" && store.has(key)) {
        return null;
      }
      store.set(key, value);
      if (ex === "EX" && ttl) {
        expiry.set(key, Date.now() + ttl * 1000);
      }
      return "OK";
    }),
    setex: vi.fn(async (key: string, ttl: number, value: string) => {
      store.set(key, value);
      expiry.set(key, Date.now() + ttl * 1000);
      return "OK";
    }),
    del: vi.fn(async (...keys: string[]) => {
      let count = 0;
      for (const key of keys) {
        if (store.delete(key)) count++;
      }
      return count;
    }),
    lpush: vi.fn(async (key: string, ...values: string[]) => {
      const list = lists.get(key) || [];
      list.unshift(...values);
      lists.set(key, list);
      return list.length;
    }),
    ltrim: vi.fn(async (key: string, start: number, stop: number) => {
      const list = lists.get(key) || [];
      lists.set(key, list.slice(start, stop + 1));
      return "OK";
    }),
    lrange: vi.fn(async (key: string, start: number, stop: number) => {
      const list = lists.get(key) || [];
      return list.slice(start, stop === -1 ? undefined : stop + 1);
    }),
    watch: vi.fn(async () => "OK"),
    unwatch: vi.fn(async () => "OK"),
    multi: vi.fn(() => {
      const commands: Array<{ cmd: string; args: any[] }> = [];
      const multiObj = {
        setex: (key: string, ttl: number, value: string) => {
          commands.push({ cmd: "setex", args: [key, ttl, value] });
          return multiObj;
        },
        lpush: (key: string, value: string) => {
          commands.push({ cmd: "lpush", args: [key, value] });
          return multiObj;
        },
        ltrim: (key: string, start: number, stop: number) => {
          commands.push({ cmd: "ltrim", args: [key, start, stop] });
          return multiObj;
        },
        exec: async () => {
          const results: Array<[null, any]> = [];
          for (const { cmd, args } of commands) {
            if (cmd === "setex") {
              store.set(args[0], args[2]);
              results.push([null, "OK"]);
            } else if (cmd === "lpush") {
              const list = lists.get(args[0]) || [];
              list.unshift(args[1]);
              lists.set(args[0], list);
              results.push([null, list.length]);
            } else if (cmd === "ltrim") {
              const list = lists.get(args[0]) || [];
              lists.set(args[0], list.slice(args[1], args[2] + 1));
              results.push([null, "OK"]);
            }
          }
          return results;
        }
      };
      return multiObj;
    }),
    defineCommand: vi.fn((name: string, options: any) => {
      (redisMock as any)[name] = vi.fn(async (...args: any[]) => {
        if (name === "updateReputationAtomic") {
          const [identityKey, logKey, delta, timestamp, reason] = args;
          const data = store.get(identityKey);
          if (!data) return [-1, 0];
          const identity = JSON.parse(data);
          const oldRep = identity.reputation;
          identity.reputation = Math.max(0, Math.min(100, oldRep + delta));
          identity.lastSeen = timestamp;
          store.set(identityKey, JSON.stringify(identity));

          // Log to list
          const list = lists.get(logKey) || [];
          list.unshift(JSON.stringify({
            timestamp,
            oldReputation: oldRep,
            newReputation: identity.reputation,
            delta,
            reason
          }));
          lists.set(logKey, list.slice(0, 100));

          return [identity.reputation, 1];
        }
        if (name === "conditionalUpdate") {
          return [0, 1];
        }
        return [0, 1];
      });
    }),
    _store: store,
    _lists: lists,
    _clear: () => {
      store.clear();
      expiry.clear();
      lists.clear();
    }
  };
  return redisMock;
};

describe("AgentKeyGenerator", () => {
  describe("generate", () => {
    it("should generate valid Ed25519 key pair", () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();

      expect(privateKey).toContain("-----BEGIN PRIVATE KEY-----");
      expect(privateKey).toContain("-----END PRIVATE KEY-----");
      expect(publicKey).toContain("-----BEGIN PUBLIC KEY-----");
      expect(publicKey).toContain("-----END PUBLIC KEY-----");
    });

    it("should generate unique key pairs each time", () => {
      const pair1 = AgentKeyGenerator.generate();
      const pair2 = AgentKeyGenerator.generate();

      expect(pair1.publicKey).not.toBe(pair2.publicKey);
      expect(pair1.privateKey).not.toBe(pair2.privateKey);
    });
  });

  describe("signRequest", () => {
    it("should sign request and generate nonce", () => {
      const { privateKey } = AgentKeyGenerator.generate();
      const request = {
        method: "GET",
        path: "/api/test",
        body: { data: "test" },
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);

      expect(signedPayload.nonce).toBeDefined();
      expect(signedPayload.nonce).toHaveLength(32); // 16 bytes hex = 32 chars
      expect(signature).toBeDefined();
      expect(signature.length).toBeGreaterThan(0);
    });

    it("should include all request fields in signed payload", () => {
      const { privateKey } = AgentKeyGenerator.generate();
      const request = {
        method: "POST",
        path: "/api/users",
        body: { name: "test" },
        timestamp: 1234567890
      };

      const { signedPayload } = AgentKeyGenerator.signRequest(request, privateKey);

      expect(signedPayload.method).toBe("POST");
      expect(signedPayload.path).toBe("/api/users");
      expect(signedPayload.body).toEqual({ name: "test" });
      expect(signedPayload.timestamp).toBe(1234567890);
    });

    it("should generate different signatures for different requests", () => {
      const { privateKey } = AgentKeyGenerator.generate();

      const { signature: sig1 } = AgentKeyGenerator.signRequest(
        { method: "GET", path: "/api/a", body: {}, timestamp: Date.now() },
        privateKey
      );

      const { signature: sig2 } = AgentKeyGenerator.signRequest(
        { method: "GET", path: "/api/b", body: {}, timestamp: Date.now() },
        privateKey
      );

      expect(sig1).not.toBe(sig2);
    });
  });
});

describe("KeyStore", () => {
  let redis: ReturnType<typeof createMockRedis>;
  let keyStore: KeyStore;

  beforeEach(() => {
    redis = createMockRedis();
    keyStore = new KeyStore(redis as any);
  });

  describe("saveIdentity", () => {
    it("should save agent identity to Redis", async () => {
      const identity: AgentIdentity = {
        id: "agent_123",
        publicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        fingerprint: "abc123",
        registeredAt: new Date(),
        lastSeen: new Date(),
        reputation: 50,
        permissions: {
          allowedEndpoints: ["*"],
          deniedEndpoints: [],
          maxRequestsPerMinute: 60,
          maxPayloadSize: 1024,
          allowedMethods: ["GET", "POST"],
          sensitiveDataAccess: false
        },
        rateLimit: {},
        metadata: {}
      };

      await keyStore.saveIdentity(identity);

      expect(redis.setex).toHaveBeenCalledWith(
        "agent:identity:abc123",
        expect.any(Number),
        expect.any(String)
      );
    });
  });

  describe("getIdentity", () => {
    it("should retrieve agent identity from Redis", async () => {
      const identity: AgentIdentity = {
        id: "agent_456",
        publicKey: "test-key",
        fingerprint: "def456",
        registeredAt: new Date(),
        lastSeen: new Date(),
        reputation: 75,
        permissions: {
          allowedEndpoints: ["*"],
          deniedEndpoints: [],
          maxRequestsPerMinute: 60,
          maxPayloadSize: 1024,
          allowedMethods: ["GET"],
          sensitiveDataAccess: false
        },
        rateLimit: {},
        metadata: {}
      };

      redis._store.set("agent:identity:def456", JSON.stringify(identity));

      const result = await keyStore.getIdentity("def456");

      expect(result).not.toBeNull();
      expect(result?.id).toBe("agent_456");
      expect(result?.reputation).toBe(75);
    });

    it("should return null for non-existent identity", async () => {
      const result = await keyStore.getIdentity("nonexistent");
      expect(result).toBeNull();
    });
  });

  describe("updateReputation", () => {
    it("should increase reputation", async () => {
      const identity: AgentIdentity = {
        id: "agent_789",
        publicKey: "test",
        fingerprint: "ghi789",
        registeredAt: new Date(),
        lastSeen: new Date(),
        reputation: 50,
        permissions: {
          allowedEndpoints: ["*"],
          deniedEndpoints: [],
          maxRequestsPerMinute: 60,
          maxPayloadSize: 1024,
          allowedMethods: ["GET"],
          sensitiveDataAccess: false
        },
        rateLimit: {},
        metadata: {}
      };

      redis._store.set("agent:identity:ghi789", JSON.stringify(identity));

      const newRep = await keyStore.updateReputation("ghi789", 10);

      expect(newRep).toBe(60);
    });

    it("should decrease reputation", async () => {
      const identity: AgentIdentity = {
        id: "agent_789",
        publicKey: "test",
        fingerprint: "ghi789",
        registeredAt: new Date(),
        lastSeen: new Date(),
        reputation: 50,
        permissions: {
          allowedEndpoints: ["*"],
          deniedEndpoints: [],
          maxRequestsPerMinute: 60,
          maxPayloadSize: 1024,
          allowedMethods: ["GET"],
          sensitiveDataAccess: false
        },
        rateLimit: {},
        metadata: {}
      };

      redis._store.set("agent:identity:ghi789", JSON.stringify(identity));

      const newRep = await keyStore.updateReputation("ghi789", -20);

      expect(newRep).toBe(30);
    });

    it("should clamp reputation between 0 and 100", async () => {
      const identity: AgentIdentity = {
        id: "agent_test",
        publicKey: "test",
        fingerprint: "clamp",
        registeredAt: new Date(),
        lastSeen: new Date(),
        reputation: 95,
        permissions: {
          allowedEndpoints: ["*"],
          deniedEndpoints: [],
          maxRequestsPerMinute: 60,
          maxPayloadSize: 1024,
          allowedMethods: ["GET"],
          sensitiveDataAccess: false
        },
        rateLimit: {},
        metadata: {}
      };

      redis._store.set("agent:identity:clamp", JSON.stringify(identity));

      // Try to go above 100
      let newRep = await keyStore.updateReputation("clamp", 50);
      expect(newRep).toBe(100);

      // Try to go below 0
      newRep = await keyStore.updateReputation("clamp", -150);
      expect(newRep).toBe(0);
    });

    it("should throw error for non-existent agent", async () => {
      await expect(keyStore.updateReputation("nonexistent", 10)).rejects.toThrow("Agent not found");
    });
  });
});

describe("CryptoVerifier", () => {
  let redis: ReturnType<typeof createMockRedis>;
  let verifier: CryptoVerifier;

  beforeEach(() => {
    redis = createMockRedis();
    verifier = new CryptoVerifier(redis as any);
  });

  describe("getFingerprint", () => {
    it("should generate consistent SHA256 fingerprint", () => {
      const publicKey = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----";

      const fp1 = verifier.getFingerprint(publicKey);
      const fp2 = verifier.getFingerprint(publicKey);

      expect(fp1).toBe(fp2);
      expect(fp1).toHaveLength(64); // SHA256 hex
    });

    it("should generate different fingerprints for different keys", () => {
      const key1 = "-----BEGIN PUBLIC KEY-----\nkey1\n-----END PUBLIC KEY-----";
      const key2 = "-----BEGIN PUBLIC KEY-----\nkey2\n-----END PUBLIC KEY-----";

      expect(verifier.getFingerprint(key1)).not.toBe(verifier.getFingerprint(key2));
    });
  });

  describe("registerAgent", () => {
    it("should register agent with valid Ed25519 key", async () => {
      const { publicKey } = AgentKeyGenerator.generate();

      const agent = await verifier.registerAgent(publicKey);

      expect(agent.id).toMatch(/^agent_/);
      expect(agent.publicKey).toBe(publicKey);
      expect(agent.reputation).toBe(50);
      expect(agent.permissions.allowedEndpoints).toContain("*");
    });

    it("should apply custom permissions", async () => {
      const { publicKey } = AgentKeyGenerator.generate();

      const agent = await verifier.registerAgent(publicKey, {
        allowedEndpoints: ["/api/read/*"],
        sensitiveDataAccess: true,
        maxRequestsPerMinute: 100
      });

      expect(agent.permissions.allowedEndpoints).toContain("/api/read/*");
      expect(agent.permissions.sensitiveDataAccess).toBe(true);
      expect(agent.permissions.maxRequestsPerMinute).toBe(100);
    });

    it("should reject invalid public key format", async () => {
      await expect(verifier.registerAgent("invalid-key")).rejects.toThrow("Invalid public key format");
    });
  });

  describe("verifyRequest", () => {
    it("should verify valid signature from registered agent", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      await verifier.registerAgent(publicKey);

      const request = {
        method: "GET",
        path: "/api/test",
        body: { data: "test" },
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);
      const result = await verifier.verifyRequest(signedPayload, signature, publicKey);

      expect(result.valid).toBe(true);
      expect(result.agent).toBeDefined();
      expect(result.agent?.id).toMatch(/^agent_/);
    });

    it("should reject expired timestamp", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      await verifier.registerAgent(publicKey);

      const request = {
        method: "GET",
        path: "/api/test",
        body: {},
        timestamp: Date.now() - 60000 // 60 seconds ago
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);
      const result = await verifier.verifyRequest(signedPayload, signature, publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("expired");
    });

    it("should reject replay attacks (same nonce)", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      await verifier.registerAgent(publicKey);

      const request = {
        method: "GET",
        path: "/api/test",
        body: {},
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);

      // First request should succeed
      const result1 = await verifier.verifyRequest(signedPayload, signature, publicKey);
      expect(result1.valid).toBe(true);

      // Replay should fail
      const result2 = await verifier.verifyRequest(signedPayload, signature, publicKey);
      expect(result2.valid).toBe(false);
      expect(result2.error).toContain("Nonce already used");
    });

    it("should reject unknown agent", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      // Don't register the agent

      const request = {
        method: "GET",
        path: "/api/test",
        body: {},
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);
      const result = await verifier.verifyRequest(signedPayload, signature, publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Unknown agent");
    });

    it("should reject tampered signature", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      await verifier.registerAgent(publicKey);

      const request = {
        method: "GET",
        path: "/api/test",
        body: {},
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);

      // Tamper with signature
      const tamperedSignature = signature.replace(/[a-f]/g, "0");

      const result = await verifier.verifyRequest(signedPayload, tamperedSignature, publicKey);

      expect(result.valid).toBe(false);
      expect(result.error).toContain("Invalid signature");
    });

    it("should reject tampered payload", async () => {
      const { privateKey, publicKey } = AgentKeyGenerator.generate();
      await verifier.registerAgent(publicKey);

      const request = {
        method: "GET",
        path: "/api/test",
        body: {},
        timestamp: Date.now()
      };

      const { signedPayload, signature } = AgentKeyGenerator.signRequest(request, privateKey);

      // Tamper with payload
      signedPayload.path = "/api/admin/delete";

      const result = await verifier.verifyRequest(signedPayload, signature, publicKey);

      expect(result.valid).toBe(false);
    });
  });
});
