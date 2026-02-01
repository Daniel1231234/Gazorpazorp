// src/crypto/key-store.ts
import { Redis } from "ioredis";
import { AgentIdentity } from "./agent-identity.js";

export class KeyStore {
  private redis: Redis;
  private readonly PREFIX = "agent:identity:";

  constructor(redis: Redis) {
    this.redis = redis;
  }

  async saveIdentity(identity: AgentIdentity): Promise<void> {
    const key = `${this.PREFIX}${identity.fingerprint}`;
    await this.redis.set(key, JSON.stringify(identity));
  }

  async getIdentity(fingerprint: string): Promise<AgentIdentity | null> {
    const key = `${this.PREFIX}${fingerprint}`;
    const data = await this.redis.get(key);
    return data ? JSON.parse(data) : null;
  }

  async updateReputation(fingerprint: string, delta: number): Promise<number> {
    const identity = await this.getIdentity(fingerprint);
    if (!identity) throw new Error("Agent not found");

    identity.reputation = Math.max(0, Math.min(100, identity.reputation + delta));
    await this.saveIdentity(identity);
    return identity.reputation;
  }
}
