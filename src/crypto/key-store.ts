// src/crypto/key-store.ts
import { Redis } from "ioredis";
import { AgentIdentity } from "./agent-identity.js";

/**
 * Lua script for atomic reputation update.
 * This prevents race conditions when multiple requests
 * try to update the same agent's reputation simultaneously.
 *
 * KEYS[1] = agent identity key
 * ARGV[1] = delta value
 * ARGV[2] = reason (for audit log)
 *
 * Returns: [new_reputation, success]
 */
const UPDATE_REPUTATION_SCRIPT = `
local data = redis.call('GET', KEYS[1])
if not data then
  return {-1, 0}
end

local identity = cjson.decode(data)
local oldRep = identity.reputation
local delta = tonumber(ARGV[1])
local newRep = math.max(0, math.min(100, oldRep + delta))

identity.reputation = newRep
identity.lastSeen = ARGV[2]

redis.call('SET', KEYS[1], cjson.encode(identity))

-- Log reputation change for audit
local logEntry = cjson.encode({
  timestamp = ARGV[2],
  oldReputation = oldRep,
  newReputation = newRep,
  delta = delta,
  reason = ARGV[3]
})
redis.call('LPUSH', KEYS[2], logEntry)
redis.call('LTRIM', KEYS[2], 0, 99)

return {newRep, 1}
`;

/**
 * Lua script for conditional identity update.
 * Only updates if the lastSeen timestamp is older than the provided one.
 * This prevents lost updates in high-concurrency scenarios.
 */
const CONDITIONAL_UPDATE_SCRIPT = `
local data = redis.call('GET', KEYS[1])
if not data then
  return 0
end

local identity = cjson.decode(data)
local newData = cjson.decode(ARGV[1])

-- Only update if this is newer
if newData.lastSeen > identity.lastSeen then
  redis.call('SET', KEYS[1], ARGV[1])
  return 1
end

return 0
`;

export class KeyStore {
  private redis: Redis;
  private readonly PREFIX = "agent:identity:";
  private readonly REPUTATION_LOG_PREFIX = "agent:reputation_log:";
  private readonly IDENTITY_TTL = 86400 * 365; // 1 year

  constructor(redis: Redis) {
    this.redis = redis;
    this.registerScripts();
  }

  /**
   * Register Lua scripts with Redis for better performance.
   */
  private registerScripts(): void {
    // Define scripts for later use with evalsha
    this.redis.defineCommand("updateReputationAtomic", {
      numberOfKeys: 2,
      lua: UPDATE_REPUTATION_SCRIPT
    });

    this.redis.defineCommand("conditionalUpdate", {
      numberOfKeys: 1,
      lua: CONDITIONAL_UPDATE_SCRIPT
    });
  }

  /**
   * Save agent identity with TTL.
   */
  async saveIdentity(identity: AgentIdentity): Promise<void> {
    const key = `${this.PREFIX}${identity.fingerprint}`;
    await this.redis.setex(key, this.IDENTITY_TTL, JSON.stringify(identity));
  }

  /**
   * Get agent identity by fingerprint.
   */
  async getIdentity(fingerprint: string): Promise<AgentIdentity | null> {
    const key = `${this.PREFIX}${fingerprint}`;
    const data = await this.redis.get(key);

    if (!data) return null;

    const identity = JSON.parse(data);
    // Convert date strings back to Date objects
    identity.registeredAt = new Date(identity.registeredAt);
    identity.lastSeen = new Date(identity.lastSeen);

    return identity;
  }

  /**
   * Atomically update agent reputation using Lua script.
   * This prevents race conditions when multiple requests update the same agent.
   *
   * @param fingerprint - Agent's fingerprint
   * @param delta - Amount to change reputation (positive or negative)
   * @param reason - Reason for the change (for audit log)
   * @returns The new reputation value
   * @throws Error if agent not found
   */
  async updateReputation(fingerprint: string, delta: number, reason: string = "unspecified"): Promise<number> {
    const identityKey = `${this.PREFIX}${fingerprint}`;
    const logKey = `${this.REPUTATION_LOG_PREFIX}${fingerprint}`;
    const timestamp = new Date().toISOString();

    try {
      const result = await (this.redis as any).updateReputationAtomic(identityKey, logKey, delta, timestamp, reason);

      const [newReputation, success] = result as [number, number];

      if (success === 0) {
        throw new Error("Agent not found");
      }

      return newReputation;
    } catch (error: any) {
      // Fallback to non-atomic update if Lua script fails
      // (e.g., if Redis doesn't support Lua or script not loaded)
      if (error.message?.includes("NOSCRIPT") || error.message?.includes("not found")) {
        return this.updateReputationFallback(fingerprint, delta, reason);
      }
      throw error;
    }
  }

  /**
   * Fallback reputation update using optimistic locking with WATCH.
   * Used when Lua scripts are not available.
   */
  private async updateReputationFallback(fingerprint: string, delta: number, reason: string): Promise<number> {
    const key = `${this.PREFIX}${fingerprint}`;
    const logKey = `${this.REPUTATION_LOG_PREFIX}${fingerprint}`;
    const maxRetries = 3;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // Watch the key for changes
        await this.redis.watch(key);

        const data = await this.redis.get(key);
        if (!data) {
          await this.redis.unwatch();
          throw new Error("Agent not found");
        }

        const identity: AgentIdentity = JSON.parse(data);
        const oldReputation = identity.reputation;
        identity.reputation = Math.max(0, Math.min(100, identity.reputation + delta));
        identity.lastSeen = new Date();

        // Execute transaction
        const multi = this.redis.multi();
        multi.setex(key, this.IDENTITY_TTL, JSON.stringify(identity));
        multi.lpush(
          logKey,
          JSON.stringify({
            timestamp: new Date().toISOString(),
            oldReputation,
            newReputation: identity.reputation,
            delta,
            reason
          })
        );
        multi.ltrim(logKey, 0, 99);

        const results = await multi.exec();

        if (results === null) {
          // Transaction aborted due to concurrent modification, retry
          continue;
        }

        return identity.reputation;
      } catch (error) {
        await this.redis.unwatch();
        if (attempt === maxRetries - 1) throw error;
      }
    }

    throw new Error("Failed to update reputation after max retries");
  }

  /**
   * Get reputation history for an agent.
   */
  async getReputationHistory(fingerprint: string, limit: number = 100): Promise<
    Array<{
      timestamp: string;
      oldReputation: number;
      newReputation: number;
      delta: number;
      reason: string;
    }>
  > {
    const logKey = `${this.REPUTATION_LOG_PREFIX}${fingerprint}`;
    const entries = await this.redis.lrange(logKey, 0, limit - 1);
    return entries.map((e) => JSON.parse(e));
  }

  /**
   * Delete an agent identity.
   */
  async deleteIdentity(fingerprint: string): Promise<boolean> {
    const key = `${this.PREFIX}${fingerprint}`;
    const logKey = `${this.REPUTATION_LOG_PREFIX}${fingerprint}`;

    const result = await this.redis.del(key, logKey);
    return result > 0;
  }

  /**
   * Check if an agent exists.
   */
  async exists(fingerprint: string): Promise<boolean> {
    const key = `${this.PREFIX}${fingerprint}`;
    const result = await this.redis.exists(key);
    return result === 1;
  }

  /**
   * Get all agent fingerprints (use with caution in production).
   */
  async getAllFingerprints(): Promise<string[]> {
    const pattern = `${this.PREFIX}*`;
    const keys: string[] = [];
    let cursor = "0";

    do {
      const [newCursor, foundKeys] = await this.redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
      cursor = newCursor;
      keys.push(...foundKeys);
    } while (cursor !== "0");

    return keys.map((key) => key.replace(this.PREFIX, ""));
  }
}
